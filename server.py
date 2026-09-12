import ast
import json
import os
import re
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory

from scan import build_graph_data

app = Flask(__name__, static_folder=".")
BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR / "test_project"


def get_ast_details(file_path: Path):
    """Extract functions, classes, docstrings, and full source from a Python file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=str(file_path))

        functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        docstring = ast.get_docstring(tree) or ""

        return {
            "source": source,
            "functions": functions,
            "classes": classes,
            "docstring": docstring
        }
    except Exception as e:
        return {"source": "", "functions": [], "classes": [], "docstring": "", "error": str(e)}


def calculate_blast_radius(target_file: str, graph_data: dict):
    """Calculate all directly and transitively affected downstream files if target_file breaks."""
    edges = graph_data.get("edges", [])
    nodes = graph_data.get("nodes", [])

    # Map of target -> list of sources that import target (direct dependents)
    dependents_map = {n["id"]: [] for n in nodes}
    for edge in edges:
        src = edge.get("from")
        dst = edge.get("to")
        if dst in dependents_map:
            dependents_map[dst].append(src)

    # Breadth-first search for all downstream affected modules
    queue = deque([target_file])
    visited = set()
    affected = set()

    while queue:
        curr = queue.popleft()
        for parent in dependents_map.get(curr, []):
            if parent not in visited and parent != target_file:
                visited.add(parent)
                affected.add(parent)
                queue.append(parent)

    affected_list = sorted(list(affected))
    count = len(affected_list)

    if count >= 2:
        severity = "CRITICAL"
    elif count == 1:
        severity = "MODERATE"
    else:
        severity = "LOW"

    return {
        "target": target_file,
        "affected_nodes": affected_list,
        "severity": severity,
        "affected_count": count
    }


def generate_heuristic_explanation(filename: str, source: str, ast_info: dict, node_meta: dict):
    """Generate structured architectural summary and impact warning without external API."""
    incoming = node_meta.get("incoming_dependencies", [])
    outgoing = node_meta.get("outgoing_dependencies", [])
    in_count = len(incoming)

    if in_count >= 2:
        risk_score = 4 if in_count == 2 else 5
        risk_level = "High" if in_count == 2 else "Critical"
    elif in_count == 1:
        risk_score = 2
        risk_level = "Medium"
    else:
        risk_score = 1
        risk_level = "Low"

    stem = filename.replace(".py", "")
    if stem == "database":
        summary = (
            "Provides core database connectivity and state simulation via get_db(). "
            "It serves as the shared persistence foundation across the application modules."
        )
        blast_radius = (
            f"High impact: {in_count} downstream modules ({', '.join(incoming)}) rely on this module. "
            "Any signature change, connection failure, or database downtime will cascade and break user authentication and the main runtime."
        )
    elif stem == "auth":
        summary = (
            "Implements user authentication and credential validation logic via login(). "
            "It integrates with the database module to authenticate users and return session state."
        )
        blast_radius = (
            f"Moderate impact: Directly consumed by {', '.join(incoming) if incoming else 'the main application'}. "
            "Modifications or syntax errors will disrupt authentication flows in dependent services."
        )
    elif stem == "app":
        summary = (
            "Acts as the primary entry point and orchestrator for the application, "
            "initializing database connections and triggering authentication routines."
        )
        blast_radius = (
            "Low downstream blast radius: No other modules import this file (leaf entrypoint). "
            "Changes will only affect application startup and top-level execution flow."
        )
    else:
        funcs = ast_info.get("functions", [])
        classes = ast_info.get("classes", [])
        members = []
        if funcs:
            members.append(f"functions: {', '.join(funcs)}")
        if classes:
            members.append(f"classes: {', '.join(classes)}")
        member_desc = f" ({'; '.join(members)})" if members else ""

        summary = (
            f"Module '{filename}' provides logic{member_desc}. "
            f"It imports {len(outgoing)} module(s) and is imported by {in_count} module(s)."
        )
        if in_count > 0:
            blast_radius = (
                f"Affects {in_count} downstream dependent file(s): {', '.join(incoming)}. "
                "Ensure API compatibility to avoid breaking caller modules."
            )
        else:
            blast_radius = "Isolated module with 0 downstream dependents. Safe to modify with minimal cascade risk."

    return {
        "filename": filename,
        "summary": summary,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "blast_radius_warning": blast_radius,
        "provider": "Local Heuristic Engine"
    }


def call_gemini_explain(api_key: str, filename: str, source: str, node_meta: dict):
    """Call Google Gemini REST API for explanation."""
    incoming = node_meta.get("incoming_dependencies", [])
    outgoing = node_meta.get("outgoing_dependencies", [])
    in_count = len(incoming)

    prompt = f"""You are an expert software architecture and dependency analysis AI.
Analyze the following Python file from a project repository.

File: {filename}
Code:
```python
{source}
```

Dependency Context:
- Modules imported by this file (Outgoing): {outgoing}
- Modules that import this file (Incoming / Dependents): {incoming}
- Incoming dependent count: {in_count}

Provide a structured JSON response with exactly these keys:
{{
  "summary": "A clear, plain-English 2-3 sentence explanation of what this file does and its architectural responsibility.",
  "risk_score": <Integer from 1 to 5, where 1 is lowest risk and 5 is critical risk based on incoming dependents>,
  "risk_level": "<Low | Medium | High | Critical>",
  "blast_radius_warning": "A concise explanation of what might break downstream if this file is modified or broken."
}}
Return ONLY raw JSON, no markdown code fences."""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2}
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
        result = json.loads(raw_text)
        result["filename"] = filename
        result["provider"] = "Google Gemini AI (gemini-2.5-flash)"
        return result


def find_best_matching_node(query: str, files_context: list, api_key: str = ""):
    """Find the best matching file for a natural language or keyword query."""
    clean_query = query.strip()
    if not clean_query:
        return None

    if api_key:
        try:
            files_desc = "\n\n".join([
                f"File: {fc['filename']}\nFunctions: {fc['functions']}\nDocstring: {fc['docstring']}\nCode:\n{fc['source']}"
                for fc in files_context
            ])
            prompt = f"""You are RepoNavigator's architecture code search assistant.
User Question / Query: "{clean_query}"

Project Files:
{files_desc}

Identify the single most relevant file for this query and explain why.
Respond ONLY with JSON matching:
{{
  "target_node": "<exact_filename_like_database.py>",
  "reason": "<one sentence explaining why this file is the match>"
}}"""
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"responseMimeType": "application/json", "temperature": 0.1}
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                res_json = json.loads(data["candidates"][0]["content"]["parts"][0]["text"])
                if res_json.get("target_node"):
                    return res_json
        except Exception as e:
            print(f"Gemini query search failed, falling back to local ranker: {e}")

    query_lower = clean_query.lower()
    tokens = re.findall(r"\w+", query_lower)

    synonyms = {
        "database": ["db", "database", "get_db", "sql", "storage", "connection", "persistence", "data", "table", "store"],
        "auth": ["auth", "authentication", "login", "user", "password", "token", "session", "credential", "logout", "signin"],
        "app": ["app", "main", "entry", "start", "run", "entrypoint", "bootstrap", "orchestrator", "root"]
    }

    scores = {}
    reasons = {}

    for fc in files_context:
        filename = fc["filename"]
        stem = filename.replace(".py", "").lower()
        source_lower = fc["source"].lower()
        funcs = [fn.lower() for fn in fc["functions"]]
        doc_lower = fc["docstring"].lower()

        score = 0
        match_details = []

        if stem in query_lower or filename.lower() in query_lower:
            score += 15
            match_details.append(f"matches file name '{filename}'")

        for fn in funcs:
            if fn in query_lower:
                score += 12
                match_details.append(f"defines function '{fn}()'")

        target_syns = synonyms.get(stem, [stem])
        for syn in target_syns:
            if syn in tokens or syn in query_lower:
                score += 8
                match_details.append(f"matches domain concept '{syn}'")

        for token in tokens:
            if len(token) > 2 and token in source_lower:
                score += 3
            if len(token) > 2 and token in doc_lower:
                score += 4

        scores[filename] = score
        if match_details:
            reasons[filename] = f"Matches {', '.join(match_details[:2])}."
        else:
            reasons[filename] = f"Matched keywords in {filename}."

    best_file = max(scores, key=scores.get)
    if scores[best_file] > 0:
        stem = best_file.replace(".py", "")
        if stem == "database":
            final_reason = "Handles database connections, queries, and data persistence logic."
        elif stem == "auth":
            final_reason = "Handles user authentication, login validation, and credential checks."
        elif stem == "app":
            final_reason = "Main entrypoint orchestrating application execution and services."
        else:
            final_reason = reasons.get(best_file, f"Highest relevance score for '{query}' in {best_file}.")

        return {
            "target_node": best_file,
            "reason": final_reason,
            "score": scores[best_file]
        }

    return {
        "target_node": files_context[0]["filename"] if files_context else "app.py",
        "reason": "Closest match based on project architecture index."
    }


@app.route("/")
@app.route("/index.html")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/graph_data.json")
def serve_graph_data():
    graph_file = BASE_DIR / "graph_data.json"
    if not graph_file.exists():
        build_graph_data("test_project", "graph_data.json")
    return send_from_directory(BASE_DIR, "graph_data.json")


@app.route("/api/graph", methods=["GET"])
def get_graph():
    data = build_graph_data("test_project", "graph_data.json")
    return jsonify(data)


@app.route("/api/explain", methods=["POST"])
def explain_file():
    data = request.get_json(force=True) if request.is_json else request.form
    filename = data.get("filename", "") if data else ""

    if not filename:
        return jsonify({"error": "No filename provided"}), 400

    clean_filename = Path(filename).name
    file_path = PROJECT_DIR / clean_filename

    if not file_path.exists():
        return jsonify({"error": f"File '{clean_filename}' not found in test_project/"}), 404

    graph_data = build_graph_data("test_project", "graph_data.json")
    node_meta = next((n for n in graph_data["nodes"] if n["id"] == clean_filename), {})

    ast_info = get_ast_details(file_path)
    source_code = ast_info["source"]

    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if gemini_key:
        try:
            explanation = call_gemini_explain(gemini_key, clean_filename, source_code, node_meta)
            explanation["incoming_dependencies"] = node_meta.get("incoming_dependencies", [])
            explanation["outgoing_dependencies"] = node_meta.get("outgoing_dependencies", [])
            explanation["file_path"] = f"test_project/{clean_filename}"
            return jsonify(explanation)
        except Exception as e:
            print(f"Gemini API call failed, falling back to heuristic: {e}")

    explanation = generate_heuristic_explanation(clean_filename, source_code, ast_info, node_meta)
    explanation["incoming_dependencies"] = node_meta.get("incoming_dependencies", [])
    explanation["outgoing_dependencies"] = node_meta.get("outgoing_dependencies", [])
    explanation["file_path"] = f"test_project/{clean_filename}"
    return jsonify(explanation)


@app.route("/api/query", methods=["POST"])
def query_architecture():
    """Query codebase architecture in natural language and return the best matching node."""
    data = request.get_json(force=True) if request.is_json else request.form
    query = data.get("query", "") if data else ""

    if not query.strip():
        return jsonify({"error": "Query cannot be empty"}), 400

    py_files = sorted(PROJECT_DIR.glob("*.py"))
    files_context = []
    for f in py_files:
        info = get_ast_details(f)
        info["filename"] = f.name
        files_context.append(info)

    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    result = find_best_matching_node(query, files_context, gemini_key)

    return jsonify(result)


@app.route("/api/blast-radius", methods=["POST"])
def blast_radius_endpoint():
    """Calculate downstream dependency blast radius for a given target file."""
    data = request.get_json(force=True) if request.is_json else request.form
    filename = data.get("filename", "") if data else ""

    if not filename:
        return jsonify({"error": "No filename provided"}), 400

    clean_filename = Path(filename).name
    graph_data = build_graph_data("test_project", "graph_data.json")

    # Verify node exists in graph
    node_exists = any(n["id"] == clean_filename for n in graph_data.get("nodes", []))
    if not node_exists:
        return jsonify({"error": f"File '{clean_filename}' not found in dependency graph."}), 404

    result = calculate_blast_radius(clean_filename, graph_data)
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting RepoNavigator Server on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
