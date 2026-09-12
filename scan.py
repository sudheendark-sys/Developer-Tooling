import ast
import json
import os
from pathlib import Path


EXCLUDE_DIRS = {
    ".git", "__pycache__", "venv", ".venv", "env", ".env",
    "node_modules", "build", "dist", ".tox", ".pytest_cache",
    ".mypy_cache", "site-packages", ".idea", ".vscode"
}


def should_skip_dir(dir_path: Path) -> bool:
    """Check if directory is in exclusion list."""
    for part in dir_path.parts:
        if part in EXCLUDE_DIRS or part.startswith("."):
            return True
    return False


def is_test_file(rel_path: str, filename: str) -> bool:
    """Detect if a Python file is a unit test or integration test file."""
    rel_lower = rel_path.lower().replace("\\", "/")
    fn_lower = filename.lower()
    return (
        fn_lower.startswith("test_")
        or fn_lower.endswith("_test.py")
        or "/tests/" in f"/{rel_lower}"
        or "/test/" in f"/{rel_lower}"
        or rel_lower.startswith("tests/")
        or rel_lower.startswith("test/")
        or "conftest.py" == fn_lower
    )


def extract_imports(filepath: Path):
    """Extract imported module names and relative imports from a Python file using AST."""
    imports = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            tree = ast.parse(f.read(), filename=str(filepath))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
                    imports.append(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
                    imports.append(node.module.split(".")[0])
                    for alias in node.names:
                        imports.append(f"{node.module}.{alias.name}")
                        imports.append(alias.name)
                else:
                    for alias in node.names:
                        imports.append(alias.name)
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")

    return sorted(list(set(imports)))


def find_all_py_files(project_dir: Path):
    """Recursively find all Python files in directory excluding unwanted folders."""
    py_files = []
    for root, dirs, files in os.walk(project_dir):
        rel_root = Path(root).relative_to(project_dir)
        if should_skip_dir(rel_root):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for file in files:
            if file.endswith(".py") and not file.startswith("."):
                py_files.append(Path(root) / file)
    return sorted(py_files)


def build_graph_data(directory: str = "test_project", output_file: str = "graph_data.json"):
    """Scan Python files recursively and generate vis-network node and edge graph data."""
    project_dir = Path(directory).resolve()
    if not project_dir.exists():
        print(f"Directory '{directory}' does not exist.")
        return {"nodes": [], "edges": [], "stats": {"total_files": 0, "total_connections": 0, "critical_hubs": 0}}

    py_files = find_all_py_files(project_dir)
    if not py_files:
        py_files = sorted(project_dir.glob("*.py"))

    file_id_map = {}
    module_lookup = {}
    nodes_info = {}

    for py_file in py_files:
        rel_path = py_file.relative_to(project_dir).as_posix()
        file_id_map[rel_path] = rel_path
        
        stem = py_file.stem
        if stem not in module_lookup:
            module_lookup[stem] = rel_path
            
        if py_file.name not in module_lookup:
            module_lookup[py_file.name] = rel_path

        dotted = rel_path.replace(".py", "").replace("/", ".")
        module_lookup[dotted] = rel_path

        nodes_info[rel_path] = {
            "path": py_file,
            "rel_path": rel_path,
            "stem": stem,
            "filename": py_file.name,
            "is_test": is_test_file(rel_path, py_file.name)
        }

    raw_deps = {}
    for rel_path, info in nodes_info.items():
        raw_deps[rel_path] = extract_imports(info["path"])

    edges = []
    seen_edges = set()
    incoming_counts = {name: 0 for name in nodes_info}
    outgoing_counts = {name: 0 for name in nodes_info}
    incoming_deps = {name: [] for name in nodes_info}
    outgoing_deps = {name: [] for name in nodes_info}

    for source_file, imported_modules in raw_deps.items():
        for mod in imported_modules:
            target_file = module_lookup.get(mod)
            if target_file and target_file in nodes_info and target_file != source_file:
                edge_key = (source_file, target_file)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append({
                        "from": source_file,
                        "to": target_file,
                        "arrows": "to"
                    })
                    incoming_counts[target_file] += 1
                    outgoing_counts[source_file] += 1
                    incoming_deps[target_file].append(source_file)
                    outgoing_deps[source_file].append(target_file)

    nodes = []
    critical_hub_count = 0

    for rel_path, info in nodes_info.items():
        in_count = incoming_counts[rel_path]
        out_count = outgoing_counts[rel_path]
        is_critical = in_count >= 2

        if is_critical:
            critical_hub_count += 1
            color = "#ef4444"
            # Central bottlenecks appear larger and prominent
            node_size = 34 + min((in_count - 2) * 5, 24)
        elif in_count == 1:
            color = "#3b82f6"
            node_size = 27
        else:
            color = "#3b82f6"
            # Leaf files stay smaller and cleaner
            node_size = 22

        nodes.append({
            "id": rel_path,
            "label": info["filename"],
            "rel_path": rel_path,
            "is_test": info["is_test"],
            "color": color,
            "incoming_count": in_count,
            "outgoing_count": out_count,
            "incoming_dependencies": sorted(incoming_deps[rel_path]),
            "outgoing_dependencies": sorted(outgoing_deps[rel_path]),
            "size": node_size,
            "font": {
                "color": "#f8fafc",
                "size": 14,
                "face": "Inter, system-ui, sans-serif"
            }
        })

    graph_data = {
        "nodes": nodes,
        "edges": edges,
        "total_files": len(nodes),
        "total_connections": len(edges),
        "critical_hubs": critical_hub_count,
        "stats": {
            "total_files": len(nodes),
            "total_connections": len(edges),
            "critical_hubs": critical_hub_count
        }
    }

    if output_file:
        output_path = Path(output_file)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2)

    return graph_data


def main():
    graph_data = build_graph_data("test_project", "graph_data.json")
    print(f"Graph data generated: {len(graph_data['nodes'])} nodes, {len(graph_data['edges'])} edges, {graph_data['critical_hubs']} critical hubs.")


if __name__ == "__main__":
    main()
