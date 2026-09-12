import ast
import json
from pathlib import Path


def extract_imports(filepath: Path):
    """Extract imported module names from a Python file using AST."""
    imports = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(filepath))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module.split(".")[0])
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")

    return sorted(list(set(imports)))


def build_graph_data(directory: str = "test_project", output_file: str = "graph_data.json"):
    """Scan Python files and generate vis-network node and edge graph data."""
    project_dir = Path(directory)
    if not project_dir.exists():
        print(f"Directory '{directory}' does not exist.")
        return {"nodes": [], "edges": []}

    py_files = sorted(project_dir.glob("*.py"))
    # Map module name (e.g. 'auth') to file name (e.g. 'auth.py')
    module_to_file = {f.stem: f.name for f in py_files}
    file_names = [f.name for f in py_files]

    raw_deps = {}
    for py_file in py_files:
        raw_deps[py_file.name] = extract_imports(py_file)

    edges = []
    incoming_counts = {name: 0 for name in file_names}
    outgoing_counts = {name: 0 for name in file_names}
    incoming_deps = {name: [] for name in file_names}
    outgoing_deps = {name: [] for name in file_names}

    for source_file, imported_modules in raw_deps.items():
        for mod in imported_modules:
            target_file = module_to_file.get(mod)
            if target_file and target_file in incoming_counts:
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
    for file_name in file_names:
        in_count = incoming_counts[file_name]
        out_count = outgoing_counts[file_name]
        
        # If imported by 2 or more files, color is red (#ef4444); otherwise blue (#3b82f6)
        color = "#ef4444" if in_count >= 2 else "#3b82f6"

        nodes.append({
            "id": file_name,
            "label": file_name,
            "color": color,
            "incoming_count": in_count,
            "outgoing_count": out_count,
            "incoming_dependencies": sorted(incoming_deps[file_name]),
            "outgoing_dependencies": sorted(outgoing_deps[file_name]),
            "size": 26 + (in_count * 8),  # visual scaling with importance
            "font": {
                "color": "#f8fafc",
                "size": 14,
                "face": "Inter, system-ui, sans-serif"
            }
        })

    graph_data = {
        "nodes": nodes,
        "edges": edges
    }

    output_path = Path(output_file)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(graph_data, f, indent=2)

    print(f"Graph data successfully generated and saved to {output_file}:")
    print(json.dumps(graph_data, indent=2))
    return graph_data


def main():
    build_graph_data("test_project", "graph_data.json")


if __name__ == "__main__":
    main()
