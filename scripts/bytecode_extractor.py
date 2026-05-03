import ast
from pathlib import Path


def extract_byte_literal(filepath: Path):
    source = filepath.read_text(encoding="utf-8")
    tree = ast.parse(source)

    byte_literals = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for arg in node.args:
                if isinstance(arg, ast.Bytes):
                    byte_literals.append(arg.s)

    return byte_literals


def main():
    target = Path("dist/payload.py")
    if not target.exists():
        print("x.py not found.")
        return

    literals = extract_byte_literal(target)

    # Store results as raw bytes without interpretation
    for i, b in enumerate(literals, 1):
        print(f"Found byte literal #{i}, length={len(b)}")
        print(b)


if __name__ == "__main__":
    main()
