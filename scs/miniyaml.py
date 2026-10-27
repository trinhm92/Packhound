"""Block-mapping YAML subset, enough for pnpm-lock.yaml.

Handles nested mappings by indentation, quoted keys, and scalar values.
Flow collections ({...}, [...]) are kept as raw strings and block
sequences ("- x") are ignored: pnpm only uses them for metadata we skip.
"""
from __future__ import annotations


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        inner = s[1:-1]
        return inner.replace("''", "'") if s[0] == "'" else inner.replace('\\"', '"')
    return s


def _split_key(line: str) -> tuple[str, str] | None:
    if line[0] in "'\"":
        q = line[0]
        i = 1
        while i < len(line):
            if line[i] == q:
                if q == "'" and line[i + 1:i + 2] == "'":  # escaped '' inside single quotes
                    i += 2
                    continue
                break
            i += 1
        key, rest = line[:i + 1], line[i + 1:]
        if not rest.startswith(":"):
            return None
        return _unquote(key), rest[1:].strip()
    idx = line.find(": ")
    if idx == -1:
        if line.endswith(":"):
            return line[:-1].strip(), ""
        return None
    return line[:idx].strip(), line[idx + 2:].strip()


def loads(text: str) -> dict:
    root: dict = {}
    stack: list[tuple[int, dict]] = [(-1, root)]
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("- ") or stripped == "-":
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            stack = [(-1, root)]
        parent = stack[-1][1]
        kv = _split_key(stripped)
        if kv is None:
            continue
        key, val = kv
        if val == "" or val in ("|", ">", "|-", ">-"):
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            if " #" in val and val[0] not in "'\"":
                val = val.split(" #", 1)[0].rstrip()
            parent[key] = _unquote(val)
    return root
