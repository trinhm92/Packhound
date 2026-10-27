"""TOML reader: stdlib tomllib on 3.11+, otherwise a small subset parser.

The subset covers what lockfiles and pyproject/Cargo manifests use: tables,
arrays of tables, dotted/quoted keys, strings (basic, literal, multi-line),
numbers, booleans, dates (kept as strings), arrays and inline tables.
"""
from __future__ import annotations

import re
from typing import Any

try:  # Python 3.11+
    import tomllib as _tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - depends on interpreter
    _tomllib = None


class TomlError(ValueError):
    pass


def loads(text: str) -> dict:
    if _tomllib is not None:
        return _tomllib.loads(text)
    return _Parser(text).parse()


def load_path(path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return loads(f.read())


_BARE = re.compile(r"[A-Za-z0-9_-]+")
_SCALAR = re.compile(r"[^\s,\]\}#]+")
_ESC = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}


class _Parser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0

    # -- helpers
    def _peek(self, n: int = 1) -> str:
        return self.s[self.i:self.i + n]

    def _ws(self, newlines: bool = False) -> None:
        while self.i < len(self.s):
            c = self.s[self.i]
            if c in " \t" or (newlines and c in "\r\n"):
                self.i += 1
            elif c == "#":
                while self.i < len(self.s) and self.s[self.i] != "\n":
                    self.i += 1
            else:
                break

    def _expect(self, ch: str) -> None:
        if self._peek(len(ch)) != ch:
            raise TomlError(f"expected {ch!r} at {self.i}: {self.s[self.i:self.i + 30]!r}")
        self.i += len(ch)

    # -- grammar
    def parse(self) -> dict:
        root: dict = {}
        cur = root
        while True:
            self._ws(newlines=True)
            if self.i >= len(self.s):
                return root
            if self._peek(2) == "[[":
                self.i += 2
                keys = self._key()
                self._expect("]]")
                parent = self._walk(root, keys[:-1])
                arr = parent.setdefault(keys[-1], [])
                if not isinstance(arr, list):
                    raise TomlError(f"{keys} is not an array of tables")
                cur = {}
                arr.append(cur)
            elif self._peek() == "[":
                self.i += 1
                keys = self._key()
                self._expect("]")
                cur = self._walk(root, keys)
            else:
                keys = self._key()
                self._ws()
                self._expect("=")
                self._ws()
                target = self._walk(cur, keys[:-1])
                target[keys[-1]] = self._value()
            self._ws()
            if self.i < len(self.s) and self.s[self.i] not in "\r\n":
                raise TomlError(f"trailing data at {self.i}: {self.s[self.i:self.i + 30]!r}")

    @staticmethod
    def _walk(d: dict, keys: list[str]) -> dict:
        for k in keys:
            nxt = d.setdefault(k, {})
            if isinstance(nxt, list):  # [a.b] after [[a]] refers to the last element
                nxt = nxt[-1]
            d = nxt
        return d

    def _key(self) -> list[str]:
        keys = []
        while True:
            self._ws()
            c = self._peek()
            if c == '"':
                keys.append(self._basic_string())
            elif c == "'":
                keys.append(self._literal_string())
            else:
                m = _BARE.match(self.s, self.i)
                if not m:
                    raise TomlError(f"bad key at {self.i}")
                keys.append(m.group())
                self.i = m.end()
            self._ws()
            if self._peek() == ".":
                self.i += 1
                continue
            return keys

    def _value(self) -> Any:
        c = self._peek()
        if self._peek(3) == '"""':
            return self._ml_basic()
        if self._peek(3) == "'''":
            return self._ml_literal()
        if c == '"':
            return self._basic_string()
        if c == "'":
            return self._literal_string()
        if c == "[":
            return self._array()
        if c == "{":
            return self._inline_table()
        m = _SCALAR.match(self.s, self.i)
        if not m:
            raise TomlError(f"bad value at {self.i}")
        tok = m.group()
        self.i = m.end()
        # dates like "1979-05-27 07:32:00" may contain one space
        if re.match(r"^\d{4}-\d{2}-\d{2}$", tok) and re.match(r" \d{2}:\d{2}", self.s[self.i:self.i + 6]):
            m2 = _SCALAR.match(self.s, self.i + 1)
            tok += " " + m2.group()
            self.i = m2.end()
        if tok == "true":
            return True
        if tok == "false":
            return False
        num = tok.replace("_", "")
        try:
            return int(num, 0) if re.match(r"^[+-]?(0[xob])?[0-9a-fA-F]+$", num) and not re.match(r"^[+-]?0\d", num) else float(num)
        except ValueError:
            return tok  # dates/times and anything exotic stay strings

    def _basic_string(self) -> str:
        self._expect('"')
        out = []
        while True:
            if self.i >= len(self.s):
                raise TomlError("unterminated string")
            c = self.s[self.i]
            if c == '"':
                self.i += 1
                return "".join(out)
            if c == "\\":
                out.append(self._escape())
                continue
            out.append(c)
            self.i += 1

    def _escape(self) -> str:
        nxt = self.s[self.i + 1]
        if nxt in _ESC:
            self.i += 2
            return _ESC[nxt]
        if nxt in "uU":
            n = 4 if nxt == "u" else 8
            code = self.s[self.i + 2:self.i + 2 + n]
            self.i += 2 + n
            return chr(int(code, 16))
        raise TomlError(f"bad escape at {self.i}")

    def _literal_string(self) -> str:
        self._expect("'")
        end = self.s.index("'", self.i)
        val = self.s[self.i:end]
        self.i = end + 1
        return val

    def _ml_basic(self) -> str:
        self._expect('"""')
        if self._peek() == "\n":
            self.i += 1
        out = []
        while True:
            if self._peek(3) == '"""':
                self.i += 3
                return "".join(out)
            c = self.s[self.i]
            if c == "\\":
                if self.s[self.i + 1] in " \t\r\n":  # line-ending backslash
                    self.i += 1
                    self._ws(newlines=True)
                    continue
                out.append(self._escape())
                continue
            out.append(c)
            self.i += 1

    def _ml_literal(self) -> str:
        self._expect("'''")
        if self._peek() == "\n":
            self.i += 1
        end = self.s.index("'''", self.i)
        val = self.s[self.i:end]
        self.i = end + 3
        return val

    def _array(self) -> list:
        self._expect("[")
        out = []
        while True:
            self._ws(newlines=True)
            if self._peek() == "]":
                self.i += 1
                return out
            out.append(self._value())
            self._ws(newlines=True)
            if self._peek() == ",":
                self.i += 1

    def _inline_table(self) -> dict:
        self._expect("{")
        out: dict = {}
        while True:
            self._ws()
            if self._peek() == "}":
                self.i += 1
                return out
            keys = self._key()
            self._ws()
            self._expect("=")
            self._ws()
            self._walk(out, keys[:-1])[keys[-1]] = self._value()
            self._ws()
            if self._peek() == ",":
                self.i += 1
