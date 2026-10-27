"""Shell dialects for generated commands: POSIX sh/bash and Windows cmd.exe.

Plans are built for the machine they will run on. cmd.exe differs in quoting
(`^ & | < > %` are special, quotes are "..."), `cd /d`, `%VAR%`, NUL, and has
no `#` comments, so trailing notes are stripped (they also live in the plan notes).
"""
from __future__ import annotations

import os
import re
import shlex


class Posix:
    name = "sh"
    devnull = "/dev/null"
    script_ext = ".sh"

    @staticmethod
    def q(s: str) -> str:
        return shlex.quote(s)

    def cd(self, d: str) -> str:
        return f"cd {self.q(d)}"

    @staticmethod
    def path(var: str, name: str) -> str:
        return f'"${var}/{name}"'

    def copy_files(self, files: list[str], dest: str) -> str:
        return f"mkdir -p {dest} && cp {' '.join(self.q(f) for f in files)} {dest}/"

    def copy_back(self, src: str, dest: str) -> str:
        return f"cp {src}/* {self.q(dest)}/"

    @staticmethod
    def adapt(cmd: str) -> str:
        return cmd

    @staticmethod
    def split(cmd: str) -> list[str]:
        return shlex.split(cmd, comments=True)


class Cmd:
    name = "cmd"
    devnull = "NUL"
    script_ext = ".cmd"
    _SAFE = re.compile(r"^[A-Za-z0-9_@+=:,./\\-]+$")

    def q(self, s: str) -> str:
        if s and self._SAFE.match(s):
            return s
        return '"' + s.replace('"', '""') + '"'

    def cd(self, d: str) -> str:
        return f"cd /d {self.q(d)}"

    @staticmethod
    def path(var: str, name: str) -> str:
        return f'"%{var}%\\{name}"'

    def copy_files(self, files: list[str], dest: str) -> str:
        return f"(if not exist {dest} mkdir {dest}) && " + " && ".join(f"copy /y {self.q(f)} {dest}" for f in files)

    def copy_back(self, src: str, dest: str) -> str:
        return f"copy /y {src}\\* {self.q(dest)}"

    @staticmethod
    def adapt(cmd: str) -> str:
        if cmd.lstrip().startswith("# "):
            return "rem " + cmd.lstrip()[2:]
        return re.sub(r"\s{2,}#\s.*$", "", cmd)

    @staticmethod
    def split(cmd: str) -> list[str]:
        return [t.strip('"') for t in shlex.split(cmd, posix=False)]


def current():
    return Cmd() if os.name == "nt" else Posix()


def by_name(name: str):
    return Cmd() if name == "cmd" else Posix()
