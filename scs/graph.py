"""Dependency graphs per install location (lockfile, Python env, Homebrew).

Collectors build a DepGraph and tag each Package with meta["graph"] (key in
Context.graphs) and meta["node"]. Analysis then asks for the shortest paths
from the project's direct dependencies to a vulnerable node: the chain of effect.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from scs.models import Package


@dataclass
class DepGraph:
    edges: dict[str, set[str]] = field(default_factory=dict)   # node -> children
    roots: dict[str, str] = field(default_factory=dict)        # direct dependency node -> "prod" | "dev"
    labels: dict[str, str] = field(default_factory=dict)       # node -> "name@version"
    _rev: dict[str, set[str]] | None = None

    def add_node(self, node: str, label: str) -> None:
        self.edges.setdefault(node, set())
        self.labels.setdefault(node, label)

    def add_edge(self, parent: str, child: str) -> None:
        if parent != child:
            self.edges.setdefault(parent, set()).add(child)
            self.edges.setdefault(child, set())
            self._rev = None

    def add_root(self, node: str, kind: str = "prod") -> None:
        if self.roots.get(node) != "prod":  # prod wins over dev
            self.roots[node] = kind
        self.edges.setdefault(node, set())

    def reverse(self) -> dict[str, set[str]]:
        if self._rev is None:
            rev: dict[str, set[str]] = {n: set() for n in self.edges}
            for p, kids in self.edges.items():
                for k in kids:
                    rev.setdefault(k, set()).add(p)
            self._rev = rev
        return self._rev

    def reachable(self, starts) -> set[str]:
        seen = set(starts)
        q = deque(seen)
        while q:
            n = q.popleft()
            for k in self.edges.get(n, ()):
                if k not in seen:
                    seen.add(k)
                    q.append(k)
        return seen

    def paths_to(self, node: str, limit: int = 3) -> list[list[str]]:
        """Shortest root→node paths, at most one per root, nearest roots first."""
        if node not in self.edges:
            return []
        rev = self.reverse()
        toward: dict[str, str | None] = {node: None}  # ancestor -> next hop toward node
        order: list[str] = []
        q = deque([node])
        while q:
            n = q.popleft()
            if n in self.roots:
                order.append(n)
            for p in rev.get(n, ()):
                if p not in toward:
                    toward[p] = n
                    q.append(p)
        paths = []
        for r in order[:limit]:
            path, cur = [], r
            while cur is not None:
                path.append(self.labels.get(cur, cur))
                cur = toward[cur]
            paths.append(path)
        return paths

    def introduced_by(self, node: str) -> list[str]:
        """All direct dependencies that (transitively) pull this node in."""
        rev = self.reverse()
        seen = {node}
        q = deque([node])
        roots = []
        while q:
            n = q.popleft()
            if n in self.roots:
                roots.append(self.labels.get(n, n))
            for p in rev.get(n, ()):
                if p not in seen:
                    seen.add(p)
                    q.append(p)
        return sorted(roots)


def finalize(graph: DepGraph, pkgs: list[Package], key: str) -> None:
    """Tag packages with the graph key and derive direct/dev from reachability."""
    prod_roots = [n for n, k in graph.roots.items() if k == "prod"]
    prod = graph.reachable(prod_roots) if graph.roots else set()
    for p in pkgs:
        node = p.meta.get("node")
        if not node or node not in graph.edges:
            continue
        p.meta["graph"] = key
        if graph.roots:
            p.direct = node in graph.roots
            if prod_roots or any(k == "dev" for k in graph.roots.values()):
                p.dev = p.dev or node not in prod


def annotate(pkgs: list[Package], graphs: dict[str, DepGraph]) -> None:
    """Fill chain-of-effect fields for packages that are part of a finding."""
    for p in pkgs:
        g = graphs.get(p.meta.get("graph", ""))
        node = p.meta.get("node")
        if not g or not node:
            continue
        paths = g.paths_to(node)
        if paths:
            p.chain = paths[0][:-1]
            p.meta["paths"] = paths
        intro = g.introduced_by(node)
        if intro:
            p.meta["introduced_by"] = intro[:25]
            p.meta["introduced_by_count"] = len(intro)
