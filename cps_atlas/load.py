"""Загрузка атласа: записи, источники, словари и схемы."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent
VOCABS = ("scii", "positions", "sectors", "attack", "slsa")


class _Loader(yaml.SafeLoader):
    """SafeLoader без неявного преобразования дат: даты остаются строками, как в схеме."""


_Loader.yaml_implicit_resolvers = {
    ch: [(tag, rx) for tag, rx in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for ch, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def read_yaml(path: Path):
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=_Loader)  # загрузчик наследует SafeLoader


def find_root(start: Path | None = None) -> Path:
    """Каталог атласа: ближайший вверх от start (или текущего) с data/records, vocab и schema."""
    here = (start or Path.cwd()).resolve()
    for cand in (here, *here.parents, PACKAGE_DIR.parent):
        if all((cand / d).is_dir() for d in ("data/records", "vocab", "schema")):
            return cand
    raise FileNotFoundError("не найден каталог атласа: нужны data/records, vocab и schema")


@dataclass
class Atlas:
    root: Path
    records: list
    record_files: dict
    sources: list
    vocab: dict
    schemas: dict
    sources_doc: dict = field(default_factory=dict)
    load_errors: list = field(default_factory=list)

    @property
    def source_index(self) -> dict:
        return {s["id"]: s for s in self.sources if isinstance(s, dict) and "id" in s}

    @property
    def evidence_index(self) -> dict:
        return {e["id"]: e for e in self.vocab["scii"]["evidence"]}

    @property
    def technique_index(self) -> dict:
        return {t["id"]: t for t in self.vocab["attack"]["techniques"]}

    @property
    def object_index(self) -> dict:
        return {o["id"]: o for o in self.vocab["attack"]["objects"]}

    @property
    def position_index(self) -> dict:
        return {p["id"]: p for p in self.vocab["positions"]["positions"]}

    @property
    def sector_index(self) -> dict:
        return {s["id"]: s for s in self.vocab["sectors"]["sectors"]}

    @property
    def slsa_index(self) -> dict:
        return {t["id"]: t for t in self.vocab["slsa"]["threats"]}

    def record(self, rid: str) -> dict:
        for r in self.records:
            if r.get("id") == rid:
                return r
        raise KeyError(rid)


def load(root: Path | None = None) -> Atlas:
    root = Path(root) if root else find_root()
    errors = []
    records, files = [], {}
    for path in sorted((root / "data" / "records").glob("*.yaml")):
        try:
            rec = read_yaml(path)
        except yaml.YAMLError as e:
            errors.append(f"{path.name}: YAML: {e}")
            continue
        if not isinstance(rec, dict):
            errors.append(f"{path.name}: запись должна быть словарём")
            continue
        rid = rec.get("id", path.stem)
        if rid in files:
            errors.append(f"{path.name}: id {rid} уже есть в {files[rid].name}")
            continue
        records.append(rec)
        files[rid] = path
    records.sort(key=lambda r: str(r.get("id", "")))
    src = read_yaml(root / "data" / "sources.yaml")
    vocab = {name: read_yaml(root / "vocab" / f"{name}.yaml") for name in VOCABS}
    schemas = {name: json.loads((root / "schema" / f"{name}.schema.json").read_text(encoding="utf-8"))
               for name in ("record", "sources")}
    src = src if isinstance(src, dict) else {}
    return Atlas(root=root, records=records, record_files=files, sources=src.get("sources") or [],
                 vocab=vocab, schemas=schemas, sources_doc=src, load_errors=errors)
