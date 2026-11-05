"""Командная строка: cps-atlas validate | build | check | stats | show ID."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analysis import states_by_evidence, summary
from .export import build_exports
from .load import find_root, load
from .tables import render
from .validate import check

EXPORTS_DIR = "exports"
TABLES_PATH = "docs/tables.md"


def generated(atlas) -> dict:
    """{относительный путь: содержимое} для всех создаваемых файлов."""
    out = {f"{EXPORTS_DIR}/{name}": text for name, text in build_exports(atlas).items()}
    out[TABLES_PATH] = render(atlas)
    return out


def _validated(root):
    atlas = load(root)
    errors = check(atlas)
    for e in errors:
        print(f"ошибка: {e}", file=sys.stderr)
    return atlas, errors


def cmd_validate(args) -> int:
    atlas, errors = _validated(args.root)
    if errors:
        print(f"ошибок: {len(errors)}", file=sys.stderr)
        return 1
    print(f"атлас корректен: записей {len(atlas.records)}, источников {len(atlas.sources)}")
    return 0


def cmd_build(args) -> int:
    atlas, errors = _validated(args.root)
    if errors:
        print("выгрузки не созданы: исправьте ошибки", file=sys.stderr)
        return 1
    for rel, text in generated(atlas).items():
        path = atlas.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"записан {rel}")
    return 0


def cmd_check(args) -> int:
    atlas, errors = _validated(args.root)
    stale = []
    if not errors:
        for rel, text in generated(atlas).items():
            path = atlas.root / rel
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(rel)
    for rel in stale:
        print(f"устарел: {rel} (выполните cps-atlas build)", file=sys.stderr)
    if errors or stale:
        return 1
    print(f"атлас корректен, выгрузки актуальны: записей {len(atlas.records)}")
    return 0


def cmd_stats(args) -> int:
    atlas, errors = _validated(args.root)
    if errors:
        return 1
    print(json.dumps(summary(atlas), ensure_ascii=False, indent=2))
    return 0


def cmd_show(args) -> int:
    atlas = load(args.root)
    try:
        r = atlas.record(args.id)
    except KeyError:
        print(f"нет записи {args.id}", file=sys.stderr)
        return 2
    src = atlas.source_index
    print(f"{r['id']}: {r['title']} ({r['type']}, {r['cps_relevance']}, {r['year']})")
    print(" ".join(r["summary"].split()))
    print("\nФакты:")
    for i, f in enumerate(r["facts"], 1):
        loc = f" [{f['locator']}]" if f.get("locator") else ""
        print(f"  {i}. {' '.join(f['text'].split())}{loc}")
        for s in f["sources"]:
            print(f"     — {src[s]['publisher']}: {src[s]['title']} — {src[s]['url']}")
    print(f"\nSCII ({r['scii']['scope']}), оценка автора:")
    for e, st in states_by_evidence(r).items():
        print(f"  {e}: {'/'.join(st)}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cps-atlas", description=__doc__)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--root", type=Path, default=None, help="каталог атласа (по умолчанию ищется от текущего)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate", help="проверить схемы, словари и ссылки").set_defaults(func=cmd_validate)
    sub.add_parser("build", help="проверить и создать exports/ и docs/tables.md").set_defaults(func=cmd_build)
    sub.add_parser("check", help="проверить и убедиться, что выгрузки актуальны").set_defaults(func=cmd_check)
    sub.add_parser("stats", help="сводные счётчики в JSON").set_defaults(func=cmd_stats)
    p = sub.add_parser("show", help="показать запись с фактами и источниками")
    p.add_argument("id")
    p.set_defaults(func=cmd_show)
    args = ap.parse_args(argv)
    if args.root is None:
        try:
            args.root = find_root()
        except FileNotFoundError as e:
            print(f"ошибка: {e}", file=sys.stderr)
            return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
