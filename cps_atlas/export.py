"""Выгрузки атласа: JSON со всеми данными и плоские таблицы CSV."""
from __future__ import annotations

import csv
import io
import json

from . import __version__
from .analysis import bypassed, gost_artifacts, position_stages, stopping, stopping_stages
from .load import Atlas

SEP = "; "


def _join(values) -> str:
    return SEP.join(str(v) for v in values)


def export_json(atlas: Atlas) -> str:
    records = []
    for r in atlas.records:
        rec = dict(r)
        rec["derived"] = {
            "position_stages": position_stages(atlas, r),
            "stopping_evidence": stopping(atlas, r),
            "stopping_stages": stopping_stages(atlas, r),
            "bypassed_evidence": bypassed(atlas, r),
            "gost_artifacts": gost_artifacts(atlas, r),
        }
        records.append(rec)
    doc = {
        "schema": "cps-atlas/export/v1",
        "version": __version__,
        "attack_version": atlas.vocab["attack"]["version"],
        "slsa_version": atlas.vocab["slsa"]["version"],
        "note": ("Поля scii, а также сопоставления ATT&CK и SLSA с основанием author — оценка автора. "
                 "Факты — пересказ источников, на которые они ссылаются."),
        "records": records,
        "sources": atlas.sources,
        "vocab": atlas.vocab,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def _csv(header: list, rows: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


def records_csv(atlas: Atlas) -> str:
    header = ["id", "title", "type", "cps_relevance", "year", "sectors", "positions", "position_stages",
              "scii_scope", "stopping_evidence", "bypassed_evidence", "gost_artifacts", "attack_techniques",
              "slsa_threats", "confidence", "sources"]
    rows = []
    for r in atlas.records:
        srcs = sorted({s for f in r["facts"] for s in f["sources"]})
        rows.append([
            r["id"], r["title"], r["type"], r["cps_relevance"], r["year"], _join(r["sectors"]),
            _join(r["positions"]), _join(position_stages(atlas, r)), r["scii"]["scope"],
            _join(stopping(atlas, r)), _join(bypassed(atlas, r)), _join(gost_artifacts(atlas, r)),
            _join(f"{t['id']} ({t['basis']})" for t in r.get("attack", {}).get("techniques", [])),
            _join(f"{t['id']} ({t['basis']})" for t in r.get("slsa", {}).get("threats", [])),
            r["confidence"], _join(srcs)])
    return _csv(header, rows)


def facts_csv(atlas: Atlas) -> str:
    rows = [[r["id"], i, " ".join(f["text"].split()), _join(f["sources"]), f.get("locator", "")]
            for r in atlas.records for i, f in enumerate(r["facts"], 1)]
    return _csv(["record", "n", "text", "sources", "locator"], rows)


def evidence_csv(atlas: Atlas) -> str:
    idx = atlas.evidence_index
    rows = [[r["id"], e["evidence"], idx[e["evidence"]]["stage"], e["state"], " ".join(e["condition"].split()),
             " ".join(e["rationale"].split()), _join(idx[e["evidence"]].get("gost", []))]
            for r in atlas.records for e in r["scii"]["evidence"]]
    return _csv(["record", "evidence", "stage", "state", "condition", "rationale", "gost_artifacts"], rows)


def techniques_csv(atlas: Atlas) -> str:
    idx = atlas.technique_index
    rows = [[r["id"], t["id"], idx[t["id"]]["domain"], idx[t["id"]]["name"], t["basis"],
             _join(t.get("sources", [])), t.get("note", "")]
            for r in atlas.records for t in r.get("attack", {}).get("techniques", [])]
    return _csv(["record", "technique", "domain", "name", "basis", "sources", "note"], rows)


def sources_csv(atlas: Atlas) -> str:
    used = {}
    for r in atlas.records:
        refs = {s for f in r["facts"] for s in f["sources"]}
        refs |= {s for ev in r.get("timeline", []) for s in ev["sources"]}
        refs |= {s for t in r.get("attack", {}).get("techniques", []) for s in t.get("sources", [])}
        refs |= {s for o in r.get("attack", {}).get("objects", []) for s in o.get("sources", [])}
        refs |= {s for t in r.get("slsa", {}).get("threats", []) for s in t.get("sources", [])}
        for s in refs:
            used.setdefault(s, []).append(r["id"])
    rows = [[s["id"], s["title"], _join(s.get("authors", [])), s["publisher"], s.get("date") or "",
             s.get("updated", ""), s["url"], s["kind"], s["language"], s["checked"],
             _join(sorted(used.get(s["id"], [])))] for s in atlas.sources]
    return _csv(["id", "title", "authors", "publisher", "date", "updated", "url", "kind", "language",
                 "checked", "records"], rows)


def build_exports(atlas: Atlas) -> dict:
    """{имя файла: содержимое} — детерминированно, чтобы выгрузки можно было хранить в репозитории."""
    return {
        "atlas.json": export_json(atlas),
        "records.csv": records_csv(atlas),
        "facts.csv": facts_csv(atlas),
        "evidence.csv": evidence_csv(atlas),
        "techniques.csv": techniques_csv(atlas),
        "sources.csv": sources_csv(atlas),
    }
