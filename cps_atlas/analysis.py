"""Производные данные: состояния свидетельств, стадии, артефакты ГОСТ, сводные счётчики.

Всё, что здесь вычисляется из поля scii записей, наследует его статус: это оценка автора.
"""
from __future__ import annotations

from collections import Counter

from .load import Atlas

STATE_ORDER = ("F", "N", "P")


def clause_key(clause: str) -> tuple:
    return tuple(int(x) for x in clause.split("."))


def evidence_order(atlas: Atlas) -> list:
    return [e["id"] for e in atlas.vocab["scii"]["evidence"]]


def states_by_evidence(rec: dict) -> dict:
    """{свидетельство: [состояния в порядке F, N, P]} — у одного свидетельства может быть несколько условий."""
    acc = {}
    for e in rec.get("scii", {}).get("evidence", []):
        acc.setdefault(e["evidence"], set()).add(e["state"])
    return {k: [s for s in STATE_ORDER if s in v] for k, v in acc.items()}


def stopping(atlas: Atlas, rec: dict) -> list:
    """Свидетельства, которые при своих условиях атаку останавливают (F или N)."""
    st = states_by_evidence(rec)
    return [e for e in evidence_order(atlas) if any(s in ("F", "N") for s in st.get(e, []))]


def bypassed(atlas: Atlas, rec: dict) -> list:
    """Свидетельства, которые при своих условиях подтверждаются несмотря на атаку (P)."""
    st = states_by_evidence(rec)
    return [e for e in evidence_order(atlas) if "P" in st.get(e, [])]


def position_stages(atlas: Atlas, rec: dict) -> list:
    pos = atlas.position_index
    stages = {pos[p]["scii_stage"] for p in rec.get("positions", []) if p in pos and pos[p]["scii_stage"]}
    return sorted(stages)


def stopping_stages(atlas: Atlas, rec: dict) -> list:
    idx = atlas.evidence_index
    return sorted({idx[e]["stage"] for e in stopping(atlas, rec)})


def gost_artifacts(atlas: Atlas, rec: dict) -> list:
    """Артефакты ГОСТ Р 56939-2024, связанные со свидетельствами, которые атаку останавливают."""
    idx = atlas.evidence_index
    arts = {a for e in stopping(atlas, rec) for a in idx[e].get("gost", [])}
    return sorted(arts, key=clause_key)


def evidence_summary(atlas: Atlas) -> list:
    """По каждому свидетельству: в скольких записях оно дало бы F, N, P (запись учитывается в каждом своём состоянии)."""
    rows = []
    per = {r["id"]: states_by_evidence(r) for r in atlas.records}
    for e in atlas.vocab["scii"]["evidence"]:
        recs = {s: sorted(rid for rid, st in per.items() if s in st.get(e["id"], [])) for s in STATE_ORDER}
        stop = sorted({*recs["F"], *recs["N"]})
        rows.append({"evidence": e["id"], "stage": e["stage"], "label": e["label"], "gost": e.get("gost", []),
                     "F": recs["F"], "N": recs["N"], "P": recs["P"], "stops": stop,
                     "only_bypassed": sorted(set(recs["P"]) - set(stop))})
    return rows


def summary(atlas: Atlas) -> dict:
    recs = atlas.records
    direct = [r for r in recs if r["cps_relevance"] == "direct"]
    with_slsa = [r for r in recs if r.get("slsa", {}).get("threats")]
    v5_stop = [r for r in recs if "v5" in stopping_stages(atlas, r)]
    return {
        "records": len(recs),
        "type": dict(Counter(r["type"] for r in recs)),
        "cps_relevance": dict(Counter(r["cps_relevance"] for r in recs)),
        "scope": dict(Counter(r["scii"]["scope"] for r in recs)),
        "confidence": dict(Counter(r["confidence"] for r in recs)),
        "positions": dict(Counter(p for r in recs for p in r["positions"])),
        "sectors": dict(Counter(s for r in recs for s in r["sectors"])),
        "years": [min(r["year"] for r in recs), max(r["year"] for r in recs)] if recs else [],
        "sources": len(atlas.sources),
        "facts": sum(len(r["facts"]) for r in recs),
        "with_stopping_evidence": sum(1 for r in recs if stopping(atlas, r)),
        "only_bypassed": sorted(r["id"] for r in recs if bypassed(atlas, r) and not stopping(atlas, r)),
        "with_slsa_threat": len(with_slsa),
        "direct_with_slsa_threat": sum(1 for r in direct if r in with_slsa),
        "direct_stopped_on_v5": sum(1 for r in direct if r in v5_stop),
        "direct_v5_without_slsa": sorted(r["id"] for r in direct if r in v5_stop and r not in with_slsa),
    }
