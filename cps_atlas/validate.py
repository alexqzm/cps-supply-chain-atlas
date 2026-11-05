"""Проверка атласа: схемы JSON, словари, ссылки на источники и согласованность сопоставлений."""
from __future__ import annotations

import datetime as dt
import re
from urllib.parse import urlparse

from jsonschema import Draft202012Validator

from .load import Atlas

_DATE = re.compile(r"^(\d{4})(?:-(\d{2})(?:-(\d{2}))?)?$")


def date_ok(value) -> bool:
    """Дата ISO 8601 с точностью до года, месяца или дня, существующая в календаре."""
    m = _DATE.match(value) if isinstance(value, str) else None
    if not m:
        return False
    year, month, day = m.groups()
    try:
        dt.date(int(year), int(month or 1), int(day or 1))
    except ValueError:
        return False
    return True


def _host(url: str) -> str:
    return urlparse(url).hostname or ""


def _schema_errors(validator, doc, label: str) -> list:
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "(корень)"
        out.append(f"{label}: {where}: {err.message}")
    return out


def _vocab_errors(atlas: Atlas) -> list:
    errs = []
    v = atlas.vocab
    for name, key in (("positions", "positions"), ("sectors", "sectors"), ("attack", "techniques"),
                      ("attack", "objects"), ("slsa", "threats"), ("scii", "evidence"), ("scii", "stages")):
        ids = [x.get("id") for x in (v[name] or {}).get(key, [])]
        dups = sorted({i for i in ids if ids.count(i) > 1})
        if dups:
            errs.append(f"vocab/{name}.yaml: повторяющиеся id в {key}: {', '.join(dups)}")
    stages = {s["id"] for s in v["scii"]["stages"]}
    gost = v["scii"]["gost"]["artifacts"]
    for e in v["scii"]["evidence"]:
        if e["stage"] not in stages:
            errs.append(f"vocab/scii.yaml: {e['id']}: неизвестная стадия {e['stage']}")
        for a in e.get("gost", []):
            if a not in gost:
                errs.append(f"vocab/scii.yaml: {e['id']}: артефакт {a} не описан в gost.artifacts")
        if not re.fullmatch(r"s[1-5][1-4]", e["id"]) or e["id"][1] != e["stage"][1]:
            errs.append(f"vocab/scii.yaml: {e['id']}: id не соответствует стадии {e['stage']}")
    for p in v["positions"]["positions"]:
        if p.get("scii_stage") is not None and p["scii_stage"] not in stages:
            errs.append(f"vocab/positions.yaml: {p['id']}: неизвестная стадия {p['scii_stage']}")
    return errs


def _record_errors(atlas: Atlas, rec: dict, used: set) -> list:
    errs = []
    rid = rec.get("id", "?")
    path = atlas.record_files.get(rid)
    if path is not None and path.stem != rid:
        errs.append(f"{rid}: id не совпадает с именем файла {path.name}")
    src = atlas.source_index

    def refs(where: str, ids) -> None:
        for sid in ids or []:
            used.add(sid)
            if sid not in src:
                errs.append(f"{rid}: {where}: нет источника {sid}")

    for i, f in enumerate(rec.get("facts", []), 1):
        refs(f"факт {i}", f.get("sources"))
    for i, ev in enumerate(rec.get("timeline", []), 1):
        refs(f"событие {i}", ev.get("sources"))
        if not date_ok(ev.get("date")):
            errs.append(f"{rid}: событие {i}: неверная дата {ev.get('date')}")
    for s in rec.get("sectors", []):
        if s not in atlas.sector_index:
            errs.append(f"{rid}: неизвестная отрасль {s}")
    for p in rec.get("positions", []):
        if p not in atlas.position_index:
            errs.append(f"{rid}: неизвестная позиция {p}")

    attack = rec.get("attack")
    if attack:
        if attack.get("version") != atlas.vocab["attack"]["version"]:
            errs.append(f"{rid}: версия ATT&CK {attack.get('version')} не совпадает со словарём "
                        f"({atlas.vocab['attack']['version']})")
        seen = set()
        for t in attack.get("techniques", []):
            tid = t.get("id")
            if tid in seen:
                errs.append(f"{rid}: техника {tid} указана дважды")
            seen.add(tid)
            if tid not in atlas.technique_index:
                errs.append(f"{rid}: техники {tid} нет в vocab/attack.yaml")
            refs(f"техника {tid}", t.get("sources"))
            if t.get("basis") == "mitre" and not any(
                    _host(src[s]["url"]) == "attack.mitre.org" for s in t.get("sources", []) if s in src):
                errs.append(f"{rid}: техника {tid}: основание mitre требует ссылки на страницу attack.mitre.org")
        for o in attack.get("objects", []):
            if o.get("id") not in atlas.object_index:
                errs.append(f"{rid}: объекта ATT&CK {o.get('id')} нет в vocab/attack.yaml")
            refs(f"объект {o.get('id')}", o.get("sources"))
            if not any(_host(src[s]["url"]) == "attack.mitre.org" for s in o.get("sources", []) if s in src):
                errs.append(f"{rid}: объект {o.get('id')}: нужна ссылка на страницу attack.mitre.org")

    slsa = rec.get("slsa")
    if slsa:
        if slsa.get("version") != atlas.vocab["slsa"]["version"]:
            errs.append(f"{rid}: версия SLSA {slsa.get('version')} не совпадает со словарём")
        for t in slsa.get("threats", []):
            if t.get("id") not in atlas.slsa_index:
                errs.append(f"{rid}: угрозы SLSA {t.get('id')} нет в vocab/slsa.yaml")
            refs(f"угроза SLSA {t.get('id')}", t.get("sources"))
            if t.get("basis") == "slsa" and not any(
                    _host(src[s]["url"]) == "slsa.dev" for s in t.get("sources", []) if s in src):
                errs.append(f"{rid}: угроза SLSA {t.get('id')}: основание slsa требует ссылки на slsa.dev")

    scii = rec.get("scii") or {}
    if "assessed" in scii and not date_ok(scii["assessed"]):
        errs.append(f"{rid}: неверная дата оценки {scii['assessed']}")
    pairs = set()
    for e in scii.get("evidence", []):
        eid = e.get("evidence")
        if eid not in atlas.evidence_index:
            errs.append(f"{rid}: свидетельства {eid} нет в vocab/scii.yaml")
        key = (eid, e.get("condition"))
        if key in pairs:
            errs.append(f"{rid}: свидетельство {eid} с тем же условием указано дважды")
        pairs.add(key)
    if scii.get("scope") == "in" and not scii.get("evidence"):
        errs.append(f"{rid}: атака в области SCII, но нет ни одного сопоставления со свидетельствами")

    if rec.get("confidence") == "high":
        kinds = {src[s]["kind"] for f in rec.get("facts", []) for s in f.get("sources", []) if s in src}
        if kinds and kinds <= {"news"}:
            errs.append(f"{rid}: высокая достоверность требует хотя бы одного источника, кроме новостей")
    return errs


def check(atlas: Atlas) -> list:
    """Список ошибок; пустой список — атлас корректен."""
    errs = list(atlas.load_errors)
    errs += _schema_errors(Draft202012Validator(atlas.schemas["sources"]), atlas.sources_doc, "data/sources.yaml")
    rv = Draft202012Validator(atlas.schemas["record"])
    for rec in atlas.records:
        errs += _schema_errors(rv, rec, f"{rec.get('id', '?')}")
    errs += _vocab_errors(atlas)

    ids = [s.get("id") for s in atlas.sources if isinstance(s, dict)]
    for sid in sorted({i for i in ids if ids.count(i) > 1}):
        errs.append(f"data/sources.yaml: id {sid} повторяется")
    urls = [s.get("url") for s in atlas.sources if isinstance(s, dict)]
    for url in sorted({u for u in urls if urls.count(u) > 1}):
        errs.append(f"data/sources.yaml: адрес {url} повторяется")
    for s in atlas.sources:
        if not isinstance(s, dict):
            continue
        for key in ("date", "updated", "checked"):
            if s.get(key) is not None and not date_ok(s[key]):
                errs.append(f"data/sources.yaml: {s.get('id')}: неверная дата {key}={s[key]}")

    used = set()
    for name in ("attack", "slsa"):
        for sid in atlas.vocab[name].get("sources", []):
            used.add(sid)
            if sid not in atlas.source_index:
                errs.append(f"vocab/{name}.yaml: нет источника {sid}")
    for rec in atlas.records:
        errs += _record_errors(atlas, rec, used)
    for sid in sorted(set(atlas.source_index) - used):
        errs.append(f"data/sources.yaml: источник {sid} ни на что не ссылается")
    return errs
