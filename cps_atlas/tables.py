"""Сводные таблицы атласа в Markdown (docs/tables.md)."""
from __future__ import annotations

from . import __version__
from .analysis import (bypassed, evidence_order, evidence_summary, position_stages, states_by_evidence,
                       stopping, summary)
from .load import Atlas

TYPE = {"incident": "инцидент", "demonstration": "демонстрация"}
RELEVANCE = {"direct": "прямо", "general": "общего назначения"}
SCOPE = {"in": "в области", "partial": "частично", "out": "вне"}
CONFIDENCE = {"high": "высокая", "medium": "средняя", "low": "низкая"}


def _row(cells) -> str:
    return "| " + " | ".join(str(c).replace("|", "\\|") for c in cells) + " |"


def _table(header, rows) -> list:
    return [_row(header), "|" + "---|" * len(header), *(_row(r) for r in rows), ""]


def _link(rid: str) -> str:
    return f"[{rid}](../data/records/{rid}.yaml)"


def render(atlas: Atlas) -> str:
    s = summary(atlas)
    n = s["records"]
    ndir = s["cps_relevance"].get("direct", 0)
    L = ["# Таблицы атласа", "",
         "Файл создаётся командой `cps-atlas build`, вручную его не правят. "
         f"Данные {__version__}, ATT&CK {atlas.vocab['attack']['version']}, SLSA {atlas.vocab['slsa']['version']}.",
         "",
         "Состояния свидетельств SCII получены при условиях, указанных в записях (полный список условий — "
         "[`exports/evidence.csv`](../exports/evidence.csv)), и вместе с сопоставлениями ATT&CK и SLSA с "
         "основанием «автор» являются оценкой автора. **F** — свидетельство опровергло бы атаку, **N** — "
         "не могло бы быть предъявлено (гейт не допустит обновление, если свидетельство обязательно), "
         "**P** — подтвердилось бы несмотря на атаку, то есть обойдено.", ""]

    L += ["## Сводка", ""]
    L += _table(["Показатель", "Значение"], [
        ["Записей", f"{n} (инцидентов {s['type'].get('incident', 0)}, демонстраций {s['type'].get('demonstration', 0)})"],
        ["Прямо касаются КФС / общего назначения", f"{ndir} / {s['cps_relevance'].get('general', 0)}"],
        ["Годы", f"{s['years'][0]}–{s['years'][1]}" if s["years"] else "—"],
        ["Фактов / источников", f"{s['facts']} / {s['sources']}"],
        ["Область SCII: в области / частично / вне",
         f"{s['scope'].get('in', 0)} / {s['scope'].get('partial', 0)} / {s['scope'].get('out', 0)}"],
        ["Есть свидетельство, которое атаку останавливает (F или N)", f"{s['with_stopping_evidence']} из {n}"],
        ["Только обойдённые свидетельства", ", ".join(s["only_bypassed"]) or "—"],
        ["С сопоставленной угрозой SLSA", f"{s['with_slsa_threat']} из {n}"],
        ["Прямо касаются КФС и останавливаются на стадии v5 (устройство)",
         f"{s['direct_stopped_on_v5']} из {ndir}; из них без угрозы SLSA: {len(s['direct_v5_without_slsa'])}"],
    ])

    L += ["## Записи", ""]
    rows = []
    for r in sorted(atlas.records, key=lambda r: (r["year"], r["id"])):
        rows.append([_link(r["id"]), r["title"], TYPE[r["type"]], RELEVANCE[r["cps_relevance"]], r["year"],
                     ", ".join(r["positions"]), SCOPE[r["scii"]["scope"]], ", ".join(stopping(atlas, r)) or "—",
                     ", ".join(bypassed(atlas, r)) or "—", CONFIDENCE[r["confidence"]]])
    L += _table(["Запись", "Название", "Тип", "КФС", "Год", "Позиция нарушителя", "Область SCII",
                 "Останавливают", "Обойдены", "Достоверность"], rows)

    L += ["## Матрица «запись × свидетельство SCII»", "",
          "Пустая клетка — свидетельство для записи не оценивалось. Несколько букв — разные условия.", ""]
    order = evidence_order(atlas)
    rows = []
    for r in sorted(atlas.records, key=lambda r: (r["year"], r["id"])):
        st = states_by_evidence(r)
        rows.append([r["id"], *("/".join(st.get(e, [])) for e in order)])
    L += _table(["Запись", *order], rows)

    L += ["## Свидетельства", "",
          "Число записей, в которых свидетельство дало бы F, N или P; «только P» — записи, где свидетельство "
          "оценено лишь как обойдённое. Артефакты ГОСТ Р 56939-2024 — по сопоставлению rbpo-evidence.", ""]
    rows = [[e["evidence"], e["label"], e["stage"], len(e["F"]), len(e["N"]), len(e["P"]), len(e["only_bypassed"]),
             ", ".join(e["gost"]) or "нет прямого артефакта"] for e in evidence_summary(atlas)]
    L += _table(["Свидетельство", "Название", "Стадия", "F", "N", "P", "Только P", "ГОСТ Р 56939-2024"], rows)

    L += ["## Позиции нарушителя", ""]
    rows =[[p["id"], p["label"], p["scii_stage"] or "вне цепочки", s["positions"].get(p["id"], 0)]
            for p in atlas.vocab["positions"]["positions"]]
    L += _table(["Позиция", "Описание", "Стадия SCII", "Записей"], rows)

    L += ["## Отрасли", ""]
    rows = [[x["id"], x["label"], s["sectors"].get(x["id"], 0)] for x in atlas.vocab["sectors"]["sectors"]
            if s["sectors"].get(x["id"])]
    L += _table(["Отрасль", "Описание", "Записей"], rows)

    L += ["## Прямо касаются КФС: стадия v5 без угрозы SLSA", "",
          "Записи, которые останавливаются свидетельствами устройства (v5), но не сопоставлены ни с одной "
          "угрозой SLSA 1.2: атака идёт через загрузку ПО или логики в устройство, а не через производство ПО.", ""]
    rows = [[_link(rid), atlas.record(rid)["title"], ", ".join(position_stages(atlas, atlas.record(rid))) or "—"]
            for rid in s["direct_v5_without_slsa"]]
    L += _table(["Запись", "Название", "Стадии позиций"], rows) if rows else ["—", ""]
    return "\n".join(L).rstrip() + "\n"
