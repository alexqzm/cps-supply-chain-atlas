# cps-supply-chain-atlas

[![CI](https://github.com/alexqzm/cps-supply-chain-atlas/actions/workflows/ci.yml/badge.svg)](https://github.com/alexqzm/cps-supply-chain-atlas/actions/workflows/ci.yml)

Атлас атак на цепочки поставок и обновления ПО киберфизических систем (КФС): инциденты и
исследовательские демонстрации с проверенными источниками, позицией нарушителя в цепочке,
техниками MITRE ATT&CK и угрозами SLSA. Для каждой записи указано, какие свидетельства графа
доказательств SCII атаку остановили бы, а какие были бы обойдены, и при каких условиях.

Данные — YAML с проверкой по JSON Schema, выгрузки — JSON и CSV, сводные таблицы — Markdown.

## Что внутри

| Каталог | Содержимое |
|---|---|
| [`data/records/`](data/records) | 28 записей: 22 инцидента и 6 демонстраций, 2010–2026 гг.; 17 прямо касаются КФС |
| [`data/sources.yaml`](data/sources.yaml) | 47 источников с датой сверки; 125 фактов записей ссылаются на них |
| [`vocab/`](vocab) | свидетельства SCII и артефакты ГОСТ Р 56939-2024, позиции нарушителя, отрасли, ATT&CK v20, SLSA 1.2 |
| [`schema/`](schema) | JSON Schema записи и списка источников |
| [`exports/`](exports) | `atlas.json` и таблицы CSV: записи, факты, свидетельства, техники, источники |
| [`docs/tables.md`](docs/tables.md) | сводка, матрица «запись × свидетельство», итоги по свидетельствам |
| [`docs/methodology.md`](docs/methodology.md) | критерии включения, правила сопоставления, достоверность, ограничения |

Запись содержит краткое описание, факты (пересказ, у каждого — ссылка на источник и, где
возможно, страница), хронологию, позицию нарушителя, отрасль, техники ATT&CK с основанием
(`mitre` — MITRE приводит этот случай как пример; `author` — сопоставление автора), угрозы SLSA,
сопоставление со свидетельствами SCII и уровень достоверности.

```yaml
# data/records/solarwinds-2020.yaml (фрагмент)
scii:
  scope: in
  evidence:
    - evidence: s22
      state: P
      condition: "Аттестацию происхождения формирует тот же сборочный сервер."
      rationale: "Аттестация верно укажет исходную ревизию, но не подмену файла на диске во время сборки."
    - evidence: s24
      state: F
      condition: "Та же ревизия независимо пересобирается в отдельной среде, и результаты сравниваются."
      rationale: "Независимая сборка не содержит SUNBURST и не совпадёт с выпуском."
```

**F** — свидетельство опровергло бы атаку; **N** — не могло бы быть предъявлено, и гейт не
допустит обновление, если свидетельство обязательно; **P** — подтвердилось бы несмотря на атаку,
то есть обойдено.

## Что показывает атлас

Сопоставления со свидетельствами SCII — оценка автора при условиях, указанных в записях. Счётчики
описывают атлас, а не все атаки (отбор авторский). Полные таблицы — в [`docs/tables.md`](docs/tables.md).

- **Подпись не доказывает легитимность.** Подпись пакета (`s42`) обойдена в 9 записях:
  вредоносный пакет имел действительную подпись — похищенным ключом, ключом самого производителя
  или сопровождающего либо сертификатом, выведенным из корня производителя (Stuxnet, X_TRADER,
  SolarWinds, ShadowHammer, xz, Flame и др.). Опровергает атаку она в 5 записях, причём у Flame —
  только при проверке по закреплённому ключу, а не по цепочке сертификатов.
- **Независимая пересборка ловит атаки на сборку.** В SolarWinds и TanStack свидетельства
  штатного конвейера (подпись агента, аттестация происхождения) подтверждаются, а атаку
  опровергает только независимая пересборка (`s24`) с воспроизводимостью (`s23`). Всего `s24`
  опровергает атаку в 5 записях.
- **У КФС свой путь атаки — загрузка в устройство.** Из 17 записей, прямо касающихся КФС, 9
  останавливаются свидетельствами устройства (`s51`, `s53`, `s54`), и 8 из них не сопоставлены ни с
  одной угрозой SLSA: Stuxnet, Украина 2015, TRITON, Jeep Cherokee, PLC-Blaster, Rogue7,
  ControlLogix, головные устройства DoFun. Нарушитель загружает код в устройство в обход цепочки
  выпуска, и остановить его может только проверка на самом устройстве.
- **Граница метода.** 6 записей SCII не останавливает: угроза со стороны производителя (Contec
  CMS8000, node-ipc, BADBOX 2.0), атака через канал управления (KA-SAT, перехват мастер-аккаунтов
  Li Auto) и компрометация аппаратного корня доверия (Thrangrycat). У Li Auto источники не
  сообщают об изменении ПО: нарушитель получает учётную запись владельца, и гейту нечего проверять.

## Использование

```sh
git clone https://github.com/alexqzm/cps-supply-chain-atlas
cd cps-supply-chain-atlas
pip install -e .

cps-atlas validate        # схемы, словари, ссылки на источники, даты
cps-atlas show xz-utils-2024
cps-atlas stats           # сводные счётчики в JSON
cps-atlas build           # пересоздать exports/ и docs/tables.md
cps-atlas check           # проверка и актуальность выгрузок (выполняет CI)
```

Инструменты работают с клоном репозитория (данные не входят в пакет); каталог атласа ищется от
текущего или задаётся `--root`. Без установки: `python -m cps_atlas validate`.

Выгрузки можно читать без инструментов: `exports/atlas.json` содержит записи, источники, словари
и производные поля (`stopping_evidence`, `bypassed_evidence`, `gost_artifacts`), CSV — плоские
таблицы в UTF-8.

## Связь с графом доказательств

| Где | Что |
|---|---|
| SCII | 17 свидетельств пяти стадий: источник, сборка, репозиторий артефактов, пакет обновления, устройство ([`vocab/scii.yaml`](vocab/scii.yaml)) |
| ГОСТ Р 56939-2024 | артефакты, связанные со свидетельствами, — по сопоставлению [`rbpo-evidence`](https://github.com/alexqzm/rbpo-evidence); у свидетельств устройства прямого артефакта нет |
| MITRE ATT&CK | v20, Enterprise и ICS; идентификаторы сверены 05.11.2026 |
| SLSA | v1.2, угрозы A–I и угрозы зависимостей |

## Связанные репозитории

- [`scii-gate`](https://github.com/alexqzm/scii-gate) — гейт допуска обновлений ПО КФС по графу
  доказательств (метод SCII), DOI [10.5281/zenodo.23833592](https://doi.org/10.5281/zenodo.23833592).
- [`scii-verify`](https://github.com/alexqzm/scii-verify) — проверка квитанции допуска SCII на устройстве.
- [`rbpo-evidence`](https://github.com/alexqzm/rbpo-evidence) — ГОСТ Р 56939-2024 как граф доказательств.
- [`rbpo-pipeline`](https://github.com/alexqzm/rbpo-pipeline) — конвейер GitHub Actions с
  техническими артефактами ГОСТ Р 56939-2024.
- [`source-match`](https://github.com/alexqzm/source-match) — свидетельство «выпускной архив
  соответствует подписанному тегу».

## Лицензия и цитирование

Данные (`data/`, `vocab/`, `exports/`, `docs/tables.md`) — CC BY 4.0 ([`LICENSE-DATA`](LICENSE-DATA)),
код и схемы — Apache-2.0 ([`LICENSE`](LICENSE)). Права на источники принадлежат их авторам; атлас
содержит ссылки и пересказы, а не тексты источников. Метаданные для цитирования — в
[`CITATION.cff`](CITATION.cff).

---

### Summary (EN)

`cps-supply-chain-atlas` is a dataset of attacks on the software build, release, delivery and
loading chains of cyber-physical systems: 28 records (22 incidents, 6 research demonstrations,
2010–2026; 17 directly involving CPS) with 125 facts, each paraphrased and linked to one of 47
sources checked by the author. Records give the attacker position in the chain, MITRE ATT&CK v20
techniques (marked as listed by MITRE or mapped by the author), SLSA v1.2 threats, and the author's
assessment of which SCII evidence graph items would refute the attack, could not be presented, or
would be bypassed, under explicit conditions. GOST R 56939-2024 artifacts are derived through the
rbpo-evidence crosswalk. Data is YAML validated by JSON Schema, with JSON and CSV exports. Data is
licensed under CC BY 4.0, code under Apache-2.0.
