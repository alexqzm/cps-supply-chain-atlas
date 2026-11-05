import shutil
from pathlib import Path

import pytest
import yaml

from cps_atlas.analysis import evidence_summary, gost_artifacts, states_by_evidence, stopping, summary
from cps_atlas.cli import generated, main
from cps_atlas.export import build_exports
from cps_atlas.load import load, read_yaml
from cps_atlas.validate import check, date_ok

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def atlas():
    return load(ROOT)


@pytest.fixture
def copy(tmp_path):
    """Копия атласа во временном каталоге для проверок с порчей данных."""
    for d in ("data", "vocab", "schema", "exports", "docs"):
        shutil.copytree(ROOT / d, tmp_path / d)
    return tmp_path


def edit_record(root: Path, rid: str, change) -> None:
    path = root / "data" / "records" / f"{rid}.yaml"
    rec = read_yaml(path)
    change(rec)
    path.write_text(yaml.safe_dump(rec, allow_unicode=True, sort_keys=False), encoding="utf-8")


def errors_for(root: Path) -> list:
    return check(load(root))


# --- данные репозитория ---

def test_repository_atlas_is_valid(atlas):
    assert check(atlas) == []


def test_generated_files_are_up_to_date(atlas):
    for rel, text in generated(atlas).items():
        assert (ROOT / rel).read_text(encoding="utf-8") == text, f"{rel} устарел: выполните cps-atlas build"


def test_exports_are_deterministic(atlas):
    assert build_exports(atlas) == build_exports(load(ROOT))


def test_summary_is_consistent(atlas):
    s = summary(atlas)
    assert s["records"] == len(list((ROOT / "data" / "records").glob("*.yaml")))
    assert sum(s["type"].values()) == s["records"] == sum(s["cps_relevance"].values()) == sum(s["scope"].values())
    assert s["facts"] == sum(len(r["facts"]) for r in atlas.records)


def test_every_record_has_sources_for_every_fact(atlas):
    ids = set(atlas.source_index)
    for r in atlas.records:
        for f in r["facts"]:
            assert f["sources"] and set(f["sources"]) <= ids


def test_states_and_gost_derivation(atlas):
    flame = atlas.record("flame-2012")
    assert states_by_evidence(flame)["s42"] == ["F", "P"]
    assert stopping(atlas, flame) == ["s42", "s53"]
    assert gost_artifacts(atlas, flame) == ["5.20.3.4"]
    sw = atlas.record("solarwinds-2020")
    assert gost_artifacts(atlas, sw) == ["5.13.3.6"]


def test_evidence_summary_counts_records_once_per_state(atlas):
    rows = {e["evidence"]: e for e in evidence_summary(atlas)}
    assert "flame-2012" in rows["s42"]["F"] and "flame-2012" in rows["s42"]["P"]
    assert "flame-2012" not in rows["s42"]["only_bypassed"]


def test_dates():
    assert date_ok("2026") and date_ok("2026-02") and date_ok("2024-02-29")
    assert not date_ok("2025-02-30") and not date_ok("2025-13") and not date_ok("26-01-01") and not date_ok(None)


def test_yaml_dates_stay_strings(tmp_path):
    p = tmp_path / "x.yaml"
    p.write_text("date: 2025-01-30\n", encoding="utf-8")
    assert read_yaml(p) == {"date": "2025-01-30"}


# --- порча данных обнаруживается ---

def test_unknown_source(copy):
    edit_record(copy, "stuxnet-2010", lambda r: r["facts"][0].update(sources=["no-such-source"]))
    assert any("нет источника no-such-source" in e for e in errors_for(copy))


def test_unused_source(copy):
    path = copy / "data" / "sources.yaml"
    doc = read_yaml(path)
    extra = dict(doc["sources"][-1], id="orphan-source", url="https://example.org/orphan")
    doc["sources"].append(extra)
    path.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    assert any("orphan-source ни на что не ссылается" in e for e in errors_for(copy))


def test_unknown_evidence(copy):
    edit_record(copy, "triton-2017", lambda r: r["scii"]["evidence"][0].update(evidence="s44"))
    assert any("свидетельства s44 нет" in e for e in errors_for(copy))


def test_mitre_basis_requires_attack_page(copy):
    edit_record(copy, "havex-2014", lambda r: r["attack"]["techniques"][0].update(sources=["cisa-icsa-14-178-01"]))
    assert any("основание mitre требует" in e for e in errors_for(copy))


def test_general_requires_relevance_note(copy):
    edit_record(copy, "solarwinds-2020", lambda r: r.pop("relevance_note"))
    assert any("relevance_note" in e for e in errors_for(copy))


def test_partial_scope_requires_note(copy):
    edit_record(copy, "triton-2017", lambda r: r["scii"].pop("scope_note"))
    assert any("scope_note" in e for e in errors_for(copy))


def test_invalid_calendar_date(copy):
    edit_record(copy, "tj-actions-2025", lambda r: r["timeline"][0].update(date="2025-02-30"))
    assert any("неверная дата 2025-02-30" in e for e in errors_for(copy))


def test_id_must_match_file_name(copy):
    edit_record(copy, "triton-2017", lambda r: r.update(id="triton-2018"))
    assert any("не совпадает с именем файла" in e for e in errors_for(copy))


def test_duplicate_evidence_condition(copy):
    def dup(r):
        r["scii"]["evidence"].append(dict(r["scii"]["evidence"][0]))
    edit_record(copy, "triton-2017", dup)
    assert any("с тем же условием указано дважды" in e for e in errors_for(copy))


def test_high_confidence_needs_non_news_source(copy):
    def news_only(r):
        for f in r["facts"]:
            f["sources"] = ["securityweek-havex"]
    edit_record(copy, "havex-2014", news_only)
    errs = errors_for(copy)
    assert any("высокая достоверность" in e for e in errs)


def test_unknown_technique_and_version(copy):
    def bad(r):
        r["attack"]["version"] = "v19"
        r["attack"]["techniques"].append({"id": "T0999", "basis": "author"})
    edit_record(copy, "triton-2017", bad)
    errs = errors_for(copy)
    assert any("версия ATT&CK v19" in e for e in errs)
    assert any("техники T0999 нет" in e for e in errs)


def test_state_outside_three_values(copy):
    edit_record(copy, "triton-2017", lambda r: r["scii"]["evidence"][0].update(state="X"))
    assert any("state" in e for e in errors_for(copy))


# --- командная строка ---

def test_cli_check_and_stale_detection(copy, capsys):
    assert main(["--root", str(copy), "check"]) == 0
    (copy / "docs" / "tables.md").write_text("устарело\n", encoding="utf-8")
    assert main(["--root", str(copy), "check"]) == 1
    assert "устарел: docs/tables.md" in capsys.readouterr().err
    assert main(["--root", str(copy), "build"]) == 0
    assert main(["--root", str(copy), "check"]) == 0


def test_cli_build_refuses_invalid_data(copy):
    edit_record(copy, "stuxnet-2010", lambda r: r["facts"][0].update(sources=["no-such-source"]))
    assert main(["--root", str(copy), "build"]) == 1


def test_cli_show(capsys):
    assert main(["--root", str(ROOT), "show", "xz-utils-2024"]) == 0
    out = capsys.readouterr().out
    assert "tukaani.org" in out and "s14: F" in out
    assert main(["--root", str(ROOT), "show", "no-such-record"]) == 2
