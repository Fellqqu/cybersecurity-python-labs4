import json
from pathlib import Path

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE_ID = "CVE-2099-10001"
SAMPLE = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture
def payload():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def report(payload):
    return build_report(extract_record(payload, CVE_ID), CVE_ID, 11)


# перевіряємо межу порога і випадок коли потрібна ознака не збігається
@pytest.mark.parametrize(
    ("score", "interaction", "expected"),
    [
        (5.9, "REQUIRED", "other"),
        (6.0, "REQUIRED", "review"),
        (6.1, "REQUIRED", "review"),
        (9.8, "NONE", "other"),
    ],
)
def test_variant_rule(payload, score, interaction, expected):
    data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    data.update(baseScore=score, userInteraction=interaction)
    assert report(payload)["decision"] == expected


# перевіряємо рішення для порожнього списку записів
def test_not_found():
    assert report({"vulnerabilities": []})["decision"] == "not_found"


# перевіряємо рішення коли в записі немає оцінки
def test_missing_score(payload):
    del payload["vulnerabilities"][0]["cve"]["metrics"]
    assert report(payload)["decision"] == "insufficient_data"


# перевіряємо що для відхиленого запису оцінка пропускається
def test_rejected_ignores_metrics(payload):
    payload["vulnerabilities"][0]["cve"].update(vulnStatus="Rejected", metrics=None)
    result = report(payload)
    assert result["decision"] == "rejected"
    assert result["score"] is None


# перевіряємо рішення коли немає поля про дію користувача
def test_missing_interaction(payload):
    data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    del data["userInteraction"]
    assert report(payload)["decision"] == "insufficient_data"


# перевіряємо помилку для неправильного типу і недопустимого значення поля
@pytest.mark.parametrize("interaction", [1, "LOW"])
def test_invalid_interaction(payload, interaction):
    data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    data["userInteraction"] = interaction
    with pytest.raises(ValueError, match="userInteraction"):
        report(payload)


# перевіряємо вибір основної оцінки та вибір першої якщо основної немає
@pytest.mark.parametrize(
    ("second_type", "expected_source", "expected_decision"),
    [("Primary", "primary", "review"), ("Secondary", "first", "other")],
)
def test_score_selection(payload, second_type, expected_source, expected_decision):
    scores = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]
    scores[0].update(type="Secondary", source="first")
    scores.append(
        {
            "type": second_type,
            "source": "primary",
            "cvssData": {"baseScore": 7, "userInteraction": "REQUIRED"},
        }
    )
    result = report(payload)
    assert result["score_source"] == expected_source
    assert result["decision"] == expected_decision
