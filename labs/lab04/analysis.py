# для кожного варіанта задаємо поріг поле і його очікуване значення
RULES = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}

IMPACT_VALUES = ("NONE", "LOW", "HIGH")
FIELD_VALUES = {
    "attackVector": ("NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"),
    "attackComplexity": ("LOW", "HIGH"),
    "privilegesRequired": IMPACT_VALUES,
    "userInteraction": ("NONE", "REQUIRED"),
    "scope": ("UNCHANGED", "CHANGED"),
    "confidentialityImpact": IMPACT_VALUES,
    "integrityImpact": IMPACT_VALUES,
    "availabilityImpact": IMPACT_VALUES,
}


def optional_text(data: dict, key: str) -> str | None:
    if key not in data:
        return None
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Некоректне поле {key}")
    return value


def require_object(value: object, key: str) -> dict:
    if isinstance(value, dict):
        return value
    raise ValueError(f"Некоректне поле {key}")


# повертаємо поля для звіту та дані вибраної оцінки або порожнє значення якщо запису немає
def extract_record(payload: object, cve_id: str) -> dict | None:
    entries = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or len(entries) > 1:
        raise ValueError("Некоректне поле vulnerabilities")
    if not entries:
        return None
    cve = entries[0].get("cve") if isinstance(entries[0], dict) else None
    if not isinstance(cve, dict) or cve.get("id") != cve_id:
        raise ValueError("Запис cve відсутній або його ID не збігається із запитом")

    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("lang"), str)
        or not isinstance(item.get("value"), str)
        for item in descriptions
    ):
        raise ValueError("Некоректне поле descriptions")
    description = next(
        (
            item["value"]
            for item in descriptions
            if item["lang"] == "en" and item["value"].strip()
        ),
        None,
    )
    status = optional_text(cve, "vulnStatus")
    record = {"description": description, "vuln_status": status}
    if status is None or status == "Rejected":
        return record

    metrics = require_object(cve.get("metrics", {}), "metrics")
    scores = metrics.get("cvssMetricV31", [])
    if not isinstance(scores, list) or any(
        not isinstance(item, dict) for item in scores
    ):
        raise ValueError("Некоректне поле cvssMetricV31")
    if not scores:
        return record

    # беремо першу основну оцінку або першу зі списку
    selected = next(
        (item for item in scores if item.get("type") == "Primary"), scores[0]
    )
    data = require_object(selected.get("cvssData"), "cvssData")
    score = data.get("baseScore")
    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or not 0 <= score <= 10
    ):
        raise ValueError("baseScore має бути числом від 0 до 10")
    version = optional_text(data, "version")
    if version is not None and version != "3.1":
        raise ValueError("Очікується версія CVSS 3.1")
    record.update(
        cvss_version=version,
        score=score,
        score_source=optional_text(selected, "source"),
        vector=optional_text(data, "vectorString"),
        cvss_data=data,
    )
    return record


# визначаємо рішення і збираємо поля звіту
def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    if type(variant) is not int or variant not in RULES:
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15")
    threshold, field, expected = RULES[variant]
    report = dict.fromkeys(
        (
            "description",
            "vuln_status",
            "cvss_version",
            "score",
            "score_source",
            "vector",
        )
    )
    if record is not None:
        report.update((key, record.get(key)) for key in report)

    # перевіряємо наявність запису і потрібних даних перед порівнянням
    observed = None
    if record is None:
        decision = "not_found"
    elif report["vuln_status"] == "Rejected":
        decision = "rejected"
    elif report["vuln_status"] is None or field not in record.get("cvss_data", {}):
        decision = "insufficient_data"
    else:
        observed = record["cvss_data"][field]
        if observed not in FIELD_VALUES[field]:
            raise ValueError(f"Некоректне поле {field}")
        decision = (
            "review"
            if report["score"] >= threshold and observed == expected
            else "other"
        )

    return {
        "cve_id": cve_id,
        "variant": variant,
        **report,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": observed,
        "decision": decision,
    }
