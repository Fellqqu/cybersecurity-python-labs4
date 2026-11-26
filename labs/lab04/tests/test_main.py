import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

import pytest

from labs.lab04 import main
from labs.lab04.tests.test_analysis import CVE_ID, SAMPLE


# перевіряємо повний звіт з локального файла та відсутність запиту до сервера
def test_local_report(monkeypatch, capsys):
    fetch = Mock()
    monkeypatch.setattr(main, "fetch_response", fetch)
    assert main.main(["--cve", CVE_ID, "--input", str(SAMPLE)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "cve_id": CVE_ID,
        "variant": 11,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
        "observed": "NONE",
        "decision": "other",
    }
    fetch.assert_not_called()


# перевіряємо помилки для відсутнього файла і некоректних даних у файлі
@pytest.mark.parametrize(("content", "message"), [(None, "прочитати"), ("{", "JSON")])
def test_local_file_errors(capsys, content, message):
    with TemporaryDirectory(prefix="lab04-") as directory:
        path = Path(directory) / "response.json"
        if content is not None:
            path.write_text(content, encoding="utf-8")
        assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert message in captured.err
