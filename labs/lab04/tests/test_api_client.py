from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE_ID = "CVE-2099-10001"


# перевіряємо заголовки з вигаданим ключем і без нього
@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (None, {"Accept": "application/json"}),
        (" fake-key ", {"Accept": "application/json", "apiKey": "fake-key"}),
    ],
)
def test_headers(monkeypatch, key, expected):
    if key is not None:
        monkeypatch.setenv("NVD_API_KEY", key)
    assert api_client.build_headers() == expected


# перевіряємо параметри запиту та дані успішної відповіді
def test_fetch_response(monkeypatch):
    payload = {"vulnerabilities": []}
    response = Mock(spec=requests.Response, status_code=200)
    response.json.return_value = payload
    get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", get)

    assert api_client.fetch_response(CVE_ID) == payload
    get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": CVE_ID},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


# перевіряємо повідомлення про помилку коли сервер повертає статус 404
def test_http_error(monkeypatch):
    response = Mock(spec=requests.Response, status_code=404)
    response.raise_for_status.side_effect = requests.HTTPError(
        "hidden", response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(api_client.NvdError, match=r"^HTTP-помилка NVD \(404\)$"):
        api_client.fetch_response(CVE_ID)
