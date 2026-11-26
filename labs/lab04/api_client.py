import os

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# помилка запиту з повідомленням без секретних даних
class NvdError(RuntimeError):
    pass


def build_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    # додаємо ключ лише якщо він заданий
    key = os.getenv("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    return headers


def fetch_response(cve_id: str) -> object:
    try:
        # надсилаємо один запит без перенаправлень
        response = requests.get(
            NVD_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=(3.05, 10),
            allow_redirects=False,
        )
        response.raise_for_status()
        if response.status_code != 200:
            raise NvdError(f"Неочікуваний HTTP-статус NVD ({response.status_code})")
        return response.json()
    except requests.exceptions.HTTPError as error:
        status = (
            error.response.status_code if error.response is not None else "невідомий"
        )
        raise NvdError(f"HTTP-помилка NVD ({status})") from None
    except requests.exceptions.JSONDecodeError:
        raise NvdError("NVD повернула некоректний JSON") from None
    except requests.exceptions.Timeout:
        raise NvdError("Перевищено час очікування відповіді NVD") from None
    except requests.exceptions.RequestException:
        raise NvdError("Не вдалося виконати запит до NVD") from None
