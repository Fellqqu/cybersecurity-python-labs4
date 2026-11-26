# Лабораторна робота №4. NVD API та pytest

Варіант 11. Рішення `review` формується, коли базова оцінка CVSS v3.1
не менша за 6.0 і `userInteraction` у тій самій оцінці дорівнює `REQUIRED`.
Ця метрика показує, чи потрібна участь іншого користувача для експлуатації
вразливості.

Репозиторій — [Fellqqu/cybersecurity-python-labs4](https://github.com/Fellqqu/cybersecurity-python-labs4).

## Запуск

З кореня репозиторію в активованому віртуальному середовищі з Python 3.12+:

```powershell
python -m pip install -r requirements.txt
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
python -m labs.lab04.main --cve CVE-2021-44228
```

Команда з `--input` читає локальний файл. Команда без цього аргументу
виконує один запит до NVD. Ключ можна задати через `NVD_API_KEY`.

## Результат локального запуску

```json
{
  "cve_id": "CVE-2099-10001",
  "variant": 11,
  "description": "Synthetic vulnerability for offline API testing.",
  "vuln_status": "Analyzed",
  "cvss_version": "3.1",
  "score": 9.8,
  "score_source": "nvd@nist.gov",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "rule": {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
  "observed": "NONE",
  "decision": "other"
}
```

Поле `decision` може містити `not_found`, `rejected`, `insufficient_data`,
`review` або `other`. Відсутні значення у звіті передаються як `null`.
Код завершення 0 означає, що звіт сформовано, 1 означає помилку
отримання чи перевірки даних, а 2 означає помилку аргументів або варіанта.

## Перевірка

```powershell
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```

Результат — 19 тестів пройшли, обидві перевірки Ruff успішні.
Тест межі порівнює 5.9, 6.0 та 6.1 за однакового значення `REQUIRED`.
При 6.0 очікується `review`, тому тест виявить заміну `>=` на `>`.
Для демонстрації обробки помилки можна запустити тести з `-k http_error -v`.

25 листопада 2026 року команда
`python -m labs.lab04.main --cve CVE-2021-44228`
завершилася з кодом 1 і повідомленням «Не вдалося виконати запит до NVD».
Результат від реального сервісу не отримано.

Локальні тести перевіряють параметри запиту, обробку відповідей, правило
відбору й поведінку CLI. Запит до реального сервісу потрібен, щоб перевірити
доступність NVD і обробку його поточної відповіді. Якщо оцінки або потрібної
метрики бракує, даних недостатньо для рішення за правилом варіанта.
