import argparse
import json
import re
import sys
from pathlib import Path

from labs.lab04.analysis import build_report, extract_record
from labs.lab04.api_client import NvdError, fetch_response
from shared.student import VARIANT_NUMBER


# читаємо дані з локального файла
def load_response(path: str | Path) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="JSON-звіт про вразливість з NVD")
    parser.add_argument("--cve", required=True, help="Ідентифікатор CVE")
    parser.add_argument("--input", type=Path, help="Шлях до локальної відповіді JSON")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", args.cve):
        parser.error("Некоректний ідентифікатор CVE")
    if type(VARIANT_NUMBER) is not int or not 1 <= VARIANT_NUMBER <= 15:
        parser.error("Номер варіанта має бути цілим числом від 1 до 15")

    try:
        # за наявності файла звернення до сервера не потрібне
        payload = load_response(args.input) if args.input else fetch_response(args.cve)
        report = build_report(
            extract_record(payload, args.cve), args.cve, VARIANT_NUMBER
        )
    except OSError:
        print("Не вдалося прочитати локальний файл", file=sys.stderr)
        return 1
    except (json.JSONDecodeError, UnicodeError):
        print("Локальний файл має містити коректний JSON у UTF-8", file=sys.stderr)
        return 1
    except (NvdError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1

    # виводимо звіт у термінал
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
