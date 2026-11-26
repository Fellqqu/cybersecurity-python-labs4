import pytest


# ця фікстура автоматично запускається перед кожним тестом
@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    # прибираємо справжній ключ щоб результат не залежав від налаштувань системи
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    # блокуємо справжні запити щоб тести працювали без інтернету
    monkeypatch.delattr("requests.sessions.Session.request")
