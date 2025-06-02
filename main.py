"""
main.py — стартовый файл Marzban-Node
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
• Добавлена переменная окружения **DISABLE_INTERNAL_TLS**
  (если = "1" — REST-API внутри контейнера работает **без** TLS,
  удобно для Cloud Run/Ingress, где внешний TLS уже есть).
• В остальном логика оригинального проекта сохранена.

Для новичка:
  1. Скрипт читает переменные из config.py: порты, пути к сертификатам и т.д.
  2. Если SERVICE_PROTOCOL="rpyc" — запускает RPC-сервер.
     Если "rest" — запускает Uvicorn-сервер (FastAPI).
  3. Если TLS не отключён, генерирует самоподписанные server-cert/key
     и требует client-cert от панели.
"""

import os
import uvicorn
from rpyc.utils.authenticators import SSLAuthenticator
from rpyc.utils.server import ThreadedServer

import rest_service
import rpyc_service
from certificate import generate_certificate
from config import (
    SERVICE_HOST,
    SERVICE_PORT,
    SERVICE_PROTOCOL,
    SSL_CERT_FILE,
    SSL_KEY_FILE,
    SSL_CLIENT_CERT_FILE,
)
from logger import logger

# ─────────────────────────── Новая опция ────────────────────────────
DISABLE_INTERNAL_TLS = os.getenv("DISABLE_INTERNAL_TLS", "0") == "1"
# Если DISABLE_INTERNAL_TLS == True, Uvicorn стартует без ssl_* параметров.


def generate_ssl_files() -> None:
    """Генерирует server-side сертификат/ключ, если их ещё нет."""
    pems = generate_certificate()

    with open(SSL_KEY_FILE, "w") as f:
        f.write(pems["key"])

    with open(SSL_CERT_FILE, "w") as f:
        f.write(pems["cert"])


if __name__ == "__main__":
    # 1. Генерируем server-cert/key при первом запуске
    if not all((os.path.isfile(SSL_CERT_FILE), os.path.isfile(SSL_KEY_FILE))):
        generate_ssl_files()

    # 2. Проверяем наличие client-cert (нужно для mTLS, если TLS не отключён)
    if not DISABLE_INTERNAL_TLS:
        if not SSL_CLIENT_CERT_FILE:
            logger.warning(
                "Запуск без SSL_CLIENT_CERT_FILE небезопасен: любой может подключиться к узлу!"
            )
        elif not os.path.isfile(SSL_CLIENT_CERT_FILE):
            logger.error("Файл клиентского сертификата (SSL_CLIENT_CERT_FILE) не найден")
            exit(1)

    # ────────────────────── Протокол rpyc ──────────────────────
    if SERVICE_PROTOCOL == "rpyc":
        authenticator = SSLAuthenticator(
            keyfile=SSL_KEY_FILE,
            certfile=SSL_CERT_FILE,
            ca_certs=SSL_CLIENT_CERT_FILE or None,
        )
        server = ThreadedServer(
            rpyc_service.XrayService(),
            port=SERVICE_PORT,
            authenticator=authenticator,
        )
        logger.info(f"Node (rpyc) запущен на :{SERVICE_PORT}")
        server.start()

    # ────────────────────── Протокол REST ─────────────────────
    elif SERVICE_PROTOCOL == "rest":
        # Если TLS включён, но нет client-cert — останавливаемся
        if not DISABLE_INTERNAL_TLS and not SSL_CLIENT_CERT_FILE:
            logger.error("REST-службе требуется SSL_CLIENT_CERT_FILE (mTLS).")
            exit(1)

        logger.info(
            f"Node (rest) запущен на :{SERVICE_PORT} "
            f"{'(TLS отключён)' if DISABLE_INTERNAL_TLS else '(mTLS)'}"
        )

        uvicorn_kwargs = {
            "app": rest_service.app,
            "host": SERVICE_HOST,
            "port": SERVICE_PORT,
        }

        # Добавляем ssl_* только если TLS нужен
        if not DISABLE_INTERNAL_TLS:
            uvicorn_kwargs.update(
                {
                    "ssl_keyfile": SSL_KEY_FILE,
                    "ssl_certfile": SSL_CERT_FILE,
                    "ssl_ca_certs": SSL_CLIENT_CERT_FILE,
                    "ssl_cert_reqs": 2,  # require client cert
                }
            )

        uvicorn.run(**uvicorn_kwargs)

    # ──────────────────────── Ошибка протокола ───────────────────────
    else:
        logger.error('SERVICE_PROTOCOL должен быть "rpyc" или "rest".')
        exit(1)
