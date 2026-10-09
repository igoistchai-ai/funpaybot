#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Secure-ish, opt-in FunPay session bootstrap for FUNPAY LISTER.

Passwords are accepted only on the short-lived HTTPS web form, used once by
Playwright, never written to disk or logs. Browser storage state is encrypted
with Fernet before it is persisted to SQLite. Set SESSION_ENCRYPTION_KEY.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

log = logging.getLogger("funpay_auth")
FUNPAY_LOGIN_URL = "https://funpay.com/account/login"
TOKEN_TTL_SECONDS = 15 * 60


class AuthNotConfigured(RuntimeError):
    pass


class FunPayAuthStore:
    def __init__(self, database_path: str) -> None:
        key = os.getenv("SESSION_ENCRYPTION_KEY", "").strip()
        if not key:
            self.fernet = None
        else:
            try:
                self.fernet = Fernet(key.encode("ascii"))
            except (ValueError, UnicodeEncodeError) as exc:
                raise AuthNotConfigured(
                    "SESSION_ENCRYPTION_KEY should be a valid Fernet key."
                ) from exc
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        return db

    def _init_db(self) -> None:
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS funpay_connect_tokens (
                token_hash TEXT PRIMARY KEY,
                telegram_user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS funpay_sessions (
                telegram_user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                encrypted_state BLOB NOT NULL,
                connected_at INTEGER NOT NULL,
                checked_at INTEGER NOT NULL
            )""")

    def make_token(self, telegram_user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._db() as db:
            db.execute("DELETE FROM funpay_connect_tokens WHERE expires_at < ? OR used_at IS NOT NULL", (now,))
            db.execute(
                "INSERT INTO funpay_connect_tokens(token_hash,telegram_user_id,created_at,expires_at) VALUES(?,?,?,?)",
                (digest, telegram_user_id, now, now + TOKEN_TTL_SECONDS),
            )
        return token

    def user_for_token(self, token: str) -> int | None:
        if not token or len(token) > 128:
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._db() as db:
            row = db.execute(
                "SELECT telegram_user_id,expires_at,used_at FROM funpay_connect_tokens WHERE token_hash=?",
                (digest,),
            ).fetchone()
        if not row or row["used_at"] is not None or int(row["expires_at"]) < int(time.time()):
            return None
        return int(row["telegram_user_id"])

    def consume_token(self, token: str) -> int | None:
        if not token or len(token) > 128:
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        now = int(time.time())
        with self._db() as db:
            row = db.execute(
                "SELECT telegram_user_id,expires_at,used_at FROM funpay_connect_tokens WHERE token_hash=?",
                (digest,),
            ).fetchone()
            if not row or row["used_at"] is not None or int(row["expires_at"]) < now:
                return None
            cur = db.execute(
                "UPDATE funpay_connect_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL",
                (now, digest),
            )
            if cur.rowcount != 1:
                return None
            return int(row["telegram_user_id"])

    def save_session(self, user_id: int, username: str, state: dict[str, Any]) -> None:
        if self.fernet is None:
            raise AuthNotConfigured("SESSION_ENCRYPTION_KEY is not configured.")
        raw = json.dumps(state, separators=(",", ":")).encode("utf-8")
        encrypted = self.fernet.encrypt(raw)
        now = int(time.time())
        with self._db() as db:
            db.execute("""INSERT INTO funpay_sessions(telegram_user_id,username,encrypted_state,connected_at,checked_at)
                VALUES(?,?,?,?,?) ON CONFLICT(telegram_user_id) DO UPDATE SET
                username=excluded.username, encrypted_state=excluded.encrypted_state,
                connected_at=excluded.connected_at, checked_at=excluded.checked_at""",
                (user_id, username[:128], encrypted, now, now))

    def get_status(self, user_id: int) -> dict[str, Any] | None:
        with self._db() as db:
            row = db.execute(
                "SELECT username,connected_at,checked_at FROM funpay_sessions WHERE telegram_user_id=?",
                (user_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_decrypted_state(self, user_id: int) -> dict[str, Any] | None:
        if self.fernet is None:
            return None
        with self._db() as db:
            row = db.execute(
                "SELECT encrypted_state FROM funpay_sessions WHERE telegram_user_id=?", (user_id,)
            ).fetchone()
        if not row:
            return None
        try:
            raw = self.fernet.decrypt(bytes(row["encrypted_state"]))
            value = json.loads(raw.decode("utf-8"))
            return value if isinstance(value, dict) else None
        except (InvalidToken, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            log.error("Could not decrypt stored FunPay session for one user; state not logged.")
            return None

    def disconnect(self, user_id: int) -> bool:
        with self._db() as db:
            cur = db.execute("DELETE FROM funpay_sessions WHERE telegram_user_id=?", (user_id,))
            return cur.rowcount > 0


def attempt_login(username: str, password: str, timeout_ms: int = 20_000) -> tuple[bool, str, dict[str, Any] | None]:
    """Attempt official web login; never log or persist user-provided credentials."""
    username = username.strip()
    if not username or not password:
        return False, "Введи логин и пароль.", None
    if len(username) > 320 or len(password) > 1024:
        return False, "Слишком длинное значение поля.", None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                context = browser.new_context(locale="ru-RU", accept_downloads=False)
                page = context.new_page()
                page.set_default_timeout(timeout_ms)
                page.goto(FUNPAY_LOGIN_URL, wait_until="domcontentloaded", timeout=timeout_ms)
                # Official login form; do not print form contents or browser logs.
                login_locator = page.locator('input[name="login"], input[name="username"], input[type="email"]').first
                password_locator = page.locator('input[name="password"]').first
                login_locator.fill(username)
                password_locator.fill(password)
                password_locator.press("Enter")
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=12_000)
                except PlaywrightTimeoutError:
                    pass
                page.wait_for_timeout(1500)
                current_url = urlparse(page.url)
                still_login = (current_url.path.rstrip("/") == "/account/login" and
                               page.locator('input[name="password"]').count() > 0)
                if still_login:
                    try:
                        page_text = page.locator("body").inner_text(timeout=2500).lower()
                    except PlaywrightError:
                        page_text = ""
                    if any(word in page_text for word in ("captcha", "капч", "подтверд", "verification", "провер")):
                        return False, "FunPay запросил CAPTCHA/подтверждение. Автоматически завершить вход не удалось; сессия не сохранена.", None
                    return False, "FunPay не подтвердил вход. Проверь логин/пароль или дополнительную проверку; пароль не сохранён.", None

                cookies = context.cookies(["https://funpay.com"])
                cookie_names = {c.get("name", "") for c in cookies}
                # Require an expected FunPay session cookie before declaring success.
                if not ("golden_key" in cookie_names or "PHPSESSID" in cookie_names):
                    return False, "Страница изменилась, но сессионная cookie не обнаружена. Подключение не подтверждено.", None
                state = context.storage_state()
                return True, "Аккаунт авторизован; состояние сессии сохранено зашифрованно.", state
            finally:
                browser.close()
    except PlaywrightTimeoutError:
        return False, "FunPay не ответил вовремя. Попробуй ещё раз позже.", None
    except PlaywrightError:
        # Keep technical details and any page/user data out of logs and responses.
        log.warning("Playwright login attempt failed (details intentionally omitted).")
        return False, "Не удалось запустить браузер или завершить вход. Проверь установку Chromium и повтори позже.", None
    except Exception:
        log.warning("Unexpected error during FunPay login attempt; details omitted.")
        return False, "Неожиданная ошибка при подключении. Пароль не сохранён.", None
