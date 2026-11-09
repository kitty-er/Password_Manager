import base64
import hmac
import json
import secrets
import string
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
    ITERATIONS = 600_000
    MIN_MASTER_LENGTH = 8

    def __init__(self, vault_path: str | Path = "vault.json") -> None:
        self.vault_path = Path(vault_path)
        self._fernet: Fernet | None = None
        self._entries: dict[str, dict[str, str]] = {}

    @staticmethod
    def _derive_keys(password: str, salt: bytes) -> tuple[str, bytes]:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            iterations=PasswordManager.ITERATIONS,
        )
        material = kdf.derive(password.encode("utf-8"))
        password_hash = material[:32].hex()
        encryption_key = base64.urlsafe_b64encode(material[32:])
        return password_hash, encryption_key

    def init_master(self, password: str) -> None:
        if self.vault_path.exists():
            raise FileExistsError("Хранилище уже существует.")
        if len(password) < self.MIN_MASTER_LENGTH:
            raise ValueError("Мастер-пароль должен содержать минимум 8 символов.")
        salt = secrets.token_bytes(16)
        password_hash, encryption_key = self._derive_keys(password, salt)
        self._fernet = Fernet(encryption_key)
        self._entries = {}
        self._persist_new_vault(salt, password_hash)

    def _persist_new_vault(self, salt: bytes, password_hash: str) -> None:
        if self._fernet is None:
            raise RuntimeError("Сначала необходимо создать хранилище.")
        encrypted_data = self._fernet.encrypt(b"{}").decode("utf-8")
        vault = {
            "salt": salt.hex(),
            "password_hash": password_hash,
            "data": encrypted_data,
        }
        self._write_vault(vault)

    def _write_vault(self, vault: dict[str, str]) -> None:
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.vault_path.with_suffix(self.vault_path.suffix + ".tmp")
        temporary_path.write_text(
            json.dumps(vault, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary_path.replace(self.vault_path)

    def unlock(self, password: str) -> bool:
        if not self.vault_path.exists():
            return False
        try:
            vault: Any = json.loads(self.vault_path.read_text(encoding="utf-8"))
            if not isinstance(vault, dict):
                return False
            salt_hex = vault.get("salt")
            saved_hash = vault.get("password_hash")
            encrypted_data = vault.get("data")
            if not isinstance(salt_hex, str):
                return False
            if not isinstance(saved_hash, str):
                return False
            if not isinstance(encrypted_data, str):
                return False
            salt = bytes.fromhex(salt_hex)
            password_hash, encryption_key = self._derive_keys(password, salt)
            if not hmac.compare_digest(password_hash, saved_hash):
                return False
            fernet = Fernet(encryption_key)
            decrypted = fernet.decrypt(encrypted_data.encode("utf-8"))
            entries: Any = json.loads(decrypted.decode("utf-8"))
            if not isinstance(entries, dict):
                return False
            checked_entries: dict[str, dict[str, str]] = {}
            for name, entry in entries.items():
                if not isinstance(name, str) or not isinstance(entry, dict):
                    return False
                if not all(
                    isinstance(entry.get(field), str) for field in ("login", "password")
                ):
                    return False
                checked_entries[name] = {
                    "login": entry["login"],
                    "password": entry["password"],
                }
            self._fernet = fernet
            self._entries = checked_entries
            return True
        except (OSError, ValueError, TypeError, KeyError, InvalidToken):
            return False

    def _require_unlocked(self) -> Fernet:
        if self._fernet is None:
            raise RuntimeError("Сначала войдите в хранилище.")
        return self._fernet

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        fernet = self._require_unlocked()
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Название сайта не может быть пустым.")
        if not login:
            raise ValueError("Логин не может быть пустым.")
        if not pwd:
            raise ValueError("Пароль не может быть пустым.")
        self._entries[clean_name] = {"login": login, "password": pwd}
        self._persist(fernet)

    def list_entries(self) -> list[str]:
        self._require_unlocked()
        return sorted(self._entries)

    def get_entry(self, name: str) -> dict[str, str] | None:
        self._require_unlocked()
        entry = self._entries.get(name)
        return dict(entry) if entry is not None else None

    def delete_entry(self, name: str) -> bool:
        fernet = self._require_unlocked()
        if name not in self._entries:
            return False
        del self._entries[name]
        self._persist(fernet)
        return True

    def _persist(self, fernet: Fernet | None = None) -> None:
        active_fernet = fernet if fernet is not None else self._require_unlocked()
        vault: Any = json.loads(self.vault_path.read_text(encoding="utf-8"))
        encrypted_data = active_fernet.encrypt(
            json.dumps(self._entries, ensure_ascii=False).encode("utf-8")
        ).decode("utf-8")
        vault["data"] = encrypted_data
        self._write_vault(vault)

    @staticmethod
    def generate_password(length: int = 20) -> str:
        if length < 12:
            raise ValueError("Длина пароля должна быть не меньше 12 символов.")
        groups = (
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            "!@#$%^&*()-_=+",
        )
        password_chars = [secrets.choice(group) for group in groups]
        alphabet = "".join(groups)
        password_chars.extend(
            secrets.choice(alphabet) for _ in range(length - len(password_chars))
        )
        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)
