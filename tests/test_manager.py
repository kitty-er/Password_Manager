"""Tests for the password manager."""

import json

import pytest

from password_manager.manager import PasswordManager


def test_unlock_with_correct_and_wrong_password(tmp_path) -> None:
    """The correct master password opens the vault and a wrong one does not."""
    vault = tmp_path / "vault.json"
    manager = PasswordManager(vault)
    manager.init_master("correct horse battery")
    assert manager.unlock("correct horse battery") is True
    assert manager.unlock("wrong password") is False


def test_init_cannot_overwrite_existing_vault(tmp_path) -> None:
    """A second initialization must not overwrite an existing vault."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master("correct horse battery")
    with pytest.raises(FileExistsError):
        manager.init_master("another master password")


def test_add_list_and_get_entry(tmp_path) -> None:
    """Added entries appear in the list and can be retrieved."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master("correct horse battery")
    manager.add_entry("example.com", "alice", "secret123")
    assert manager.list_entries() == ["example.com"]
    assert manager.get_entry("example.com") == {
        "login": "alice",
        "password": "secret123",
    }


def test_delete_entry(tmp_path) -> None:
    """Deleting an entry removes it from the vault."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master("correct horse battery")
    manager.add_entry("example.com", "alice", "secret123")
    assert manager.delete_entry("example.com") is True
    assert manager.list_entries() == []
    assert manager.delete_entry("missing.com") is False


def test_secrets_are_not_saved_in_plain_text(tmp_path) -> None:
    """The master password and account password must not appear in the file."""
    vault = tmp_path / "vault.json"
    manager = PasswordManager(vault)
    manager.init_master("correct horse battery")
    manager.add_entry("example.com", "alice", "very-secret-password")
    contents = vault.read_text(encoding="utf-8")
    assert "correct horse battery" not in contents
    assert "very-secret-password" not in contents
    stored = json.loads(contents)
    assert "password_hash" in stored
    assert "salt" in stored


def test_generate_password() -> None:
    """Generated passwords have the requested length and character groups."""
    password = PasswordManager.generate_password(24)
    assert len(password) == 24
    assert any(char.islower() for char in password)
    assert any(char.isupper() for char in password)
    assert any(char.isdigit() for char in password)
    assert any(char in "!@#$%^&*()-_=+" for char in password)
