from pathlib import Path

import pytest

from safevibe.vault import Vault


def test_encrypted_export_round_trip(tmp_path: Path):
    vault = Vault()
    token = vault.placeholder_for("SECRET", "demo-value")
    path = tmp_path / "vault.bin"
    vault.export_encrypted(path, "correct horse")
    loaded = Vault.import_encrypted(path, "correct horse")
    assert loaded.restore(f"x {token} y") == "x demo-value y"


def test_encrypted_export_rejects_bad_passphrase(tmp_path: Path):
    vault = Vault()
    vault.placeholder_for("SECRET", "demo-value")
    path = tmp_path / "vault.bin"
    vault.export_encrypted(path, "correct horse")
    with pytest.raises(Exception):
        Vault.import_encrypted(path, "wrong")
