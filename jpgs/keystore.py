"""Хранилище нескольких ключей шифрования с необязательным паролем на программу.

Файл ~/.config/jpgs/keystore.json хранит список именованных ключей и то, какой из них
активен. Пароль на программу — необязательный: если он задан, весь список ключей
хранится в зашифрованном виде, а сам пароль на диск не пишется вовсе — хранится только
соль и HMAC-проверка (по ним нельзя восстановить пароль, но можно проверить введённый).

Шифрование хранилища:
  * ключ выводится из пароля через PBKDF2-HMAC-SHA256 (стандартная библиотека);
  * список ключей шифруется AES-256-CBC — CBC собран поверх того же блочного AES,
    что и весь проект (crypto.block_cipher), поэтому не зависит от бэкенда и не «светит»
    одинаковые блоки, как ECB;
  * HMAC-SHA256 проверяет и целостность, и правильность пароля.

Само ключевое слово на диск не пишется: в записи хранятся только готовые байты ключа
(material). Для ключей старого формата слово при необходимости восстанавливается из этих
байтов (там оно и было ключом), для усиленных — не восстанавливается и не нужно.
Это не защищает файлы само по себе — material и есть ключ, — но не оставляет на диске
слово, которое человек мог использовать где-то ещё как пароль. От чтения файла защищает
только пароль на программу: с ним шифруется вся запись целиком.

Формат без пароля:
  {"version":1, "active":"<id>", "keys":[{"id","name","kind","material","weak"}, ...]}
Формат с паролем:
  {"version":1, "encrypted":true, "kdf":{...}, "iv":"hex", "ct":"hex", "mac":"hex"}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from typing import Optional

from .crypto import (BLOCK, KeyLocked, KeyMissing, block_cipher, config_dir,
                     fingerprint_material, key_file, material_for, _legacy_key)

PBKDF2_ITERS = 200_000
_VERSION = 1


def keystore_file() -> str:
    return os.path.join(config_dir(), "keystore.json")


# --------------------------------------------------------------------------- CBC поверх ECB

def _pkcs7(data: bytes) -> bytes:
    pad = BLOCK - len(data) % BLOCK
    return data + bytes([pad]) * pad


def _unpkcs7(data: bytes) -> bytes:
    if not data or len(data) % BLOCK:
        raise ValueError("повреждённые данные")
    p = data[-1]
    if p < 1 or p > BLOCK or data[-p:] != bytes([p]) * p:
        raise ValueError("неверный паддинг")
    return data[:-p]


def _cbc_encrypt(key32: bytes, iv: bytes, plaintext: bytes) -> bytes:
    bc = block_cipher(key32)
    data = _pkcs7(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK):
        blk = bytes(a ^ b for a, b in zip(data[i:i + BLOCK], prev))
        prev = bc.encrypt_blocks(blk)
        out += prev
    return bytes(out)


def _cbc_decrypt(key32: bytes, iv: bytes, ct: bytes) -> bytes:
    if len(ct) % BLOCK:
        raise ValueError("повреждённые данные")
    bc = block_cipher(key32)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), BLOCK):
        blk = ct[i:i + BLOCK]
        dec = bc.decrypt_blocks(blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return _unpkcs7(bytes(out))


def _derive(password: str, salt: bytes, iters: int) -> tuple[bytes, bytes]:
    """(ключ шифрования, ключ HMAC) из пароля."""
    enc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, 32)
    mac = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt + b"\x01mac", iters, 32)
    return enc, mac


# --------------------------------------------------------------------------- хранилище

class Keystore:
    def __init__(self):
        self._loaded = False
        self._exists = False
        self._encrypted = False
        self._locked = False
        self._data: Optional[dict] = None       # {"active":..., "keys":[...]} когда открыто
        self._password: Optional[str] = None     # пароль в памяти, пока программа открыта
        self._enc: Optional[dict] = None         # kdf/iv/ct/mac когда зашифровано

    # ---- загрузка

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        path = keystore_file()
        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            self._maybe_migrate_legacy()
            return
        self._exists = True
        if raw.get("encrypted"):
            self._encrypted = True
            self._locked = True
            self._enc = raw
        else:
            self._data = {"active": raw.get("active"), "keys": list(raw.get("keys", []))}
            if self._normalize():
                self._save()  # чистим файл от слова, оставшегося от версий ≤ 2.4

    def _maybe_migrate_legacy(self):
        """Если хранилища нет, но есть старый ~/.config/jpgs/key — перенести его сюда.

        Обязательно как ключ старого формата: им зашифрованы уже существующие файлы.
        """
        legacy = _legacy_key()
        if not legacy:
            return
        self._exists = True
        self._data = {"active": None, "keys": []}
        self.add("Основной (старый формат)", legacy, kind="raw")

    def reload(self):
        self.__init__()
        self._load()

    # ---- состояние

    def exists(self) -> bool:
        self._load()
        return self._exists

    def is_encrypted(self) -> bool:
        self._load()
        return self._encrypted

    def is_locked(self) -> bool:
        self._load()
        return self._encrypted and self._locked

    def is_unlocked(self) -> bool:
        self._load()
        return self._exists and not self._locked

    # ---- разблокировка

    def unlock(self, password: str) -> bool:
        self._load()
        if not self._encrypted:
            return True
        if not self._locked:
            return True
        try:
            self._decrypt(password)
        except (ValueError, KeyError):
            return False
        self._password = password
        self._locked = False
        if self._normalize():
            self._save()
        return True

    def _decrypt(self, password: str):
        meta = self._enc
        kdf = meta["kdf"]
        salt = bytes.fromhex(kdf["salt"])
        iters = int(kdf["iters"])
        iv = bytes.fromhex(meta["iv"])
        ct = bytes.fromhex(meta["ct"])
        mac = bytes.fromhex(meta["mac"])
        enc_key, mac_key = _derive(password, salt, iters)
        if not hmac.compare_digest(mac, hmac.new(mac_key, iv + ct, hashlib.sha256).digest()):
            raise ValueError("неверный пароль")
        plain = _cbc_decrypt(enc_key, iv, ct)
        payload = json.loads(plain.decode("utf-8"))
        self._data = {"active": payload.get("active"), "keys": list(payload.get("keys", []))}

    def _require_open(self):
        self._load()
        if self._encrypted and self._locked:
            raise KeyLocked("Хранилище ключей защищено паролем. Введите пароль.")

    # ---- доступ к ключам

    @staticmethod
    def kind_of(entry: dict) -> str:
        """Тип записи: 'raw' — старый формат (записи без поля kind), 'derived' — усиленный."""
        return entry.get("kind") or "raw"

    def _material_of(self, entry: dict) -> bytes:
        """Байты ключа записи — это всё, что хранится на диске."""
        cached = entry.get("material")
        if cached:
            try:
                mat = bytes.fromhex(cached)
                if len(mat) == 32:
                    return mat
            except ValueError:
                pass
        word = entry.get("key")  # запись из версии ≤ 2.4, ещё со словом
        if word is None:
            raise KeyMissing(f"у ключа «{entry.get('name')}» нет данных ключа")
        mat = material_for(word, self.kind_of(entry))
        entry["material"] = mat.hex()
        return mat

    @staticmethod
    def _word_from_material(material: bytes, kind: str) -> Optional[str]:
        """Слово по байтам ключа — возможно только для старого формата.

        Там слово и было ключом: байты строки, добитые нулями. Усиленный ключ выведен
        необратимо, слово из него не достать (и хранить его незачем).
        """
        if kind != "raw":
            return None
        try:
            return material.rstrip(b"\0").decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _word_of(self, entry: dict) -> Optional[str]:
        word = entry.get("key")
        if word:
            return word
        return self._word_from_material(self._material_of(entry), self.kind_of(entry))

    def _normalize(self) -> bool:
        """Привести записи к текущему формату: посчитать material и убрать слово с диска."""
        changed = False
        for entry in (self._data or {}).get("keys", []):
            if "material" not in entry:
                self._material_of(entry)  # посчитает и положит в запись
                changed = True
            if "kind" not in entry:
                entry["kind"] = self.kind_of(entry)
                changed = True
            if "weak" not in entry:
                word = entry.get("key")
                if word is not None:
                    entry["weak"] = len(word.encode("utf-8")) < 16
                    changed = True
            if "key" in entry:  # слову на диске не место
                del entry["key"]
                changed = True
        return changed

    def _active_entry(self) -> dict:
        self._require_open()
        if not self._data or not self._data.get("keys"):
            raise KeyMissing("Ключ шифрования не задан. Добавьте ключ.")
        aid = self._data.get("active")
        for k in self._data["keys"]:
            if k["id"] == aid:
                return k
        first = self._data["keys"][0]  # активный не найден — чиним на первый
        self._data["active"] = first["id"]
        return first

    def active_key(self) -> str:
        """Ключевое слово активной записи, если его вообще можно узнать (старый формат).

        Для усиленных ключей слово не хранится и не восстанавливается — поднимается
        KeyMissing. Шифрование пользуется active_material(), слово ему не нужно.
        """
        word = self._word_of(self._active_entry())
        if word is None:
            raise KeyMissing("ключевое слово не хранится (усиленный ключ)")
        return word

    def active_material(self) -> bytes:
        """Байты активного ключа — этим шифруются файлы."""
        return self._material_of(self._active_entry())

    def material_by_id(self, kid: str) -> bytes:
        self._require_open()
        for k in (self._data or {}).get("keys", []):
            if k["id"] == kid:
                return self._material_of(k)
        raise KeyError(kid)

    def active_id(self) -> Optional[str]:
        self._require_open()
        return self._data.get("active") if self._data else None

    def key_by_id(self, kid: str) -> str:
        """Слово ключа, если оно узнаваемо (старый формат). Для шифрования — material_by_id."""
        self._require_open()
        for k in (self._data or {}).get("keys", []):
            if k["id"] == kid:
                word = self._word_of(k)
                if word is None:
                    raise KeyMissing("ключевое слово не хранится (усиленный ключ)")
                return word
        raise KeyError(kid)

    def entries(self) -> list[dict]:
        """[{id, name, fingerprint, active, weak, kind}] — для интерфейса и CLI."""
        self._require_open()
        aid = self._data.get("active") if self._data else None
        out = []
        for k in (self._data or {}).get("keys", []):
            kind = self.kind_of(k)
            out.append({"id": k["id"], "name": k["name"],
                        "fingerprint": fingerprint_material(self._material_of(k)),
                        "active": k["id"] == aid,
                        "kind": kind,
                        # слово не хранится, поэтому «короткий» помечается при создании
                        "weak": bool(k.get("weak"))})
        return out

    # ---- изменения

    def add(self, name: str, key: str, activate: Optional[bool] = None,
            kind: str = "derived") -> str:
        """Добавить ключ. По умолчанию усиленный (слово → PBKDF2 → 32 байта);
        kind='raw' — ключ старого формата, чтобы открывать файлы прежних версий."""
        self._require_open()
        if not key:
            raise ValueError("пустой ключ")
        if kind not in ("derived", "raw"):
            raise ValueError("неизвестный тип ключа")
        if self._data is None:
            self._data = {"active": None, "keys": []}
            self._exists = True
        kid = secrets.token_hex(6)
        # на диск идут только байты ключа: само слово не сохраняем
        entry = {"id": kid, "name": name or "Ключ", "kind": kind,
                 "material": material_for(key, kind).hex(),
                 "weak": len(key.encode("utf-8")) < 16}
        self._data["keys"].append(entry)
        if activate or (activate is None and self._data.get("active") is None):
            self._data["active"] = kid
        self._save()
        return kid

    def upgrade(self, kid: str, name: Optional[str] = None,
                activate: bool = False) -> str:
        """Усилить ключ старого формата: то же слово, но ключ выводится через PBKDF2.

        Старая запись остаётся — ею открываются уже существующие файлы, пока они не
        перешифрованы новым ключом (см. container.reencrypt_media).
        """
        self._require_open()
        for k in (self._data or {}).get("keys", []):
            if k["id"] == kid:
                if self.kind_of(k) == "derived":
                    raise ValueError("этот ключ уже усилен")
                word = self._word_of(k)  # у старого формата слово выводится из его же байтов
                if word is None:
                    raise ValueError("не удалось определить слово этого ключа — "
                                     "добавьте усиленный ключ вручную, введя слово")
                return self.add(name or f"{k['name']} (усиленный)", word,
                                activate=activate, kind="derived")
        raise KeyError(kid)

    def remove(self, kid: str):
        self._require_open()
        keys = self._data.get("keys", [])
        self._data["keys"] = [k for k in keys if k["id"] != kid]
        if self._data.get("active") == kid:
            self._data["active"] = self._data["keys"][0]["id"] if self._data["keys"] else None
        self._save()

    def set_active(self, kid: str):
        self._require_open()
        if any(k["id"] == kid for k in self._data.get("keys", [])):
            self._data["active"] = kid
            self._save()

    def rename(self, kid: str, name: str):
        self._require_open()
        for k in self._data.get("keys", []):
            if k["id"] == kid:
                k["name"] = name or k["name"]
                break
        self._save()

    def count(self) -> int:
        self._require_open()
        return len((self._data or {}).get("keys", []))

    # ---- пароль

    def set_password(self, new_password: Optional[str]):
        """Задать/сменить пароль (строка) или снять его (None). Требует открытого хранилища."""
        self._require_open()
        if new_password:
            self._password = new_password
            self._encrypted = True
        else:
            self._password = None
            self._encrypted = False
        self._save()

    # ---- запись

    def _payload(self) -> dict:
        return {"active": self._data.get("active"), "keys": self._data.get("keys", [])}

    def _save(self):
        path = keystore_file()
        os.makedirs(config_dir(), mode=0o700, exist_ok=True)
        if self._encrypted and self._password:
            salt = secrets.token_bytes(16)
            iv = secrets.token_bytes(16)
            enc_key, mac_key = _derive(self._password, salt, PBKDF2_ITERS)
            plain = json.dumps(self._payload(), ensure_ascii=False).encode("utf-8")
            ct = _cbc_encrypt(enc_key, iv, plain)
            mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
            doc = {"version": _VERSION, "encrypted": True,
                   "kdf": {"algo": "pbkdf2-sha256", "salt": salt.hex(), "iters": PBKDF2_ITERS},
                   "iv": iv.hex(), "ct": ct.hex(), "mac": mac.hex()}
            self._enc = doc
            self._locked = False
        else:
            doc = {"version": _VERSION, "active": self._data.get("active"),
                   "keys": self._data.get("keys", [])}
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        self._exists = True
        self._mirror_legacy()

    def _mirror_legacy(self):
        """Дублировать активный ключ в старый ~/.config/jpgs/key — только если это имеет смысл.

        Зеркалим, когда нет пароля И активный ключ старого формата: тогда прежние версии
        программы продолжают открывать те же файлы. Для усиленного ключа зеркало вредно —
        старая версия взяла бы слово как ключ напрямую и получила бы не тот ключ, поэтому
        файл удаляем. С паролем удаляем тоже: открытому ключу на диске там не место.
        """
        legacy = key_file()
        try:
            active = None
            if self._data and self._data.get("keys"):
                for k in self._data["keys"]:
                    if k["id"] == self._data.get("active"):
                        active = k
                        break
                active = active or self._data["keys"][0]
            word = self._word_of(active) if active is not None else None
            if not self._encrypted and active is not None \
                    and self.kind_of(active) == "raw" and word:
                fd = os.open(legacy + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(word + "\n")
                os.replace(legacy + ".tmp", legacy)
                os.chmod(legacy, 0o600)
            elif os.path.exists(legacy):
                os.unlink(legacy)
        except OSError:
            pass


_INSTANCE: Optional[Keystore] = None


def get_keystore() -> Keystore:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = Keystore()
    return _INSTANCE
