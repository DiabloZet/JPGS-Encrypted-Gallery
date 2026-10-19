"""Хранилище нескольких ключей шифрования с необязательным паролем на программу.

Файл ~/.config/jpgs/keystore.json хранит список именованных ключей и то, какой из них
активен. Пароль на программу — необязательный: если он задан, весь список ключей
хранится в зашифрованном виде, а сам пароль на диск не пишется вовсе — хранится только
соль и HMAC-проверка (по ним нельзя восстановить пароль, но можно проверить введённый).

Шифрование хранилища:
  * ключ выводится из пароля через scrypt (N=2^17, r=8 — 128 МиБ памяти на попытку) со
    случайной солью; хранилища прежних версий (PBKDF2) читаются и при первом же сохранении
    переводятся на scrypt;
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

Запоминание пароля (необязательно, settings.json → "unlock_minutes"): после ввода пароля
выведенные из него ключи хранилища (не сам пароль) кладутся в $XDG_RUNTIME_DIR — это
каталог в памяти (tmpfs), доступный только пользователю и очищаемый при выходе из системы.
До истечения срока программа открывается без пароля. «Заблокировать сейчас» стирает его.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

from .crypto import (DEFAULT_KIND, KEY_KINDS, SCRYPT_MAXMEM, KeyLocked, KeyMissing,
                     cbc_decrypt, cbc_encrypt, config_dir, fingerprint_material, key_file, key_strength,
                     material_for, _legacy_key)

PBKDF2_ITERS = 200_000          # только для чтения хранилищ прежних версий
PW_SCRYPT = {"n": 1 << 17, "r": 8, "p": 1}
_VERSION = 1


def keystore_file() -> str:
    return os.path.join(config_dir(), "keystore.json")


# CBC (cbc_encrypt / cbc_decrypt) — в crypto.py: им же шифруется индекс архивов.
_cbc_encrypt, _cbc_decrypt = cbc_encrypt, cbc_decrypt


def _derive(password: str, kdf: dict) -> tuple[bytes, bytes]:
    """(ключ шифрования, ключ HMAC) из пароля по параметрам kdf из файла."""
    salt = bytes.fromhex(kdf["salt"])
    pw = password.encode("utf-8")
    if kdf.get("algo") == "scrypt":
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        if not (1 << 14 <= n <= 1 << 22 and 1 <= r <= 32 and 1 <= p <= 16):
            raise ValueError("недопустимые параметры scrypt")
        out = hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM * 2, dklen=64)
        return out[:32], out[32:]
    iters = int(kdf["iters"])
    if not 1000 <= iters <= 10_000_000:
        raise ValueError("недопустимое число итераций")
    enc = hashlib.pbkdf2_hmac("sha256", pw, salt, iters, 32)
    mac = hashlib.pbkdf2_hmac("sha256", pw, salt + b"\x01mac", iters, 32)
    return enc, mac


def _new_kdf() -> dict:
    return {"algo": "scrypt", "salt": secrets.token_hex(16), **PW_SCRYPT}


# --------------------------------------------------------------------------- запоминание пароля

def _settings_path() -> str:
    return os.path.join(config_dir(), "settings.json")


def unlock_minutes() -> int:
    """Сколько минут помнить пароль (0 — спрашивать каждый раз). Хранится в settings.json."""
    try:
        with open(_settings_path(), encoding="utf-8") as f:
            v = int(json.load(f).get("unlock_minutes") or 0)
        return max(0, min(v, 7 * 24 * 60))
    except (OSError, ValueError, TypeError):
        return 0


def _cache_path() -> Optional[str]:
    """Файл кэша в $XDG_RUNTIME_DIR (tmpfs, 0700). Без него запоминание недоступно."""
    rt = os.environ.get("XDG_RUNTIME_DIR")
    if not rt or not os.path.isdir(rt):
        return None
    try:
        st = os.stat(rt)
        if hasattr(os, "getuid") and (st.st_uid != os.getuid() or st.st_mode & 0o077):
            return None  # чужой или доступный другим каталог — не доверяем
    except OSError:
        return None
    return os.path.join(rt, "jpgs-unlock.json")


def unlock_cache_available() -> bool:
    return _cache_path() is not None


def forget_unlock():
    p = _cache_path()
    if p:
        try:
            os.unlink(p)
        except OSError:
            pass


# --------------------------------------------------------------------------- хранилище

class Keystore:
    def __init__(self):
        self._loaded = False
        self._exists = False
        self._encrypted = False
        self._locked = False
        self._data: Optional[dict] = None       # {"active":..., "keys":[...]} когда открыто
        self._keys: Optional[tuple] = None       # (kdf, enc_key, mac_key) пока открыто с паролем
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
            if not isinstance(raw, dict):
                raise ValueError("не объект JSON")
        except FileNotFoundError:
            self._maybe_migrate_legacy()
            return
        except (OSError, ValueError):
            # Файл есть, но не читается: не затираем его новым пустым хранилищем при
            # следующем сохранении — откладываем копию, чтобы ключи можно было спасти.
            if os.path.exists(path):
                try:
                    os.replace(path, f"{path}.broken-{int(time.time())}")
                except OSError:
                    pass
            self._maybe_migrate_legacy()
            return
        self._exists = True
        if raw.get("encrypted"):
            self._encrypted = True
            self._locked = True
            self._enc = raw
            self._try_cached_unlock()
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
        kdf = self._enc["kdf"]
        try:
            enc_key, mac_key = _derive(password, kdf)
            self._decrypt(enc_key, mac_key)
        except (ValueError, KeyError, TypeError):
            return False
        self._keys = (kdf, enc_key, mac_key)
        self._locked = False
        upgrade = kdf.get("algo") != "scrypt"
        if upgrade:  # хранилище прежней версии (PBKDF2) — перевести на scrypt
            self._keys = None
            self._set_password_keys(password)
        if self._normalize() or upgrade:
            self._save()
        self._remember()
        return True

    def lock(self):
        """Забыть открытое хранилище и сохранённую разблокировку (если пароль задан)."""
        forget_unlock()
        if self._encrypted:
            self._data = None
            self._keys = None
            self._locked = True

    def _decrypt(self, enc_key: bytes, mac_key: bytes):
        meta = self._enc
        iv = bytes.fromhex(meta["iv"])
        ct = bytes.fromhex(meta["ct"])
        mac = bytes.fromhex(meta["mac"])
        if not hmac.compare_digest(mac, hmac.new(mac_key, iv + ct, hashlib.sha256).digest()):
            raise ValueError("неверный пароль")
        plain = _cbc_decrypt(enc_key, iv, ct)
        payload = json.loads(plain.decode("utf-8"))
        self._data = {"active": payload.get("active"), "keys": list(payload.get("keys", []))}

    def _set_password_keys(self, password: str):
        kdf = _new_kdf()
        enc_key, mac_key = _derive(password, kdf)
        self._keys = (kdf, enc_key, mac_key)

    # ---- запоминание разблокировки

    def _remember(self):
        mins = unlock_minutes()
        path = _cache_path()
        if not mins or not path or not self._keys:
            forget_unlock()
            return
        kdf, enc_key, mac_key = self._keys
        doc = {"salt": kdf["salt"], "enc": enc_key.hex(), "mac": mac_key.hex(),
               "expires": time.time() + mins * 60}
        try:
            fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            os.replace(path + ".tmp", path)
        except OSError:
            pass

    def _try_cached_unlock(self):
        path = _cache_path()
        if not path or not unlock_minutes():
            return
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
            if float(doc["expires"]) < time.time():
                raise ValueError("срок истёк")
            kdf = self._enc["kdf"]
            if doc["salt"] != kdf.get("salt"):
                raise ValueError("пароль сменился")
            enc_key, mac_key = bytes.fromhex(doc["enc"]), bytes.fromhex(doc["mac"])
            self._decrypt(enc_key, mac_key)
        except (OSError, ValueError, KeyError, TypeError):
            forget_unlock()
            return
        self._keys = (self._enc["kdf"], enc_key, mac_key)
        self._locked = False

    def unlock_expires(self) -> Optional[float]:
        """Время (unix), до которого пароль запомнен, или None."""
        path = _cache_path()
        if not path:
            return None
        try:
            with open(path, encoding="utf-8") as f:
                t = float(json.load(f)["expires"])
            return t if t > time.time() else None
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _require_open(self):
        self._load()
        if self._encrypted and self._locked:
            raise KeyLocked("Хранилище ключей защищено паролем. Введите пароль.")

    # ---- доступ к ключам

    @staticmethod
    def kind_of(entry: dict) -> str:
        """Тип записи: 'raw' — старый формат (записи без поля kind), 'derived' — PBKDF2,
        'scrypt' — самый стойкий."""
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
                    entry["weak"] = not key_strength(word)[0]
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

    def all_materials(self) -> list[bytes]:
        """Байты всех ключей (активный первым) — для открытия файлов любым из них."""
        self._require_open()
        keys = (self._data or {}).get("keys", [])
        aid = self._data.get("active") if self._data else None
        order = sorted(keys, key=lambda k: k["id"] != aid)
        return [self._material_of(k) for k in order]

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
            kind: str = DEFAULT_KIND, material: Optional[bytes] = None) -> str:
        """Добавить ключ. По умолчанию самый стойкий (слово → scrypt → 32 байта);
        kind='raw'/'derived' — ключи прежних версий, чтобы открывать их файлы.
        material — уже посчитанные байты (окно ключей считает их в фоне)."""
        self._require_open()
        if not key:
            raise ValueError("пустой ключ")
        if kind not in KEY_KINDS:
            raise ValueError("неизвестный тип ключа")
        if material is None:
            material = material_for(key, kind)
        if any(self._material_of(k) == material for k in (self._data or {}).get("keys", [])):
            raise ValueError("такой ключ уже есть в списке")
        if self._data is None:
            self._data = {"active": None, "keys": []}
            self._exists = True
        kid = secrets.token_hex(6)
        # на диск идут только байты ключа: само слово не сохраняем
        entry = {"id": kid, "name": name or "Ключ", "kind": kind,
                 "material": material.hex(),
                 "weak": not key_strength(key)[0]}
        self._data["keys"].append(entry)
        if activate or (activate is None and self._data.get("active") is None):
            self._data["active"] = kid
        self._save()
        return kid

    def upgrade(self, kid: str, name: Optional[str] = None,
                activate: bool = False, word: Optional[str] = None) -> str:
        """Усилить ключ: то же слово, но ключ выводится через scrypt.

        Для ключа старого формата слово восстанавливается из его байтов; для PBKDF2-ключа
        слово не хранится — его нужно передать (word) и оно проверяется по байтам ключа.

        Старая запись остаётся — ею открываются уже существующие файлы, пока они не
        перешифрованы новым ключом (см. container.reencrypt_media).
        """
        self._require_open()
        for k in (self._data or {}).get("keys", []):
            if k["id"] == kid:
                kind = self.kind_of(k)
                if kind == "scrypt":
                    raise ValueError("этот ключ уже максимально усилен")
                if word is None:
                    word = self._word_of(k)  # у старого формата слово — это его же байты
                if word is None:
                    raise ValueError("нужно ввести слово этого ключа")
                if material_for(word, kind) != self._material_of(k):
                    raise ValueError("слово не подходит к этому ключу")
                return self.add(name or f"{k['name']} (усиленный)", word,
                                activate=activate, kind="scrypt")
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
            self._set_password_keys(new_password)
            self._encrypted = True
        else:
            self._keys = None
            self._encrypted = False
        forget_unlock()
        self._save()
        if new_password:
            self._remember()

    # ---- запись

    def _payload(self) -> dict:
        return {"active": self._data.get("active"), "keys": self._data.get("keys", [])}

    def _save(self):
        path = keystore_file()
        os.makedirs(config_dir(), mode=0o700, exist_ok=True)
        if self._encrypted and not self._keys:
            raise KeyLocked("хранилище заблокировано — сохранить нельзя")
        if self._encrypted:
            kdf, enc_key, mac_key = self._keys
            iv = secrets.token_bytes(16)
            plain = json.dumps(self._payload(), ensure_ascii=False).encode("utf-8")
            ct = _cbc_encrypt(enc_key, iv, plain)
            mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
            doc = {"version": _VERSION, "encrypted": True, "kdf": kdf,
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
