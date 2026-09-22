"""AES-256-ECB, совместимо с Java `Cipher.getInstance("AES")` (= AES/ECB/PKCS5Padding).

Ключ формируется как в исходной программе: байты строки-ключа, обрезанные/дополненные
нулями до 32 байт. Встроенного ключа нет — он хранится у пользователя в ~/.config/jpgs/key. ECB шифрует каждый 16-байтный блок независимо, поэтому любой
выровненный фрагмент файла можно расшифровать отдельно — на этом построено чтение
больших файлов без загрузки их целиком в память.

Бэкенд: пакет `cryptography`, если установлен, иначе libcrypto (OpenSSL) через ctypes.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os

BLOCK = 16
KEY_ENV = "JPGS_KEY"        # ключ старого формата (байты строки как есть)
WORD_ENV = "JPGS_WORD"      # слово нового формата (усиливается PBKDF2)

# Усиление ключа: слово → 32 байта через PBKDF2-HMAC-SHA256.
# Соль намеренно фиксированная, а не случайная: одно и то же слово должно давать один и тот
# же ключ на любом компьютере — иначе потеря файла keystore.json означала бы потерю файлов,
# даже если слово помнишь. Стойкость даёт не соль, а цена одной попытки перебора: вместо
# одного блока AES злоумышленнику нужно KDF_ITERS итераций HMAC на каждого кандидата.
KDF_SALT = b"jpgs-kdf-v1"
KDF_ITERS = 300_000


class KeyMissing(Exception):
    """Ключ шифрования не задан (см. `jpgs set-key`)."""


class KeyLocked(KeyMissing):
    """Хранилище ключей защищено паролем и ещё не разблокировано.

    Наследует KeyMissing, чтобы старый код (`except KeyMissing`) продолжал работать,
    но интерфейс может отличить «нет ключа» от «нужен пароль» и спросить пароль.
    """


def config_dir() -> str:
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "jpgs")


def key_file() -> str:
    return os.path.join(config_dir(), "key")


def key_bytes(key: str) -> bytes:
    """Старый формат (как в Java-версии): байты строки, обрезанные/дополненные нулями до 32.

    Слабое место: слово становится ключом напрямую, поэтому кандидат при переборе проверяется
    одним блоком AES. Оставлено ради файлов, зашифрованных прежними версиями. Для новых
    ключей — derive_material().
    """
    raw = key.encode("utf-8")[:32]
    return raw + b"\0" * (32 - len(raw))


def derive_material(word: str, iters: int = KDF_ITERS) -> bytes:
    """Новый формат: слово любой длины → полноценные 32 байта ключа AES-256."""
    import hashlib
    return hashlib.pbkdf2_hmac("sha256", word.encode("utf-8"), KDF_SALT, iters, 32)


def material_for(key: str, kind: str = "derived") -> bytes:
    """Байты ключа по слову и типу записи: 'raw' — старый формат, 'derived' — усиленный."""
    return key_bytes(key) if kind == "raw" else derive_material(key)


def fingerprint_material(material: bytes) -> str:
    """Отпечаток по готовым байтам ключа."""
    import hashlib
    h = hashlib.sha256(b"jpgs-key-fingerprint:" + material).hexdigest()
    return f"{h[0:4]}-{h[4:8]}-{h[8:12]}".upper()


def fingerprint(key: str) -> str:
    """Отпечаток ключа старого формата — сверить, что на двух компьютерах ключ одинаковый.

    Значения намеренно совпадают с прежними версиями (считается от key_bytes).
    """
    return fingerprint_material(key_bytes(key))


def _legacy_key() -> str | None:
    """Ключ из старых мест: файл ~/.config/jpgs/key → (устар.) settings.json."""
    try:
        with open(key_file(), encoding="utf-8") as f:
            k = f.read().strip("\r\n")
            if k:
                return k
    except OSError:
        pass
    try:  # совместимость с 2.0: ключ в settings.json
        with open(os.path.join(config_dir(), "settings.json"), encoding="utf-8") as f:
            k = json.load(f).get("key")
            if k:
                return k
    except (OSError, ValueError):
        pass
    return None


def configured_key() -> str:
    """Активное ключевое слово: JPGS_WORD → JPGS_KEY → хранилище → (устар.) ~/.config/jpgs/key.

    Возвращает именно слово. Для шифрования нужны байты — см. configured_material():
    у ключей нового формата слово и байты уже не одно и то же.
    """
    env = os.environ.get(WORD_ENV) or os.environ.get(KEY_ENV)
    if env:
        return env
    from . import keystore  # ленивый импорт: keystore зависит от crypto
    ks = keystore.get_keystore()
    if ks.exists():
        return ks.active_key()  # может поднять KeyLocked / KeyMissing
    legacy = _legacy_key()
    if legacy:
        return legacy
    raise KeyMissing("Ключ шифрования не задан. Выполните: jpgs set-key")


def configured_material() -> bytes:
    """Байты активного ключа — то, чем реально шифруется.

    JPGS_WORD — слово нового формата (усиливается), JPGS_KEY — ключ старого формата
    (байты как есть, поведение прежних версий не меняется). Дальше — активный ключ
    хранилища с его собственным типом, затем старый файл ~/.config/jpgs/key.
    """
    word = os.environ.get(WORD_ENV)
    if word:
        return derive_material(word)
    env = os.environ.get(KEY_ENV)
    if env:
        return key_bytes(env)
    from . import keystore
    ks = keystore.get_keystore()
    if ks.exists():
        return ks.active_material()  # может поднять KeyLocked / KeyMissing
    legacy = _legacy_key()
    if legacy:
        return key_bytes(legacy)
    raise KeyMissing("Ключ шифрования не задан. Выполните: jpgs set-key")


def has_key() -> bool:
    """Есть ли рабочий ключ. Проверяем именно байты: слово может не храниться."""
    try:
        configured_material()
        return True
    except KeyMissing:
        return False


def save_key(key: str) -> str:
    """Сохраняет ключ в ~/.config/jpgs/key с правами 600. Возвращает путь."""
    if not key:
        raise ValueError("пустой ключ")
    os.makedirs(config_dir(), mode=0o700, exist_ok=True)
    path = key_file()
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return path


def generate_key() -> str:
    """Случайный ключ: 32 символа base64url = 32 байта ключа AES-256 (~192 бита энтропии)."""
    import secrets
    return secrets.token_urlsafe(24)


class _CryptographyBackend:
    def __init__(self, key: bytes):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        self._cipher = Cipher(algorithms.AES(key), modes.ECB())

    def decrypt_blocks(self, data: bytes) -> bytes:
        d = self._cipher.decryptor()
        return d.update(data) + d.finalize()

    def encrypt_blocks(self, data: bytes) -> bytes:
        e = self._cipher.encryptor()
        return e.update(data) + e.finalize()


class _OpenSSLBackend:
    _lib = None

    def __init__(self, key: bytes):
        if _OpenSSLBackend._lib is None:
            name = ctypes.util.find_library("crypto") or "libcrypto.so.3"
            lib = ctypes.CDLL(name)
            lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            lib.EVP_aes_256_ecb.restype = ctypes.c_void_p
            for fn in ("EVP_DecryptInit_ex", "EVP_EncryptInit_ex"):
                getattr(lib, fn).argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_char_p, ctypes.c_char_p]
            for fn in ("EVP_DecryptUpdate", "EVP_EncryptUpdate"):
                getattr(lib, fn).argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
            lib.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
            _OpenSSLBackend._lib = lib
        self._key = key

    def _run(self, data: bytes, enc: bool) -> bytes:
        lib = self._lib
        ctx = lib.EVP_CIPHER_CTX_new()
        try:
            init = lib.EVP_EncryptInit_ex if enc else lib.EVP_DecryptInit_ex
            upd = lib.EVP_EncryptUpdate if enc else lib.EVP_DecryptUpdate
            if init(ctx, lib.EVP_aes_256_ecb(), None, self._key, None) != 1:
                raise RuntimeError("OpenSSL: init failed")
            lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
            out = ctypes.create_string_buffer(len(data) + BLOCK)
            n = ctypes.c_int(0)
            if upd(ctx, out, ctypes.byref(n), data, len(data)) != 1:
                raise RuntimeError("OpenSSL: update failed")
            return out.raw[:n.value]
        finally:
            lib.EVP_CIPHER_CTX_free(ctx)

    def decrypt_blocks(self, data: bytes) -> bytes:
        return self._run(data, False)

    def encrypt_blocks(self, data: bytes) -> bytes:
        return self._run(data, True)


def _make_backend(kb: bytes, backend: str | None = None):
    """Лучший доступный AES-бэкенд для 32-байтного ключа."""
    if backend == "openssl":
        return _OpenSSLBackend(kb)
    try:
        return _CryptographyBackend(kb)
    except ImportError:
        return _OpenSSLBackend(kb)


def block_cipher(key32: bytes, backend: str | None = None):
    """AES-256-ECB над готовыми 32 байтами ключа (без key_bytes-дополнения).

    Отдаёт объект с encrypt_blocks/decrypt_blocks — низкоуровневый примитив,
    на котором keystore строит CBC для шифрования хранилища ключей паролем.
    """
    if len(key32) != 32:
        raise ValueError("нужен 32-байтный ключ")
    return _make_backend(key32, backend)


class Cipher:
    """AES-256-ECB. *_blocks — без паддинга (длина кратна 16).

    Cipher()                      — активный ключ (хранилище/окружение);
    Cipher(material=b"…32 байта") — готовые байты ключа (ключ любого формата);
    Cipher("слово")               — СТАРЫЙ формат (байты слова), оставлен для совместимости
                                    со скриптами и файлами прежних версий.
    """

    def __init__(self, key: str | None = None, backend: str | None = None,
                 material: bytes | None = None):
        if material is None:
            material = key_bytes(key) if key is not None else configured_material()
        if len(material) != 32:
            raise ValueError("ключ должен быть длиной 32 байта")
        self._b = _make_backend(material, backend)
        self.backend = type(self._b).__name__

    def decrypt_blocks(self, data: bytes) -> bytes:
        return self._b.decrypt_blocks(data)

    def encrypt_blocks(self, data: bytes) -> bytes:
        return self._b.encrypt_blocks(data)

    def encrypt(self, data: bytes) -> bytes:
        """Шифрование с PKCS#5/7 паддингом — как делает Java."""
        pad = BLOCK - len(data) % BLOCK
        return self._b.encrypt_blocks(data + bytes([pad]) * pad)

    def decrypt(self, data: bytes) -> bytes:
        usable = len(data) - len(data) % BLOCK
        plain = self._b.decrypt_blocks(data[:usable])
        return strip_padding(plain)


def strip_padding(plain: bytes) -> bytes:
    if plain:
        p = plain[-1]
        if 1 <= p <= BLOCK and plain.endswith(bytes([p]) * p):
            return plain[:-p]
    return plain
