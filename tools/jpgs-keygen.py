#!/usr/bin/env python3
"""jpgs-keygen — генератор ключей для JPGS, без зависимости от установленного jpgs.

ВНИМАНИЕ: по умолчанию тут считается ключ СТАРОГО формата (как в JPGS до 2.4 и в Java-версии):
UTF-8-байты слова, обрезанные/дополненные нулями до 32 байт. Начиная с 2.4 программа выводит
ключ из слова через PBKDF2-HMAC-SHA256 — для него используйте флаг --derived. Обратное
преобразование (-r) и перебор (--check-file) имеют смысл только для старого формата: PBKDF2
необратим, а перебор по нему в 300 000 раз дороже.

Умеет:
  - сделать ключ из введённого слова/фразы,
  - сгенерировать случайный ключ,
  - показать hex ключа и отпечаток (fingerprint),
  - сохранить в ~/.config/jpgs/key (формат, который понимает сама программа).

Использование:
  jpgs-keygen.py                      # спросит слово интерактивно (ввод скрыт)
  jpgs-keygen.py -w "моя фраза"       # ключ из слова, сразу в аргументе
  jpgs-keygen.py -g                   # случайный ключ
  jpgs-keygen.py -w "мой кот" --save  # ещё и сохранить в ~/.config/jpgs/key

Перебор забытого слова (проверка по реальному файлу — самый надёжный способ,
не зависит от того, помните вы отпечаток или нет):
  jpgs-keygen.py -w "кандидат" --check-file фото.jpgs
  jpgs-keygen.py --wordlist слова.txt --check-file фото.jpgs
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import secrets
import sys

KEY_LEN = 32  # AES-256
BLOCK = 16
KDF_SALT = b"jpgs-kdf-v1"   # должно совпадать с jpgs/crypto.py
KDF_ITERS = 300_000

DERIVED = False  # включается флагом --derived


def key_bytes(word: str) -> bytes:
    """Ключ нужного формата: старый (байты слова) или усиленный (PBKDF2)."""
    if DERIVED:
        return hashlib.pbkdf2_hmac("sha256", word.encode("utf-8"), KDF_SALT, KDF_ITERS, KEY_LEN)
    raw = word.encode("utf-8")[:KEY_LEN]
    return raw + b"\0" * (KEY_LEN - len(raw))


def fingerprint(word: str) -> str:
    h = hashlib.sha256(b"jpgs-key-fingerprint:" + key_bytes(word)).hexdigest()
    return f"{h[0:4]}-{h[4:8]}-{h[8:12]}".upper()


def config_dir() -> str:
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "jpgs")


def key_file() -> str:
    return os.path.join(config_dir(), "key")


def save_key(word: str) -> str:
    os.makedirs(config_dir(), mode=0o700, exist_ok=True)
    path = key_file()
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(word + "\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return path


def word_from_key_hex(hex_str: str) -> str:
    """Обратное преобразование: убрать нулевые байты с конца и раскодировать UTF-8.

    Работает только для ключей, полученных из слова (key_bytes добивает нулями).
    Для случайно сгенерированных ключей (-g) осмысленного слова нет.
    """
    hex_str = hex_str.strip().replace(" ", "")
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f"это не hex: {e}") from e
    if len(raw) != KEY_LEN:
        raise ValueError(f"ожидалось {KEY_LEN} байт ({KEY_LEN * 2} hex-символов), получено {len(raw)}")
    trimmed = raw.rstrip(b"\0")
    try:
        return trimmed.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(
            "не раскодировалось как UTF-8 — похоже, это случайный ключ (-g), "
            "а не полученный из слова"
        ) from e


SOI = b"\xff\xd8\xff"  # начало JPEG — так .jpgs-файлы начинаются без всякого заголовка
VIDEO_MAGICS = (  # частые сигнатуры контейнеров для .vids (после первых 4 байт может быть смещение)
    (0, b"\x1a\x45\xdf\xa3"),      # mkv/webm
    (4, b"ftyp"),                   # mp4/mov
    (0, b"RIFF"),                   # avi
)


def _decrypt_block16(key32: bytes, block: bytes) -> bytes:
    """Расшифровывает ровно один 16-байтный блок AES-256-ECB (без паддинга)."""
    if len(block) != BLOCK:
        raise ValueError(f"нужен ровно один блок по {BLOCK} байт, получено {len(block)}")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _C, algorithms, modes
        d = _C(algorithms.AES(key32), modes.ECB()).decryptor()
        return d.update(block) + d.finalize()
    except ImportError:
        pass
    # запасной путь — OpenSSL через ctypes (как в jpgs/crypto.py)
    import ctypes
    import ctypes.util
    name = ctypes.util.find_library("crypto") or "libcrypto.so.3"
    lib = ctypes.CDLL(name)
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_aes_256_ecb.restype = ctypes.c_void_p
    lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
    lib.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
    ctx = lib.EVP_CIPHER_CTX_new()
    try:
        if lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_256_ecb(), None, key32, None) != 1:
            raise RuntimeError("OpenSSL: init failed")
        lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        out = ctypes.create_string_buffer(len(block) + BLOCK)
        n = ctypes.c_int(0)
        if lib.EVP_DecryptUpdate(ctx, out, ctypes.byref(n), block, len(block)) != 1:
            raise RuntimeError("OpenSSL: update failed")
        return out.raw[:n.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def looks_valid(decrypted: bytes) -> str | None:
    """Возвращает описание, если расшифрованный первый блок похож на настоящий файл."""
    if decrypted.startswith(SOI):
        return "JPEG (SOI FF D8 FF) — похоже на верный ключ!"
    for off, magic in VIDEO_MAGICS:
        if decrypted[off:off + len(magic)] == magic:
            return f"видео-контейнер ({magic!r}) — похоже на верный ключ!"
    return None


def check_word_against_file(word: str, path: str) -> tuple[bool, bytes]:
    with open(path, "rb") as f:
        block = f.read(BLOCK)
    if len(block) < BLOCK:
        raise ValueError("файл короче 16 байт")
    dec = _decrypt_block16(key_bytes(word), block)
    return looks_valid(dec) is not None, dec


def ask_word_twice() -> str:
    while True:
        a = getpass.getpass("Ключ (ввод скрыт): ")
        b = getpass.getpass("Повторите ключ: ")
        if a != b:
            print("Не совпадает, попробуйте ещё раз.\n", file=sys.stderr)
            continue
        if not a:
            print("Пустой ключ не годится.\n", file=sys.stderr)
            continue
        return a


def main() -> int:
    p = argparse.ArgumentParser(description="Генератор ключей для JPGS (AES-256, из слова или случайный).")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-w", "--word", help="ключ-слово/фраза (иначе спросит интерактивно)")
    g.add_argument("-g", "--generate", action="store_true", help="сгенерировать случайный ключ")
    g.add_argument("-r", "--reverse", metavar="HEX",
                   help="обратно: из hex AES-ключа получить исходное слово (только для ключей из слова)")
    p.add_argument("--save", action="store_true", help=f"сохранить в {key_file()}")
    p.add_argument("--check-file", metavar="PATH",
                   help="проверить слово(-а) реальной расшифровкой первого блока файла .jpgs/.vids")
    p.add_argument("--wordlist", metavar="PATH",
                   help="файл со словами-кандидатами (по одному на строку) для перебора с --check-file")
    p.add_argument("--derived", action="store_true",
                   help="новый формат JPGS 2.4+: ключ выводится из слова через PBKDF2")
    args = p.parse_args()
    global DERIVED
    DERIVED = args.derived
    if args.derived and args.reverse is not None:
        print("Обратное преобразование невозможно: PBKDF2 необратим.", file=sys.stderr)
        return 1

    if args.check_file:
        if args.wordlist:
            candidates = [w for w in (line.strip() for line in
                          open(args.wordlist, encoding="utf-8")) if w]
        elif args.word is not None:
            candidates = [args.word]
        else:
            candidates = [ask_word_twice()]

        found = []
        for w in candidates:
            try:
                ok, dec = check_word_against_file(w, args.check_file)
            except (OSError, ValueError) as e:
                print(f"Ошибка чтения {args.check_file}: {e}", file=sys.stderr)
                return 1
            mark = "✅" if ok else "  "
            print(f"{mark} {w!r}  ->  {dec[:8].hex()}...")
            if ok:
                found.append(w)
        print()
        if found:
            print(f"Подходит: {found!r} (fingerprint: {fingerprint(found[0])})")
        else:
            print("Ни одно слово не подошло (первый блок не похож на JPEG/видео-заголовок).")
        return 0 if found else 1

    if args.reverse is not None:
        try:
            word = word_from_key_hex(args.reverse)
        except ValueError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            return 1
        print(f"Слово:  {word!r}")
        print(f"Отпечаток: {fingerprint(word)}  (сверьте с `jpgs key`)")
        return 0

    if args.generate:
        word = secrets.token_urlsafe(24)  # 32 символа -> 32 байта ключа, ~192 бита энтропии
        print("Сгенерирован случайный ключ (сохраните его — восстановить нельзя):")
        print(f"  {word}")
    elif args.word is not None:
        word = args.word
    else:
        word = ask_word_twice()

    kb = key_bytes(word)
    print()
    print(f"Формат:           {'усиленный (PBKDF2)' if DERIVED else 'старый (байты слова)'}")
    print(f"Ключ (слово):     {word!r}")
    print(f"AES-256 ключ:     {kb.hex()}")
    print(f"Отпечаток:        {fingerprint(word)}")
    if len(word.encode('utf-8')) < 16:
        if DERIVED:
            print("⚠ Слово короткое: PBKDF2 делает каждую попытку дорогой, но словарную атаку "
                  "это не исключает — лучше фразу подлиннее.", file=sys.stderr)
        else:
            print("⚠ Ключ короче 16 символов (в байтах UTF-8) — его легко подобрать.",
                  file=sys.stderr)

    if args.save:
        if DERIVED:
            # в ~/.config/jpgs/key программа кладёт ключ СТАРОГО формата; записать туда слово
            # усиленного ключа — значит получить неверный ключ при чтении
            print("\n--save не поддерживается для --derived: старый файл key хранит ключ "
                  "прежнего формата.\nДобавьте ключ штатно:  jpgs keys add --name ИМЯ",
                  file=sys.stderr)
            return 1
        path = save_key(word)
        print(f"\nСохранено в {path} (права 600).")
    else:
        print("\n(не сохранено; для нового формата используйте  jpgs keys add)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
