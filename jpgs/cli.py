"""Команды, совместимые с Java-версией (работают с текущей папкой):

    jpgs ?            справка
    jpgs encryptor    зашифровать все изображения папки в .jpgs
    jpgs merge        склеить все .jpgs папки в merged.jpgs
    jpgs decoder      расшифровать все .jpgs папки
    jpgs recovery     то же, но вытащить всё возможное из повреждённых файлов

Дополнительно:
    jpgs encrypt ФАЙЛЫ… [-o ПАПКА] [--remove]
    jpgs decrypt ФАЙЛЫ… [-o ПАПКА]
    jpgs info ФАЙЛЫ…
    jpgs pack АРХИВ.jpgs ФАЙЛЫ…     картинки и видео (и другие .jpgs/.vids) в один архив
    jpgs note ФАЙЛ [N] [ТЕКСТ]      показать / задать заметку к записи N (с 1)
    jpgs lock                       забыть запомненный пароль

Файлы открываются любым ключом из хранилища — нужный подбирается сам.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from . import container as C
from .crypto import (DEFAULT_KIND, Cipher, KeyLocked, KeyMissing, KeyRing, fingerprint_material,
                     generate_key, key_strength, material_for)

COMMANDS = ("?", "encryptor", "merge", "decoder", "recovery", "encrypt", "decrypt", "info",
            "thumbnail", "set-key", "key", "keys", "pack", "note", "lock")

HELP = ("Command:\n"
        "1. encryptor - Encrypt file to jpg format.\n"
        "2. merge - Merge multiple single jpgs files into one.\n"
        "3. decoder - Decrypt all files.\n"
        "4. recovery - Recovering possible data from a damaged file.\n"
        "Extra: encrypt FILES [-o DIR] [--remove], decrypt FILES [-o DIR], info FILES\n"
        "       pack OUT.jpgs FILES (images + videos in one archive), note FILE [N] [TEXT], lock\n"
        "Videos: encryptor/encrypt produce .vids, decoder/decrypt restore the original video\n"
        "Key: jpgs set-key [--generate | --stdin | --legacy]  |  jpgs key  (fingerprint)\n"
        "Keys: jpgs keys [list | add | remove | use | rename | passwd | upgrade | rekey]\n"
        "      ~/.config/jpgs/keystore.json; env JPGS_WORD (усиленный) / JPGS_KEY (старый формат)\n"
        "      / JPGS_PASSWORD")


def _ensure_unlocked() -> bool:
    """Если хранилище защищено паролем — спросить пароль (или взять из JPGS_PASSWORD).

    Возвращает False, если разблокировать не удалось (тогда команда должна прерваться).
    """
    from .keystore import get_keystore
    ks = get_keystore()
    if not ks.is_locked():
        return True
    env = os.environ.get("JPGS_PASSWORD")
    if env and ks.unlock(env):
        return True
    if not sys.stdin.isatty():
        why = "неверный пароль в JPGS_PASSWORD" if env else "задайте JPGS_PASSWORD"
        print(f"Хранилище ключей защищено паролем ({why}).", file=sys.stderr)
        return False
    import getpass
    import time
    for attempt in range(3):
        if ks.unlock(getpass.getpass("Пароль JPGS: ")):
            return True
        print("Неверный пароль.", file=sys.stderr)
        time.sleep(2 ** attempt)  # перебор через терминал бессмыслен
    return False


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("?", "-h", "--help"):
        print(HELP)
        return 0
    if argv[0] == "--version":
        print(f"JPGS {__version__}")
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "set-key":
        return set_key(rest)
    if cmd == "keys":
        return keys_cmd(rest)
    if cmd == "lock":
        from .keystore import forget_unlock
        forget_unlock()
        print("Запомненный пароль забыт.")
        return 0
    try:
        if cmd == "key":
            from .crypto import configured_material
            if not _ensure_unlocked():
                return 1
            print(f"Ключ задан, отпечаток: {fingerprint_material(configured_material())}")
            return 0
        if cmd == "thumbnail":
            return thumbnail(rest)
        if not _ensure_unlocked():
            return 1
        return _main(cmd, rest)
    except KeyLocked as e:
        print(e, file=sys.stderr)
        return 2
    except KeyMissing as e:
        print(e, file=sys.stderr)
        return 2


def set_key(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="jpgs set-key",
                                 description="Добавить ключ шифрования и сделать его активным")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--generate", action="store_true", help="создать случайный ключ")
    g.add_argument("--stdin", action="store_true", help="прочитать ключ из stdin (для скриптов)")
    ap.add_argument("--name", help="имя ключа в списке (по умолчанию «Ключ»)")
    ap.add_argument("--legacy", action="store_true",
                    help="ключ старого формата (для файлов, созданных прежними версиями)")
    ap.add_argument("--pbkdf2", action="store_true",
                    help="ключ из JPGS 2.4 (PBKDF2) — для файлов той версии")
    ap.add_argument("--force", action="store_true", help="без подтверждения (совместимость)")
    a = ap.parse_args(rest)
    from .keystore import get_keystore
    if not _ensure_unlocked():
        return 1
    if a.generate:
        key = generate_key()
    elif a.stdin:
        key = sys.stdin.readline().strip("\r\n")
    else:
        import getpass
        key = getpass.getpass("Ключ шифрования: ")
        if getpass.getpass("Повторите: ") != key:
            print("Ключи не совпадают.", file=sys.stderr)
            return 1
    if not key:
        print("Пустой ключ.", file=sys.stderr)
        return 1
    kind = _kind(a)
    if not _check_strength(key, kind):
        return 1
    ks = get_keystore()
    try:
        ks.add(a.name or "Ключ", key, activate=True, kind=kind)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1
    what = _KIND_NAMES[kind]
    print(f"Ключ добавлен и активен ({what}). Отпечаток: {fingerprint_material(material_for(key, kind))}")
    if a.generate:
        print(f"Сгенерированный ключ: {key}\nСохраните его в надёжном месте — без него файлы не открыть.")
    return 0


_KIND_NAMES = {"raw": "старого формата", "derived": "PBKDF2 (JPGS 2.4)", "scrypt": "scrypt"}


def _kind(a) -> str:
    if getattr(a, "legacy", False):
        return "raw"
    if getattr(a, "pbkdf2", False):
        return "derived"
    return DEFAULT_KIND


def _check_strength(key: str, kind: str) -> bool:
    """Новые ключи (scrypt) должны быть стойкими; для старых типов — только предупреждение."""
    ok, why = key_strength(key)
    if ok:
        return True
    if kind == DEFAULT_KIND:
        print(f"Ключ не принят: {why}. Сгенерируйте случайный: --generate", file=sys.stderr)
        return False
    print(f"⚠ {why} — такой ключ подбирается быстро.", file=sys.stderr)
    return True


def _keyring() -> KeyRing:
    return KeyRing.from_config()


def _rekey_files(paths: list[str], old, new: Cipher, to_id: str) -> int:
    """Перешифровать файлы на новый ключ. old — ключ или связка (каждый файл — своим ключом).
    Файлы, к которым исходный ключ не подходит, пропускаются: иначе они превратились бы в мусор."""
    rc = 0
    for p in paths:
        try:
            src = old.cipher_for(p) if isinstance(old, KeyRing) else (
                old if C.verify_media(p, old) else None)
            if src is None:
                print(f"{p}: пропущен — не расшифровывается исходным ключом", file=sys.stderr)
                rc = 1
                continue
            if src == new:
                print(f"{p}: уже зашифрован ключом {to_id}")
                continue
            C.reencrypt_media(p, src, new)
            print(f"{p}: перешифрован ключом {to_id}")
        except Exception as e:  # noqa: BLE001
            print(f"{p}: не удалось — {e}", file=sys.stderr)
            rc = 1
    return rc


def keys_cmd(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="jpgs keys", description="Управление ключами шифрования")
    sub = ap.add_subparsers(dest="sub")
    sub.add_parser("list", help="показать ключи")
    p_add = sub.add_parser("add", help="добавить ключ")
    p_add.add_argument("--name", help="имя ключа")
    g = p_add.add_mutually_exclusive_group()
    g.add_argument("--generate", action="store_true", help="случайный ключ")
    g.add_argument("--stdin", action="store_true", help="ключ из stdin")
    p_add.add_argument("--legacy", action="store_true",
                       help="ключ старого формата (для файлов из прежних версий)")
    p_add.add_argument("--pbkdf2", action="store_true", help="ключ из JPGS 2.4 (PBKDF2)")
    p_add.add_argument("--activate", action="store_true", help="сразу сделать активным")
    p_rm = sub.add_parser("remove", help="удалить ключ")
    p_rm.add_argument("id", help="id ключа (см. keys list)")
    p_use = sub.add_parser("use", help="сделать ключ активным")
    p_use.add_argument("id")
    p_ren = sub.add_parser("rename", help="переименовать ключ")
    p_ren.add_argument("id")
    p_ren.add_argument("name")
    p_pw = sub.add_parser("passwd", help="задать/сменить/снять пароль на программу")
    p_pw.add_argument("--remove", action="store_true", help="снять пароль")
    p_up = sub.add_parser("upgrade", help="усилить ключ (то же слово, ключ scrypt)")
    p_up.add_argument("id", help="id ключа старого формата или PBKDF2")
    p_up.add_argument("--name", help="имя нового ключа")
    p_up.add_argument("--rekey", nargs="+", metavar="ФАЙЛ",
                      help="сразу перешифровать эти файлы новым ключом")
    p_up.add_argument("--activate", action="store_true",
                      help="сделать усиленный ключ активным (обычно вместе с --rekey)")
    p_rk = sub.add_parser("rekey", help="перешифровать файлы другим ключом")
    p_rk.add_argument("files", nargs="+")
    p_rk.add_argument("--to", required=True, help="id ключа назначения (см. keys list)")
    a = ap.parse_args(rest)
    from .keystore import get_keystore
    ks = get_keystore()

    if a.sub in (None, "list"):
        if not _ensure_unlocked():
            return 1
        if not ks.exists() or ks.count() == 0:
            print("Ключей нет. Добавьте: jpgs set-key")
            return 0
        lock = " (пароль установлен)" if ks.is_encrypted() else ""
        print(f"Ключи{lock}:")
        has_raw = False
        for e in ks.entries():
            mark = "*" if e["active"] else " "
            kind = _KIND_NAMES.get(e["kind"], e["kind"])
            has_raw = has_raw or e["kind"] != "scrypt"
            weak = "  ⚠ слабый" if e["weak"] else ""
            print(f" {mark} {e['id']}  {e['fingerprint']}  {e['name']}  [{kind}]{weak}")
        print("(* — активный)")
        if has_raw:
            print("Усилить старый ключ: jpgs keys upgrade <id> --rekey ФАЙЛЫ --activate")
        return 0

    if not _ensure_unlocked():
        return 1

    if a.sub == "add":
        if a.generate:
            key = generate_key()
        elif a.stdin:
            key = sys.stdin.readline().strip("\r\n")
        else:
            import getpass
            key = getpass.getpass("Ключ: ")
            if getpass.getpass("Повторите: ") != key:
                print("Ключи не совпадают.", file=sys.stderr)
                return 1
        if not key:
            print("Пустой ключ.", file=sys.stderr)
            return 1
        kind = _kind(a)
        if not _check_strength(key, kind):
            return 1
        try:
            kid = ks.add(a.name or "Ключ", key, activate=a.activate, kind=kind)
        except ValueError as e:
            print(e, file=sys.stderr)
            return 1
        what = _KIND_NAMES[kind]
        print(f"Добавлен ключ {kid} ({what}) · отпечаток "
              f"{fingerprint_material(material_for(key, kind))}"
              + (" (активен)" if a.activate else ""))
        if a.generate:
            print(f"Сгенерированный ключ: {key}\nСохраните его — без него файлы не открыть.")
        return 0

    known = {e["id"] for e in ks.entries()}
    if a.sub in ("remove", "use", "rename") and a.id not in known:
        print(f"Нет ключа с id {a.id} (см. jpgs keys list).", file=sys.stderr)
        return 1

    if a.sub == "remove":
        ks.remove(a.id)
        print(f"Ключ {a.id} удалён.")
        return 0

    if a.sub == "use":
        ks.set_active(a.id)
        print(f"Активный ключ: {a.id}")
        return 0

    if a.sub == "rename":
        ks.rename(a.id, a.name)
        print(f"Ключ {a.id} переименован в «{a.name}».")
        return 0

    if a.sub == "passwd":
        if a.remove:
            ks.set_password(None)
            print("Пароль снят. Ключи снова хранятся без пароля.")
            return 0
        import getpass
        pw = getpass.getpass("Новый пароль: ")
        if pw != getpass.getpass("Повторите пароль: "):
            print("Пароли не совпадают.", file=sys.stderr)
            return 1
        if not pw:
            print("Пустой пароль. Чтобы снять пароль: jpgs keys passwd --remove", file=sys.stderr)
            return 1
        ok, why = key_strength(pw)
        if not ok:
            print(f"Пароль не принят: {why}.", file=sys.stderr)
            return 1
        ks.set_password(pw)
        print("Пароль установлен. Список ключей теперь хранится зашифрованным.")
        return 0

    if a.sub == "upgrade":
        word = None
        if any(e["id"] == a.id and e["kind"] == "derived" for e in ks.entries()):
            import getpass
            word = getpass.getpass("Слово этого ключа: ")
        try:
            new_id = ks.upgrade(a.id, a.name, activate=a.activate and not a.rekey, word=word)
        except KeyError:
            print(f"Нет ключа с id {a.id} (см. jpgs keys list).", file=sys.stderr)
            return 1
        except ValueError as e:
            print(f"{e}", file=sys.stderr)
            return 1
        mat = ks.material_by_id(new_id)
        print(f"Создан усиленный ключ {new_id} · отпечаток {fingerprint_material(mat)}")
        rc = 0
        if a.rekey:
            old = Cipher(material=ks.material_by_id(a.id))
            new = Cipher(material=mat)
            rc = _rekey_files(a.rekey, old, new, new_id)
            if a.activate:
                ks.set_active(new_id)
                print(f"Активный ключ: {new_id}")
        else:
            print("Файлы пока зашифрованы старым ключом. Перешифровать:\n"
                  f"  jpgs keys rekey ФАЙЛЫ --to {new_id}")
        return rc

    if a.sub == "rekey":
        try:
            new = Cipher(material=ks.material_by_id(a.to))
        except KeyError:
            print(f"Нет ключа с id {a.to} (см. jpgs keys list).", file=sys.stderr)
            return 1
        return _rekey_files(a.files, _keyring(), new, a.to)

    ap.print_help()
    return 0


def _cipher_or_skip(ring: KeyRing, p: str) -> Cipher | None:
    c = ring.cipher_for(p)
    if c is None:
        print(f"{p}: не расшифровывается ни одним ключом (или файл повреждён)", file=sys.stderr)
    return c


def _encrypt_one(p: str, dest: str, cipher: Cipher, remove: bool) -> str | None:
    out = (C.encrypt_stream(p, dest, cipher) if C.is_video_source(p)
           else C.encrypt_file(p, dest, cipher))
    if out and remove:
        # удаляем только если зашифрованное расшифровывается в точности в оригинал
        if C.verify_import(out, cipher, 0, [p], cipher):
            os.remove(p)
        else:
            print(f"{p}: проверка не прошла — оригинал НЕ удалён", file=sys.stderr)
    return out


def _main(cmd: str, rest: list[str]) -> int:
    ring = _keyring()
    cipher = ring.active
    cwd = os.getcwd()

    if cmd == "encryptor":
        n = 0
        for name in sorted(os.listdir(cwd)):
            p = os.path.join(cwd, name)
            ext = name.rsplit(".", 1)[-1].lower()
            if not os.path.isfile(p) or ext not in C.IMAGE_EXTS + C.VIDEO_EXTS:
                continue
            try:
                out = _encrypt_one(p, cwd, cipher, False)
            except Exception as e:  # noqa: BLE001
                print(f"Ошибка обработки файла {name}: {e}")
                continue
            if out:
                n += 1
                print(f"Зашифрован: {name} → {os.path.basename(out)}")
            else:
                print(f"Файл {name} не удалось прочитать как изображение")
        print(f"Шифрование завершено ({n}).")
        return 0

    if cmd == "merge":
        files = C.list_jpgs(cwd)
        dest = os.path.join(cwd, "merged.jpgs")
        files = [f for f in files if os.path.abspath(f) != dest]
        if not files:
            print("Нет файлов .jpgs в директории.")
            return 1
        for f in files:
            print(f"Добавляю: {os.path.basename(f)}")
        try:
            C.merge_media(files, dest, ring)
        except C.ArchiveError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            return 1
        print(f"Готово! Файл сохранён: {dest}")
        return 0

    if cmd in ("decoder", "recovery"):
        files = C.list_media(cwd)
        if not files:
            print("Нет файлов .jpgs для расшифровки.")
            return 1
        for f in files:
            c = ring.cipher_for(f)
            if c is None and cmd == "recovery":
                c = cipher  # повреждённый файл может не пройти проверку — пробуем активным
            if c is None:
                print(f"{os.path.basename(f)}: не подходит ни один ключ — пропущен")
                continue
            try:
                if C.is_video_path(f):
                    out = [C.decrypt_video_to(f, cwd, c)]
                else:
                    out = C.decrypt_to_dir(f, cwd, c, tolerant=(cmd == "recovery"))
                print(f"Декодировано {len(out)} файлов из {os.path.basename(f)}")
            except Exception as e:  # noqa: BLE001
                print(f"Ошибка при декодировании {os.path.basename(f)}: {e}")
        print("Расшифровка завершена.")
        return 0

    if cmd == "pack":
        ap = argparse.ArgumentParser(prog="jpgs pack",
                                     description="Картинки и видео (и другие .jpgs/.vids) в один архив")
        ap.add_argument("archive", help="новый архив .jpgs")
        ap.add_argument("files", nargs="+")
        ap.add_argument("--remove", action="store_true",
                        help="удалить оригиналы после проверки архива")
        a = ap.parse_args(rest)
        if os.path.exists(a.archive):
            print(f"{a.archive} уже существует", file=sys.stderr)
            return 1
        try:
            out = C.build_archive(a.files, a.archive, cipher, ring)
        except C.ArchiveError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            return 1
        n = C.JpgsFile(out, cipher).count()
        print(f"Готово: {out} ({n} записей)")
        if a.remove:
            if C.verify_import(out, cipher, 0, a.files, ring):
                for p in a.files:
                    os.remove(p)
                print("Оригиналы удалены.")
            else:
                print("Проверка не прошла — оригиналы НЕ удалены.", file=sys.stderr)
                return 1
        return 0

    if cmd == "note":
        ap = argparse.ArgumentParser(prog="jpgs note", description="Заметка к записи файла")
        ap.add_argument("file")
        ap.add_argument("n", nargs="?", type=int, default=None, help="номер записи (с 1)")
        ap.add_argument("text", nargs="?", default=None, help="новый текст ('' — удалить)")
        a = ap.parse_args(rest)
        c = _cipher_or_skip(ring, a.file)
        if c is None:
            return 1
        jf = C.open_media(a.file, c)
        es = jf.entries()
        if a.text is None:
            for k, e in enumerate(es, 1):
                if a.n in (None, k):
                    print(f"{k}: {'видео' if e.is_video else 'изображение'} {e.ext}"
                          + (f" — {e.note}" if e.note else ""))
            return 0
        n = a.n or 1
        if not 1 <= n <= len(es):
            print(f"Нет записи {n} (всего {len(es)})", file=sys.stderr)
            return 1
        C.set_note(a.file, n - 1, a.text, c)
        print("Заметка сохранена." if a.text.strip() else "Заметка удалена.")
        return 0

    ap = argparse.ArgumentParser(prog=f"jpgs {cmd}")
    ap.add_argument("files", nargs="+")
    if cmd in ("encrypt", "decrypt"):
        ap.add_argument("-o", "--out", help="папка назначения (по умолчанию рядом с файлом)")
    if cmd == "encrypt":
        ap.add_argument("--remove", action="store_true",
                        help="удалить оригиналы после шифрования (только если проверка прошла)")
    a = ap.parse_args(rest)

    rc = 0
    if cmd == "encrypt":
        for p in a.files:
            dest = a.out or os.path.dirname(os.path.abspath(p))
            out = _encrypt_one(p, dest, cipher, a.remove)
            print(f"{p} → {out}" if out else f"{p}: не изображение и не видео")
            rc |= 0 if out else 1
    elif cmd == "decrypt":
        for p in a.files:
            dest = a.out or os.path.dirname(os.path.abspath(p))
            c = _cipher_or_skip(ring, p)
            if c is None:
                rc = 1
                continue
            if C.is_video_path(p):
                print(f"{p} → {C.decrypt_video_to(p, dest, c)}")
            else:
                out = C.decrypt_to_dir(p, dest, c)
                print(f"{p}: {len(out)} записей")
    elif cmd == "info":
        for p in a.files:
            c = ring.cipher_for(p)
            if c is None:
                print(f"{p}: не расшифровывается (другой ключ или файл повреждён)")
                rc = 1
                continue
            jf = C.open_media(p, c)
            es = jf.entries()
            vids = sum(e.is_video for e in es)
            notes = sum(bool(e.note) for e in es)
            what = (f"видео {jf.video_ext()}" if jf.is_video else
                    f"{len(es) - vids} изображений" + (f", {vids} видео" if vids else ""))
            print(f"{p}: {what}, {os.path.getsize(p)} байт, ключ «{ring.name_of(c)}»"
                  + (f", заметок: {notes}" if notes else "")
                  + (", архив v2" if jf.is_v2 else ""))
    return rc


def thumbnail(rest: list[str]) -> int:
    """Миниатюра для файловых менеджеров: jpgs thumbnail [-s РАЗМЕР] ВХОД.jpgs ВЫХОД.png

    Вызывается через /usr/share/thumbnailers/jpgs.thumbnailer (Dolphin, Nautilus, Nemo, Thunar).
    Расшифровывается только первый кадр, JPEG декодируется сразу в уменьшенном виде.
    """
    ap = argparse.ArgumentParser(prog="jpgs thumbnail")
    ap.add_argument("-s", "--size", type=int, default=256)
    ap.add_argument("input")
    ap.add_argument("output")
    a = ap.parse_args(rest)
    src = a.input
    if src.startswith("file://"):
        from urllib.parse import unquote, urlparse
        src = unquote(urlparse(src).path)
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf
    try:
        ring = _keyring()
    except KeyMissing:
        return 1
    c = ring.cipher_for(src)
    if c is None:
        return 1  # чужой ключ: миниатюры нет (а не картинка из мусора)
    jf = C.open_media(src, c)
    if jf.is_video or jf.first_kind() == "video":
        from .video import frame_pixbuf
        pb, _info = frame_pixbuf(src, c, max(16, a.size),
                                 entry=None if jf.is_video else jf.entry(0))
        pb.savev(a.output, "png", [], [])
        return 0
    data = jf.read_first()
    if not data:
        return 1
    size = max(16, a.size)
    loader = GdkPixbuf.PixbufLoader()

    def prepared(ld, w, h):
        k = size / max(w, h)
        if k < 1:
            ld.set_size(max(1, round(w * k)), max(1, round(h * k)))
    loader.connect("size-prepared", prepared)
    loader.write(data)
    loader.close()
    pb = loader.get_pixbuf()
    pb = pb.apply_embedded_orientation() or pb
    pb.savev(a.output, "png", [], [])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
