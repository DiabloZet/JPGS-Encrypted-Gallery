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
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from . import container as C
from .crypto import Cipher, KeyMissing, fingerprint, generate_key, key_file, save_key

COMMANDS = ("?", "encryptor", "merge", "decoder", "recovery", "encrypt", "decrypt", "info",
            "thumbnail", "set-key", "key")

HELP = ("Command:\n"
        "1. encryptor - Encrypt file to jpg format.\n"
        "2. merge - Merge multiple single jpgs files into one.\n"
        "3. decoder - Decrypt all files.\n"
        "4. recovery - Recovering possible data from a damaged file.\n"
        "Extra: encrypt FILES [-o DIR] [--remove], decrypt FILES [-o DIR], info FILES\n"
        "Videos: encryptor/encrypt produce .vids, decoder/decrypt restore the original video\n"
        "Key: jpgs set-key [--generate | --stdin]  |  jpgs key  (fingerprint)\n"
        "     stored in ~/.config/jpgs/key (mode 600) or env JPGS_KEY")


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
    try:
        if cmd == "key":
            from .crypto import configured_key
            print(f"Ключ задан, отпечаток: {fingerprint(configured_key())}")
            return 0
        if cmd == "thumbnail":
            return thumbnail(rest)
        return _main(cmd, rest)
    except KeyMissing as e:
        print(e, file=sys.stderr)
        return 2


def set_key(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="jpgs set-key",
                                 description="Задать ключ шифрования (хранится в ~/.config/jpgs/key)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--generate", action="store_true", help="создать случайный ключ")
    g.add_argument("--stdin", action="store_true", help="прочитать ключ из stdin (для скриптов)")
    ap.add_argument("--force", action="store_true", help="перезаписать существующий ключ без вопроса")
    a = ap.parse_args(rest)
    if os.path.exists(key_file()) and not a.force:
        if not sys.stdin.isatty():
            print(f"Ключ уже задан ({key_file()}). Используйте --force.", file=sys.stderr)
            return 1
        ans = input("Ключ уже задан. Файлы, зашифрованные старым ключом, с новым не откроются.\n"
                    "Заменить? [y/N] ").strip().lower()
        if ans not in ("y", "yes", "д", "да"):
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
    if len(key.encode()) < 16:
        print("⚠ Ключ короче 16 символов — его легко подобрать.", file=sys.stderr)
    path = save_key(key)
    print(f"Ключ сохранён в {path} (доступ только для вас). Отпечаток: {fingerprint(key)}")
    if a.generate:
        print(f"Сгенерированный ключ: {key}\nСохраните его в надёжном месте — без него файлы не открыть.")
    return 0


def _main(cmd: str, rest: list[str]) -> int:
    cipher = Cipher()
    cwd = os.getcwd()

    if cmd == "encryptor":
        n = 0
        for name in sorted(os.listdir(cwd)):
            p = os.path.join(cwd, name)
            ext = name.rsplit(".", 1)[-1].lower()
            if not os.path.isfile(p) or ext not in C.IMAGE_EXTS + C.VIDEO_EXTS:
                continue
            try:
                out = (C.encrypt_stream(p, cwd, cipher) if ext in C.VIDEO_EXTS
                       else C.encrypt_file(p, cwd, cipher))
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
        C.merge_files(files, dest)
        print(f"Готово! Файл сохранён: {dest}")
        return 0

    if cmd in ("decoder", "recovery"):
        files = C.list_media(cwd)
        if not files:
            print("Нет файлов .jpgs для расшифровки.")
            return 1
        for f in files:
            try:
                if C.is_video_path(f):
                    out = [C.decrypt_video_to(f, cwd, cipher)]
                else:
                    out = C.decrypt_to_dir(f, cwd, cipher, tolerant=(cmd == "recovery"))
                print(f"Декодировано {len(out)} файлов из {os.path.basename(f)}")
            except Exception as e:  # noqa: BLE001
                print(f"Ошибка при декодировании {os.path.basename(f)}: {e}")
        print("Расшифровка завершена.")
        return 0

    ap = argparse.ArgumentParser(prog=f"jpgs {cmd}")
    ap.add_argument("files", nargs="+")
    if cmd in ("encrypt", "decrypt"):
        ap.add_argument("-o", "--out", help="папка назначения (по умолчанию рядом с файлом)")
    if cmd == "encrypt":
        ap.add_argument("--remove", action="store_true", help="удалить оригиналы после шифрования")
    a = ap.parse_args(rest)

    if cmd == "encrypt":
        for p in a.files:
            dest = a.out or os.path.dirname(os.path.abspath(p))
            out = (C.encrypt_stream(p, dest, cipher) if C.is_video_source(p)
                   else C.encrypt_file(p, dest, cipher))
            print(f"{p} → {out}" if out else f"{p}: не изображение и не видео")
            if out and a.remove:
                os.remove(p)
    elif cmd == "decrypt":
        for p in a.files:
            dest = a.out or os.path.dirname(os.path.abspath(p))
            if C.is_video_path(p):
                print(f"{p} → {C.decrypt_video_to(p, dest, cipher)}")
            else:
                out = C.decrypt_to_dir(p, dest, cipher)
                print(f"{p}: {len(out)} изображений")
    elif cmd == "info":
        for p in a.files:
            if C.is_video_path(p):
                from .video import grab_frame
                try:
                    _d, _w, _h, _s, info = grab_frame(p, cipher, 16)
                except Exception:  # noqa: BLE001
                    print(f"{p}: не расшифровывается (другой ключ или файл повреждён)")
                    continue
                print(f"{p}: видео {info.width}×{info.height}, {info.duration:.1f} с, "
                      f"{os.path.getsize(p)} байт")
                continue
            jf = C.JpgsFile(p, cipher)
            first = jf.read_first()
            if not first or not C.is_real_jpeg(first):
                print(f"{p}: не расшифровывается (другой ключ или файл повреждён)")
                continue
            print(f"{p}: {jf.count()} изображений, {os.path.getsize(p)} байт")
    return 0


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
    if C.is_video_path(src):
        from .video import frame_pixbuf
        pb, _info = frame_pixbuf(src, Cipher(), max(16, a.size))
        pb.savev(a.output, "png", [], [])
        return 0
    data = C.JpgsFile(src, Cipher()).read_first()
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
