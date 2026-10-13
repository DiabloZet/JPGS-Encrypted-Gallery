"""Файлы .jpgs: чтение (ленивое, по блокам), поиск JPEG внутри, шифрование, слияние.

Формат (совместим с исходной Java-версией):
  * одиночный файл — AES/ECB/PKCS5(JPEG);
  * «merged» — просто конкатенация нескольких таких файлов. После расшифровки всего
    потока между JPEG остаются байты паддинга (1–16 байт), их пропускаем.

Главное отличие от старого кода: границы JPEG определяются разбором структуры
(маркеры + длины сегментов + энтропийные данные), а не поиском первого FFD9.
Старый способ обрезал снимки с EXIF-миниатюрой (внутри EXIF есть свой FFD8…FFD9).
"""

from __future__ import annotations

import io
import os
import threading
import uuid
from collections import OrderedDict
from typing import Callable, Optional

from .crypto import BLOCK, Cipher

CHUNK = 1 << 20  # 1 МиБ, кратно 16
SOI = b"\xff\xd8\xff"


class DecryptingReader:
    """Случайный доступ к расшифрованному содержимому файла без чтения его целиком."""

    def __init__(self, path: str, cipher: Cipher, max_chunks: int = 6):
        self.path = path
        self.cipher = cipher
        self.f = open(path, "rb")
        size = os.fstat(self.f.fileno()).st_size
        self.enc_size = size - size % BLOCK  # хвост некратной длины (повреждение) отбрасываем
        self._chunks: OrderedDict[int, bytes] = OrderedDict()
        self._max = max_chunks
        self.size = self.enc_size
        if self.enc_size:
            last = self._chunk((self.enc_size - 1) // CHUNK)
            p = last[-1]
            if 1 <= p <= BLOCK and last.endswith(bytes([p]) * p):
                self.size = self.enc_size - p

    def close(self):
        self.f.close()
        self._chunks.clear()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _chunk(self, i: int) -> bytes:
        c = self._chunks.get(i)
        if c is not None:
            self._chunks.move_to_end(i)
            return c
        self.f.seek(i * CHUNK)
        raw = self.f.read(min(CHUNK, self.enc_size - i * CHUNK))
        c = self.cipher.decrypt_blocks(raw)
        self._chunks[i] = c
        if len(self._chunks) > self._max:
            self._chunks.popitem(last=False)
        return c

    def read(self, off: int, n: int) -> bytes:
        end = min(off + n, self.size)
        if off >= end:
            return b""
        first, last = off // CHUNK, (end - 1) // CHUNK
        if first == last:
            c = self._chunk(first)
            return c[off - first * CHUNK:end - first * CHUNK]
        parts = []
        for i in range(first, last + 1):
            c = self._chunk(i)
            a = max(off, i * CHUNK) - i * CHUNK
            b = min(end, (i + 1) * CHUNK) - i * CHUNK
            parts.append(c[a:b])
        return b"".join(parts)

    def byte(self, off: int) -> int:
        if off >= self.size:
            return -1
        i = off // CHUNK
        return self._chunk(i)[off - i * CHUNK]

    def find(self, pat: bytes, start: int, end: Optional[int] = None) -> int:
        end = self.size if end is None else min(end, self.size)
        pos = start
        ov = len(pat) - 1
        while pos < end:
            i = pos // CHUNK
            base = i * CHUNK
            c = self._chunk(i)
            lim = min(end, base + len(c)) - base
            r = c.find(pat, pos - base, lim)
            if r >= 0:
                return base + r
            nxt = base + len(c)
            if nxt >= end:
                break
            # образец может лежать на стыке блоков
            if ov:
                tail = self.read(nxt - ov, ov * 2)
                r = tail.find(pat)
                if r >= 0 and nxt - ov + r >= pos and nxt - ov + r + len(pat) <= end:
                    return nxt - ov + r
            pos = nxt
        return -1


def jpeg_end(r: DecryptingReader, s: int) -> Optional[int]:
    """Конец JPEG, начинающегося в s (после FFD9), либо None, если структура битая."""
    p = s + 2
    n = r.size
    while p < n:
        if r.byte(p) != 0xFF:
            return None
        while r.byte(p + 1) == 0xFF:  # байты-заполнители
            p += 1
        m = r.byte(p + 1)
        if m < 0:
            return None
        p += 2
        if m == 0xD9:
            return p
        if 0xD0 <= m <= 0xD7 or m == 0x01:
            continue
        if m == 0xD8 or m == 0x00:
            return None
        hi, lo = r.byte(p), r.byte(p + 1)
        if hi < 0 or lo < 0:
            return None
        seg = (hi << 8) | lo
        if seg < 2:
            return None
        p += seg
        if m == 0xDA:  # SOS: дальше энтропийные данные до следующего маркера
            while True:
                q = r.find(b"\xff", p)
                if q < 0:
                    return None
                nb = r.byte(q + 1)
                if nb == 0x00 or 0xD0 <= nb <= 0xD7 or nb == 0xFF:
                    p = q + 1
                    continue
                p = q
                break
    return None


def scan_images(r: DecryptingReader, limit: Optional[int] = None,
                tolerant: bool = False) -> list[tuple[int, int]]:
    """Диапазоны [начало, конец) изображений в расшифрованном потоке."""
    out: list[tuple[int, int]] = []
    pos = 0
    while limit is None or len(out) < limit:
        s = r.find(SOI, pos)
        if s < 0:
            break
        e = jpeg_end(r, s)
        if e is None:
            # запасной путь, как в старой версии: до ближайшего FFD9
            e2 = r.find(b"\xff\xd9", s + 2)
            if e2 < 0:
                if tolerant:
                    out.append((s, r.size))
                break
            e = e2 + 2
        out.append((s, e))
        pos = e
    if not out and r.size and limit is None:
        out.append((0, r.size))  # не JPEG (например, PNG) — пробуем целиком
    return out


class JpgsFile:
    """Один файл .jpgs. Индекс изображений кэшируется, данные — нет."""

    is_video = False

    def __init__(self, path: str, cipher: Cipher):
        self.path = path
        self.cipher = cipher
        self._ranges: Optional[list[tuple[int, int]]] = None
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def indexed(self) -> bool:
        return self._ranges is not None

    def ranges(self) -> list[tuple[int, int]]:
        with self._lock:
            if self._ranges is None:
                with DecryptingReader(self.path, self.cipher) as r:
                    self._ranges = scan_images(r)
            return self._ranges

    def count(self) -> int:
        return len(self.ranges())

    def read_image(self, i: int) -> bytes:
        rs = self.ranges()
        s, e = rs[i]
        with DecryptingReader(self.path, self.cipher) as r:
            return r.read(s, e - s)

    def read_first(self) -> Optional[bytes]:
        """Первое изображение — для миниатюр; не расшифровывает файл дальше нужного."""
        with self._lock:
            rs = self._ranges
        if rs is None:
            with DecryptingReader(self.path, self.cipher) as r:
                found = scan_images(r, limit=1)
                if not found:
                    found = [(0, r.size)] if r.size else []
                if not found:
                    return None
                s, e = found[0]
                return r.read(s, e - s)
        if not rs:
            return None
        return self.read_image(0)


# ---------------------------------------------------------------------------
# Шифрование / слияние / расшифровка
# ---------------------------------------------------------------------------

IMAGE_EXTS = ("jpg", "jpeg", "png", "bmp", "gif", "tiff", "tif", "webp")


def is_real_jpeg(data: bytes) -> bool:
    return data[:2] == b"\xff\xd8"


def to_jpeg_bytes(path: str, quality: int = 95) -> Optional[bytes]:
    """JPEG — как есть; остальное конвертируется в JPEG (прозрачность — на белом фоне)."""
    with open(path, "rb") as f:
        head = f.read(2)
    ext = path.rsplit(".", 1)[-1].lower()
    if ext in ("jpg", "jpeg"):
        if not is_real_jpeg(head):
            return None
        with open(path, "rb") as f:
            return f.read()
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf
    pb = GdkPixbuf.Pixbuf.new_from_file(path)
    pb = pb.apply_embedded_orientation() or pb
    if pb.get_has_alpha():
        w, h = pb.get_width(), pb.get_height()
        bg = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, False, 8, w, h)
        bg.fill(0xFFFFFFFF)
        pb.composite(bg, 0, 0, w, h, 0, 0, 1, 1, GdkPixbuf.InterpType.NEAREST, 255)
        pb = bg
    ok, buf = pb.save_to_bufferv("jpeg", ["quality"], [str(quality)])
    return bytes(buf) if ok else None


def encrypt_file(src: str, out_dir: str, cipher: Cipher) -> Optional[str]:
    data = to_jpeg_bytes(src)
    if data is None:
        return None
    out = os.path.join(out_dir, f"{uuid.uuid4()}.jpgs")
    tmp = out + ".part"
    with open(tmp, "wb") as f:
        f.write(cipher.encrypt(data))
    os.replace(tmp, out)
    return out


def merge_files(paths: list[str], dest: str,
                progress: Optional[Callable[[int, int], None]] = None) -> str:
    """Склейка, как у Java-версии: побайтовая конкатенация зашифрованных файлов."""
    tmp = dest + ".part"
    with open(tmp, "wb") as out:
        for i, p in enumerate(paths):
            with open(p, "rb") as f:
                while True:
                    b = f.read(CHUNK)
                    if not b:
                        break
                    out.write(b)
            if progress:
                progress(i + 1, len(paths))
    os.replace(tmp, dest)
    return dest


def decrypt_to_dir(path: str, out_dir: str, cipher: Cipher, tolerant: bool = False) -> list[str]:
    """Сохраняет изображения как есть (без перекодирования): <имя>_1.jpg, <имя>_2.jpg…"""
    base = os.path.basename(path)
    if base.lower().endswith(".jpgs"):
        base = base[:-5]
    os.makedirs(out_dir, exist_ok=True)
    written = []
    with DecryptingReader(path, cipher) as r:
        for k, (s, e) in enumerate(scan_images(r, tolerant=tolerant), 1):
            data = r.read(s, e - s)
            ext = "jpg" if is_real_jpeg(data) else sniff_ext(data)
            out = os.path.join(out_dir, f"{base}_{k}.{ext}")
            with open(out, "wb") as f:
                f.write(data)
            written.append(out)
    return written


def sniff_ext(data: bytes) -> str:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:2] == b"BM":
        return "bmp"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:3] == b"GIF":
        return "gif"
    return "bin"


def list_jpgs(folder: str) -> list[str]:
    try:
        names = [n for n in os.listdir(folder) if n.lower().endswith(".jpgs")]
    except OSError:
        return []
    return [os.path.join(folder, n) for n in sorted(names, key=natural_key)]


def list_media(folder: str) -> list[str]:
    """.jpgs и .vids вперемешку, по имени."""
    try:
        names = [n for n in os.listdir(folder) if n.lower().endswith((".jpgs", ".vids"))]
    except OSError:
        return []
    return [os.path.join(folder, n) for n in sorted(names, key=natural_key)]


# ---------------------------------------------------------------------------
# Видео (.vids): тот же AES-256-ECB, но шифруется потоково, без загрузки в память
# ---------------------------------------------------------------------------

VIDEO_EXTS = ("mp4", "m4v", "mov", "mkv", "webm", "avi", "wmv", "flv", "3gp", "ts", "mts",
              "m2ts", "mpg", "mpeg", "ogv")


def is_video_path(path: str) -> bool:
    return path.lower().endswith(".vids")


def gif_frame_count(path: str, limit: int = 2) -> int:
    """Число кадров GIF (подсчёт останавливается на limit). 0 — не GIF или файл битый.

    Разбирает только структуру блоков, пиксели не распаковывает — быстро даже для больших файлов.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return 0
    if data[:6] not in (b"GIF87a", b"GIF89a") or len(data) < 13:
        return 0
    p = 13
    if data[10] & 0x80:  # глобальная палитра
        p += 3 << ((data[10] & 7) + 1)
    frames = 0

    def skip_sub_blocks(p: int) -> int:
        while p < len(data):
            n = data[p]
            p += 1 + n
            if n == 0:
                return p
        return -1

    while p < len(data) and frames < limit:
        b = data[p]
        if b == 0x3B:  # конец файла
            break
        if b == 0x21:  # расширение
            p = skip_sub_blocks(p + 2)
        elif b == 0x2C:  # кадр
            if p + 10 > len(data):
                break
            flags = data[p + 9]
            p += 10
            if flags & 0x80:  # локальная палитра
                p += 3 << ((flags & 7) + 1)
            p = skip_sub_blocks(p + 1)  # +1 — минимальный размер кода LZW
            if p < 0:
                break
            frames += 1
        else:
            break
        if p < 0:
            break
    return frames


def is_animated_gif(path: str) -> bool:
    return path.lower().endswith(".gif") and gif_frame_count(path) > 1


def is_video_source(path: str) -> bool:
    """Что шифровать в .vids: видео и анимированные GIF (в .jpgs анимация потерялась бы)."""
    return path.rsplit(".", 1)[-1].lower() in VIDEO_EXTS or is_animated_gif(path)


def encrypt_stream(src: str, out_dir: str, cipher: Cipher,
                   progress: Optional[Callable[[int, int], None]] = None,
                   ext: str = ".vids") -> str:
    """Шифрует файл любого размера кусками по 1 МБ (результат идентичен шифрованию целиком)."""
    total = os.path.getsize(src)
    out = os.path.join(out_dir, f"{uuid.uuid4()}{ext}")
    tmp = out + ".part"
    done = 0
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            while True:
                chunk = fin.read(CHUNK)
                if len(chunk) < CHUNK:
                    pad = BLOCK - len(chunk) % BLOCK
                    fout.write(cipher.encrypt_blocks(chunk + bytes([pad]) * pad))
                    done += len(chunk)
                    break
                fout.write(cipher.encrypt_blocks(chunk))
                done += len(chunk)
                if progress:
                    progress(done, total)
        os.replace(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if progress:
        progress(total, total)
    return out


def sniff_video_ext(head: bytes) -> str:
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        return "mov" if brand == b"qt  " else "mp4"
    if head[:4] == b"\x1a\x45\xdf\xa3":
        return "webm" if b"webm" in head[:64] else "mkv"
    if head[:4] == b"RIFF" and head[8:11] == b"AVI":
        return "avi"
    if head[:3] == b"FLV":
        return "flv"
    if head[:4] == b"OggS":
        return "ogv"
    if head[:1] == b"\x47":
        return "ts"
    if head[:4] == b"\x00\x00\x01\xba":
        return "mpg"
    if head[:4] == b"\x30\x26\xb2\x75":
        return "wmv"
    return "mp4"


class VidsFile:
    """Зашифрованное видео .vids (одно видео в файле)."""

    is_video = True

    def __init__(self, path: str, cipher: Cipher):
        self.path = path
        self.cipher = cipher

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    def count(self) -> int:
        return 1

    def video_ext(self) -> str:
        with DecryptingReader(self.path, self.cipher, max_chunks=1) as r:
            return sniff_video_ext(r.read(0, 64))


def open_media(path: str, cipher: Cipher):
    return VidsFile(path, cipher) if is_video_path(path) else JpgsFile(path, cipher)


def decrypt_video_file(path: str, dest: str, cipher: Cipher,
                       progress: Optional[Callable[[int, int], None]] = None) -> str:
    with DecryptingReader(path, cipher, max_chunks=2) as r:
        with open(dest + ".part", "wb") as f:
            pos = 0
            while pos < r.size:
                n = min(CHUNK, r.size - pos)
                f.write(r.read(pos, n))
                pos += n
                if progress:
                    progress(pos, r.size)
    os.replace(dest + ".part", dest)
    return dest


def decrypt_video_to(path: str, out_dir: str, cipher: Cipher,
                     progress: Optional[Callable[[int, int], None]] = None) -> str:
    base = os.path.basename(path)
    if base.lower().endswith(".vids"):
        base = base[:-5]
    os.makedirs(out_dir, exist_ok=True)
    ext = VidsFile(path, cipher).video_ext()
    return decrypt_video_file(path, os.path.join(out_dir, f"{base}.{ext}"), cipher, progress)


class DecryptedFile(io.RawIOBase):
    """Файловый объект с расшифровкой на лету — для FFmpeg (PyAV) и libmpv."""

    def __init__(self, path: str, cipher: Cipher):
        super().__init__()
        self.r = DecryptingReader(path, cipher, max_chunks=4)
        self.pos = 0

    @property
    def size(self) -> int:
        return self.r.size

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self.pos = off
        elif whence == io.SEEK_CUR:
            self.pos += off
        elif whence == io.SEEK_END:
            self.pos = self.r.size + off
        self.pos = max(0, self.pos)
        return self.pos

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.r.size - self.pos
        data = self.r.read(self.pos, n)
        self.pos += len(data)
        return data

    def readinto(self, b):
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)

    def close(self):
        if not self.closed:
            self.r.close()
        super().close()


def natural_key(s: str):
    import re
    return [int(t) if t.isdigit() else t.casefold() for t in re.split(r"(\d+)", s)]


# ---------------------------------------------------------------------------
# Работа с .jpgs как с архивом кадров
# ---------------------------------------------------------------------------

class ArchiveError(Exception):
    pass


def _same(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def append_frames(target: str, sources: list[str], cipher: Cipher) -> int:
    """Дописывает изображения (и кадры других .jpgs) в конец target, без пересборки файла.

    Формат тот же, что у «merge»: зашифрованные JPEG подряд. Возвращает число новых кадров.
    """
    size = os.path.getsize(target)
    if size % BLOCK:
        raise ArchiveError("файл повреждён (размер не кратен 16 байтам) — дописывать нельзя")
    parts: list[tuple[str, object]] = []
    added = 0
    for src in sources:
        if _same(src, target):
            continue
        if src.lower().endswith(".jpgs"):
            jf = JpgsFile(src, cipher)
            first = jf.read_first()
            if not first or not is_real_jpeg(first):
                raise ArchiveError(f"{os.path.basename(src)}: не расшифровывается текущим ключом")
            if os.path.getsize(src) % BLOCK:
                raise ArchiveError(f"{os.path.basename(src)}: файл повреждён")
            parts.append(("file", src))
            added += jf.count()
        else:
            if is_animated_gif(src):
                raise ArchiveError(f"{os.path.basename(src)}: анимированный GIF — "
                                   "его можно зашифровать отдельно, в .vids")
            data = to_jpeg_bytes(src)
            if data is None:
                raise ArchiveError(f"{os.path.basename(src)}: не изображение")
            parts.append(("data", cipher.encrypt(data)))
            added += 1
    if not parts:
        return 0
    with open(target, "ab") as out:
        for kind, val in parts:
            if kind == "data":
                out.write(val)
            else:
                with open(val, "rb") as f:
                    while True:
                        b = f.read(CHUNK)
                        if not b:
                            break
                        out.write(b)
        out.flush()
        os.fsync(out.fileno())
    return added


def rewrite_frames(path: str, order: list[int], cipher: Cipher) -> None:
    """Пересобирает файл из кадров в указанном порядке (удаление = кадра нет в order)."""
    rs = JpgsFile(path, cipher).ranges()
    if any(i < 0 or i >= len(rs) for i in order):
        raise ArchiveError("неверный номер кадра")
    if not order:
        raise ArchiveError("в файле не останется кадров — удалите файл целиком")
    tmp = os.path.join(os.path.dirname(path), f".{os.path.basename(path)}.{os.getpid()}.tmp")
    try:
        with DecryptingReader(path, cipher) as r, open(tmp, "wb") as out:
            for i in order:
                s, e = rs[i]
                out.write(cipher.encrypt(r.read(s, e - s)))
            out.flush()
            os.fsync(out.fileno())
        try:
            os.chmod(tmp, os.stat(path).st_mode & 0o7777)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def reencrypt_jpgs(path: str, old: Cipher, new: Cipher) -> None:
    """Перешифровывает архив .jpgs со старого ключа на новый (кадры сохраняются)."""
    rs = JpgsFile(path, old).ranges()
    if not rs:
        raise ArchiveError("файл не расшифровывается текущим ключом (или в нём нет кадров)")
    tmp = os.path.join(os.path.dirname(path), f".{os.path.basename(path)}.{os.getpid()}.rekey")
    try:
        with DecryptingReader(path, old) as r, open(tmp, "wb") as out:
            for s, e in rs:
                out.write(new.encrypt(r.read(s, e - s)))
            out.flush()
            os.fsync(out.fileno())
        try:
            os.chmod(tmp, os.stat(path).st_mode & 0o7777)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def reencrypt_vids(path: str, old: Cipher, new: Cipher,
                   progress: Optional[Callable[[int, int], None]] = None) -> None:
    """Перешифровывает видео .vids со старого ключа на новый, потоково."""
    tmp = os.path.join(os.path.dirname(path), f".{os.path.basename(path)}.{os.getpid()}.rekey")
    try:
        with DecryptingReader(path, old, max_chunks=2) as r, open(tmp, "wb") as out:
            pos = 0
            while pos < r.size:
                n = min(CHUNK, r.size - pos)
                plain = r.read(pos, n)
                pos += n
                if pos >= r.size:  # последний кусок: восстановить PKCS#7-паддинг
                    pad = BLOCK - len(plain) % BLOCK
                    out.write(new.encrypt_blocks(plain + bytes([pad]) * pad))
                else:
                    out.write(new.encrypt_blocks(plain))
                if progress:
                    progress(pos, r.size)
        try:
            os.chmod(tmp, os.stat(path).st_mode & 0o7777)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def reencrypt_media(path: str, old: Cipher, new: Cipher,
                    progress: Optional[Callable[[int, int], None]] = None) -> None:
    if is_video_path(path):
        reencrypt_vids(path, old, new, progress)
    else:
        reencrypt_jpgs(path, old, new)


_VIDEO_MAGIC_OK = (b"ftyp", b"\x1a\x45\xdf\xa3", b"RIFF", b"FLV", b"OggS",
                   b"\x00\x00\x01\xba", b"\x30\x26\xb2\x75", b"GIF8")


def verify_media(path: str, cipher: Cipher) -> bool:
    """Проверяет, что файл действительно расшифровывается этим ключом (по сигнатуре).

    Нужно перед пакетной сменой ключа, чтобы не «перешифровать» мусором файлы,
    зашифрованные другим ключом.
    """
    try:
        if is_video_path(path):
            with DecryptingReader(path, cipher, max_chunks=1) as r:
                head = r.read(0, 16)
            if head[4:8] == b"ftyp" or head[:1] == b"\x47":  # mp4/mov или TS
                return True
            return any(head.startswith(m) for m in _VIDEO_MAGIC_OK)
        first = JpgsFile(path, cipher).read_first()
        return bool(first) and (is_real_jpeg(first) or sniff_ext(first) != "bin")
    except Exception:  # noqa: BLE001
        return False


def extract_frames(path: str, indices: list[int], cipher: Cipher) -> list[str]:
    """Сохраняет указанные кадры отдельными .jpgs рядом с исходным файлом."""
    jf = JpgsFile(path, cipher)
    folder = os.path.dirname(path)
    out = []
    for i in indices:
        dest = os.path.join(folder, f"{uuid.uuid4()}.jpgs")
        with open(dest + ".part", "wb") as f:
            f.write(cipher.encrypt(jf.read_image(i)))
        os.replace(dest + ".part", dest)
        out.append(dest)
    return out
