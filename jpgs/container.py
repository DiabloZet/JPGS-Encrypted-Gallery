"""Файлы .jpgs / .vids: чтение (ленивое, по блокам), поиск JPEG внутри, шифрование, архивы.

Формат (совместим с исходной Java-версией):
  * одиночный файл — AES/ECB/PKCS5(JPEG);
  * «merged» — просто конкатенация нескольких таких файлов. После расшифровки всего
    потока между JPEG остаются байты паддинга (1–16 байт), их пропускаем.
  * .vids — одно видео, AES/ECB/PKCS5 целиком (шифруется потоково).

Границы JPEG определяются разбором структуры (маркеры + длины сегментов + энтропийные
данные), а не поиском первого FFD9: старый способ обрезал снимки с EXIF-миниатюрой.

Архив v2 (видео и картинки вперемешку, заметки)
-----------------------------------------------
Каждая запись (кадр или видео) лежит в файле так же, как в старом формате: свой
AES/ECB/PKCS5-блок с выровненного по 16 байт смещения. В КОНЦЕ файла дописан индекс:

    … записи … | iv(16) + AES-256-CBC(JSON индекса) | хвост (64 байта)
    хвост: "JPGSIDX2" | версия u16 | флаги u16 | 0 u32 | смещение индекса u64 |
           длина индекса u64 | HMAC-SHA256(хвост[:32] + индекс)

Индекс шифруется и проверяется отдельными подключами (HMAC от ключа файла), поэтому
HMAC одновременно подтверждает целостность и то, что файл открыт верным ключом.
Индекс всегда дописывается в конец, старые данные не перезаписываются: обычный .jpgs
или .vids становится архивом с заметками без копирования гигабайт видео, а прерванная
запись не портит уже имеющееся. Прежние версии программы, не знающие индекса, видят в
таком файле те же картинки (индекс для них — мусор в конце, который они пропускают).

Запись хранит диапазон [s, s+n) в «расшифрованных координатах» файла: ECB сохраняет
смещения, поэтому один и тот же диапазон описывает и кадры старых склеенных .jpgs, и
новые записи. Архив, где только JPEG без заметок, пишется по-старому — без индекса.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import struct
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Optional, Union

from .crypto import BLOCK, Cipher, KeyRing, cbc_decrypt, cbc_encrypt

CHUNK = 1 << 20  # 1 МиБ, кратно 16
SOI = b"\xff\xd8\xff"

Progress = Optional[Callable[[int, int], None]]
Keys = Union[Cipher, KeyRing]


class ArchiveError(Exception):
    pass


class WrongKey(ArchiveError):
    """У файла есть индекс, но он не сходится с этим ключом."""


class DecryptingReader:
    """Случайный доступ к расшифрованному содержимому файла без чтения его целиком.

    Без start/length — весь файл (длина по паддингу последнего блока, как в старом
    формате). С ними — окно [start, start+length) «расшифрованных координат»: одна запись
    архива v2. Все смещения в методах — внутри окна.
    """

    def __init__(self, path: str, cipher: Cipher, max_chunks: int = 6,
                 start: int = 0, length: Optional[int] = None):
        self.path = path
        self.cipher = cipher
        self.f = open(path, "rb")
        size = os.fstat(self.f.fileno()).st_size
        self.enc_size = size - size % BLOCK  # хвост некратной длины (повреждение) отбрасываем
        self._chunks: OrderedDict[int, bytes] = OrderedDict()
        self._max = max_chunks
        self.base = start
        if length is not None:
            if start < 0 or length < 0 or start + length > self.enc_size:
                self.f.close()
                raise ArchiveError("запись выходит за пределы файла (файл повреждён)")
            self.size = length
            return
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

    def _pread(self, a: int, b: int) -> bytes:
        """Физический диапазон [a, b) расшифрованного файла."""
        if a >= b:
            return b""
        first, last = a // CHUNK, (b - 1) // CHUNK
        if first == last:
            c = self._chunk(first)
            return c[a - first * CHUNK:b - first * CHUNK]
        parts = []
        for i in range(first, last + 1):
            c = self._chunk(i)
            lo = max(a, i * CHUNK) - i * CHUNK
            hi = min(b, (i + 1) * CHUNK) - i * CHUNK
            parts.append(c[lo:hi])
        return b"".join(parts)

    def read(self, off: int, n: int) -> bytes:
        end = min(off + n, self.size)
        if off >= end:
            return b""
        return self._pread(self.base + off, self.base + end)

    def byte(self, off: int) -> int:
        if off >= self.size or off < 0:
            return -1
        p = self.base + off
        i = p // CHUNK
        return self._chunk(i)[p - i * CHUNK]

    def find(self, pat: bytes, start: int, end: Optional[int] = None) -> int:
        end = self.size if end is None else min(end, self.size)
        b0 = self.base
        pos, end = start + b0, end + b0
        ov = len(pat) - 1
        while pos < end:
            i = pos // CHUNK
            base = i * CHUNK
            c = self._chunk(i)
            lim = min(end, base + len(c)) - base
            r = c.find(pat, pos - base, lim)
            if r >= 0:
                return base + r - b0
            nxt = base + len(c)
            if nxt >= end:
                break
            # образец может лежать на стыке блоков
            if ov:
                tail = self._pread(nxt - ov, min(nxt + ov, self.enc_size))
                r = tail.find(pat)
                if r >= 0 and nxt - ov + r >= pos and nxt - ov + r + len(pat) <= end:
                    return nxt - ov + r - b0
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


# ---------------------------------------------------------------------------
# Индекс архива v2
# ---------------------------------------------------------------------------

TRAILER_MAGIC = b"JPGSIDX2"
TRAILER_SIZE = 64
_HEAD = struct.Struct("<8sHHIQQ")  # 32 байта, затем HMAC (32)
INDEX_FORMAT = 1
MAX_INDEX_BYTES = 64 << 20
NOTE_MAX = 64 * 1024
_EXT_RE = re.compile(r"^[a-z0-9]{0,8}$")


@dataclass
class Entry:
    kind: str           # "image" | "video"
    start: int          # начало в расшифрованных координатах файла
    length: int         # длина без паддинга
    ext: str = ""       # jpg, png, mp4, webm, gif…
    note: str = ""

    @property
    def is_video(self) -> bool:
        return self.kind == "video"

    def to_json(self) -> dict:
        d = {"k": "v" if self.is_video else "i", "s": self.start, "n": self.length,
             "x": self.ext}
        if self.note:
            d["note"] = self.note
        return d

    @classmethod
    def from_json(cls, d: dict, limit: int) -> "Entry":
        if not isinstance(d, dict):
            raise ArchiveError("повреждённый индекс")
        kind = {"i": "image", "v": "video"}.get(d.get("k"))
        s, n = d.get("s"), d.get("n")
        ext, note = d.get("x", ""), d.get("note", "")
        if (kind is None or not isinstance(s, int) or not isinstance(n, int) or s < 0 or n < 0
                or s + n > limit or not isinstance(ext, str) or not _EXT_RE.match(ext)
                or not isinstance(note, str) or len(note) > NOTE_MAX):
            raise ArchiveError("повреждённый индекс")
        return cls(kind, s, n, ext, note)


def _read_trailer(f) -> Optional[tuple[int, int, bytes, bytes]]:
    """(смещение индекса, длина, HMAC, заголовок хвоста) или None, если индекса нет."""
    size = os.fstat(f.fileno()).st_size
    if size < TRAILER_SIZE + 32 or size % BLOCK:
        return None
    f.seek(size - TRAILER_SIZE)
    t = f.read(TRAILER_SIZE)
    if len(t) != TRAILER_SIZE or t[:8] != TRAILER_MAGIC:
        return None
    head, mac = t[:32], t[32:]
    _m, ver, _flags, _r, off, ln = _HEAD.unpack(head)
    if (ver != INDEX_FORMAT or off % BLOCK or ln % BLOCK or ln < 32 or ln > MAX_INDEX_BYTES
            or off + ln > size - TRAILER_SIZE):
        raise ArchiveError("повреждённый индекс архива")
    return off, ln, mac, head


def has_index(path: str) -> bool:
    """Есть ли у файла индекс v2 (проверка по открытому хвосту, ключ не нужен)."""
    try:
        with open(path, "rb") as f:
            return _read_trailer(f) is not None
    except (OSError, ArchiveError):
        return False


def _mac(cipher: Cipher, head: bytes, region: bytes) -> bytes:
    return hmac.new(cipher.subkey(b"index-mac"), head + region, hashlib.sha256).digest()


def load_index(path: str, cipher: Cipher) -> Optional[list[Entry]]:
    """Записи архива v2, None — индекса нет. WrongKey — индекс не от этого ключа."""
    with open(path, "rb") as f:
        t = _read_trailer(f)
        if t is None:
            return None
        off, ln, mac, head = t
        f.seek(off)
        region = f.read(ln)
    if len(region) != ln:
        raise ArchiveError("повреждённый индекс архива")
    if not hmac.compare_digest(mac, _mac(cipher, head, region)):
        raise WrongKey("файл зашифрован другим ключом (или повреждён)")
    try:
        plain = cbc_decrypt(cipher.subkey(b"index-enc"), region[:16], region[16:])
        doc = json.loads(plain.decode("utf-8"))
        items = doc["entries"]
        if not isinstance(items, list):
            raise ValueError
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise ArchiveError("повреждённый индекс архива") from None
    return [Entry.from_json(d, off) for d in items]


def _index_blob(entries: list[Entry], cipher: Cipher, at: int) -> bytes:
    """Индекс + хвост для записи с выровненного смещения at."""
    if at % BLOCK:
        raise ArchiveError("индекс должен начинаться с границы блока")
    doc = {"v": INDEX_FORMAT, "entries": [e.to_json() for e in entries]}
    plain = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    iv = secrets.token_bytes(16)
    region = iv + cbc_encrypt(cipher.subkey(b"index-enc"), iv, plain)
    if len(region) > MAX_INDEX_BYTES:
        raise ArchiveError("слишком большой индекс (заметки слишком длинные)")
    head = _HEAD.pack(TRAILER_MAGIC, INDEX_FORMAT, 0, 0, at, len(region))
    return region + head + _mac(cipher, head, region)


# ---------------------------------------------------------------------------
# Файлы: .jpgs (кадры) и .vids (видео)
# ---------------------------------------------------------------------------

class JpgsFile:
    """Один файл .jpgs: старый (склейка JPEG) или архив v2 (кадры и видео, заметки).

    Индекс записей кэшируется, данные — нет.
    """

    is_video = False  # True только у .vids: «файл = одно видео»

    def __init__(self, path: str, cipher: Cipher):
        self.path = path
        self.cipher = cipher
        self._entries: Optional[list[Entry]] = None
        self._v2: Optional[bool] = None
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def indexed(self) -> bool:
        return self._entries is not None

    def invalidate(self):
        """Файл изменился на диске — перечитать индекс при следующем обращении."""
        with self._lock:
            self._entries = None
            self._v2 = None

    # совместимость: старый код сбрасывал кэш через jf._ranges = None
    @property
    def _ranges(self):
        return self._entries

    @_ranges.setter
    def _ranges(self, v):
        if v is None:
            self.invalidate()

    def entries(self) -> list[Entry]:
        with self._lock:
            if self._entries is None:
                try:
                    idx = load_index(self.path, self.cipher)
                except WrongKey:
                    idx = []  # чужой ключ: показывать нечего
                if idx is not None:
                    self._v2 = True
                    self._entries = idx
                else:
                    self._v2 = False
                    self._entries = self._legacy_entries()
            return self._entries

    def _legacy_entries(self) -> list[Entry]:
        out = []
        with DecryptingReader(self.path, self.cipher) as r:
            for s, e in scan_images(r):
                head = r.read(s, 16)
                out.append(Entry("image", s, e - s, "jpg" if is_real_jpeg(head) else sniff_ext(head)))
        return out

    @property
    def is_v2(self) -> bool:
        if self._v2 is None:
            self.entries()
        return bool(self._v2)

    def ranges(self) -> list[tuple[int, int]]:
        return [(e.start, e.start + e.length) for e in self.entries()]

    def count(self) -> int:
        return len(self.entries())

    def entry(self, i: int) -> Entry:
        return self.entries()[i]

    def kind(self, i: int) -> str:
        """Тип записи. Для старых .jpgs без индекса — всегда картинка, без сканирования
        файла (важно: вызывается в главном потоке)."""
        if self._entries is None and not self.is_video and not has_index(self.path):
            return "image"
        es = self.entries()
        if not es:
            return "video" if self.is_video else "image"
        return es[i if i >= 0 else len(es) - 1].kind if -len(es) <= i < len(es) else "image"

    def note(self, i: int) -> str:
        es = self.entries()
        return es[i].note if 0 <= i < len(es) else ""

    def has_notes(self) -> bool:
        return any(e.note for e in self.entries())

    def reader(self, i: int, max_chunks: int = 6) -> DecryptingReader:
        e = self.entry(i)
        return DecryptingReader(self.path, self.cipher, max_chunks, e.start, e.length)

    def open_entry(self, i: int) -> "DecryptedFile":
        e = self.entry(i)
        return DecryptedFile(self.path, self.cipher, e.start, e.length)

    def read_image(self, i: int) -> bytes:
        e = self.entry(i)
        if e.is_video:
            raise ArchiveError("это видео, а не изображение")
        with self.reader(i) as r:
            return r.read(0, e.length)

    def read_first(self) -> Optional[bytes]:
        """Первое изображение — для миниатюр; не расшифровывает файл дальше нужного.

        None, если изображений нет или первая запись — видео (см. first_kind).
        """
        with self._lock:
            es = self._entries
        if es is None:
            if self.is_video or has_index(self.path):
                es = self.entries()
            else:
                with DecryptingReader(self.path, self.cipher) as r:
                    found = scan_images(r, limit=1)
                    if not found:
                        found = [(0, r.size)] if r.size else []
                    if not found:
                        return None
                    s, e = found[0]
                    return r.read(s, e - s)
        if not es or es[0].is_video:
            return None
        return self.read_image(0)

    def first_kind(self) -> Optional[str]:
        if self._entries is None and not self.is_video and not has_index(self.path):
            return "image"
        es = self.entries()
        return es[0].kind if es else None

    def video_ext(self, i: int = 0) -> str:
        e = self.entry(i)
        if e.ext and e.ext not in ("bin",):
            return e.ext
        with self.reader(i, max_chunks=1) as r:
            return sniff_video_ext(r.read(0, 64))


class VidsFile(JpgsFile):
    """Зашифрованное видео .vids (одно видео в файле; с заметкой — с индексом v2)."""

    is_video = True

    def _legacy_entries(self) -> list[Entry]:
        with DecryptingReader(self.path, self.cipher, max_chunks=1) as r:
            ext = sniff_video_ext(r.read(0, 64)) if r.size else ""
            return [Entry("video", 0, r.size, ext)]

    def count(self) -> int:
        return 1

    def video_ext(self, i: int = 0) -> str:
        return super().video_ext(0)


def open_media(path: str, cipher: Cipher) -> JpgsFile:
    return VidsFile(path, cipher) if is_video_path(path) else JpgsFile(path, cipher)


# ---------------------------------------------------------------------------
# Шифрование отдельных файлов
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
    from gi.repository import GdkPixbuf, GLib
    try:
        pb = GdkPixbuf.Pixbuf.new_from_file(path)
    except GLib.Error:
        return None
    pb = pb.apply_embedded_orientation() or pb
    if pb.get_has_alpha():
        w, h = pb.get_width(), pb.get_height()
        bg = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, False, 8, w, h)
        bg.fill(0xFFFFFFFF)
        pb.composite(bg, 0, 0, w, h, 0, 0, 1, 1, GdkPixbuf.InterpType.NEAREST, 255)
        pb = bg
    ok, buf = pb.save_to_bufferv("jpeg", ["quality"], [str(quality)])
    return bytes(buf) if ok else None


def _write_new(out: str, write: Callable) -> str:
    """Записать файл через .part и переименование; при ошибке не оставлять обрывков."""
    tmp = out + ".part"
    try:
        with open(tmp, "wb") as f:
            write(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return out


def encrypt_file(src: str, out_dir: str, cipher: Cipher) -> Optional[str]:
    data = to_jpeg_bytes(src)
    if data is None:
        return None
    out = os.path.join(out_dir, f"{uuid.uuid4()}.jpgs")
    return _write_new(out, lambda f: f.write(cipher.encrypt(data)))


def sniff_ext(data: bytes) -> str:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:2] == b"BM":
        return "bmp"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:3] == b"GIF":
        return "gif"
    if data[:2] == b"\xff\xd8":
        return "jpg"
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


def _iter_file(path: str) -> Iterator[bytes]:
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                return
            yield b


def _write_encrypted(out, chunks: Iterable[bytes], cipher: Cipher, total: int = 0,
                     progress: Progress = None) -> int:
    """Шифрует поток кусками кратно 16 байтам + PKCS#7 в конце. Возвращает длину открытых данных.

    Результат идентичен cipher.encrypt(всё_целиком) — ECB шифрует блоки независимо.
    """
    buf = b""
    done = 0
    for piece in chunks:
        if not piece:
            continue
        buf += piece
        done += len(piece)
        cut = len(buf) - len(buf) % BLOCK
        if cut >= CHUNK or (cut and len(buf) >= CHUNK):
            out.write(cipher.encrypt_blocks(buf[:cut]))
            buf = buf[cut:]
        if progress:
            progress(done, total or done)
    cut = len(buf) - len(buf) % BLOCK
    if cut:
        out.write(cipher.encrypt_blocks(buf[:cut]))
        buf = buf[cut:]
    pad = BLOCK - len(buf) % BLOCK
    out.write(cipher.encrypt_blocks(buf + bytes([pad]) * pad))
    return done


def encrypt_stream(src: str, out_dir: str, cipher: Cipher,
                   progress: Progress = None, ext: str = ".vids") -> str:
    """Шифрует файл любого размера кусками по 1 МБ (результат идентичен шифрованию целиком)."""
    total = os.path.getsize(src)
    out = os.path.join(out_dir, f"{uuid.uuid4()}{ext}")
    _write_new(out, lambda f: _write_encrypted(f, _iter_file(src), cipher, total, progress))
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


def decrypt_video_file(path: str, dest: str, cipher: Cipher,
                       progress: Progress = None, index: int = 0) -> str:
    """Расшифровать видео (запись index; у .vids она одна) в файл dest."""
    jf = open_media(path, cipher)
    with jf.reader(index, max_chunks=2) as r:
        def write(f):
            pos = 0
            while pos < r.size:
                n = min(CHUNK, r.size - pos)
                f.write(r.read(pos, n))
                pos += n
                if progress:
                    progress(pos, r.size)
        _write_new(dest, write)
    return dest


def decrypt_video_to(path: str, out_dir: str, cipher: Cipher,
                     progress: Progress = None) -> str:
    base = os.path.basename(path)
    if base.lower().endswith(".vids"):
        base = base[:-5]
    os.makedirs(out_dir, exist_ok=True)
    jf = VidsFile(path, cipher)
    ext = jf.video_ext()
    out = decrypt_video_file(path, os.path.join(out_dir, f"{base}.{ext}"), cipher, progress)
    note = jf.note(0)
    if note:
        _write_new(os.path.join(out_dir, f"{base}.txt"), lambda f: f.write(note.encode("utf-8")))
    return out


class DecryptedFile(io.RawIOBase):
    """Файловый объект с расшифровкой на лету — для FFmpeg (PyAV) и libmpv.

    start/length — одна запись архива (видео внутри .jpgs v2).
    """

    def __init__(self, path: str, cipher: Cipher, start: int = 0, length: Optional[int] = None):
        super().__init__()
        self.r = DecryptingReader(path, cipher, max_chunks=4, start=start, length=length)
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
    return [int(t) if t.isdigit() else t.casefold() for t in re.split(r"(\d+)", s)]


# ---------------------------------------------------------------------------
# Сборка архивов
# ---------------------------------------------------------------------------

def _same(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _cipher_for(path: str, keys: Keys) -> Optional[Cipher]:
    if isinstance(keys, KeyRing):
        return keys.cipher_for(path)
    return keys if verify_media(path, keys) else None


def _legacy_ok(entries: list[Entry], vids: bool) -> bool:
    """Можно ли записать без индекса (в формате, понятном прежним версиям)."""
    if any(e.note for e in entries):
        return False
    if vids:
        return len(entries) == 1 and entries[0].is_video
    return bool(entries) and all(e.kind == "image" and e.ext == "jpg" for e in entries)


def _iter_entry(path: str, cipher: Cipher, e: Entry) -> Iterator[bytes]:
    with DecryptingReader(path, cipher, 2, e.start, e.length) as r:
        pos = 0
        while pos < r.size:
            b = r.read(pos, CHUNK)
            pos += len(b)
            yield b


class ArchiveWriter:
    """Пишет новый файл (.jpgs или .vids) во временный файл и атомарно заменяет dest."""

    def __init__(self, dest: str, cipher: Cipher, mode: Optional[int] = None):
        self.dest = dest
        self.cipher = cipher
        self.vids = is_video_path(dest)
        self.tmp = os.path.join(os.path.dirname(os.path.abspath(dest)),
                                f".{os.path.basename(dest)}.{os.getpid()}.{secrets.token_hex(3)}.tmp")
        self.f = open(self.tmp, "wb")
        self.pos = 0
        self.entries: list[Entry] = []
        self.mode = mode

    def add_bytes(self, kind: str, data: bytes, ext: str, note: str = ""):
        enc = self.cipher.encrypt(data)
        self.f.write(enc)
        self.entries.append(Entry(kind, self.pos, len(data), ext, note))
        self.pos += len(enc)

    def add_stream(self, kind: str, chunks: Iterable[bytes], ext: str, note: str = "",
                   total: int = 0, progress: Progress = None):
        start = self.pos
        n = _write_encrypted(self.f, chunks, self.cipher, total, progress)
        self.pos = self.f.tell()
        self.entries.append(Entry(kind, start, n, ext, note))

    def finish(self) -> str:
        try:
            if not self.entries:
                raise ArchiveError("нечего записывать")
            if not _legacy_ok(self.entries, self.vids):
                self.f.write(_index_blob(self.entries, self.cipher, self.pos))
            self.f.flush()
            os.fsync(self.f.fileno())
            self.f.close()
            if self.mode is not None:
                try:
                    os.chmod(self.tmp, self.mode)
                except OSError:
                    pass
            os.replace(self.tmp, self.dest)
        except BaseException:
            self.abort()
            raise
        return self.dest

    def abort(self):
        try:
            self.f.close()
        except OSError:
            pass
        try:
            os.unlink(self.tmp)
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        if et is not None:
            self.abort()


@dataclass
class _Item:
    """Что добавить в архив: готовые байты или поток (файл / запись другого архива)."""
    kind: str
    ext: str
    note: str = ""
    data: Optional[bytes] = None
    chunks: Optional[Callable[[], Iterable[bytes]]] = None
    size: int = 0
    raw_copy: Optional[tuple[str, int, int]] = None  # (путь, начало, длина) — тот же ключ, выровнено


def _expand_source(src: str, keys: Keys) -> list[_Item]:
    """Источник → записи: .jpgs/.vids (любым ключом из связки), видео, GIF, картинка."""
    low = src.lower()
    if low.endswith((".jpgs", ".vids")):
        c = _cipher_for(src, keys)
        if c is None:
            raise ArchiveError(f"{os.path.basename(src)}: не расшифровывается ни одним ключом")
        jf = open_media(src, c)
        es = jf.entries()
        if not es:
            raise ArchiveError(f"{os.path.basename(src)}: в файле нет записей")
        items = []
        for e in es:
            items.append(_Item(e.kind, e.ext, e.note, size=e.length,
                               chunks=lambda e=e, c=c: _iter_entry(src, c, e)))
        return items
    ext = low.rsplit(".", 1)[-1] if "." in low else ""
    if is_video_source(src):
        size = os.path.getsize(src)
        return [_Item("video", "gif" if ext == "gif" else ext, size=size,
                      chunks=lambda: _iter_file(src))]
    if ext in IMAGE_EXTS:
        data = to_jpeg_bytes(src)
        if data is None:
            raise ArchiveError(f"{os.path.basename(src)}: не изображение")
        return [_Item("image", "jpg", data=data)]
    raise ArchiveError(f"{os.path.basename(src)}: неподдерживаемый тип файла")


def build_archive(sources: list[str], dest: str, cipher: Cipher, keys: Optional[Keys] = None,
                  progress: Progress = None) -> str:
    """Новый архив dest из файлов (картинки, видео, .jpgs, .vids) — ключом cipher.

    Источники-архивы расшифровываются своими ключами (keys — связка или один ключ).
    Только JPEG без заметок → старый формат (склейка); иначе — архив v2 с индексом.
    """
    keys = keys if keys is not None else cipher
    items = [it for s in sources for it in _expand_source(s, keys)]
    if not items:
        raise ArchiveError("нечего добавлять")
    total = sum(it.size or len(it.data or b"") for it in items)
    done = [0]
    with ArchiveWriter(dest, cipher) as w:
        for it in items:
            base = done[0]
            if it.data is not None:
                w.add_bytes(it.kind, it.data, it.ext, it.note)
                done[0] += len(it.data)
            else:
                w.add_stream(it.kind, it.chunks(), it.ext, it.note, it.size,
                             (lambda d, t, b=base: progress(b + d, total)) if progress else None)
                done[0] += it.size
            if progress:
                progress(done[0], total)
        return w.finish()


def merge_files(paths: list[str], dest: str,
                progress: Progress = None) -> str:
    """Склейка, как у Java-версии: побайтовая конкатенация зашифрованных файлов.

    Только для старых .jpgs одним ключом; файлы с индексом или повреждённые (длина не
    кратна 16 — дальше все кадры «съехали» бы) не склеиваются: для них build_archive.
    """
    for p in paths:
        if os.path.getsize(p) % BLOCK:
            raise ArchiveError(f"{os.path.basename(p)}: файл повреждён (длина не кратна 16)")
        if has_index(p) or is_video_path(p):
            raise ArchiveError(f"{os.path.basename(p)}: архив с видео/заметками — "
                               "объединяйте через build_archive")

    def write(out):
        for i, p in enumerate(paths):
            for b in _iter_file(p):
                out.write(b)
            if progress:
                progress(i + 1, len(paths))
    return _write_new(dest, write)


def merge_media(paths: list[str], dest: str, keys: Keys, cipher: Optional[Cipher] = None,
                progress: Progress = None) -> str:
    """Объединить .jpgs/.vids (с любыми ключами из связки) в один архив ключом cipher.

    Если все файлы — старые .jpgs активным ключом, склеиваем побайтово (быстро и
    совместимо с прежними версиями); иначе пересобираем в архив v2.
    """
    cipher = cipher or (keys.active if isinstance(keys, KeyRing) else keys)
    simple = all(p.lower().endswith(".jpgs") and not has_index(p)
                 and os.path.getsize(p) % BLOCK == 0
                 and _cipher_for(p, keys) == cipher for p in paths)
    if simple:
        return merge_files(paths, dest, progress)
    return build_archive(paths, dest, cipher, keys, progress)


def _file_mode(path: str) -> Optional[int]:
    try:
        return os.stat(path).st_mode & 0o7777
    except OSError:
        return None


def rewrite_entries(path: str, order: list[int], cipher: Cipher, new_cipher: Optional[Cipher] = None,
                    notes: Optional[dict[int, str]] = None, progress: Progress = None,
                    replace: Optional[dict[int, tuple[str, Cipher, int]]] = None) -> None:
    """Пересобрать файл из записей в указанном порядке (удаление = записи нет в order).

    new_cipher — перешифровать другим ключом; notes — новые заметки {номер: текст};
    replace — {номер: (файл, его ключ, номер записи)}: подставить другую запись (результат
    конвертации) вместо этой. Видео копируются потоково; файл заменяется атомарно.
    """
    jf = open_media(path, cipher)
    es = jf.entries()
    if not es:
        raise ArchiveError("файл не расшифровывается этим ключом (или в нём нет записей)")
    if any(i < 0 or i >= len(es) for i in order):
        raise ArchiveError("неверный номер кадра")
    if not order:
        raise ArchiveError("в файле не останется кадров — удалите файл целиком")
    if jf.is_video and len(order) != 1:
        raise ArchiveError("в .vids может быть только одно видео")
    notes = notes or {}
    replace = replace or {}
    src = {i: (path, cipher, es[i]) for i in order}
    for i, (rp, rc, rk) in replace.items():
        re_ = open_media(rp, rc).entries()
        if not 0 <= rk < len(re_):
            raise ArchiveError("нет записи для замены")
        src[i] = (rp, rc, re_[rk])
    total = sum(src[i][2].length for i in order)
    done = 0
    with ArchiveWriter(path, new_cipher or cipher, _file_mode(path)) as w:
        for i in order:
            sp, sc, e = src[i]
            base = done
            w.add_stream(e.kind, _iter_entry(sp, sc, e), e.ext, notes.get(i, es[i].note),
                         e.length, (lambda d, t, b=base: progress(b + d, total)) if progress else None)
            done += e.length
        w.finish()
    if progress:
        progress(total, total)


def rewrite_frames(path: str, order: list[int], cipher: Cipher) -> None:
    rewrite_entries(path, order, cipher)


def dead_bytes(path: str, cipher: Cipher) -> int:
    """Сколько места занимают устаревшие индексы и удалённые записи (для сжатия)."""
    es = open_media(path, cipher).entries()
    live = sum(e.length + BLOCK - e.length % BLOCK for e in es)
    try:
        with open(path, "rb") as f:
            t = _read_trailer(f)
    except (OSError, ArchiveError):
        return 0
    if t is None:
        return 0
    off, ln, _m, _h = t
    return max(0, off - live)


SMALL_FILE = 64 << 20


def set_note(path: str, i: int, text: str, cipher: Cipher) -> None:
    """Заметка к записи i (картинке или видео). Пустой текст — удалить заметку.

    Небольшие файлы пересобираются целиком (старые версии заметки не остаются в файле).
    У больших (видео) новый индекс дописывается в конец — без копирования гигабайт;
    накопившиеся старые индексы убираются, когда их становится заметно много.
    """
    text = (text or "").replace("\r\n", "\n").strip()
    if len(text) > NOTE_MAX:
        raise ArchiveError(f"заметка длиннее {NOTE_MAX} символов")
    jf = open_media(path, cipher)
    es = [Entry(e.kind, e.start, e.length, e.ext, e.note) for e in jf.entries()]
    if not es:
        raise ArchiveError("файл не расшифровывается этим ключом")
    if not 0 <= i < len(es):
        raise ArchiveError("неверный номер кадра")
    if es[i].note == text:
        return
    size = os.path.getsize(path)
    if size <= SMALL_FILE:
        rewrite_entries(path, list(range(len(es))), cipher, notes={i: text})
        return
    if size % BLOCK:
        raise ArchiveError("файл повреждён (размер не кратен 16 байтам)")
    es[i].note = text
    _append_index(path, es, cipher)
    if dead_bytes(path, cipher) > max(4 << 20, size // 10):
        rewrite_entries(path, list(range(len(es))), cipher)


def _append_index(path: str, entries: list[Entry], cipher: Cipher):
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        try:
            f.seek(size)
            f.write(_index_blob(entries, cipher, size))
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            f.truncate(size)
            raise


def append_frames(target: str, sources: list[str], cipher: Cipher,
                  keys: Optional[Keys] = None, progress: Progress = None) -> int:
    """Дописывает в конец архива target картинки, видео и записи других .jpgs/.vids.

    Старый .jpgs, в который добавляются только JPEG, остаётся в старом формате (кадры
    просто дописываются). Если добавляется видео или у архива есть индекс — пишется
    новый индекс (архив v2). Данные не перезаписываются, только дописываются; при
    ошибке файл обрезается до исходного размера. Возвращает число новых записей.
    """
    if is_video_path(target):
        raise ArchiveError("в .vids нельзя добавлять — объедините файлы в архив .jpgs")
    size = os.path.getsize(target)
    if size % BLOCK:
        raise ArchiveError("файл повреждён (размер не кратен 16 байтам) — дописывать нельзя")
    keys = keys if keys is not None else cipher
    if not verify_media(target, cipher):
        raise WrongKey(f"{os.path.basename(target)}: не расшифровывается этим ключом")
    jf = JpgsFile(target, cipher)
    old = [Entry(e.kind, e.start, e.length, e.ext, e.note) for e in jf.entries()]
    if not old:
        raise ArchiveError("файл не расшифровывается этим ключом")
    items: list[_Item] = []
    for src in sources:
        if _same(src, target):
            continue
        items.extend(_expand_source(src, keys))
    if not items:
        return 0
    new_entries = [Entry(it.kind, 0, 0, it.ext, it.note) for it in items]
    need_index = jf.is_v2 or not _legacy_ok(old + new_entries, False)
    total = sum(it.size or len(it.data or b"") for it in items)
    done = 0
    with open(target, "r+b") as out:
        try:
            pos = size
            out.seek(pos)  # у архива v2 — после старого хвоста: старый индекс станет «мёртвым»
            entries = list(old)
            for it in items:
                start = pos
                if it.data is not None:
                    enc = cipher.encrypt(it.data)
                    out.write(enc)
                    n = len(it.data)
                else:
                    base = done
                    n = _write_encrypted(out, it.chunks(), cipher, it.size,
                                         (lambda d, t, b=base: progress(b + d, total))
                                         if progress else None)
                pos = out.tell()
                done += n
                entries.append(Entry(it.kind, start, n, it.ext, it.note))
            if need_index:
                out.write(_index_blob(entries, cipher, pos))
            out.flush()
            os.fsync(out.fileno())
        except BaseException:
            out.truncate(size)
            raise
    return len(items)


def extract_frames(path: str, indices: list[int], cipher: Cipher) -> list[str]:
    """Сохраняет указанные записи отдельными файлами рядом с исходным
    (картинки — .jpgs, видео — .vids; заметки сохраняются)."""
    jf = open_media(path, cipher)
    es = jf.entries()
    folder = os.path.dirname(path)
    out = []
    for i in indices:
        e = es[i]
        dest = os.path.join(folder, f"{uuid.uuid4()}.{'vids' if e.is_video else 'jpgs'}")
        with ArchiveWriter(dest, cipher) as w:
            w.add_stream(e.kind, _iter_entry(path, cipher, e), e.ext, e.note, e.length)
            w.finish()
        out.append(dest)
    return out


def decrypt_to_dir(path: str, out_dir: str, cipher: Cipher, tolerant: bool = False) -> list[str]:
    """Сохраняет записи как есть (без перекодирования): <имя>_1.jpg, <имя>_2.mp4…

    Заметки — рядом, в <имя>_N.txt.
    """
    base = os.path.basename(path)
    if base.lower().endswith((".jpgs", ".vids")):
        base = base[:-5]
    os.makedirs(out_dir, exist_ok=True)
    written = []
    if tolerant and not has_index(path):
        with DecryptingReader(path, cipher) as r:
            ranges = scan_images(r, tolerant=True)
            for k, (s, e) in enumerate(ranges, 1):
                data = r.read(s, e - s)
                out = os.path.join(out_dir, f"{base}_{k}.{sniff_ext(data)}")
                _write_new(out, lambda f, d=data: f.write(d))
                written.append(out)
        return written
    jf = open_media(path, cipher)
    es = jf.entries()
    for k, e in enumerate(es, 1):
        if e.is_video:
            ext = jf.video_ext(k - 1)
            out = decrypt_video_file(path, os.path.join(out_dir, f"{base}_{k}.{ext}"), cipher,
                                     index=k - 1)
        else:
            data = jf.read_image(k - 1)
            out = os.path.join(out_dir, f"{base}_{k}.{sniff_ext(data)}")
            _write_new(out, lambda f, d=data: f.write(d))
        written.append(out)
        if e.note:
            _write_new(os.path.join(out_dir, f"{base}_{k}.txt"),
                       lambda f, t=e.note: f.write(t.encode("utf-8")))
    return written


# ---------------------------------------------------------------------------
# Смена ключа и проверка
# ---------------------------------------------------------------------------

def reencrypt_jpgs(path: str, old: Cipher, new: Cipher) -> None:
    """Перешифровывает архив .jpgs со старого ключа на новый (кадры и заметки сохраняются)."""
    rs = JpgsFile(path, old).entries()
    if not rs:
        raise ArchiveError("файл не расшифровывается текущим ключом (или в нём нет кадров)")
    rewrite_entries(path, list(range(len(rs))), old, new)


def reencrypt_vids(path: str, old: Cipher, new: Cipher, progress: Progress = None) -> None:
    """Перешифровывает видео .vids со старого ключа на новый, потоково."""
    if has_index(path):
        rewrite_entries(path, [0], old, new, progress=progress)
        return
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
            if r.size == 0:
                out.write(new.encrypt(b""))
            out.flush()
            os.fsync(out.fileno())
        mode = _file_mode(path)
        if mode is not None:
            try:
                os.chmod(tmp, mode)
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def reencrypt_media(path: str, old: Cipher, new: Cipher, progress: Progress = None) -> None:
    """Перешифровать файл другим ключом. Сначала проверяет, что old действительно его ключ:
    иначе «перешифровка» превратила бы файл в мусор."""
    if not verify_media(path, old):
        raise WrongKey(f"{os.path.basename(path)}: не расшифровывается исходным ключом")
    if is_video_path(path):
        reencrypt_vids(path, old, new, progress)
    else:
        reencrypt_jpgs(path, old, new)


def plausible_image_head(h: bytes) -> bool:
    """Похоже ли начало расшифровки на картинку. Проверяем побольше байт, чтобы чужой ключ
    не прошёл случайно (у 2-байтной сигнатуры это 1 шанс из 65 536)."""
    if h[:3] == b"\xff\xd8\xff":
        return len(h) > 3 and 0xC0 <= h[3] <= 0xFE
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return True
    if h[:2] == b"BM":
        return len(h) >= 10 and h[6:10] == b"\0\0\0\0"  # зарезервированные поля BMP
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return True
    return h[:6] in (b"GIF87a", b"GIF89a")


def plausible_video_head(h: bytes) -> bool:
    if h[4:8] == b"ftyp":
        return True
    if h[:4] == b"\x1a\x45\xdf\xa3":            # Matroska / WebM
        return True
    if h[:4] == b"RIFF" and h[8:11] == b"AVI":
        return True
    if h[:4] in (b"OggS", b"\x00\x00\x01\xba", b"\x30\x26\xb2\x75"):
        return True
    if h[:3] == b"FLV" and len(h) > 3 and h[3] == 1:
        return True
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return True
    # MPEG-TS: синхробайт 0x47 в начале каждого 188-байтного пакета (проверяем три)
    return len(h) >= 377 and h[0] == h[188] == h[376] == 0x47


def verify_media(path: str, cipher: Cipher) -> bool:
    """Проверяет, что файл действительно расшифровывается этим ключом.

    Архив v2 — по HMAC индекса (надёжно); старые файлы — по сигнатуре первого блока.
    Нужно перед сменой ключа и для подбора ключа к файлу.
    """
    try:
        if has_index(path):
            load_index(path, cipher)
            return True
        with open(path, "rb") as f:
            blk = f.read(384)
        blk = blk[:len(blk) - len(blk) % BLOCK]
        if not blk:
            return False
        head = cipher.decrypt_blocks(blk)
        if is_video_path(path):
            return plausible_video_head(head)
        return plausible_image_head(head)
    except Exception:  # noqa: BLE001
        return False


def verify_import(path: str, cipher: Cipher, first: int, sources: list[str], keys: Keys) -> bool:
    """Записи path начиная с first точно совпадают с содержимым sources (по SHA-256).

    Проверка перед удалением оригиналов: расшифровываем то, что записали, и сравниваем
    с тем, что должно было записаться (картинки — после той же конвертации в JPEG).
    """
    try:
        es = open_media(path, cipher).entries()
        items = [it for s in sources if not _same(s, path) for it in _expand_source(s, keys)]
        if not items or len(es) < first + len(items):
            return False
        for k, it in enumerate(items):
            e = es[first + k]
            if e.kind != it.kind:
                return False
            h1 = hashlib.sha256()
            for b in _iter_entry(path, cipher, e):
                h1.update(b)
            h2 = hashlib.sha256()
            if it.data is not None:
                h2.update(it.data)
            else:
                for b in it.chunks():
                    h2.update(b)
            if h1.digest() != h2.digest():
                return False
        return True
    except Exception:  # noqa: BLE001
        return False
