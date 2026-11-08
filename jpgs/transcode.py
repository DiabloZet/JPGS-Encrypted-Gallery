"""Сжатие и конвертация картинок и видео через FFmpeg — без расшифровки на диск.

Как данные попадают в FFmpeg и обратно:
  * видео: локальный HTTP-сервер на 127.0.0.1 со случайным портом и одноразовым
    256-битным адресом отдаёт расшифрованные байты записи, поддерживая Range — FFmpeg
    перематывает по нему, как по файлу (mp4 с индексом в конце тоже читается). Без
    адреса сервер отвечает 404, после конвертации сразу закрывается;
  * картинка: целиком через stdin (она небольшая);
  * результат FFmpeg пишет в stdout (mp4 — фрагментированный, чтобы не нужна была
    перемотка вывода), программа сразу шифрует его в новый файл;
  * WebM/MKV так писать нельзя: индекс перемотки (Cues) и длительность муксер дописывает,
    возвращаясь в начало файла, а в канал вернуться нельзя — получилось бы видео, которое
    плееры не умеют перематывать. Поэтому для них FFmpeg пишет в анонимный файл в памяти
    (memfd: без имени, на диск не попадает), а после — программа шифрует его содержимое.

Открытые данные живут только в памяти этого процесса и FFmpeg.
"""

from __future__ import annotations

import http.server
import os
import re
import secrets
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from . import container as C
from .crypto import Cipher

Progress = Optional[Callable[[float], None]]  # доля 0..1 (или -1 — неизвестно)


class TranscodeError(Exception):
    pass


def ffmpeg_path() -> Optional[str]:
    return os.environ.get("JPGS_FFMPEG") or shutil.which("ffmpeg")


_ENCODERS: Optional[set] = None


def encoders() -> set:
    """Имена доступных кодировщиков FFmpeg (кэшируется)."""
    global _ENCODERS
    if _ENCODERS is None:
        _ENCODERS = set()
        exe = ffmpeg_path()
        if exe:
            try:
                out = subprocess.run([exe, "-hide_banner", "-encoders"], capture_output=True,
                                     text=True, timeout=15).stdout
                for line in out.splitlines():
                    m = re.match(r"\s*[VAS][.A-Z]{5}\s+(\S+)", line)
                    if m:
                        _ENCODERS.add(m.group(1))
            except (OSError, subprocess.SubprocessError):
                pass
    return _ENCODERS


# --------------------------------------------------------------------------- параметры

# формат → (кодек видео, контейнер FFmpeg, расширение, кодек звука или None)
VIDEO_FORMATS = {
    "mp4-h264": ("libx264", "mp4", "mp4", "aac"),
    "mp4-h265": ("libx265", "mp4", "mp4", "aac"),
    "webm-vp9": ("libvpx-vp9", "webm", "webm", "libopus"),
    "webm-av1": ("libsvtav1", "webm", "webm", "libopus"),
    "mkv-h264": ("libx264", "matroska", "mkv", "aac"),
    "gif": ("gif", "gif", "gif", None),
    "copy": ("copy", None, None, "copy"),   # без перекодирования (обрезка, смена контейнера)
}
VIDEO_FORMAT_LABELS = {
    "mp4-h264": "MP4 · H.264 (совместимость)",
    "mp4-h265": "MP4 · H.265 (меньше размер)",
    "webm-vp9": "WebM · VP9",
    "webm-av1": "WebM · AV1 (самый компактный, медленно)",
    "mkv-h264": "MKV · H.264",
    "gif": "GIF (анимация без звука)",
    "copy": "Без перекодирования (только обрезка)",
}
# качество → CRF для кодека (чем больше, тем сильнее сжатие)
QUALITY = ("high", "good", "medium", "low")
QUALITY_LABELS = {"high": "Высокое", "good": "Хорошее", "medium": "Среднее",
                  "low": "Низкое (сильное сжатие)"}
_CRF = {"libx264": (18, 23, 28, 33), "libx265": (20, 26, 30, 35),
        "libvpx-vp9": (24, 32, 38, 45), "libsvtav1": (24, 32, 40, 48)}
_ABITRATE = ("192k", "128k", "96k", "64k")


@dataclass
class VideoOpts:
    fmt: str = "mp4-h264"
    quality: str = "good"
    max_height: Optional[int] = None     # None — исходное разрешение
    fps: Optional[float] = None          # None — исходная частота кадров
    audio: bool = True
    start: Optional[float] = None        # обрезка, секунды
    end: Optional[float] = None
    need_index: bool = False             # только перепаковка ради индекса — нужен memfd

    @property
    def ext(self) -> Optional[str]:
        return VIDEO_FORMATS[self.fmt][2]


@dataclass
class ImageOpts:
    fmt: str = "jpg"                     # jpg | png | webp
    quality: int = 85                    # 1..100 (для jpg/webp)
    max_side: Optional[int] = None


def available_video_formats() -> list[str]:
    enc = encoders()
    return [f for f, (v, *_r) in VIDEO_FORMATS.items() if v in ("copy", "gif") or v in enc]


def available_image_formats() -> list[str]:
    out = ["jpg", "png"]
    if "libwebp" in encoders():
        try:
            import gi
            gi.require_version("GdkPixbuf", "2.0")
            from gi.repository import GdkPixbuf
            if any(f.get_name() == "webp" for f in GdkPixbuf.Pixbuf.get_formats()):
                out.append("webp")  # только если просмотрщик потом сможет её показать
        except (ImportError, ValueError):
            pass
    return out


def parse_time(text: str) -> Optional[float]:
    """«1:23», «01:02:03», «75», «75.5» → секунды; пусто → None."""
    text = (text or "").strip().replace(",", ".")
    if not text:
        return None
    parts = text.split(":")
    if len(parts) > 3:
        raise ValueError(text)
    t = 0.0
    for p in parts:
        t = t * 60 + float(p)
    if t < 0:
        raise ValueError(text)
    return t


def video_args(o: VideoOpts) -> list[str]:
    """Аргументы FFmpeg между входом и выходом (без -i и pipe:1)."""
    vcodec, mux, _ext, acodec = VIDEO_FORMATS[o.fmt]
    q = QUALITY.index(o.quality) if o.quality in QUALITY else 1
    args: list[str] = []
    if o.end is not None and o.start is not None and o.end <= o.start:
        raise TranscodeError("конец обрезки раньше начала")
    if o.end is not None:
        args += ["-t", f"{o.end - (o.start or 0):.3f}"]
    if o.fmt == "copy":
        args += ["-map", "0", "-c", "copy"] + ([] if o.audio else ["-an"])
        return args
    filters = []
    if o.fps:
        filters.append(f"fps={o.fps:g}")
    if o.max_height:
        # не увеличиваем; ширина — чётная, сохраняя пропорции
        filters.append(f"scale=-2:'min({o.max_height},ih)':flags=lanczos")
    if o.fmt == "gif":
        if not o.fps:
            filters.insert(0, "fps=15")
        chain = ",".join(filters) if filters else "null"
        args += ["-filter_complex",
                 f"[0:v:0]{chain},split[a][b];[a]palettegen=stats_mode=diff[p];"
                 f"[b][p]paletteuse=dither=bayer:bayer_scale=4", "-an", "-loop", "0"]
        return args
    args += ["-map", "0:v:0"]
    if filters:
        args += ["-vf", ",".join(filters)]
    args += ["-c:v", vcodec]
    crf = _CRF.get(vcodec, (23, 28, 32, 36))[q]
    if vcodec == "libvpx-vp9":
        args += ["-crf", str(crf), "-b:v", "0", "-row-mt", "1", "-deadline", "good",
                 "-cpu-used", "4"]
    elif vcodec == "libsvtav1":
        args += ["-crf", str(crf), "-preset", "8"]
    else:
        args += ["-crf", str(crf), "-preset", "medium", "-pix_fmt", "yuv420p"]
        if vcodec == "libx265":
            args += ["-tag:v", "hvc1"]
    if o.audio and acodec:
        args += ["-map", "0:a:0?", "-c:a", acodec, "-b:a", _ABITRATE[q]]
    else:
        args += ["-an"]
    return args


def output_args(mux: Optional[str]) -> list[str]:
    if mux == "mp4":
        # фрагментированный mp4 пишется последовательно — не нужна перемотка выхода
        return ["-movflags", "frag_keyframe+empty_moov+default_base_moof", "-f", "mp4"]
    return ["-f", mux] if mux else []


# --------------------------------------------------------------------------- HTTP-источник

class _SourceServer:
    """Отдаёт расшифрованную запись по http://127.0.0.1:порт/<токен> с поддержкой Range."""

    def __init__(self, path: str, cipher: Cipher, entry: Optional[C.Entry]):
        self.path, self.cipher, self.entry = path, cipher, entry
        self.token = secrets.token_urlsafe(32)
        srv = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # тишина: никаких путей и токенов в журналах
                pass

            def _open(self):
                if srv.entry is None:
                    return C.DecryptedFile(srv.path, srv.cipher)
                return C.DecryptedFile(srv.path, srv.cipher, srv.entry.start, srv.entry.length)

            def _serve(self, body: bool):
                if self.path != "/" + srv.token:
                    self.send_error(404)
                    return
                with self._open() as f:
                    size = f.size
                    start, end = 0, size - 1
                    rng = self.headers.get("Range")
                    m = re.match(r"bytes=(\d*)-(\d*)$", rng or "")
                    if m and (m.group(1) or m.group(2)):
                        if m.group(1):
                            start = int(m.group(1))
                            if m.group(2):
                                end = min(int(m.group(2)), size - 1)
                        else:
                            start = max(0, size - int(m.group(2)))
                        if start >= size:
                            self.send_response(416)
                            self.send_header("Content-Range", f"bytes */{size}")
                            self.send_header("Content-Length", "0")
                            self.end_headers()
                            return
                        self.send_response(206)
                        self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                    else:
                        self.send_response(200)
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(end - start + 1))
                    self.end_headers()
                    if not body:
                        return
                    f.seek(start)
                    left = end - start + 1
                    try:
                        while left > 0:
                            b = f.read(min(C.CHUNK, left))
                            if not b:
                                break
                            self.wfile.write(b)
                            left -= len(b)
                    except (BrokenPipeError, ConnectionResetError):
                        pass  # FFmpeg перематывает и закрывает соединение — это нормально

            def do_GET(self):
                self._serve(True)

            def do_HEAD(self):
                self._serve(False)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}/{self.token}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


# --------------------------------------------------------------------------- запуск FFmpeg

class Job:
    """Одна конвертация. cancel() можно вызвать из любого потока."""

    def __init__(self):
        self.proc: Optional[subprocess.Popen] = None
        self.cancelled = False
        self.stderr_tail: list[str] = []

    def cancel(self):
        self.cancelled = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.kill()
            except OSError:
                pass


def memory_budget() -> int:
    """Сколько байт результата можно держать в памяти (memfd): половина доступной ОЗУ.
    0 — memfd недоступен (не Linux)."""
    if not hasattr(os, "memfd_create"):
        return 0
    try:
        with open("/proc/meminfo", encoding="ascii") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024 // 2
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _run(job: Job, args: list[str], stdin_data: Optional[bytes], duration: float,
         progress: Progress, out_fd: Optional[int] = None) -> Iterator[bytes]:
    """Запустить FFmpeg и отдавать результат кусками; прогресс — из -progress.

    out_fd — memfd, куда FFmpeg пишет результат как в обычный файл (с перемоткой); его
    содержимое отдаётся после завершения FFmpeg. Без него — stdout (args кончаются pipe:1).
    """
    exe = ffmpeg_path()
    if not exe:
        raise TranscodeError("FFmpeg не найден — установите пакет ffmpeg")
    cmd = [exe, "-hide_banner"] + (["-nostdin"] if stdin_data is None else []) + \
        ["-loglevel", "error", "-progress", "pipe:2", "-nostats"] + args
    if out_fd is not None:
        # -y обязателен: без него FFmpeg считает /dev/fd/N «уже существующим файлом»,
        # ничего не пишет — и выходит с кодом 0, как будто всё получилось
        cmd += ["-y", f"/dev/fd/{out_fd}"]
    job.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_data is not None else
                                subprocess.DEVNULL,
                                stdout=subprocess.PIPE if out_fd is None else subprocess.DEVNULL,
                                stderr=subprocess.PIPE,
                                pass_fds=(out_fd,) if out_fd is not None else ())
    proc = job.proc

    def feed():
        try:
            proc.stdin.write(stdin_data)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def watch():
        for raw in proc.stderr:
            line = raw.decode("utf-8", "replace").strip()
            m = re.match(r"out_time_(?:us|ms)=(\d+)", line)
            if m and progress and duration > 0:
                progress(min(0.999, int(m.group(1)) / 1e6 / duration))
            elif line and "=" not in line:
                job.stderr_tail = (job.stderr_tail + [line])[-8:]

    if stdin_data is not None:
        threading.Thread(target=feed, daemon=True).start()
    w = threading.Thread(target=watch, daemon=True)
    w.start()
    eof = False
    try:
        if out_fd is None:
            while True:
                b = proc.stdout.read(C.CHUNK)
                if not b:
                    eof = True
                    break
                yield b
        else:
            proc.wait()
            eof = True
    finally:
        if not eof and proc.poll() is None:
            # потребитель бросил чтение (ошибка записи результата) — не оставлять FFmpeg висеть
            try:
                proc.kill()
            except OSError:
                pass
        rc = proc.wait()
        w.join(timeout=5)
        for pipe in (proc.stdout, proc.stderr):
            try:
                if pipe is not None:
                    pipe.close()
            except OSError:
                pass
    if job.cancelled:
        raise TranscodeError("отменено")
    if rc != 0:
        tail = "; ".join(job.stderr_tail[-3:]) or f"код {rc}"
        raise TranscodeError(f"FFmpeg: {tail}")
    if out_fd is not None:
        pos = 0
        while True:
            b = os.pread(out_fd, C.CHUNK, pos)
            if not b:
                break
            pos += len(b)
            yield b


def probe_duration(jf: C.JpgsFile, ii: int) -> float:
    """Длительность видео (для процентов); 0 — неизвестно. Досчитывается и для WebM без
    записанной длительности."""
    try:
        from .video import video_duration
        return video_duration(jf.path, jf.cipher, None if jf.is_video else jf.entry(ii))
    except Exception:  # noqa: BLE001
        return 0.0


# --------------------------------------------------------------------------- операции

@dataclass
class Result:
    path: str            # файл, в который записан результат
    index: int           # номер записи результата в этом файле
    before: int          # размер исходной записи (байт)
    after: int           # размер результата (байт)
    replaced: bool = False
    extra: dict = field(default_factory=dict)


def _note(jf: C.JpgsFile, ii: int) -> str:
    try:
        return jf.note(ii)
    except (IndexError, OSError, C.ArchiveError):
        return ""


def transcode_video(jf: C.JpgsFile, ii: int, o: VideoOpts, replace: bool, job: Job,
                    progress: Progress = None) -> Result:
    vcodec, mux, ext, _a = VIDEO_FORMATS[o.fmt]
    entry = None if jf.is_video else jf.entry(ii)
    src_ext = jf.video_ext(ii)
    if o.fmt == "copy":
        ext = src_ext if src_ext in ("mp4", "mov", "mkv", "webm") else "mkv"
        mux = {"mov": "mp4", "mkv": "matroska"}.get(ext, ext)
    before = entry.length if entry else jf.entry(0).length
    duration = probe_duration(jf, ii)
    if o.end is not None:
        duration = o.end - (o.start or 0)
    elif o.start and duration:
        duration -= o.start
    # WebM/MKV — через файл в памяти, чтобы муксер записал индекс перемотки и длительность
    use_mem = mux in ("webm", "matroska") and memory_budget() > before * 1.5 + (64 << 20)
    if o.need_index and not use_mem:
        raise TranscodeError("не хватает свободной памяти, чтобы перепаковать это видео")
    fd = os.memfd_create("jpgs-transcode", os.MFD_CLOEXEC) if use_mem else None
    try:
        with _SourceServer(jf.path, jf.cipher, entry) as srv:
            pre = ["-ss", f"{o.start:.3f}"] if o.start else []
            args = pre + ["-i", srv.url] + video_args(o) + output_args(mux)
            if fd is None:
                args.append("pipe:1")
            chunks = _run(job, args, None, duration, progress, fd)
            return _store(jf, ii, "video", ext, chunks, replace, before)
    finally:
        if fd is not None:
            os.close(fd)


def needs_index_repair(jf: C.JpgsFile, ii: int) -> bool:
    """WebM/MKV без индекса перемотки и длительности (запись «потоком», старая конвертация)."""
    try:
        if jf.video_ext(ii) not in ("webm", "mkv"):
            return False
        from .video import has_container_duration
        return not has_container_duration(jf.path, jf.cipher, None if jf.is_video else jf.entry(ii))
    except Exception:  # noqa: BLE001
        return False


def repair_index(jf: C.JpgsFile, ii: int, job: Job, progress: Progress = None) -> Result:
    """Перепаковать WebM/MKV без перекодирования (качество то же), записав индекс перемотки
    и длительность. Заменяет запись; заметка сохраняется."""
    o = VideoOpts(fmt="copy", need_index=True)
    return transcode_video(jf, ii, o, True, job, progress)


def transcode_image(jf: C.JpgsFile, ii: int, o: ImageOpts, replace: bool, job: Job,
                    progress: Progress = None) -> Result:
    data = jf.read_image(ii)
    src = _upright_png(data, keep_alpha=o.fmt != "jpg")
    filters = []
    if o.max_side:
        s = int(o.max_side)
        filters.append(f"scale='if(gt(iw,ih),min({s},iw),-2)':'if(gt(iw,ih),-2,min({s},ih))'"
                       ":flags=lanczos")
    q = max(1, min(100, int(o.quality)))
    if o.fmt == "jpg":
        # mjpeg: q:v 2 (лучше) … 31 (хуже); переводим из привычной шкалы 1..100
        codec = ["-c:v", "mjpeg", "-q:v", str(round(2 + (100 - q) * 29 / 99)),
                 "-pix_fmt", "yuvj444p" if q >= 90 else "yuvj420p", "-f", "image2pipe"]
    elif o.fmt == "png":
        codec = ["-c:v", "png", "-compression_level", "9", "-f", "image2pipe"]
    elif o.fmt == "webp":
        codec = ["-c:v", "libwebp", "-quality", str(q), "-f", "webp"]
    else:
        raise TranscodeError(f"неизвестный формат {o.fmt}")
    args = ["-f", "image2pipe", "-i", "pipe:0", "-frames:v", "1", "-map_metadata", "-1"]
    if filters:
        args += ["-vf", ",".join(filters)]
    args += codec + ["pipe:1"]
    if progress:
        progress(-1)
    out = b"".join(_run(job, args, src, 0, None))
    if not out:
        raise TranscodeError("FFmpeg не вернул изображение")
    return _store(jf, ii, "image", o.fmt, iter([out]), replace, len(data))


def _upright_png(data: bytes, keep_alpha: bool) -> bytes:
    """Картинка → PNG без потерь с уже применённым EXIF-поворотом.

    FFmpeg не поворачивает JPEG по EXIF, а метаданные мы вырезаем — без этого фото с
    телефона «легли бы на бок». Прозрачность для JPEG заливаем белым (как при шифровании).
    """
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf, GLib
    loader = GdkPixbuf.PixbufLoader()
    try:
        loader.write(data)
        loader.close()
    except GLib.Error as e:
        raise TranscodeError(f"не удалось прочитать изображение: {e.message}") from None
    pb = loader.get_pixbuf()
    pb = pb.apply_embedded_orientation() or pb
    if pb.get_has_alpha() and not keep_alpha:
        w, h = pb.get_width(), pb.get_height()
        bg = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, False, 8, w, h)
        bg.fill(0xFFFFFFFF)
        pb.composite(bg, 0, 0, w, h, 0, 0, 1, 1, GdkPixbuf.InterpType.NEAREST, 255)
        pb = bg
    ok, buf = pb.save_to_bufferv("png", ["compression"], ["1"])
    if not ok:
        raise TranscodeError("не удалось подготовить изображение")
    return bytes(buf)


def _validate(path: str, cipher: Cipher, kind: str, length: int):
    """Результат должен быть не пустым и читаемым — иначе оригинал не трогаем."""
    if length <= 0:
        raise TranscodeError("FFmpeg вернул пустой результат — оригинал не изменён")
    jf = C.open_media(path, cipher)
    try:
        if kind == "image":
            from .imaging import decode
            decode(jf.read_image(0), 64)
            return
        try:
            import av  # noqa: F401
        except ImportError:
            return  # без PyAV проверить нечем; длина уже не нулевая
        from .video import grab_frame
        grab_frame(path, cipher, 32, at=0.0)
    except TranscodeError:
        raise
    except Exception as e:  # noqa: BLE001
        raise TranscodeError(f"результат не читается ({e}) — оригинал не изменён") from None


def _store(jf: C.JpgsFile, ii: int, kind: str, ext: str, chunks, replace: bool,
           before: int) -> Result:
    """Зашифровать результат: заменить запись (в архиве или .vids) либо новым файлом рядом."""
    folder = os.path.dirname(jf.path)
    note = _note(jf, ii)
    new_ext = "vids" if kind == "video" else "jpgs"
    tmp = os.path.join(folder, f"{secrets.token_hex(8)}.{new_ext}")
    w = C.ArchiveWriter(tmp, jf.cipher)
    try:
        if kind == "image":
            w.add_bytes("image", b"".join(chunks), ext, note)
        else:
            w.add_stream("video", chunks, ext, note)
        w.finish()
    except BaseException:
        w.abort()
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        after = C.open_media(tmp, jf.cipher).entry(0).length
        _validate(tmp, jf.cipher, kind, after)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if not replace:
        return Result(tmp, 0, before, after)
    try:
        if jf.is_video and kind == "video":
            mode = C._file_mode(jf.path)
            if mode is not None:
                os.chmod(tmp, mode)
            with C.WRITE_LOCK:  # не посреди дописывания индекса фоновой ИИ-индексацией
                os.replace(tmp, jf.path)
            return Result(jf.path, 0, before, after, replaced=True)
        n = jf.count()
        C.rewrite_entries(jf.path, list(range(n)), jf.cipher,
                          replace={ii: (tmp, jf.cipher, 0)})
        return Result(jf.path, ii, before, after, replaced=True)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
