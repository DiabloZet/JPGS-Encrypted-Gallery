"""Сжатие и конвертация картинок и видео через FFmpeg — без расшифровки на диск.

Как данные попадают в FFmpeg и обратно:
  * видео: локальный HTTP-сервер на 127.0.0.1 со случайным портом и одноразовым
    256-битным адресом отдаёт расшифрованные байты записи, поддерживая Range — FFmpeg
    перематывает по нему, как по файлу (mp4 с индексом в конце тоже читается). Без
    адреса сервер отвечает 404, после конвертации сразу закрывается;
  * картинка: целиком через stdin (она небольшая);
  * результат FFmpeg пишет в stdout (mp4 — фрагментированный, чтобы не нужна была
    перемотка вывода), программа сразу шифрует его в новый файл.

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


def _run(job: Job, args: list[str], stdin_data: Optional[bytes], duration: float,
         progress: Progress) -> Iterator[bytes]:
    """Запустить FFmpeg и отдавать его stdout кусками; прогресс — из -progress."""
    exe = ffmpeg_path()
    if not exe:
        raise TranscodeError("FFmpeg не найден — установите пакет ffmpeg")
    cmd = [exe, "-hide_banner"] + (["-nostdin"] if stdin_data is None else []) + \
        ["-loglevel", "error", "-progress", "pipe:2", "-nostats"] + args
    job.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_data is not None else
                                subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
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
        while True:
            b = proc.stdout.read(C.CHUNK)
            if not b:
                eof = True
                break
            yield b
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
                pipe.close()
            except OSError:
                pass
    if job.cancelled:
        raise TranscodeError("отменено")
    if rc != 0:
        tail = "; ".join(job.stderr_tail[-3:]) or f"код {rc}"
        raise TranscodeError(f"FFmpeg: {tail}")


def probe_duration(jf: C.JpgsFile, ii: int) -> float:
    """Длительность видео (для процентов) через PyAV; 0 — неизвестно."""
    try:
        import av
        e = None if jf.is_video else jf.entry(ii)
        from .video import _open_src
        with _open_src(jf.path, jf.cipher, e) as f, av.open(f, mode="r") as ct:
            return float(ct.duration) / 1e6 if ct.duration else 0.0
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
    with _SourceServer(jf.path, jf.cipher, entry) as srv:
        pre = ["-ss", f"{o.start:.3f}"] if o.start else []
        args = pre + ["-i", srv.url] + video_args(o) + output_args(mux) + ["pipe:1"]
        chunks = _run(job, args, None, duration, progress)
        return _store(jf, ii, "video", ext, chunks, replace, before)


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
    after = C.open_media(tmp, jf.cipher).entry(0).length
    if not replace:
        return Result(tmp, 0, before, after)
    try:
        if jf.is_video and kind == "video":
            mode = C._file_mode(jf.path)
            if mode is not None:
                os.chmod(tmp, mode)
            os.replace(tmp, jf.path)
            return Result(jf.path, 0, before, after, replaced=True)
        n = jf.count()
        C.rewrite_entries(jf.path, list(range(n)), jf.cipher,
                          replace={ii: (tmp, jf.cipher, 0)})
        return Result(jf.path, ii, before, after, replaced=True)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
