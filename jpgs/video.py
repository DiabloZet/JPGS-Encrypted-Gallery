"""Видео .vids: воспроизведение через libmpv (FFmpeg) и кадры-миниатюры через PyAV (FFmpeg).

Расшифровка идёт на лету: libmpv читает поток через собственный протокол `jpgsvid://`
(mpv_stream_cb_add_ro), каждый запрос — это расшифровка нужных блоков AES-ECB.
Незашифрованное видео на диск не попадает. Перемотка работает, потому что ECB
позволяет расшифровать любой участок файла независимо.

Картинка рисуется через mpv render API (OpenGL) прямо в Gtk.GLArea — с аппаратным
декодированием, без копирования кадров через Python.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import itertools
import os
import threading
from ctypes import (CFUNCTYPE, POINTER, Structure, byref, c_char_p, c_double, c_int, c_int64,
                    c_uint64, c_void_p)
from typing import Callable, Optional

from . import container as C
from .crypto import Cipher

# ---------------------------------------------------------------------------
# Кадр для миниатюры (PyAV)
# ---------------------------------------------------------------------------


class VideoInfo:
    def __init__(self, width=0, height=0, duration=0.0, rotation=0):
        self.width, self.height, self.duration, self.rotation = width, height, duration, rotation


def _open_src(path: str, cipher: Cipher, entry=None) -> "C.DecryptedFile":
    """Поток расшифровки: весь .vids или одна запись-видео архива (entry)."""
    if entry is None:
        jf = C.open_media(path, cipher)
        entry = jf.entry(0) if jf.is_video else None
    if entry is None:
        return C.DecryptedFile(path, cipher)
    return C.DecryptedFile(path, cipher, entry.start, entry.length)


def grab_frame(path: str, cipher: Cipher, max_side: Optional[int] = 256,
               at: Optional[float] = None, entry=None):
    """(pixels: bytes, w, h, stride, info) — кадр из зашифрованного видео.

    at=None — кадр примерно с 10% длительности (для миниатюр); иначе кадр у времени at.
    max_side=None — без уменьшения (полное разрешение, для сохранения кадра).
    entry — запись архива (видео внутри .jpgs); по умолчанию — видео .vids целиком.
    """
    import av  # PyAV — привязка к libavformat/libavcodec
    with _open_src(path, cipher, entry) as f, av.open(f, mode="r") as ct:
        vs = ct.streams.video[0]
        vs.thread_type = "AUTO"
        dur = float(ct.duration) / 1e6 if ct.duration else 0.0
        if at is not None:
            target = max(0.0, at)
        else:
            target = dur * 0.1 if dur > 3 else 0.0
        if target and vs.time_base:
            try:
                ct.seek(int(target / vs.time_base), stream=vs)
            except av.error.FFmpegError:
                ct.seek(0)
        frame = None
        for i, fr in enumerate(ct.decode(vs)):
            frame = fr
            if fr.time is None or fr.time >= target - 0.05 or i > 90:
                break
        if frame is None:
            raise ValueError("в файле нет видеокадров")
        rot = int(round(getattr(frame, "rotation", 0) or 0)) % 360
        w, h = frame.width, frame.height
        if max_side:
            k = min(1.0, max_side / max(w, h))
            tw, th = max(2, int(w * k) // 2 * 2), max(2, int(h * k) // 2 * 2)
        else:
            tw, th = w, h
        rgb = frame.reformat(width=tw, height=th, format="rgb24")
        plane = rgb.planes[0]
        info = VideoInfo(w, h, dur, rot)
        if rot in (90, 270):
            info.width, info.height = h, w
        return bytes(plane), tw, th, plane.line_size, info


def save_frame_png(path: str, cipher: Cipher, time_pos: float, dest: str, entry=None) -> None:
    """Сохраняет кадр видео у времени time_pos как PNG (полное разрешение, с учётом поворота).

    Декодирует нужный кадр через PyAV прямо из зашифрованного потока — надёжнее, чем
    screenshot в mpv при аппаратном декодировании и выводе через render API.
    """
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf, GLib
    data, w, h, stride, info = grab_frame(path, cipher, max_side=None, at=time_pos, entry=entry)
    pb = GdkPixbuf.Pixbuf.new_from_bytes(GLib.Bytes.new(data), GdkPixbuf.Colorspace.RGB,
                                         False, 8, w, h, stride)
    if info.rotation:
        pb = pb.rotate_simple(GdkPixbuf.PixbufRotation(info.rotation)) or pb
    if not pb.savev(dest, "png", [], []):
        raise OSError("не удалось записать PNG")


def frame_pixbuf(path: str, cipher: Cipher, max_side: int = 256, entry=None):
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf, GLib
    data, w, h, stride, info = grab_frame(path, cipher, max_side, entry=entry)
    pb = GdkPixbuf.Pixbuf.new_from_bytes(GLib.Bytes.new(data), GdkPixbuf.Colorspace.RGB,
                                         False, 8, w, h, stride)
    if info.rotation:
        # поворот из метаданных FFmpeg задан против часовой стрелки
        pb = pb.rotate_simple(GdkPixbuf.PixbufRotation(info.rotation)) or pb
    return pb, info


# ---------------------------------------------------------------------------
# libmpv через ctypes
# ---------------------------------------------------------------------------

MPV_FORMAT_NONE, MPV_FORMAT_STRING, MPV_FORMAT_FLAG, MPV_FORMAT_INT64, MPV_FORMAT_DOUBLE = 0, 1, 3, 4, 5
EV_SHUTDOWN, EV_END_FILE, EV_FILE_LOADED, EV_VIDEO_RECONFIG, EV_PROPERTY_CHANGE = 1, 7, 8, 17, 22
MPV_ERROR_GENERIC, MPV_ERROR_UNSUPPORTED, MPV_ERROR_LOADING_FAILED = -20, -18, -13

RP_INVALID, RP_API_TYPE, RP_OPENGL_INIT, RP_OPENGL_FBO, RP_FLIP_Y = 0, 1, 2, 3, 4
RP_X11_DISPLAY, RP_WL_DISPLAY = 8, 9
UPDATE_FRAME = 1


class MpvEvent(Structure):
    _fields_ = [("event_id", c_int), ("error", c_int), ("reply_userdata", c_uint64), ("data", c_void_p)]


class MpvEventProperty(Structure):
    _fields_ = [("name", c_char_p), ("format", c_int), ("data", c_void_p)]


class MpvEventEndFile(Structure):
    _fields_ = [("reason", c_int), ("error", c_int)]


class MpvRenderParam(Structure):
    _fields_ = [("type", c_int), ("data", c_void_p)]


GETPROC = CFUNCTYPE(c_void_p, c_void_p, c_char_p)


class MpvOpenGLInitParams(Structure):
    _fields_ = [("get_proc_address", GETPROC), ("get_proc_address_ctx", c_void_p)]


class MpvOpenGLFbo(Structure):
    _fields_ = [("fbo", c_int), ("w", c_int), ("h", c_int), ("internal_format", c_int)]


READ_FN = CFUNCTYPE(c_int64, c_void_p, c_void_p, c_uint64)
SEEK_FN = CFUNCTYPE(c_int64, c_void_p, c_int64)
SIZE_FN = CFUNCTYPE(c_int64, c_void_p)
CLOSE_FN = CFUNCTYPE(None, c_void_p)
CANCEL_FN = CFUNCTYPE(None, c_void_p)


class MpvStreamCbInfo(Structure):
    _fields_ = [("cookie", c_void_p), ("read_fn", READ_FN), ("seek_fn", SEEK_FN),
                ("size_fn", SIZE_FN), ("close_fn", CLOSE_FN), ("cancel_fn", CANCEL_FN)]


OPEN_FN = CFUNCTYPE(c_int, c_void_p, c_char_p, POINTER(MpvStreamCbInfo))
WAKEUP_FN = CFUNCTYPE(None, c_void_p)

_lib = None


def libmpv():
    """Загружает libmpv или возвращает None (тогда видео недоступно)."""
    global _lib
    if _lib is not None:
        return _lib or None
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("mpv") or "libmpv.so.2")
    except OSError:
        _lib = False
        return None
    lib.mpv_create.restype = c_void_p
    lib.mpv_initialize.argtypes = [c_void_p]
    lib.mpv_set_option_string.argtypes = [c_void_p, c_char_p, c_char_p]
    lib.mpv_set_property_string.argtypes = [c_void_p, c_char_p, c_char_p]
    lib.mpv_set_property.argtypes = [c_void_p, c_char_p, c_int, c_void_p]
    lib.mpv_get_property.argtypes = [c_void_p, c_char_p, c_int, c_void_p]
    lib.mpv_command.argtypes = [c_void_p, POINTER(c_char_p)]
    lib.mpv_command_async.argtypes = [c_void_p, c_uint64, POINTER(c_char_p)]
    lib.mpv_observe_property.argtypes = [c_void_p, c_uint64, c_char_p, c_int]
    lib.mpv_wait_event.argtypes = [c_void_p, c_double]
    lib.mpv_wait_event.restype = POINTER(MpvEvent)
    lib.mpv_set_wakeup_callback.argtypes = [c_void_p, WAKEUP_FN, c_void_p]
    lib.mpv_terminate_destroy.argtypes = [c_void_p]
    lib.mpv_stream_cb_add_ro.argtypes = [c_void_p, c_char_p, c_void_p, OPEN_FN]
    lib.mpv_render_context_create.argtypes = [POINTER(c_void_p), c_void_p, POINTER(MpvRenderParam)]
    lib.mpv_render_context_render.argtypes = [c_void_p, POINTER(MpvRenderParam)]
    lib.mpv_render_context_set_update_callback.argtypes = [c_void_p, WAKEUP_FN, c_void_p]
    lib.mpv_render_context_update.argtypes = [c_void_p]
    lib.mpv_render_context_update.restype = c_uint64
    lib.mpv_render_context_free.argtypes = [c_void_p]
    lib.mpv_error_string.argtypes = [c_int]
    lib.mpv_error_string.restype = c_char_p
    _lib = lib
    return lib


def _gl_get_proc():
    """eglGetProcAddress (Wayland и X11 в GTK4) с запасным glXGetProcAddressARB."""
    for name, fn in (("libEGL.so.1", "eglGetProcAddress"), ("libGL.so.1", "glXGetProcAddressARB")):
        try:
            lib = ctypes.CDLL(name)
            f = getattr(lib, fn)
            f.restype = c_void_p
            f.argtypes = [c_char_p]
            return f
        except (OSError, AttributeError):
            continue
    return None


class _Stream:
    """Состояние одного открытого потока для libmpv (вызывается из потока демуксера mpv)."""

    def __init__(self, path: str, cipher: Cipher, entry=None):
        self.f = _open_src(path, cipher, entry)
        self.lock = threading.Lock()


class MpvPlayer:
    """Обёртка над mpv_handle. События доставляются в главный поток через GLib.idle_add."""

    _ids = itertools.count(1)

    def __init__(self, cipher: Cipher, on_event: Callable[[str, object], None]):
        from gi.repository import GLib
        self.GLib = GLib
        self.lib = libmpv()
        if not self.lib:
            raise RuntimeError("libmpv не найдена — установите пакет mpv")
        self.cipher = cipher
        self.on_event = on_event
        self.streams: dict[int, _Stream] = {}
        self.paths: dict[str, tuple] = {}  # ключ потока → (путь, шифр, запись)
        self.render_ctx = c_void_p()
        self._pending_wakeup = False
        # libmpv работает только с LC_NUMERIC="C" (иначе mpv_create() возвращает NULL).
        # GTK выставляет системную локаль (ru_RU — десятичная запятая), поэтому
        # возвращаем числовой формат к "C"; язык интерфейса это не затрагивает.
        import locale
        locale.setlocale(locale.LC_NUMERIC, "C")
        h = self.lib.mpv_create()
        if not h:
            raise RuntimeError("mpv_create() не удалось")
        self.h = h
        opts = {
            "vo": "libmpv", "hwdec": os.environ.get("JPGS_HWDEC", "auto-safe"),
            "keep-open": "yes", "idle": "yes",
            "osc": "no", "input-default-bindings": "no", "input-vo-keyboard": "no",
            "cache": "no", "demuxer-max-bytes": "24MiB", "demuxer-max-back-bytes": "8MiB",
            "audio-client-name": "JPGS", "terminal": "no", "msg-level": "all=error",
            "save-position-on-quit": "no",
            "ytdl": "no", "load-scripts": "no", "config": "no",
            **(dict(x.split("=", 1) for x in os.environ["JPGS_MPV_OPTS"].split(","))
               if os.environ.get("JPGS_MPV_OPTS") else {}),
        }
        if os.environ.get("JPGS_MPV_LOG"):  # отладка: журнал mpv в файл
            opts["log-file"] = os.environ["JPGS_MPV_LOG"]
            opts["msg-level"] = "all=v"
        for k, v in opts.items():
            self.lib.mpv_set_option_string(h, k.encode(), v.encode())
        if self.lib.mpv_initialize(h) < 0:
            raise RuntimeError("mpv_initialize() не удалось")
        # колбэки должны жить столько же, сколько плеер
        self._cb_open = OPEN_FN(self._open)
        self._cb_read = READ_FN(self._read)
        self._cb_seek = SEEK_FN(self._seek)
        self._cb_size = SIZE_FN(self._size)
        self._cb_close = CLOSE_FN(self._close)
        self._cb_cancel = CANCEL_FN(lambda cookie: None)
        self._cb_wakeup = WAKEUP_FN(self._wakeup)
        self.lib.mpv_stream_cb_add_ro(h, b"jpgsvid", None, self._cb_open)
        for i, (name, fmt) in enumerate((("pause", MPV_FORMAT_FLAG), ("time-pos", MPV_FORMAT_DOUBLE),
                                         ("duration", MPV_FORMAT_DOUBLE), ("volume", MPV_FORMAT_DOUBLE),
                                         ("mute", MPV_FORMAT_FLAG), ("eof-reached", MPV_FORMAT_FLAG),
                                         ("width", MPV_FORMAT_INT64), ("height", MPV_FORMAT_INT64),
                                         ("video-params/rotate", MPV_FORMAT_INT64)), 1):
            self.lib.mpv_observe_property(h, i, name.encode(), fmt)
        self.lib.mpv_set_wakeup_callback(h, self._cb_wakeup, None)

    # ---- поток данных (вызывается из потоков mpv)
    def _open(self, user, uri, info_p):
        try:
            key = uri.decode()[len("jpgsvid://"):]
            path, cipher, entry = self.paths[key]
            sid = next(self._ids)
            self.streams[sid] = _Stream(path, cipher, entry)
            info = info_p.contents
            info.cookie = sid
            info.read_fn, info.seek_fn = self._cb_read, self._cb_seek
            info.size_fn, info.close_fn, info.cancel_fn = self._cb_size, self._cb_close, self._cb_cancel
            return 0
        except Exception:  # noqa: BLE001
            return MPV_ERROR_LOADING_FAILED

    def _read(self, cookie, buf, n):
        st = self.streams.get(cookie)
        if st is None:
            return -1
        try:
            with st.lock:
                data = st.f.read(min(n, 4 << 20))
            if data:
                ctypes.memmove(buf, data, len(data))
            return len(data)
        except Exception:  # noqa: BLE001
            return -1

    def _seek(self, cookie, off):
        st = self.streams.get(cookie)
        if st is None:
            return MPV_ERROR_GENERIC
        with st.lock:
            return st.f.seek(off)

    def _size(self, cookie):
        st = self.streams.get(cookie)
        return st.f.size if st else MPV_ERROR_UNSUPPORTED

    def _close(self, cookie):
        st = self.streams.pop(cookie, None)
        if st:
            st.f.close()

    # ---- события
    def _wakeup(self, _d):
        if not self._pending_wakeup:
            self._pending_wakeup = True
            self.GLib.idle_add(self._drain)

    def _emit(self, name, val):
        try:
            self.on_event(name, val)
        except Exception:  # noqa: BLE001 — ошибка в интерфейсе не должна ломать очередь событий
            import traceback
            traceback.print_exc()

    def _drain(self):
        self._pending_wakeup = False
        if not self.h:
            return False
        while True:
            ev = self.lib.mpv_wait_event(self.h, 0).contents
            if ev.event_id == 0:
                break
            if ev.event_id == EV_PROPERTY_CHANGE:
                p = ctypes.cast(ev.data, POINTER(MpvEventProperty)).contents
                name = p.name.decode()
                val = None
                if p.data:
                    if p.format == MPV_FORMAT_FLAG:
                        val = bool(ctypes.cast(p.data, POINTER(c_int)).contents.value)
                    elif p.format == MPV_FORMAT_DOUBLE:
                        val = ctypes.cast(p.data, POINTER(c_double)).contents.value
                    elif p.format == MPV_FORMAT_INT64:
                        val = ctypes.cast(p.data, POINTER(c_int64)).contents.value
                self._emit(name, val)
            elif ev.event_id == EV_END_FILE:
                ef = ctypes.cast(ev.data, POINTER(MpvEventEndFile)).contents
                if ef.reason == 4:  # MPV_END_FILE_REASON_ERROR
                    msg = self.lib.mpv_error_string(ef.error).decode(errors="replace")
                    self._emit("error", msg)
                else:
                    self._emit("end-file", ef.reason)
            elif ev.event_id == EV_FILE_LOADED:
                self._emit("file-loaded", None)
            elif ev.event_id == EV_SHUTDOWN:
                break
        return False

    # ---- команды
    def command(self, *args):
        if not self.h:
            return -1
        arr = (c_char_p * (len(args) + 1))(*[str(a).encode() for a in args], None)
        return self.lib.mpv_command(self.h, arr)

    def set(self, name, value):
        if self.h:
            if isinstance(value, bool):
                value = "yes" if value else "no"
            self.lib.mpv_set_property_string(self.h, name.encode(), str(value).encode())

    def load(self, path: str, cipher: Optional[Cipher] = None, entry=None):
        """Открыть видео: .vids целиком или запись-видео архива. cipher — ключ этого файла
        (у разных файлов могут быть разные ключи)."""
        key = f"v{next(self._ids)}"
        self.paths = {key: (path, cipher or self.cipher, entry)}  # старые потоки закроет mpv
        self.command("loadfile", f"jpgsvid://{key}")

    def stop(self):
        self.command("stop")

    # ---- отрисовка (вызывается с текущим GL-контекстом GLArea)
    def init_gl(self, on_update: Callable[[], None], wl_display: Optional[int] = None,
                x11_display: Optional[int] = None, simple: bool = False) -> bool:
        getproc = _gl_get_proc()
        if getproc is None:
            return False
        self._getproc = getproc
        # На программном OpenGL (llvmpipe и т.п.) продвинутый конвейер mpv с fp16-буферами
        # даёт чёрный кадр — включаем простой режим. Его же можно включить вручную.
        renderer = ""
        gs = getproc(b"glGetString")
        if gs:
            s = CFUNCTYPE(c_char_p, c_int)(gs)(0x1F01)  # GL_RENDERER
            renderer = (s or b"").decode(errors="replace").lower()
        self.gl_renderer = renderer
        if simple or any(x in renderer for x in ("llvmpipe", "softpipe", "swrast")):
            self.set("gpu-dumb-mode", "yes")
        self._cb_getproc = GETPROC(lambda ctx, name: getproc(name))
        init = MpvOpenGLInitParams(self._cb_getproc, None)
        self._api_name = ctypes.create_string_buffer(b"opengl")  # живёт вместе с плеером
        params = [MpvRenderParam(RP_API_TYPE, ctypes.cast(self._api_name, c_void_p)),
                  MpvRenderParam(RP_OPENGL_INIT, ctypes.cast(byref(init), c_void_p))]
        if wl_display:
            params.append(MpvRenderParam(RP_WL_DISPLAY, c_void_p(wl_display)))
        elif x11_display:
            params.append(MpvRenderParam(RP_X11_DISPLAY, c_void_p(x11_display)))
        params.append(MpvRenderParam(RP_INVALID, None))
        arr = (MpvRenderParam * len(params))(*params)
        self._init = init
        err = self.lib.mpv_render_context_create(byref(self.render_ctx), self.h, arr)
        if err < 0:
            self.render_ctx = c_void_p()
            return False
        self._on_update = on_update
        self._cb_update = WAKEUP_FN(lambda d: self.GLib.idle_add(self._update_idle))
        self.lib.mpv_render_context_set_update_callback(self.render_ctx, self._cb_update, None)
        gi_fn = getproc(b"glGetIntegerv")
        self._glGetIntegerv = CFUNCTYPE(None, c_int, POINTER(c_int))(gi_fn) if gi_fn else None
        return True

    def _update_idle(self):
        if self.render_ctx:
            flags = self.lib.mpv_render_context_update(self.render_ctx)
            if flags & UPDATE_FRAME:
                self._on_update()
        return False

    def render(self, width: int, height: int):
        if not self.render_ctx:
            return
        fbo_id = c_int(0)
        if self._glGetIntegerv:
            self._glGetIntegerv(0x8CA6, byref(fbo_id))  # GL_DRAW_FRAMEBUFFER_BINDING
        fbo = MpvOpenGLFbo(fbo_id.value, width, height, 0)
        flip = c_int(1)
        params = (MpvRenderParam * 3)(MpvRenderParam(RP_OPENGL_FBO, ctypes.cast(byref(fbo), c_void_p)),
                                      MpvRenderParam(RP_FLIP_Y, ctypes.cast(byref(flip), c_void_p)),
                                      MpvRenderParam(RP_INVALID, None))
        self.lib.mpv_render_context_render(self.render_ctx, params)

    def free_gl(self):
        if self.render_ctx:
            self.lib.mpv_render_context_free(self.render_ctx)
            self.render_ctx = c_void_p()

    def destroy(self):
        self.free_gl()
        if self.h:
            h, self.h = self.h, None
            self.lib.mpv_terminate_destroy(h)
        for st in list(self.streams.values()):
            st.f.close()
        self.streams.clear()

