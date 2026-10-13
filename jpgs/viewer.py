"""JPGS — просмотрщик зашифрованных изображений (GTK 4 + libadwaita, нативно под Wayland).

Что держится в памяти в каждый момент:
  * текущее изображение, декодированное под размер экрана (+ полное — только при увеличении);
  * соседние (предыдущее/следующее) — тоже под размер экрана, для мгновенного листания;
  * сжатые JPEG-байты последних просмотренных кадров (LRU, ≤ 64 МБ);
  * миниатюры видимой ленты (LRU, ~150 шт.).
Расшифрованные данные никогда не пишутся на диск (кроме явного «Сохранить»/«Расшифровать»).
"""

from __future__ import annotations

import json
import os
import threading
import traceback
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
gi.require_version("Gsk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Graphene", "1.0")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Graphene, Gsk, Gtk  # noqa: E402

from . import APP_ID, __version__  # noqa: E402
from . import container as C  # noqa: E402
from . import keys_ui  # noqa: E402
from .crypto import Cipher, KeyMissing  # noqa: E402
from .imaging import DecodeError, decode  # noqa: E402
from .memory import trim as trim_memory  # noqa: E402
from .video_ui import VideoPane, fmt_time  # noqa: E402

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
BYTES_CACHE_LIMIT = 64 * 1024 * 1024
THUMB_LIMIT = 150
THUMB_SIDE = 192
EDGE_CLICK = 100
ZOOM_MAX = 20.0

CSS = b"""
.jpgs-view { background-color: #111; }
.jpgs-view.fullscreen { background-color: #000; }
.nav-button { min-width: 48px; min-height: 48px; background-color: alpha(#1e1e1e, 0.7);
              box-shadow: 0 0 0 1px alpha(white, 0.18); color: white; }
.nav-button:hover { background-color: alpha(#3a3a3a, 0.85); }
.filmstrip { background: transparent; padding: 6px 4px; }
.filmstrip > row { padding: 3px; border-radius: 10px; background: transparent; }
.filmstrip > row:selected { background: alpha(@accent_bg_color, 0.85); }
.thumb { border-radius: 8px; background-color: alpha(@view_fg_color, 0.06); }
.video-controls { border-radius: 14px; padding: 4px 10px; }
.badge { font-size: 0.8em; font-weight: bold; padding: 1px 6px; border-radius: 99px; }
"""


# ---------------------------------------------------------------------------
# Настройки
# ---------------------------------------------------------------------------

class Settings:
    DEFAULTS = {"upscale_small": True, "filmstrip": True, "slideshow_seconds": 4,
                "volume": 100, "mute": False, "loop_video": False, "video_simple": False}

    def __init__(self):
        self.path = os.path.join(GLib.get_user_config_dir(), "jpgs", "settings.json")
        self.data = dict(self.DEFAULTS)
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data.update(json.load(f))
        except (OSError, ValueError):
            pass

    def get(self, k):
        return self.data.get(k, self.DEFAULTS.get(k))

    def set(self, k, v):
        self.data[k] = v
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Область просмотра: масштаб и панорамирование на GPU, без пересчёта пикселей
# ---------------------------------------------------------------------------

class ImageView(Gtk.Widget):
    __gtype_name__ = "JpgsImageView"

    def __init__(self):
        super().__init__(focusable=True, hexpand=True, vexpand=True)
        self.add_css_class("jpgs-view")
        self.set_overflow(Gtk.Overflow.HIDDEN)
        self.tex: Optional[Gdk.Texture] = None
        self.iw = self.ih = 0          # полный размер изображения (логический)
        self.angle = 0
        self.zoom = 1.0
        self.fit_mode = True
        self.upscale = True
        self.ox = self.oy = 0.0
        self.pointer = None
        self.on_zoom: Optional[Callable[[], None]] = None
        self.on_edge_click: Optional[Callable[[int], None]] = None
        self.on_motion: Optional[Callable[[], None]] = None
        self._anim = None
        self._drag0 = None
        self._dragged = False
        self._pinch0 = None

        drag = Gtk.GestureDrag(button=Gdk.BUTTON_PRIMARY)
        drag.connect("drag-begin", self._drag_begin)
        drag.connect("drag-update", self._drag_update)
        drag.connect("drag-end", self._drag_end)
        self.add_controller(drag)

        click = Gtk.GestureClick(button=Gdk.BUTTON_PRIMARY)
        click.connect("released", self._clicked)
        self.add_controller(click)

        scroll = Gtk.EventControllerScroll(flags=Gtk.EventControllerScrollFlags.VERTICAL)
        scroll.connect("scroll", self._scroll)
        self.add_controller(scroll)

        motion = Gtk.EventControllerMotion()
        motion.connect("motion", self._motion)
        motion.connect("leave", lambda *_: setattr(self, "pointer", None))
        self.add_controller(motion)

        pinch = Gtk.GestureZoom()
        pinch.connect("begin", self._pinch_begin)
        pinch.connect("scale-changed", self._pinch)
        self.add_controller(pinch)

    # --- геометрия
    def rotated_size(self):
        return (self.ih, self.iw) if self.angle % 180 else (self.iw, self.ih)

    def fit_zoom(self) -> float:
        rw, rh = self.rotated_size()
        W, H = self.get_width(), self.get_height()
        if not rw or not rh or W <= 0 or H <= 0:
            return 1.0
        z = min(W / rw, H / rh)
        return z if self.upscale else min(z, 1.0)

    def min_zoom(self) -> float:
        return min(self.fit_zoom(), 1.0) if not self.upscale else self.fit_zoom()

    def _clamp(self):
        rw, rh = self.rotated_size()
        W, H = self.get_width(), self.get_height()
        dw, dh = rw * self.zoom, rh * self.zoom
        mx = max(0.0, (dw - W) / 2)
        my = max(0.0, (dh - H) / 2)
        self.ox = min(mx, max(-mx, self.ox))
        self.oy = min(my, max(-my, self.oy))

    def scale_factor(self) -> float:
        native = self.get_native()
        surf = native.get_surface() if native else None
        if surf is not None and hasattr(surf, "get_scale"):
            return surf.get_scale()
        return float(self.get_scale_factor())

    def needs_hires(self) -> bool:
        if not self.tex or not self.iw:
            return False
        if self.tex.get_width() >= self.iw and self.tex.get_height() >= self.ih:
            return False
        need = self.zoom * self.iw * self.scale_factor()
        return self.tex.get_width() < need * 0.97

    # --- изображение
    def set_image(self, tex, iw, ih):
        self._stop_anim()
        self.tex, self.iw, self.ih = tex, iw, ih
        self.angle = 0
        self.fit_mode = True
        self.ox = self.oy = 0.0
        self.zoom = self.fit_zoom()
        self._update_cursor()
        self.queue_draw()
        self._notify()

    def swap_texture(self, tex):
        """Та же картинка в лучшем разрешении — вид не меняется."""
        self.tex = tex
        self.queue_draw()

    def clear(self):
        self.tex = None
        self.iw = self.ih = 0
        self.queue_draw()
        self._notify()

    def rotate(self, delta):
        self.angle = (self.angle + delta) % 360
        if self.fit_mode:
            self.zoom = self.fit_zoom()
        self._clamp()
        self.queue_draw()
        self._notify()

    def zoom_to(self, z, anchor=None):
        if not self.tex:
            return
        z = max(self.min_zoom(), min(max(ZOOM_MAX, self.fit_zoom()), z))
        W, H = self.get_width(), self.get_height()
        ax, ay = anchor if anchor else (W / 2, H / 2)
        dx = ax - W / 2 - self.ox
        dy = ay - H / 2 - self.oy
        k = z / self.zoom if self.zoom else 1
        self.ox = ax - W / 2 - dx * k
        self.oy = ay - H / 2 - dy * k
        self.zoom = z
        self.fit_mode = abs(z - self.fit_zoom()) < 1e-4
        self._clamp()
        self._update_cursor()
        self.queue_draw()
        self._notify()

    def animate_zoom(self, target, anchor=None):
        self._stop_anim()
        if not self.tex:
            return
        start = self.zoom
        anchor = anchor or (self.get_width() / 2, self.get_height() / 2)
        tgt = Adw.CallbackAnimationTarget.new(lambda v: self.zoom_to(v, anchor))
        self._anim = Adw.TimedAnimation.new(self, start, target, 180, tgt)
        self._anim.set_easing(Adw.Easing.EASE_OUT_CUBIC)
        self._anim.play()

    def _stop_anim(self):
        if self._anim is not None:
            self._anim.pause()
            self._anim = None

    def zoom_fit(self, animate=True):
        z = self.fit_zoom()
        if animate:
            self.animate_zoom(z)
        else:
            self.zoom_to(z)
        self.fit_mode = True

    def zoom_step(self, factor, anchor=None, animate=True):
        target = self.zoom * factor
        if animate:
            self.animate_zoom(max(self.min_zoom(), min(ZOOM_MAX, target)), anchor)
        else:
            self.zoom_to(target, anchor)

    def _notify(self):
        if self.on_zoom:
            self.on_zoom()

    def _update_cursor(self):
        W, H = self.get_width(), self.get_height()
        rw, rh = self.rotated_size()
        pannable = self.tex and (rw * self.zoom > W + 1 or rh * self.zoom > H + 1)
        self.set_cursor(Gdk.Cursor.new_from_name("grab" if pannable else "default", None))

    # --- отрисовка
    def do_size_allocate(self, width, height, baseline):
        if self.fit_mode and self.tex:
            self.zoom = self.fit_zoom()
            self._notify()
        self._clamp()
        self._update_cursor()

    def do_snapshot(self, s):
        if not self.tex:
            return
        W, H = self.get_width(), self.get_height()
        z = self.zoom
        p = Graphene.Point()
        p.x, p.y = W / 2 + self.ox, H / 2 + self.oy
        s.save()
        s.translate(p)
        if self.angle:
            s.rotate(self.angle)
        s.scale(z, z)
        # плотность: сколько экранных пикселей на пиксель текстуры
        density = z * self.scale_factor() * self.iw / max(1, self.tex.get_width())
        if density < 1:
            filt = Gsk.ScalingFilter.TRILINEAR
        elif density > 3:
            filt = Gsk.ScalingFilter.NEAREST
        else:
            filt = Gsk.ScalingFilter.LINEAR
        r = Graphene.Rect().init(-self.iw / 2, -self.ih / 2, self.iw, self.ih)
        s.append_scaled_texture(self.tex, filt, r)
        s.restore()

    # --- ввод
    def _motion(self, ctl, x, y):
        self.pointer = (x, y)
        if self.on_motion:
            self.on_motion()

    def _scroll(self, ctl, dx, dy):
        if not self.tex or dy == 0:
            return False
        self._stop_anim()
        self.zoom_step(1.15 ** (-dy), self.pointer, animate=False)
        return True

    def _drag_begin(self, g, x, y):
        self._stop_anim()
        self._drag0 = (self.ox, self.oy)
        self._dragged = False

    def _drag_update(self, g, dx, dy):
        if self._drag0 is None:
            return
        if abs(dx) + abs(dy) > 4:
            self._dragged = True
            self.set_cursor(Gdk.Cursor.new_from_name("grabbing", None))
        self.ox, self.oy = self._drag0[0] + dx, self._drag0[1] + dy
        self._clamp()
        self.queue_draw()

    def _drag_end(self, g, dx, dy):
        self._drag0 = None
        self._update_cursor()

    def _clicked(self, g, n, x, y):
        if self._dragged:
            self._dragged = False
            return
        self.grab_focus()
        W = self.get_width()
        edge = EDGE_CLICK if W > 4 * EDGE_CLICK else W // 5
        if x <= edge or x >= W - edge:
            if n == 1 and self.on_edge_click:
                self.on_edge_click(-1 if x <= edge else 1)
            return
        if n == 2 and self.tex:
            if self.fit_mode:
                self.animate_zoom(max(1.0, self.fit_zoom() * 2) if self.fit_zoom() >= 1 else 1.0, (x, y))
            else:
                self.zoom_fit()

    def _pinch_begin(self, g, seq):
        self._stop_anim()
        self._pinch0 = self.zoom

    def _pinch(self, g, scale):
        if self._pinch0 is None:
            return
        ok, cx, cy = g.get_bounding_box_center()
        self.zoom_to(self._pinch0 * scale, (cx, cy) if ok else None)


# ---------------------------------------------------------------------------
# Элемент ленты миниатюр
# ---------------------------------------------------------------------------

class FileItem(GObject.Object):
    __gtype_name__ = "JpgsFileItem"
    thumb = GObject.Property(type=Gdk.Paintable)
    count = GObject.Property(type=int, default=0)
    badge = GObject.Property(type=str, default="")

    def __init__(self, index: int, jf: C.JpgsFile):
        super().__init__()
        self.index = index
        self.jf = jf


# ---------------------------------------------------------------------------
# Окно
# ---------------------------------------------------------------------------

class JpgsWindow(Adw.ApplicationWindow):
    @property
    def cipher(self):
        return self.app.cipher

    def __init__(self, app: "JpgsApp"):
        super().__init__(application=app, default_width=1200, default_height=800)
        self.app = app
        self.files: list[C.JpgsFile] = []
        self.folder: Optional[str] = None
        self.fi = 0
        self.ii = 0
        self.counts: dict[int, int] = {}
        self.tex_cache: dict[tuple, tuple] = {}     # (fi, ii) -> (texture, orig_w, orig_h)
        self.full_key: Optional[tuple] = None
        self.relevant: set[int] = set()
        self.inflight: set[tuple] = set()
        self.bytes_cache: OrderedDict[tuple, bytes] = OrderedDict()
        self.bytes_total = 0
        self.bytes_lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="jpgs-load")
        self.thumb_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="jpgs-thumb")
        self.thumb_lru: OrderedDict[int, FileItem] = OrderedDict()
        self.thumb_queue: list[FileItem] = []
        self.thumb_pending: set[int] = set()
        self.thumb_lock = threading.Lock()
        self._spinner_src = 0
        self._hide_nav_src = 0
        self._slideshow_src = 0
        self._syncing = False
        self._nav_hover = False
        self._trim_src = 0
        self._current_error = None

        self.set_title("JPGS")
        self._build_ui()
        self._build_actions()
        self._update_title()
        self._update_actions()
        self.connect("close-request", self._on_close)
        self.connect("notify::fullscreened", self._on_fullscreen)

    # ------------------------------------------------------------------ UI

    def _build_ui(self):
        self.toasts = Adw.ToastOverlay()
        self.set_content(self.toasts)
        self.tv = Adw.ToolbarView(top_bar_style=Adw.ToolbarStyle.FLAT,
                                  bottom_bar_style=Adw.ToolbarStyle.FLAT)
        self.toasts.set_child(self.tv)

        # --- заголовок
        hb = Adw.HeaderBar()
        self.title_w = Adw.WindowTitle(title="JPGS", subtitle="")
        hb.set_title_widget(self.title_w)
        b_open = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Открыть (Ctrl+O)",
                            action_name="win.open", focus_on_click=False)
        hb.pack_start(b_open)
        nav = Gtk.Box(css_classes=["linked"])
        for icon, act, tip in (("go-previous-symbolic", "win.prev", "Предыдущее (←)"),
                               ("go-next-symbolic", "win.next", "Следующее (→)")):
            nav.append(Gtk.Button(icon_name=icon, action_name=act, tooltip_text=tip,
                                  focus_on_click=False))
        hb.pack_start(nav)

        menu = Gio.Menu()
        s1 = Gio.Menu()
        s1.append("Открыть…", "win.open")
        s1.append("Сохранить расшифрованную копию как…", "win.save-as")
        s1.append("Копировать изображение", "win.copy")
        s1.append("Переместить файл в корзину", "win.trash")
        menu.append_section(None, s1)
        s2 = Gio.Menu()
        s2.append("Слайд-шоу", "win.slideshow")
        s2.append("Лента миниатюр", "win.filmstrip")
        s2.append("Растягивать маленькие изображения", "win.upscale")
        s2.append("Повторять видео", "win.loop")
        s2.append("Упрощённый вывод видео (если чёрный экран)", "win.video-simple")
        menu.append_section(None, s2)
        s3 = Gio.Menu()
        s3.append("Зашифровать изображения и видео…", "win.encrypt")
        s3.append("Объединить .jpgs в один файл…", "win.merge")
        s3.append("Расшифровать все файлы папки…", "win.decrypt-folder")
        s3.append("Сменить ключ у всех файлов папки…", "win.rekey-folder")
        menu.append_section(None, s3)
        s4 = Gio.Menu()
        s4.append("Ключи шифрования…", "app.key")
        s4.append("Горячие клавиши", "win.shortcuts")
        s4.append("О программе", "app.about")
        menu.append_section(None, s4)
        hb.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu,
                                   primary=True, tooltip_text="Меню", focus_on_click=False))
        hb.pack_end(Gtk.Button(icon_name="jpgs-fullscreen-symbolic", action_name="win.fullscreen",
                               tooltip_text="Во весь экран (F11)", focus_on_click=False))
        hb.pack_end(Gtk.Button(icon_name="jpgs-rotate-right-symbolic", action_name="win.rotate-cw",
                               tooltip_text="Повернуть (R)", focus_on_click=False))

        zmenu = Gio.Menu()
        zmenu.append("Увеличить", "win.zoom-in")
        zmenu.append("Уменьшить", "win.zoom-out")
        zmenu.append("Вписать в окно", "win.zoom-fit")
        zmenu.append("Исходный размер (100%)", "win.zoom-100")
        self.zoom_btn = Gtk.MenuButton(label="100%", menu_model=zmenu, tooltip_text="Масштаб",
                                       focus_on_click=False, css_classes=["numeric"])
        hb.pack_end(self.zoom_btn)
        self.tv.add_top_bar(hb)

        # --- область изображения
        self.overlay = Gtk.Overlay()
        self.view = ImageView()
        self.view.upscale = self.app.settings.get("upscale_small")
        self.view.on_zoom = self._on_zoom_changed
        self.view.on_edge_click = lambda d: self.step(d)
        self.view.on_motion = self._show_nav
        self.stack = Gtk.Stack()
        self.stack.add_named(self.view, "image")
        self.video = VideoPane(self)
        self.stack.add_named(self.video, "video")
        self.overlay.set_child(self.stack)
        rclick = Gtk.GestureClick(button=Gdk.BUTTON_SECONDARY)
        rclick.connect("pressed", self._on_secondary_click)
        self.stack.add_controller(rclick)
        self.ctx_popover = Gtk.PopoverMenu(has_arrow=False, halign=Gtk.Align.START)
        self.ctx_popover.set_parent(self.overlay)

        self.nav_revealers = []
        for d, icon, halign, tip in ((-1, "go-previous-symbolic", Gtk.Align.START, "Предыдущее"),
                                     (1, "go-next-symbolic", Gtk.Align.END, "Следующее")):
            b = Gtk.Button(icon_name=icon, tooltip_text=tip, focus_on_click=False,
                           css_classes=["circular", "osd", "nav-button"])
            b.connect("clicked", lambda _b, d=d: self.step(d))
            rv = Gtk.Revealer(child=b, transition_type=Gtk.RevealerTransitionType.CROSSFADE,
                              halign=halign, valign=Gtk.Align.CENTER, margin_start=18,
                              margin_end=18, reveal_child=False)
            hover = Gtk.EventControllerMotion()
            hover.connect("enter", lambda *_: setattr(self, "_nav_hover", True))
            hover.connect("leave", lambda *_: (setattr(self, "_nav_hover", False), self._show_nav()))
            b.add_controller(hover)
            self.overlay.add_overlay(rv)
            self.nav_revealers.append(rv)

        self.spinner = Adw.Spinner() if hasattr(Adw, "Spinner") else Gtk.Spinner(spinning=True)
        self.spinner.set_size_request(48, 48)
        self.spinner_box = Gtk.Revealer(child=self.spinner, halign=Gtk.Align.CENTER,
                                        valign=Gtk.Align.CENTER, can_target=False,
                                        transition_type=Gtk.RevealerTransitionType.CROSSFADE)
        self.overlay.add_overlay(self.spinner_box)

        self.status = Adw.StatusPage(icon_name=APP_ID, title="Откройте файл .jpgs или .vids",
                                     description="Перетащите файл в окно или нажмите «Открыть». "
                                                 "Обычные изображения и видео можно здесь же зашифровать.")
        sbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, halign=Gtk.Align.CENTER)
        sbox.append(Gtk.Button(label="Открыть…", action_name="win.open",
                               css_classes=["pill", "suggested-action"]))
        sbox.append(Gtk.Button(label="Зашифровать изображения и видео…", action_name="win.encrypt",
                               css_classes=["pill"]))
        self.status_buttons = sbox
        self.status.set_child(sbox)
        self.overlay.add_overlay(self.status)

        self.error_page = Adw.StatusPage(icon_name="dialog-warning-symbolic", visible=False,
                                         title="Не удалось показать изображение", can_target=False)
        self.overlay.add_overlay(self.error_page)
        self.tv.set_content(self.overlay)

        # --- лента миниатюр
        self.store = Gio.ListStore(item_type=FileItem)
        self.sel = Gtk.SingleSelection(model=self.store, autoselect=False, can_unselect=True)
        self.sel.connect("notify::selected", self._on_strip_selected)
        fac = Gtk.SignalListItemFactory()
        fac.connect("setup", self._thumb_setup)
        fac.connect("bind", self._thumb_bind)
        fac.connect("unbind", self._thumb_unbind)
        self.strip = Gtk.ListView(model=self.sel, factory=fac, orientation=Gtk.Orientation.HORIZONTAL,
                                  css_classes=["filmstrip"], single_click_activate=False)
        sc = Gtk.ScrolledWindow(child=self.strip, vscrollbar_policy=Gtk.PolicyType.NEVER,
                                hscrollbar_policy=Gtk.PolicyType.AUTOMATIC, min_content_height=96)
        self.strip_sw = sc
        # колёсико мыши (вертикальное) прокручивает горизонтальную ленту
        strip_scroll = Gtk.EventControllerScroll(
            flags=Gtk.EventControllerScrollFlags.BOTH_AXES)
        strip_scroll.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        strip_scroll.connect("scroll", self._strip_scroll)
        sc.add_controller(strip_scroll)
        self.strip_revealer = Gtk.Revealer(child=sc, reveal_child=False,
                                           transition_type=Gtk.RevealerTransitionType.SLIDE_UP)
        self.tv.add_bottom_bar(self.strip_revealer)

        drop = Gtk.DropTarget.new(Gdk.FileList.__gtype__, Gdk.DragAction.COPY)
        drop.connect("drop", self._on_drop)
        self.add_controller(drop)

    # ---------------------------------------------------------------- actions

    def _build_actions(self):
        def add(name, cb):
            a = Gio.SimpleAction.new(name, None)
            a.connect("activate", lambda *_: cb())
            self.add_action(a)

        add("open", self.choose_open)
        add("prev", lambda: self.step(-1))
        add("next", lambda: self.step(1))
        add("prev-file", lambda: self.step_file(-1))
        add("next-file", lambda: self.step_file(1))
        add("first", lambda: self.show(0, 0) if self.files else None)
        add("last", lambda: self.show(len(self.files) - 1, -1) if self.files else None)
        add("zoom-in", lambda: self.view.zoom_step(1.25))
        add("zoom-out", lambda: self.view.zoom_step(0.8))
        add("zoom-fit", lambda: self.view.zoom_fit())
        add("zoom-100", lambda: self.view.animate_zoom(1.0))
        add("rotate-cw", lambda: self.view.rotate(90))
        add("rotate-ccw", lambda: self.view.rotate(-90))
        add("fullscreen", lambda: self.unfullscreen() if self.is_fullscreen() else self.fullscreen())
        add("escape", self._escape)
        add("slideshow", self.toggle_slideshow)
        add("save-as", self.save_as)
        add("copy", self.copy_image)
        add("trash", self.trash_current)
        add("encrypt", self.encrypt_dialog)
        add("merge", self.merge_dialog)
        add("decrypt-folder", self.decrypt_folder_dialog)
        add("shortcuts", self.show_shortcuts)
        add("archive-add", self.archive_add_dialog)
        add("frame-left", lambda: self.frame_move(-1))
        add("frame-right", lambda: self.frame_move(1))
        add("frame-goto", self.frame_goto)
        add("frame-delete", self.frame_delete)
        add("frame-extract", self.frame_extract)
        add("archive-split", self.archive_split)
        add("rename", self.rename_current)
        add("show-in-folder", self.show_in_folder)
        add("properties", self.properties_dialog)
        add("video-frame", self.save_video_frame)
        add("rekey-file", self.rekey_current)
        add("rekey-folder", self.rekey_folder)
        sp = Gio.SimpleAction.new_stateful("speed", GLib.VariantType.new("s"), GLib.Variant("s", "1"))

        def set_speed(a, v):
            a.set_state(v)
            self.video._set("speed", v.get_string())
        sp.connect("activate", set_speed)
        self.add_action(sp)
        add("play-pause", lambda: self.video.toggle_pause())
        add("seek-back", lambda: self.video.seek(-10))
        add("seek-fwd", lambda: self.video.seek(10))
        add("vol-up", lambda: self.video.change_volume(5))
        add("vol-down", lambda: self.video.change_volume(-5))
        add("mute", lambda: self.video.toggle_mute())
        lp = Gio.SimpleAction.new_stateful("loop", None,
                                           GLib.Variant("b", self.app.settings.get("loop_video")))

        def toggle_loop(a, _p):
            v = not a.get_state().get_boolean()
            a.set_state(GLib.Variant("b", v))
            self.app.settings.set("loop_video", v)
            self.video.set_loop(v)
        lp.connect("activate", toggle_loop)
        self.add_action(lp)
        vs = Gio.SimpleAction.new_stateful("video-simple", None,
                                           GLib.Variant("b", self.app.settings.get("video_simple")))

        def toggle_simple(a, _p):
            v = not a.get_state().get_boolean()
            a.set_state(GLib.Variant("b", v))
            self.app.settings.set("video_simple", v)
            self.toast("Вступит в силу после перезапуска JPGS")
        vs.connect("activate", toggle_simple)
        self.add_action(vs)

        fs = Gio.SimpleAction.new_stateful("filmstrip", None,
                                           GLib.Variant("b", self.app.settings.get("filmstrip")))
        fs.connect("activate", self._toggle_filmstrip)
        self.add_action(fs)
        up = Gio.SimpleAction.new_stateful("upscale", None,
                                           GLib.Variant("b", self.app.settings.get("upscale_small")))
        up.connect("activate", self._toggle_upscale)
        self.add_action(up)

    def _enable(self, name, on):
        a = self.lookup_action(name)
        if a:
            a.set_enabled(on)

    def _cur_is_video(self) -> bool:
        return bool(self.files) and self.files[self.fi].is_video

    def _update_actions(self):
        has = bool(self.files)
        is_video = self._cur_is_video()
        shown = self.view.tex is not None and not is_video
        for n in ("play-pause", "seek-back", "seek-fwd", "vol-up", "vol-down", "mute"):
            self._enable(n, is_video)
        for n in ("prev", "next", "prev-file", "next-file", "first", "last", "slideshow",
                  "decrypt-folder", "trash"):
            self._enable(n, has)
        for n in ("zoom-in", "zoom-out", "zoom-fit", "zoom-100", "rotate-cw", "rotate-ccw", "copy"):
            self._enable(n, shown)
        self._enable("save-as", shown or is_video)
        arch = has and not is_video
        n = self.counts.get(self.fi, 1) if has else 1
        self._enable("archive-add", arch and self.cipher is not None)
        self._enable("frame-left", arch and n > 1 and self.ii > 0)
        self._enable("frame-right", arch and n > 1 and 0 <= self.ii < n - 1)
        self._enable("frame-goto", arch and n > 1)
        for a in ("frame-delete", "frame-extract", "archive-split"):
            self._enable(a, arch and n > 1)
        for a in ("rename", "show-in-folder", "properties"):
            self._enable(a, has)
        self._enable("rekey-file", has)
        self._enable("rekey-folder", has)
        self._enable("video-frame", is_video)
        self._enable("speed", is_video)
        self.zoom_btn.set_sensitive(shown)
        if not shown:
            self.zoom_btn.set_label("—")
        self.status.set_visible(not has)

    def _toggle_filmstrip(self, a, _p):
        v = not a.get_state().get_boolean()
        a.set_state(GLib.Variant("b", v))
        self.app.settings.set("filmstrip", v)
        self._update_strip_visibility()

    def _toggle_upscale(self, a, _p):
        v = not a.get_state().get_boolean()
        a.set_state(GLib.Variant("b", v))
        self.app.settings.set("upscale_small", v)
        self.view.upscale = v
        self.view.zoom_fit(animate=False)

    def _update_strip_visibility(self):
        on = (self.app.settings.get("filmstrip") and len(self.files) > 1
              and not self.is_fullscreen())
        self.strip_revealer.set_reveal_child(on)

    # ---------------------------------------------------------------- открытие

    def open_path(self, path: str):
        if self.app.cipher is None:
            self.app.require_key(self, lambda: self.open_path(path))
            return
        path = os.path.abspath(path)
        folder = os.path.dirname(path)
        files = C.list_media(folder)
        if path not in files and os.path.isfile(path):
            files.append(path)
        if not files:
            self.toast("В папке нет файлов .jpgs / .vids")
            return
        self._set_files(folder, files, files.index(path) if path in files else 0)

    def _set_files(self, folder, paths, start):
        self._stop_slideshow()
        self.folder = folder
        self.video.stop()
        self.files = [C.open_media(p, self.cipher) for p in paths]
        self.counts.clear()
        for i, f in enumerate(self.files):
            if f.is_video:
                self.counts[i] = 1
        self.tex_cache.clear()
        self.full_key = None
        self.inflight.clear()
        with self.bytes_lock:
            self.bytes_cache.clear()
            self.bytes_total = 0
        with self.thumb_lock:
            self.thumb_queue.clear()
            self.thumb_pending.clear()
            self.thumb_lru.clear()
        self.store.remove_all()
        self.store.splice(0, 0, [FileItem(i, f) for i, f in enumerate(self.files)])
        self._update_strip_visibility()
        self.show(start, 0)

    def choose_open(self):
        dlg = Gtk.FileDialog(title="Открыть зашифрованный файл")
        f = Gtk.FileFilter(name="Зашифрованные изображения и видео (.jpgs, .vids)")
        for pat in ("*.jpgs", "*.JPGS", "*.vids", "*.VIDS"):
            f.add_pattern(pat)
        store = Gio.ListStore(item_type=Gtk.FileFilter)
        store.append(f)
        dlg.set_filters(store)
        dlg.set_default_filter(f)
        if self.folder:
            dlg.set_initial_folder(Gio.File.new_for_path(self.folder))

        def done(d, res):
            try:
                p = d.open_finish(res).get_path()
            except GLib.Error:
                return
            if p:
                self.open_path(p)
        dlg.open(self, None, done)

    def _on_drop(self, target, value, x, y):
        paths = [f.get_path() for f in value.get_files() if f.get_path()]
        GLib.idle_add(lambda: self._handle_drop(paths) and False)
        return bool(paths)

    def _handle_drop(self, paths: list[str]):
        ext = lambda p: p.rsplit(".", 1)[-1].lower()  # noqa: E731
        jpgs = [p for p in paths if ext(p) == "jpgs"]
        vids = [p for p in paths if ext(p) == "vids"]
        videos = [p for p in paths if ext(p) in C.IMAGE_EXTS + C.VIDEO_EXTS and C.is_video_source(p)]
        imgs = [p for p in paths if ext(p) in C.IMAGE_EXTS and p not in videos]
        cur = self.files[self.fi] if self.files else None
        if cur is not None and not cur.is_video and (imgs or jpgs) and self.cipher is not None:
            self._confirm_append(imgs + [p for p in jpgs if p != cur.path], videos)
            return
        if jpgs or vids:
            self.open_path((jpgs + vids)[0])
        elif imgs or videos:
            self._confirm_encrypt(imgs + videos)

    def _confirm_append(self, sources: list[str], videos: list[str]):
        if not sources:
            return
        cur = self.files[self.fi]
        n = len(sources)
        only_jpgs = all(p.lower().endswith(".jpgs") for p in sources)
        what = plural(n, "файл", "файла", "файлов")
        d = Adw.AlertDialog(
            heading=f"Добавить {what} в «{cur.name}»?",
            body="Кадры допишутся в конец этого файла — отдельные копии не создаются."
                 + (f"\nВидео и анимированные GIF ({len(videos)}) в архив картинок не добавить — "
                    "их можно зашифровать отдельно."
                    if videos else ""))
        d.add_response("cancel", "Отмена")
        if only_jpgs:
            d.add_response("open", "Открыть")
        d.add_response("add_trash", "Добавить и удалить оригиналы")
        d.add_response("add", "Добавить")
        d.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)
        d.set_response_appearance("add_trash", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_default_response("add")
        d.set_close_response("cancel")

        def resp(_d, r):
            if r == "open":
                self.open_path(sources[0])
            elif r in ("add", "add_trash"):
                self.append_to_current(sources, trash=(r == "add_trash"))
                if videos:
                    self._confirm_encrypt(videos)
        d.connect("response", resp)
        d.present(self)

    # ---------------------------------------------------------------- архив (.jpgs)

    def _cur_archive(self):
        if not self.files or self._cur_is_video():
            return None
        return self.files[self.fi]

    def _file_changed(self, fi: int, goto_ii: int = 0):
        """Файл на диске изменился: сбросить кэши и показать нужный кадр."""
        jf = self.files[fi]
        jf._ranges = None
        self.counts.pop(fi, None)
        for k in [k for k in self.tex_cache if k[0] == fi]:
            del self.tex_cache[k]
        self.full_key = None
        self.inflight = {t for t in self.inflight if t[0] != fi}
        with self.bytes_lock:
            for k in [k for k in self.bytes_cache if k[0] == jf.path]:
                self.bytes_total -= len(self.bytes_cache.pop(k))
        item = self.store.get_item(fi)
        if item is not None:
            item.thumb = None
            item.badge = ""
            with self.thumb_lock:
                self.thumb_lru.pop(fi, None)
            self._queue_thumb(item)
        self.show(fi, goto_ii)

    def _reload_folder(self, select_path: Optional[str], ii: int = 0):
        paths = C.list_media(self.folder) if self.folder else []
        if not paths:
            self.files = []
            self.store.remove_all()
            self.view.clear()
            self.video.stop()
            self._update_title()
            self._update_actions()
            return
        start = paths.index(select_path) if select_path in paths else min(self.fi, len(paths) - 1)
        self._set_files(self.folder, paths, start)
        if ii:
            self.show(start, ii)

    def append_to_current(self, sources: list[str], trash: bool = False):
        jf = self._cur_archive()
        if jf is None:
            return
        fi = self.fi
        before = self.counts.get(fi) or jf.count()

        def work():
            return C.append_frames(jf.path, sources, self.cipher)

        def done(n):
            if trash:
                for p in sources:
                    try:
                        Gio.File.new_for_path(p).trash(None)
                    except GLib.Error:
                        pass
            self.toast(f"Добавлено кадров: {n}")
            if trash and any(os.path.dirname(p) == self.folder for p in sources):
                self._reload_folder(jf.path, before)
            else:
                self._file_changed(fi, before)
        self.run_bg("Добавление…", work, done)

    def archive_add_dialog(self):
        if self._cur_archive() is None:
            return
        dlg = Gtk.FileDialog(title="Добавить изображения в этот файл")
        f = Gtk.FileFilter(name="Изображения и .jpgs")
        for e in C.IMAGE_EXTS + ("jpgs",):
            f.add_pattern(f"*.{e}")
            f.add_pattern(f"*.{e.upper()}")
        store = Gio.ListStore(item_type=Gtk.FileFilter)
        store.append(f)
        dlg.set_filters(store)

        def done(d, res):
            try:
                files = d.open_multiple_finish(res)
            except GLib.Error:
                return
            paths = [p for p in (files.get_item(i).get_path() for i in range(files.get_n_items())) if p]
            anim = [p for p in paths if C.is_animated_gif(p)]
            self._confirm_append([p for p in paths if p not in anim], anim)
        dlg.open_multiple(self, None, done)

    def _frames_op(self, label, func, goto):
        jf = self._cur_archive()
        if jf is None:
            return
        fi = self.fi

        self.run_bg(label, func, lambda _res: self._file_changed(fi, goto))

    def frame_move(self, d: int):
        jf = self._cur_archive()
        n = self.counts.get(self.fi, 1)
        i, j = self.ii, self.ii + d
        if jf is None or not (0 <= j < n):
            return
        order = list(range(n))
        order[i], order[j] = order[j], order[i]
        self._frames_op("Перемещение кадра…", lambda: C.rewrite_frames(jf.path, order, self.cipher), j)

    def frame_goto(self):
        """Переместить текущий кадр на введённый номер (1..n); остальные сдвигаются."""
        jf = self._cur_archive()
        n = self.counts.get(self.fi, 1)
        if jf is None or n < 2:
            return
        cur = self.ii + 1
        adj = Gtk.Adjustment(value=cur, lower=1, upper=n, step_increment=1, page_increment=1)
        spin = Gtk.SpinButton(adjustment=adj, numeric=True, digits=0)
        spin.set_hexpand(True)
        d = Adw.AlertDialog(heading=f"Переместить кадр {cur} из {n}",
                            body=f"Введите новый номер кадра (1–{n}). Остальные кадры сдвинутся.")
        d.set_extra_child(spin)
        d.add_response("cancel", "Отмена")
        d.add_response("ok", "Переместить")
        d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("ok")
        d.set_close_response("cancel")

        def resp(_d, r):
            if r != "ok":
                return
            spin.update()  # применить набранное вручную значение
            target = int(spin.get_value_as_int()) - 1
            target = max(0, min(n - 1, target))
            i = self.ii
            if target == i:
                return
            order = list(range(n))
            f = order.pop(i)
            order.insert(target, f)
            self._frames_op("Перемещение кадра…",
                            lambda: C.rewrite_frames(jf.path, order, self.cipher), target)
        d.connect("response", resp)
        d.present(self)
        _focus_later(spin, select_all=True)

    def frame_delete(self):
        jf = self._cur_archive()
        n = self.counts.get(self.fi, 1)
        if jf is None or n < 2:
            return
        i = self.ii
        d = Adw.AlertDialog(heading=f"Удалить кадр {i + 1} из {n}?",
                            body=f"Кадр будет удалён из «{jf.name}». Отменить это нельзя.")
        d.add_response("cancel", "Отмена")
        d.add_response("del", "Удалить кадр")
        d.set_response_appearance("del", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_close_response("cancel")
        order = [k for k in range(n) if k != i]
        d.connect("response", lambda _d, r: r == "del" and self._frames_op(
            "Удаление кадра…", lambda: C.rewrite_frames(jf.path, order, self.cipher), min(i, n - 2)))
        d.present(self)

    def frame_extract(self):
        """Вынести текущий кадр в отдельный .jpgs (из архива он удаляется)."""
        jf = self._cur_archive()
        n = self.counts.get(self.fi, 1)
        if jf is None or n < 2:
            return
        i = self.ii

        def work():
            out = C.extract_frames(jf.path, [i], self.cipher)
            C.rewrite_frames(jf.path, [k for k in range(n) if k != i], self.cipher)
            return out

        def done(out):
            self.toast(f"Кадр вынесен в {os.path.basename(out[0])}")
            self._reload_folder(jf.path, min(i, n - 2))
        self.run_bg("Вынос кадра…", work, done)

    def archive_split(self):
        jf = self._cur_archive()
        n = self.counts.get(self.fi, 1)
        if jf is None or n < 2:
            return
        d = Adw.AlertDialog(heading=f"Разделить «{jf.name}» на {n} файлов?",
                            body="Каждый кадр станет отдельным .jpgs, исходный файл уйдёт в корзину.")
        d.add_response("cancel", "Отмена")
        d.add_response("split", "Разделить")
        d.set_response_appearance("split", Adw.ResponseAppearance.SUGGESTED)
        d.set_close_response("cancel")

        def resp(_d, r):
            if r != "split":
                return

            def work():
                out = C.extract_frames(jf.path, list(range(n)), self.cipher)
                Gio.File.new_for_path(jf.path).trash(None)
                return out
            self.run_bg("Разделение…", work,
                        lambda out: (self.toast(f"Создано файлов: {len(out)}"),
                                     self._reload_folder(out[0])))
        d.connect("response", resp)
        d.present(self)

    def rename_current(self):
        if not self.files:
            return
        jf = self.files[self.fi]
        stem, ext = os.path.splitext(jf.name)
        entry = Gtk.Entry(text=stem, activates_default=True)
        d = Adw.AlertDialog(heading="Переименовать", body=jf.name)
        d.set_extra_child(entry)
        d.add_response("cancel", "Отмена")
        d.add_response("ok", "Переименовать")
        d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("ok")
        d.set_close_response("cancel")
        ii = self.ii

        def resp(_d, r):
            new = entry.get_text().strip()
            if r != "ok" or not new or new == stem:
                return
            if "/" in new:
                self.toast("Имя не может содержать «/»")
                return
            dest = os.path.join(os.path.dirname(jf.path), new + ext)
            if os.path.exists(dest):
                self.toast("Файл с таким именем уже есть")
                return
            try:
                os.rename(jf.path, dest)
            except OSError as e:
                self.toast(f"Не удалось: {e}")
                return
            if jf.is_video:
                self.video.stop()
            self._reload_folder(dest, ii)
        d.connect("response", resp)
        d.present(self)
        _focus_later(entry, select_all=True)

    def show_in_folder(self):
        if not self.files:
            return
        launcher = Gtk.FileLauncher.new(Gio.File.new_for_path(self.files[self.fi].path))
        launcher.open_containing_folder(self, None, lambda l, res: self._ignore_launch(l, res))

    @staticmethod
    def _ignore_launch(launcher, res):
        try:
            launcher.open_containing_folder_finish(res)
        except GLib.Error:
            pass

    def properties_dialog(self):
        if not self.files:
            return
        jf = self.files[self.fi]
        try:
            size = os.path.getsize(jf.path)
        except OSError:
            size = 0
        lines = [f"Папка: {os.path.dirname(jf.path)}", f"Размер: {human_size(size)}"]
        if jf.is_video:
            vp = self.video.props
            if vp.get("width"):
                lines.append(f"Видео: {vp.get('width')}×{vp.get('height')}")
            if vp.get("duration"):
                lines.append(f"Длительность: {fmt_time(vp['duration'])}")
        else:
            n = self.counts.get(self.fi)
            if n:
                lines.append(f"Кадров в файле: {n}")
                lines.append(f"Текущий кадр: {self.ii + 1}")
            if self.view.tex is not None:
                lines.append(f"Разрешение кадра: {self.view.iw}×{self.view.ih}")
            b = self.bytes_cache.get((jf.path, self.ii))
            if b:
                lines.append(f"Размер кадра (JPEG): {human_size(len(b))}")
        d = Adw.AlertDialog(heading=jf.name, body="\n".join(lines))
        d.set_body_use_markup(False)
        d.add_response("ok", "Закрыть")
        d.present(self)

    def save_video_frame(self):
        if not self._cur_is_video() or self.video.player is None:
            return
        jf = self.files[self.fi]
        base = os.path.splitext(jf.name)[0]
        t = self.video.props.get("time-pos") or 0
        dlg = Gtk.FileDialog(title="Сохранить кадр", initial_name=f"{base}_{int(t)}s.png")

        def picked(d, res):
            try:
                dest = d.save_finish(res).get_path()
            except GLib.Error:
                return
            if not dest.lower().endswith(".png"):
                dest += ".png"
            self._do_save_video_frame(jf.path, t, dest)
        dlg.save(self, None, picked)

    def _do_save_video_frame(self, path, t, dest):
        """Декодируем кадр через PyAV (надёжно при hwdec); если PyAV нет — screenshot mpv."""
        def work():
            from .video import save_frame_png
            save_frame_png(path, self.cipher, t, dest)
            return dest

        def done(p):
            self.toast(f"Кадр сохранён: {os.path.basename(p)}")

        def fallback():
            player = self.video.player
            r = player.command("screenshot-to-file", dest, "video") if player else -1
            self.toast(f"Кадр сохранён: {os.path.basename(dest)}" if r is not None and r >= 0
                       else "Не удалось сохранить кадр")

        try:
            import av  # noqa: F401
        except ImportError:
            fallback()
            return
        self.run_bg("Сохранение кадра…", work, done)

    # ---------------------------------------------------------------- смена ключа файлов

    def rekey_current(self):
        if not self.files:
            return
        jf = self.files[self.fi]
        fi, ii = self.fi, self.ii

        def choose(kid):
            from .keystore import get_keystore
            try:
                new = Cipher(material=get_keystore().material_by_id(kid))
            except (KeyError, KeyMissing):
                self.toast("Ключ не найден")
                return
            old = self.cipher
            self.run_bg(
                "Смена ключа…",
                lambda: (C.reencrypt_media(jf.path, old, new,
                                           self._progress_toast() if jf.is_video else None), kid)[1],
                lambda k: self._after_rekey(k, jf.path, fi, ii))
        keys_ui.choose_key_dialog(
            self.app, self, "Сменить ключ файла",
            f"Выберите ключ, которым перешифровать «{jf.name}».", choose, exclude_active=True)

    def rekey_folder(self):
        if not self.files or not self.folder:
            return
        keys_ui.choose_key_dialog(
            self.app, self, "Сменить ключ у всех файлов папки",
            f"Файлы в «{os.path.basename(self.folder)}» будут перешифрованы выбранным ключом. "
            "Файлы, зашифрованные другим ключом, пропускаются.",
            self.rekey_folder_to, exclude_active=True)

    def rekey_folder_to(self, kid):
        """Перешифровать все файлы текущей папки ключом kid (без диалога выбора)."""
        if not self.files or not self.folder:
            return
        paths = [f.path for f in self.files]

        def run():
            from .keystore import get_keystore
            try:
                new = Cipher(material=get_keystore().material_by_id(kid))
            except (KeyError, KeyMissing):
                self.toast("Ключ не найден")
                return
            old = self.cipher

            def work():
                ok, skipped = 0, 0
                for p in paths:
                    if not C.verify_media(p, old):
                        skipped += 1
                        continue
                    try:
                        C.reencrypt_media(p, old, new)
                        ok += 1
                    except Exception:  # noqa: BLE001
                        skipped += 1
                return kid, ok, skipped

            def done(res):
                k, ok, skipped = res
                msg = f"Перешифровано файлов: {ok}"
                if skipped:
                    msg += f", пропущено (другой ключ): {skipped}"
                self.toast(msg)
                cur = self.files[self.fi].path if self.files else None
                self._after_rekey(k, cur, self.fi, self.ii, reload_only=(ok == 0))
            self.run_bg("Смена ключа у файлов…", work, done)
        run()

    def _after_rekey(self, kid, reload_path, fi, ii, reload_only=False):
        from .keystore import get_keystore
        ks = get_keystore()
        if reload_only or ks.active_id() == kid:
            self._file_changed(fi, ii)
            return
        name = next((e["name"] for e in ks.entries() if e["id"] == kid), "новым ключом")
        d = Adw.AlertDialog(
            heading="Сделать этот ключ активным?",
            body=f"Файлы перешифрованы ключом «{name}». Чтобы открывать их, сделайте его активным.")
        d.add_response("later", "Позже")
        d.add_response("switch", "Сделать активным")
        d.set_response_appearance("switch", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("switch")
        d.set_close_response("later")

        def resp(_d, r):
            if r != "switch":
                return
            ks.set_active(kid)
            try:
                self.app.cipher = Cipher()
            except Exception:  # noqa: BLE001
                pass
            if reload_path:
                self.open_path(reload_path)
        d.connect("response", resp)
        d.present(self)

    # ---------------------------------------------------------------- контекстное меню

    def _on_secondary_click(self, gesture, n, x, y):
        if not self.files:
            return
        gesture.set_state(Gtk.EventSequenceState.CLAIMED)
        self._show_nav()
        self.ctx_popover.set_menu_model(self._build_context_menu())
        ok, pt = self.stack.compute_point(self.overlay, Graphene.Point().init(x, y))
        rect = Gdk.Rectangle()
        rect.x, rect.y = (int(pt.x), int(pt.y)) if ok else (int(x), int(y))
        rect.width = rect.height = 1
        self.ctx_popover.set_pointing_to(rect)
        self._update_actions()
        self.ctx_popover.popup()

    def _build_context_menu(self) -> Gio.Menu:
        jf = self.files[self.fi]
        menu = Gio.Menu()
        if jf.is_video:
            s = Gio.Menu()
            s.append("Пауза / воспроизведение", "win.play-pause")
            speed = Gio.Menu()
            for v in ("0.5", "0.75", "1", "1.25", "1.5", "2"):
                speed.append(f"{v.replace('.', ',')}×", f"win.speed::{v}")
            s.append_submenu("Скорость", speed)
            s.append("Повторять видео", "win.loop")
            s.append("Звук вкл/выкл", "win.mute")
            menu.append_section("Видео", s)
            s2 = Gio.Menu()
            s2.append("Сохранить текущий кадр как PNG…", "win.video-frame")
            s2.append("Сохранить расшифрованную копию…", "win.save-as")
            menu.append_section(None, s2)
        else:
            s = Gio.Menu()
            s.append("Копировать изображение", "win.copy")
            s.append("Сохранить расшифрованную копию…", "win.save-as")
            s.append("Повернуть по часовой", "win.rotate-cw")
            s.append("Повернуть против часовой", "win.rotate-ccw")
            s.append("Вписать в окно", "win.zoom-fit")
            s.append("Исходный размер (100%)", "win.zoom-100")
            menu.append_section("Изображение", s)
            n = self.counts.get(self.fi, 1)
            a = Gio.Menu()
            a.append("Добавить изображения в этот файл…", "win.archive-add")
            if n > 1:
                a.append("Переместить кадр на номер…", "win.frame-goto")
                a.append("Вынести кадр в отдельный файл", "win.frame-extract")
                a.append("Удалить кадр из файла", "win.frame-delete")
                a.append("Разделить на отдельные файлы", "win.archive-split")
            title = f"Архив · кадр {self.ii + 1} из {n}" if n > 1 else "Архив"
            menu.append_section(title, a)
        f = Gio.Menu()
        f.append("Переименовать…", "win.rename")
        f.append("Сменить ключ файла…", "win.rekey-file")
        f.append("Показать в папке", "win.show-in-folder")
        f.append("Свойства", "win.properties")
        f.append("Переместить в корзину", "win.trash")
        menu.append_section("Файл", f)
        return menu

    # ---------------------------------------------------------------- навигация

    def _norm(self, fi):
        return fi % len(self.files)

    def step(self, d):
        if not self.files:
            return
        n = self.counts.get(self.fi)
        ii = self.ii if self.ii >= 0 else (n - 1 if n else 0)
        if d > 0:
            if n and ii + 1 < n:
                self.show(self.fi, ii + 1)
            else:
                self.show(self._norm(self.fi + 1), 0)
        else:
            if ii > 0:
                self.show(self.fi, ii - 1)
            else:
                self.show(self._norm(self.fi - 1), -1)

    def step_file(self, d):
        if self.files:
            self.show(self._norm(self.fi + d), 0)

    def _resolve(self, fi, ii):
        if ii < 0 and fi in self.counts:
            return self.counts[fi] - 1
        return ii

    def _neighbors(self):
        fi = self.fi
        n = self.counts.get(fi)
        ii = self.ii
        nxt = (fi, ii + 1) if n and 0 <= ii and ii + 1 < n else (self._norm(fi + 1), 0)
        prv = (fi, ii - 1) if ii > 0 else (self._norm(fi - 1), -1)
        prv = (prv[0], self._resolve(*prv))
        return nxt, prv

    def show(self, fi, ii):
        if not self.files:
            return
        self._current_error = None
        if self.files[fi].is_video:
            self._show_video(fi)
            return
        if self.stack.get_visible_child_name() == "video":
            self.video.stop()
            self.stack.set_visible_child_name("image")
        self.fi, self.ii = fi, self._resolve(fi, ii)
        nxt, prv = self._neighbors()
        self.relevant = {fi, nxt[0], prv[0]}
        key = (self.fi, self.ii)
        # чистим кэш текстур: только текущая и соседи
        keep = {key, nxt, prv}
        for k in list(self.tex_cache):
            if k not in keep:
                del self.tex_cache[k]
        if self.full_key and self.full_key != key:
            self.full_key = None
        if key in self.tex_cache:
            self._display(key)
        else:
            self._request(self.fi, self.ii, full=False)
            self._arm_spinner()
        self._sync_strip()
        self._update_title()

    def _show_video(self, fi):
        self.fi, self.ii = fi, 0
        self._stop_spinner()
        self.status.set_visible(False)
        self.error_page.set_visible(False)
        self.view.clear()
        self.stack.set_visible_child_name("video")
        nxt, prv = self._neighbors()
        self.relevant = {fi, nxt[0], prv[0]}
        for k in list(self.tex_cache):
            if k not in (nxt, prv):
                del self.tex_cache[k]
        self.full_key = None
        sp = self.lookup_action("speed")
        if sp is not None:
            sp.set_state(GLib.Variant("s", "1"))
            self.video._set("speed", "1")
        if not self.video.play(self.files[fi].path):
            self._video_error(self.video.error or "Видео недоступно")
        self._sync_strip()
        self._update_title()
        self._update_actions()
        self._prefetch()
        self._show_nav()
        self.video.area.grab_focus()

    def _video_error(self, msg):
        if not self._cur_is_video():
            return
        self._current_error = msg
        self.error_page.set_title("Не удалось воспроизвести видео")
        self.error_page.set_description(GLib.markup_escape_text(msg))
        self.error_page.set_visible(True)
        self._update_title()

    def _video_finished(self):
        if self._slideshow_src and self._cur_is_video():
            self.step(1)

    def _display(self, key):
        tex, ow, oh = self.tex_cache[key]
        self.view.set_image(tex, ow, oh)
        self.error_page.set_title("Не удалось показать изображение")
        self.error_page.set_visible(False)
        self.status.set_visible(False)
        self._stop_spinner()
        self._update_title()
        self._update_actions()
        self._prefetch()

    def _prefetch(self):
        for fi, ii in self._neighbors():
            if (fi, ii) not in self.tex_cache:
                self._request(fi, ii, full=False)
        # после серии перелистываний вернуть освободившуюся память системе
        if self._trim_src:
            GLib.source_remove(self._trim_src)
        self._trim_src = GLib.timeout_add(1500, self._trim)

    def _trim(self):
        self._trim_src = 0
        trim_memory()
        return False

    # ---------------------------------------------------------------- загрузка

    def _max_side(self) -> int:
        try:
            surf = self.get_surface()
            mon = self.get_display().get_monitor_at_surface(surf) if surf else None
            if mon:
                g = mon.get_geometry()
                sc = surf.get_scale() if hasattr(surf, "get_scale") else mon.get_scale_factor()
                return int(max(g.width, g.height) * sc)
        except Exception:  # noqa: BLE001
            pass
        return 2560

    def _get_bytes(self, jf: C.JpgsFile, ii: int) -> bytes:
        key = (jf.path, ii)
        with self.bytes_lock:
            b = self.bytes_cache.get(key)
            if b is not None:
                self.bytes_cache.move_to_end(key)
                return b
        b = jf.read_image(ii)
        with self.bytes_lock:
            if key not in self.bytes_cache:
                self.bytes_cache[key] = b
                self.bytes_total += len(b)
                while self.bytes_total > BYTES_CACHE_LIMIT and len(self.bytes_cache) > 1:
                    _k, old = self.bytes_cache.popitem(last=False)
                    self.bytes_total -= len(old)
        return b

    def _request(self, fi, ii, full):
        tag = (fi, ii, full)
        if tag in self.inflight or self.files[fi].is_video:
            return
        self.inflight.add(tag)
        jf = self.files[fi]
        max_side = None if full else self._max_side()
        files_ref = self.files
        self.pool.submit(self._job, files_ref, jf, fi, ii, max_side, full)

    def _job(self, files_ref, jf, fi, ii, max_side, full):
        """Выполняется в фоновом потоке."""
        try:
            if files_ref is not self.files or fi not in self.relevant:
                GLib.idle_add(self.inflight.discard, (fi, ii, full))
                return
            n = jf.count()
            if n == 0:
                raise DecodeError("В файле нет изображений (неверный ключ или файл повреждён)")
            rii = n - 1 if ii < 0 else min(ii, n - 1)
            data = self._get_bytes(jf, rii)
            dec = decode(data, max_side)
        except Exception as e:  # noqa: BLE001
            if not isinstance(e, DecodeError):
                traceback.print_exc()
            GLib.idle_add(self._job_failed, files_ref, fi, ii, full, e)
            return
        GLib.idle_add(self._job_done, files_ref, fi, ii, rii, n, dec, full)

    def _job_done(self, files_ref, fi, ii_req, ii, n, dec, full):
        self.inflight.discard((fi, ii_req, full))
        if files_ref is not self.files:
            return False
        if self.counts.get(fi) != n:
            self.counts[fi] = n
            item = self.store.get_item(fi)
            if item:
                item.count = n
                item.badge = f"×{n}" if n > 1 else ""
        if fi not in self.relevant:
            return False
        tex = dec.texture()
        key = (fi, ii)
        current = self.fi == fi and (self.ii == ii or (self.ii < 0 and ii == n - 1))
        if full:
            if current and self.view.tex is not None:
                self.full_key = key
                self.view.swap_texture(tex)
            return False
        self.tex_cache[key] = (tex, dec.orig_w, dec.orig_h)
        if current:
            self.ii = ii
            self._display(key)
        return False

    def _job_failed(self, files_ref, fi, ii, full, err):
        self.inflight.discard((fi, ii, full))
        if files_ref is not self.files:
            return False
        current = self.fi == fi and (self.ii == ii or ii < 0 and self.ii < 0)
        if current and not full:
            self._stop_spinner()
            self._current_error = str(err)
            self.view.clear()
            self.error_page.set_description(
                "Неверный ключ или файл повреждён.\nМожно попробовать «jpgs recovery» в папке с файлом."
                f"\n\n<small>{GLib.markup_escape_text(str(err))}</small>")
            self.error_page.set_visible(True)
            self._update_title()
            self._update_actions()
            self._prefetch()
        return False

    def _arm_spinner(self):
        if self._spinner_src:
            GLib.source_remove(self._spinner_src)

        def show():
            self._spinner_src = 0
            self.spinner_box.set_reveal_child(True)
            return False
        self._spinner_src = GLib.timeout_add(150, show)

    def _stop_spinner(self):
        if self._spinner_src:
            GLib.source_remove(self._spinner_src)
            self._spinner_src = 0
        self.spinner_box.set_reveal_child(False)

    def _on_zoom_changed(self):
        z = self.view.zoom
        self.zoom_btn.set_label(f"{round(z * 100)}%")
        if self.view.needs_hires() and self.files:
            key = (self.fi, self.ii)
            if self.full_key != key and key in self.tex_cache:
                self._request(self.fi, self.ii, full=True)

    # ---------------------------------------------------------------- заголовок

    def _update_title(self):
        if not self.files:
            self.title_w.set_title("JPGS")
            self.title_w.set_subtitle("")
            self.set_title("JPGS")
            return
        jf = self.files[self.fi]
        parts = [f"{self.fi + 1} из {len(self.files)}"]
        if jf.is_video:
            vp = self.video.props
            parts.append("видео")
            if vp.get("width") and vp.get("height"):
                w_, h_ = vp["width"], vp["height"]
                if (vp.get("video-params/rotate") or 0) % 180:
                    w_, h_ = h_, w_
                parts.append(f"{w_}×{h_}")
            if vp.get("duration"):
                parts.append(fmt_time(vp["duration"]))
            if self._current_error:
                parts.append("ошибка")
            self.title_w.set_title(jf.name)
            self.title_w.set_subtitle(" · ".join(parts))
            self.set_title(f"{jf.name} — JPGS")
            return
        n = self.counts.get(self.fi)
        if n and n > 1:
            parts.append(f"кадр {self.ii + 1}/{n}" if self.ii >= 0 else f"кадр ?/{n}")
        if self.view.tex is not None and self._current_error is None:
            parts.append(f"{self.view.iw}×{self.view.ih}")
        if self._current_error:
            parts.append("ошибка")
        self.title_w.set_title(jf.name)
        self.title_w.set_subtitle(" · ".join(parts))
        self.set_title(f"{jf.name} — JPGS")

    # ---------------------------------------------------------------- лента

    def _thumb_setup(self, fac, li):
        ov = Gtk.Overlay()
        pic = Gtk.Picture(content_fit=Gtk.ContentFit.COVER, can_shrink=True,
                          width_request=108, height_request=76, css_classes=["thumb"])
        pic.set_overflow(Gtk.Overflow.HIDDEN)
        badge = Gtk.Label(css_classes=["badge", "osd"], halign=Gtk.Align.END,
                          valign=Gtk.Align.END, margin_end=4, margin_bottom=4, visible=False)
        ov.set_child(pic)
        ov.add_overlay(badge)
        ov.pic, ov.badge, ov.handlers = pic, badge, []
        li.set_child(ov)

    def _thumb_bind(self, fac, li):
        ov = li.get_child()
        item: FileItem = li.get_item()
        ov.pic.set_paintable(item.thumb)
        self._set_badge(ov, item.badge)
        ov.handlers = [
            (item, item.connect("notify::thumb", lambda it, _p: ov.pic.set_paintable(it.thumb))),
            (item, item.connect("notify::badge", lambda it, _p: self._set_badge(ov, it.badge))),
        ]
        ov.set_tooltip_text(item.jf.name)
        if item.thumb is None:
            self._queue_thumb(item)
        else:
            with self.thumb_lock:
                if item.index in self.thumb_lru:
                    self.thumb_lru.move_to_end(item.index)

    def _thumb_unbind(self, fac, li):
        ov = li.get_child()
        for obj, h in ov.handlers:
            obj.disconnect(h)
        ov.handlers = []
        item = li.get_item()
        with self.thumb_lock:
            if item in self.thumb_queue:
                self.thumb_queue.remove(item)
                self.thumb_pending.discard(item.index)

    @staticmethod
    def _set_badge(ov, text):
        ov.badge.set_visible(bool(text))
        ov.badge.set_text(text or "")

    def _queue_thumb(self, item: FileItem):
        with self.thumb_lock:
            if item.index in self.thumb_pending:
                return
            self.thumb_pending.add(item.index)
            self.thumb_queue.append(item)
        self.thumb_pool.submit(self._thumb_job, self.files)

    def _thumb_job(self, files_ref):
        with self.thumb_lock:
            if not self.thumb_queue:
                return
            item = self.thumb_queue.pop()  # последним запрошенный = видимый сейчас
        try:
            if files_ref is not self.files:
                return
            if item.jf.is_video:
                from .video import frame_pixbuf
                pb, info = frame_pixbuf(item.jf.path, self.cipher, THUMB_SIDE)
                GLib.idle_add(self._video_thumb_done, files_ref, item, pb, info)
                return
            data = item.jf.read_first()
            if not data:
                raise DecodeError("пусто")
            dec = decode(data, THUMB_SIDE)
        except Exception:  # noqa: BLE001
            GLib.idle_add(self.thumb_pending.discard, item.index)
            if item.jf.is_video:
                GLib.idle_add(lambda: setattr(item, "badge", "▶") or False)
            return
        GLib.idle_add(self._thumb_done, files_ref, item, dec)

    def _video_thumb_done(self, files_ref, item, pb, info):
        self.thumb_pending.discard(item.index)
        if files_ref is not self.files:
            return False
        fmt = Gdk.MemoryFormat.R8G8B8A8 if pb.get_has_alpha() else Gdk.MemoryFormat.R8G8B8
        item.thumb = Gdk.MemoryTexture.new(pb.get_width(), pb.get_height(), fmt,
                                           pb.read_pixel_bytes(), pb.get_rowstride())
        item.badge = "▶ " + fmt_time(info.duration) if info.duration else "▶"
        with self.thumb_lock:
            self.thumb_lru[item.index] = item
            while len(self.thumb_lru) > THUMB_LIMIT:
                _i, old = self.thumb_lru.popitem(last=False)
                old.thumb = None
        return False

    def _thumb_done(self, files_ref, item, dec):
        self.thumb_pending.discard(item.index)
        if files_ref is not self.files:
            return False
        item.thumb = dec.texture()
        with self.thumb_lock:
            self.thumb_lru[item.index] = item
            self.thumb_lru.move_to_end(item.index)
            while len(self.thumb_lru) > THUMB_LIMIT:
                _i, old = self.thumb_lru.popitem(last=False)
                old.thumb = None
        return False

    def _sync_strip(self):
        if not self.files:
            return
        self._syncing = True
        self.sel.set_selected(self.fi)
        self._syncing = False
        if self.strip_revealer.get_reveal_child():
            self.strip.scroll_to(self.fi, Gtk.ListScrollFlags.NONE, None)

    def _strip_scroll(self, ctl, dx, dy):
        adj = self.strip_sw.get_hadjustment()
        delta = dy if abs(dy) >= abs(dx) else dx
        if not delta:
            return False
        step = adj.get_step_increment() or 48
        adj.set_value(adj.get_value() + delta * step * 2)
        return True

    def _on_strip_selected(self, sel, _p):
        if self._syncing:
            return
        pos = sel.get_selected()
        if pos != Gtk.INVALID_LIST_POSITION and pos != self.fi:
            self.show(pos, 0)
            self.view.grab_focus()

    # ---------------------------------------------------------------- кнопки ← →

    def _show_nav(self):
        if not self.files:
            return
        for rv in self.nav_revealers:
            rv.set_reveal_child(True)
        self.video.controls.set_reveal_child(True)
        if self._hide_nav_src:
            GLib.source_remove(self._hide_nav_src)

        def hide():
            self._hide_nav_src = 0
            if self._nav_hover:
                return False
            for rv in self.nav_revealers:
                rv.set_reveal_child(False)
            if not self.video.props.get("pause") and not self.video.props.get("eof-reached"):
                self.video.controls.set_reveal_child(False)
            return False
        self._hide_nav_src = GLib.timeout_add(1800, hide)

    # ---------------------------------------------------------------- полный экран / слайд-шоу

    def _on_fullscreen(self, *_):
        fs = self.is_fullscreen()
        self.tv.set_reveal_top_bars(not fs)
        if fs:
            self.view.add_css_class("fullscreen")
        else:
            self.view.remove_css_class("fullscreen")
            self._stop_slideshow()
        self._update_strip_visibility()

    def _escape(self):
        if self._slideshow_src:
            self._stop_slideshow()
        if self.is_fullscreen():
            self.unfullscreen()

    def toggle_slideshow(self):
        if self._slideshow_src:
            self._stop_slideshow()
            self.toast("Слайд-шоу остановлено")
            return
        if not self.files:
            return
        secs = int(self.app.settings.get("slideshow_seconds") or 4)
        self._slideshow_src = GLib.timeout_add_seconds(secs, self._slideshow_tick)
        self.fullscreen()
        self.toast(f"Слайд-шоу: каждые {secs} с · Esc — выход")

    def _slideshow_tick(self):
        # видео досматривается до конца, дальше перелистнёт _video_finished
        if self._cur_is_video() and not self.video.error and not self.video.props.get("eof-reached"):
            return True
        self.step(1)
        return True

    def _stop_slideshow(self):
        if self._slideshow_src:
            GLib.source_remove(self._slideshow_src)
            self._slideshow_src = 0

    # ---------------------------------------------------------------- действия с изображением

    def _current_bytes_async(self, cb):
        jf, ii = self.files[self.fi], self.ii

        def job():
            try:
                data = self._get_bytes(jf, ii)
                GLib.idle_add(cb, data, None)
            except Exception as e:  # noqa: BLE001
                GLib.idle_add(cb, None, e)
        self.pool.submit(job)

    def save_as(self):
        if not self.files:
            return
        jf = self.files[self.fi]
        if jf.is_video:
            self._save_video_as(jf)
            return
        if self.view.tex is None:
            return
        base = jf.name[:-5] if jf.name.lower().endswith(".jpgs") else jf.name
        dlg = Gtk.FileDialog(title="Сохранить расшифрованное изображение",
                             initial_name=f"{base}_{self.ii + 1}.jpg")

        def picked(d, res):
            try:
                dest = d.save_finish(res).get_path()
            except GLib.Error:
                return

            def write(data, err):
                if err:
                    self.toast(f"Ошибка: {err}")
                    return False
                try:
                    with open(dest, "wb") as f:
                        f.write(data)
                    self.toast(f"Сохранено: {os.path.basename(dest)}")
                except OSError as e:
                    self.toast(f"Ошибка записи: {e}")
                return False
            self._current_bytes_async(write)
        dlg.save(self, None, picked)

    def _save_video_as(self, jf):
        base = jf.name[:-5] if jf.name.lower().endswith(".vids") else jf.name
        try:
            ext = jf.video_ext()
        except OSError:
            ext = "mp4"
        dlg = Gtk.FileDialog(title="Сохранить расшифрованное видео", initial_name=f"{base}.{ext}")

        def picked(d, res):
            try:
                dest = d.save_finish(res).get_path()
            except GLib.Error:
                return
            self.run_bg("Сохранение видео…",
                        lambda: C.decrypt_video_file(jf.path, dest, self.cipher, self._progress_toast()),
                        lambda p: self.toast(f"Сохранено: {os.path.basename(p)}"))
        dlg.save(self, None, picked)

    def _progress_toast(self):
        """Колбэк прогресса для run_bg: обновляет процент в одном уведомлении."""
        toast = Adw.Toast(title="0%", timeout=0)
        self.toasts.add_toast(toast)
        state = {"last": -1}

        def upd(done, total):
            pct = int(done * 100 / max(total, 1))
            if pct != state["last"]:
                state["last"] = pct
                GLib.idle_add(lambda: (toast.set_title(f"{pct}%"),
                                       toast.dismiss() if pct >= 100 else None) and False)
        return upd

    def copy_image(self):
        if not self.files or self.view.tex is None:
            return
        jf, ii = self.files[self.fi], self.ii

        def job():
            try:
                dec = decode(self._get_bytes(jf, ii), None)
                GLib.idle_add(done, dec)
            except Exception as e:  # noqa: BLE001
                GLib.idle_add(self.toast, f"Ошибка: {e}")

        def done(dec):
            self.get_clipboard().set_texture(dec.texture())
            self.toast("Изображение скопировано")
            return False
        self.pool.submit(job)

    def trash_current(self):
        if not self.files:
            return
        jf = self.files[self.fi]
        n = self.counts.get(self.fi, 1)
        body = jf.name + (f"\nВ файле {plural(n, 'изображение', 'изображения', 'изображений')} — удалятся все." if n > 1 else "")
        d = Adw.AlertDialog(heading="Переместить в корзину?", body=body)
        d.add_response("cancel", "Отмена")
        d.add_response("trash", "В корзину")
        d.set_response_appearance("trash", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_default_response("trash")
        d.set_close_response("cancel")

        def resp(_d, r):
            if r != "trash":
                return
            try:
                Gio.File.new_for_path(jf.path).trash(None)
            except GLib.Error as e:
                self.toast(f"Не удалось: {e.message}")
                return
            paths = [f.path for f in self.files if f is not jf]
            if not paths:
                self.files = []
                self.store.remove_all()
                self.view.clear()
                self._update_title()
                self._update_actions()
                return
            self._set_files(self.folder, paths, min(self.fi, len(paths) - 1))
            self.toast("Файл перемещён в корзину")
        d.connect("response", resp)
        d.present(self)

    # ---------------------------------------------------------------- инструменты

    def run_bg(self, label: str, func: Callable, done: Callable):
        self.toast(label, timeout=2)

        def job():
            try:
                res = func()
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                GLib.idle_add(self.toast, f"Ошибка: {e}")
                return
            GLib.idle_add(lambda: done(res) and False)
        threading.Thread(target=job, daemon=True).start()

    def encrypt_dialog(self):
        dlg = Gtk.FileDialog(title="Выберите изображения или видео для шифрования")
        f = Gtk.FileFilter(name="Изображения и видео")
        for e in C.IMAGE_EXTS + C.VIDEO_EXTS:
            f.add_pattern(f"*.{e}")
            f.add_pattern(f"*.{e.upper()}")
        store = Gio.ListStore(item_type=Gtk.FileFilter)
        store.append(f)
        dlg.set_filters(store)
        dlg.set_default_filter(f)

        def done(d, res):
            try:
                files = d.open_multiple_finish(res)
            except GLib.Error:
                return
            paths = [files.get_item(i).get_path() for i in range(files.get_n_items())]
            self._confirm_encrypt([p for p in paths if p])
        dlg.open_multiple(self, None, done)

    def _confirm_encrypt(self, paths: list[str]):
        if self.app.cipher is None:
            self.app.require_key(self, lambda: self._confirm_encrypt(paths))
            return
        d = Adw.AlertDialog(heading=f"Зашифровать {plural(len(paths), 'файл', 'файла', 'файлов')}?",
                            body="Файлы .jpgs (изображения) и .vids (видео и анимированные GIF) появятся рядом с оригиналами "
                                 "со случайными именами. Оригиналы можно сразу убрать в корзину.")
        d.add_response("cancel", "Отмена")
        d.add_response("keep", "Зашифровать")
        d.add_response("trash", "Зашифровать и удалить оригиналы")
        d.set_response_appearance("trash", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_response_appearance("keep", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("keep")
        d.set_close_response("cancel")

        def resp(_d, r):
            if r == "cancel":
                return
            remove = r == "trash"
            total = sum(os.path.getsize(p) for p in paths if os.path.exists(p)) or 1
            prog = self._progress_toast() if total > 32 * 1024 * 1024 else None
            done_bytes = [0]

            def work():
                out, failed = [], []
                for p in paths:
                    try:
                        size = os.path.getsize(p)
                        if C.is_video_source(p):
                            base = done_bytes[0]
                            res = C.encrypt_stream(p, os.path.dirname(p), self.cipher,
                                                   (lambda d, t, base=base: prog(base + d, total))
                                                   if prog else None)
                        else:
                            res = C.encrypt_file(p, os.path.dirname(p), self.cipher)
                        done_bytes[0] += size
                        if prog:
                            prog(done_bytes[0], total)
                    except Exception:  # noqa: BLE001
                        res = None
                    if res:
                        out.append(res)
                        if remove:
                            try:
                                Gio.File.new_for_path(p).trash(None)
                            except GLib.Error:
                                pass
                    else:
                        failed.append(os.path.basename(p))
                return out, failed

            def done(res):
                out, failed = res
                msg = f"Зашифровано: {len(out)}"
                if failed:
                    msg += f", не удалось: {len(failed)}"
                self.toast(msg)
                if out:
                    folder = os.path.dirname(out[0])
                    if not self.files or folder == self.folder:
                        cur = self.files[self.fi].path if self.files else out[0]
                        self.open_path(cur)
            self.run_bg("Шифрование…", work, done)
        d.connect("response", resp)
        d.present(self)

    def merge_dialog(self):
        dlg = Gtk.FileDialog(title="Выберите .jpgs для объединения (в порядке имён)")
        f = Gtk.FileFilter(name=".jpgs")
        f.add_pattern("*.jpgs")
        store = Gio.ListStore(item_type=Gtk.FileFilter)
        store.append(f)
        dlg.set_filters(store)
        if self.folder:
            dlg.set_initial_folder(Gio.File.new_for_path(self.folder))

        def picked(d, res):
            try:
                files = d.open_multiple_finish(res)
            except GLib.Error:
                return
            paths = sorted((files.get_item(i).get_path() for i in range(files.get_n_items())),
                           key=lambda p: C.natural_key(os.path.basename(p)))
            if len(paths) < 2:
                self.toast("Выберите хотя бы два файла")
                return
            sd = Gtk.FileDialog(title="Сохранить объединённый файл", initial_name="merged.jpgs")
            sd.set_initial_folder(Gio.File.new_for_path(os.path.dirname(paths[0])))

            def saved(d2, res2):
                try:
                    dest = d2.save_finish(res2).get_path()
                except GLib.Error:
                    return
                self.run_bg("Объединение…", lambda: C.merge_files(paths, dest),
                            lambda p: (self.toast(f"Готово: {os.path.basename(p)}"), self.open_path(p)))
            sd.save(self, None, saved)
        dlg.open_multiple(self, None, picked)

    def decrypt_folder_dialog(self):
        if not self.files:
            return
        dlg = Gtk.FileDialog(title="Куда сохранить расшифрованные изображения")
        paths = [f.path for f in self.files]

        def picked(d, res):
            try:
                out = d.select_folder_finish(res).get_path()
            except GLib.Error:
                return

            def work():
                n = 0
                for p in paths:
                    if C.is_video_path(p):
                        C.decrypt_video_to(p, out, self.cipher)
                        n += 1
                    else:
                        n += len(C.decrypt_to_dir(p, out, self.cipher))
                return n
            self.run_bg("Расшифровка…", work,
                        lambda n: self.toast(f"Расшифровано файлов: {n} → {out}"))
        dlg.select_folder(self, None, picked)

    def show_shortcuts(self):
        text = ("← → , PgUp PgDn, клик у края — предыдущее / следующее\n"
                "Shift+← → — предыдущий / следующий файл (минуя кадры)\n"
                "Home / End — первый / последний\n"
                "Колёсико, + / −, щипок — масштаб; 0 — вписать; 1 — 100%\n"
                "Двойной клик — вписать ↔ увеличить; перетаскивание — сдвиг\n"
                "R / Shift+R — поворот\nF, F11 — полный экран; Esc — выход\n"
                "F5 — слайд-шоу; T — лента миниатюр\n"
                "Ctrl+S — сохранить; Ctrl+C — копировать; Delete — в корзину\n"
                "Ctrl+O — открыть; Ctrl+W — закрыть\n\n"
                "Видео: Пробел или клик — пауза; двойной клик — полный экран;\n"
                "Ctrl+← → — перемотка ±10 с; ↑ ↓ или колёсико — громкость; M — звук")
        d = Adw.AlertDialog(heading="Горячие клавиши", body=text)
        d.add_response("ok", "Закрыть")
        d.present(self)

    # ---------------------------------------------------------------- прочее

    def toast(self, text, timeout=3):
        t = Adw.Toast(title=GLib.markup_escape_text(str(text)), timeout=timeout)
        self.toasts.add_toast(t)
        return False

    def _on_close(self, *_):
        self._stop_slideshow()
        self.ctx_popover.unparent()
        self.video.destroy()
        self.app.settings.set("volume", self.app.settings.get("volume"))
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.thumb_pool.shutdown(wait=False, cancel_futures=True)
        return False


# ---------------------------------------------------------------------------
# Приложение
# ---------------------------------------------------------------------------

class JpgsApp(Adw.Application):
    def __init__(self, encrypt: Optional[list[str]] = None):
        flags = Gio.ApplicationFlags.HANDLES_OPEN
        if encrypt:
            flags |= Gio.ApplicationFlags.NON_UNIQUE
        super().__init__(application_id=APP_ID, flags=flags)
        self.settings = Settings()
        try:
            self.cipher: Optional[Cipher] = Cipher()
        except KeyMissing:
            self.cipher = None
        self.encrypt = [os.path.abspath(p) for p in encrypt or []]

    def do_startup(self):
        Adw.Application.do_startup(self)
        GLib.set_application_name("JPGS")
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.PREFER_DARK)
        icons = os.path.join(DATA_DIR, "icons")
        display = Gdk.Display.get_default()
        if os.path.isdir(icons):
            Gtk.IconTheme.get_for_display(display).add_search_path(icons)
        prov = Gtk.CssProvider()
        if hasattr(prov, "load_from_string"):
            prov.load_from_string(CSS.decode())
        else:
            prov.load_from_data(CSS, -1)
        Gtk.StyleContext.add_provider_for_display(display, prov,
                                                  Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        Gtk.Window.set_default_icon_name(APP_ID)

        keyact = Gio.SimpleAction.new("key", None)
        keyact.connect("activate", lambda *_: self.key_manager(self.get_active_window()))
        self.add_action(keyact)
        about = Gio.SimpleAction.new("about", None)
        about.connect("activate", self._about)
        self.add_action(about)
        q = Gio.SimpleAction.new("quit", None)
        q.connect("activate", lambda *_: [w.close() for w in self.get_windows()])
        self.add_action(q)

        accels = {
            "win.next": ["Right", "Page_Down", "KP_Right"],
            "win.prev": ["Left", "Page_Up", "KP_Left", "BackSpace"],
            "win.next-file": ["<Shift>Right", "<Shift>Page_Down"],
            "win.prev-file": ["<Shift>Left", "<Shift>Page_Up"],
            "win.first": ["Home"],
            "win.last": ["End"],
            "win.zoom-in": ["plus", "equal", "KP_Add", "<Control>plus", "<Control>equal"],
            "win.zoom-out": ["minus", "KP_Subtract", "<Control>minus"],
            "win.zoom-fit": ["0", "KP_0", "<Control>0"],
            "win.zoom-100": ["1", "KP_1", "<Control>1"],
            "win.rotate-cw": ["r"],
            "win.rotate-ccw": ["<Shift>r"],
            "win.fullscreen": ["F11", "f"],
            "win.escape": ["Escape"],
            "win.slideshow": ["F5"],
            "win.filmstrip": ["t"],
            "win.open": ["<Control>o"],
            "win.save-as": ["<Control>s"],
            "win.copy": ["<Control>c"],
            "win.trash": ["Delete"],
            "win.rename": ["F2"],
            "win.properties": ["<Alt>Return"],
            "win.play-pause": ["space", "k"],
            "win.seek-back": ["<Control>Left", "j"],
            "win.seek-fwd": ["<Control>Right", "l"],
            "win.vol-up": ["Up"],
            "win.vol-down": ["Down"],
            "win.mute": ["m"],
            "window.close": ["<Control>w"],
            "app.quit": ["<Control>q"],
        }
        for a, keys in accels.items():
            self.set_accels_for_action(a, keys)

    def do_activate(self):
        win = self.get_active_window() or JpgsWindow(self)
        win.present()
        from .keystore import get_keystore
        if get_keystore().is_locked():
            GLib.idle_add(lambda: keys_ui.unlock_dialog(self, win, None) and False)
            return
        if self.encrypt:
            paths, self.encrypt = self.encrypt, []
            GLib.idle_add(lambda: win._confirm_encrypt(paths) and False)
        elif self.cipher is None:
            GLib.idle_add(lambda: self.require_key(win, lambda: None) and False)

    # ------------------------------------------------------------------ ключ

    def require_key(self, win, then: Callable[[], None]):
        """Выполнить then(), когда ключ доступен; иначе спросить пароль либо добавить ключ."""
        if self.cipher is not None:
            then()
            return
        from .keystore import get_keystore
        ks = get_keystore()
        if ks.is_locked():
            keys_ui.unlock_dialog(self, win, then)
        else:
            keys_ui.add_key_dialog(self, win, then)

    def key_manager(self, win):
        """Меню → Ключи шифрования…"""
        from .keystore import get_keystore
        if get_keystore().is_locked():
            keys_ui.unlock_dialog(self, win, lambda: keys_ui.KeyManager(self, win).present())
        else:
            keys_ui.KeyManager(self, win).present()

    def do_open(self, files, n, hint):
        for f in files:
            p = f.get_path()
            if not p:
                continue
            win = next((w for w in self.get_windows()
                        if isinstance(w, JpgsWindow) and not w.files), None) or JpgsWindow(self)
            win.present()
            win.maximize()
            win.open_path(p)  # без ключа сначала спросит его

    def _about(self, *_):
        d = Adw.AboutDialog(application_name="JPGS", application_icon=APP_ID, version=__version__,
                            developer_name="DiabloZet",
                            comments="Просмотр зашифрованных изображений .jpgs и видео .vids (libmpv / FFmpeg). "
                                     "Расшифровка только в памяти — на диск ничего не пишется.")
        d.present(self.get_active_window())


def _focus_later(widget, select_all: bool = False):
    """Один раз перевести фокус после показа диалога.

    Колбэк обязан вернуть False: grab_focus() возвращает True, и если вернуть его из idle,
    источник не снимется — фокус будет отбираться обратно при каждом простое, а повторное
    выделение текста не даст набрать больше одного символа.
    """
    def once():
        widget.grab_focus()
        if select_all:
            widget.select_region(0, -1)
        return False
    GLib.idle_add(once)


def human_size(n: int) -> str:
    f = float(n)
    for u in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if f < 1024 or u == "ТБ":
            return f"{int(f)} {u}" if u == "Б" else f"{f:.1f} {u}".replace(".", ",")
        f /= 1024
    return str(n)


def plural(n: int, one: str, few: str, many: str) -> str:
    n10, n100 = n % 10, n % 100
    w = one if n10 == 1 and n100 != 11 else few if 2 <= n10 <= 4 and not 12 <= n100 <= 14 else many
    return f"{n} {w}"


def run_gui(argv: list[str], encrypt: Optional[list[str]] = None) -> int:
    return JpgsApp(encrypt).run(argv)
