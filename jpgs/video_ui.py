"""Панель видео: Gtk.GLArea + libmpv, поверх — панель управления (как у изображений)."""

from __future__ import annotations

from typing import Optional

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, Gtk  # noqa: E402

from .video import MpvPlayer, libmpv  # noqa: E402

EDGE_CLICK = 100


def fmt_time(t: Optional[float]) -> str:
    if t is None or t != t or t < 0:
        return "0:00"
    t = int(t)
    h, m, s = t // 3600, t % 3600 // 60, t % 60
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


class VideoPane(Gtk.Overlay):
    __gtype_name__ = "JpgsVideoPane"

    def __init__(self, win):
        super().__init__(hexpand=True, vexpand=True)
        self.win = win
        self.player: Optional[MpvPlayer] = None
        self.gl_ready = False
        self.props = {}
        self.error: Optional[str] = None
        self._pending: Optional[tuple] = None   # (путь, ключ, запись) до готовности GL
        self._ext = ""                          # формат текущего видео (gif крутится по кругу)

        self.area = Gtk.GLArea(hexpand=True, vexpand=True, auto_render=False,
                               has_depth_buffer=False, has_stencil_buffer=False, focusable=True)
        self.area.add_css_class("jpgs-view")
        self.area.connect("realize", self._realize)
        self.area.connect("unrealize", self._unrealize)
        self.area.connect("render", self._render)
        self.set_child(self.area)

        click = Gtk.GestureClick(button=Gdk.BUTTON_PRIMARY)
        click.connect("released", self._clicked)
        self.area.add_controller(click)
        scroll = Gtk.EventControllerScroll(flags=Gtk.EventControllerScrollFlags.VERTICAL)
        scroll.connect("scroll", self._scroll)
        self.area.add_controller(scroll)
        motion = Gtk.EventControllerMotion()
        motion.connect("motion", lambda *_: self.win._show_nav())
        self.area.add_controller(motion)

        # --- панель управления
        bar = Gtk.Box(spacing=8, css_classes=["toolbar", "osd", "video-controls"],
                      margin_start=72, margin_end=72, margin_bottom=16, valign=Gtk.Align.END)
        self.btn_play = Gtk.Button(icon_name="media-playback-pause-symbolic", focus_on_click=False,
                                   tooltip_text="Пауза / воспроизведение (Пробел)",
                                   css_classes=["flat", "circular"])
        self.btn_play.connect("clicked", lambda *_: self.toggle_pause())
        self.lbl_pos = Gtk.Label(label="0:00", css_classes=["numeric", "caption"], width_chars=7)
        self.scale = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 0, 1, 0.1)
        self.scale.set_hexpand(True)
        self.scale.set_draw_value(False)
        self.scale.set_focus_on_click(False)
        self.scale.connect("change-value", self._seek_changed)
        self.lbl_dur = Gtk.Label(label="0:00", css_classes=["numeric", "caption"], width_chars=7)
        self.btn_mute = Gtk.Button(icon_name="audio-volume-high-symbolic", focus_on_click=False,
                                   tooltip_text="Звук (M)", css_classes=["flat", "circular"])
        self.btn_mute.connect("clicked", lambda *_: self.toggle_mute())
        self.vol = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 0, 130, 1)
        self.vol.set_size_request(110, -1)
        self.vol.set_draw_value(False)
        self.vol.set_focus_on_click(False)
        self.vol.add_mark(100, Gtk.PositionType.BOTTOM, None)
        self.vol.connect("change-value", lambda _s, _t, v: self._set("volume", max(0, min(130, v))) or False)
        for w in (self.btn_play, self.lbl_pos, self.scale, self.lbl_dur, self.btn_mute, self.vol):
            bar.append(w)
        self.controls = Gtk.Revealer(child=bar, valign=Gtk.Align.END, reveal_child=True,
                                     transition_type=Gtk.RevealerTransitionType.CROSSFADE)
        hover = Gtk.EventControllerMotion()
        hover.connect("enter", lambda *_: setattr(self.win, "_nav_hover", True))
        hover.connect("leave", lambda *_: (setattr(self.win, "_nav_hover", False), self.win._show_nav()))
        bar.add_controller(hover)
        self.add_overlay(self.controls)

    # ------------------------------------------------------------------ mpv

    def available(self) -> Optional[str]:
        """None — всё в порядке, иначе текст ошибки."""
        if not libmpv():
            return "Для видео нужна библиотека libmpv: sudo pacman -S mpv"
        return None

    def _ensure_player(self) -> bool:
        if self.player is not None:
            return True
        err = self.available()
        if err:
            self.error = err
            return False
        try:
            self.player = MpvPlayer(self.win.cipher, self._on_event)
        except Exception as e:  # noqa: BLE001
            self.error = str(e)
            return False
        self.player.set("volume", self.win.app.settings.get("volume"))
        self.player.set("mute", bool(self.win.app.settings.get("mute")))
        self.player.set("loop-file", "inf" if self.win.app.settings.get("loop_video") else "no")
        if self.area.get_realized():
            self._init_gl()
        return True

    def _display_ptrs(self):
        wl = x11 = None
        disp = self.get_display()
        try:
            gi.require_version("GdkWayland", "4.0")
            from gi.repository import GdkWayland
            if isinstance(disp, GdkWayland.WaylandDisplay):
                wl = disp.get_wl_display()
        except (ValueError, ImportError, AttributeError, TypeError):
            pass
        if not wl:
            try:
                gi.require_version("GdkX11", "4.0")
                from gi.repository import GdkX11
                if isinstance(disp, GdkX11.X11Display):
                    x11 = disp.get_xdisplay()
            except (ValueError, ImportError, AttributeError, TypeError):
                pass
        return (wl if isinstance(wl, int) else None), (x11 if isinstance(x11, int) else None)

    def _init_gl(self):
        self.area.make_current()
        if self.area.get_error() is not None:
            self.error = f"OpenGL недоступен: {self.area.get_error().message}"
            return
        wl, x11 = self._display_ptrs()
        self.gl_ready = self.player.init_gl(self.area.queue_render, wl, x11,
                                            simple=bool(self.win.app.settings.get("video_simple")))
        if not self.gl_ready:
            self.error = "Не удалось подключить вывод видео (mpv render API)"
        elif self._pending:
            p, self._pending = self._pending, None
            self.player.load(*p)

    def _realize(self, area):
        if self.player is not None and not self.gl_ready:
            self._init_gl()

    def _unrealize(self, area):
        if self.player is not None:
            area.make_current()
            self.player.free_gl()
            self.gl_ready = False

    def _render(self, area, ctx):
        if self.player is not None and self.gl_ready:
            sf = area.get_scale_factor()
            self.player.render(area.get_width() * sf, area.get_height() * sf)
        return True

    # ------------------------------------------------------------------ управление

    def play(self, path: str, cipher=None, entry=None, ext: str = "") -> bool:
        """Воспроизвести .vids (entry=None) или запись-видео архива. cipher — ключ файла."""
        self.error = None
        self.props = {}
        self._ext = ext
        self._update_labels()
        if not self._ensure_player():
            return False
        self.player.set("pause", False)
        self.player.set("loop-file", "inf" if self._loops() else "no")
        if self.gl_ready:
            self.player.load(path, cipher, entry)
        else:
            self._pending = (path, cipher, entry)  # загрузим, когда появится GL-контекст
        return True

    def stop(self):
        self._pending = None
        if self.player is not None:
            self.player.stop()

    def destroy(self):
        if self.player is not None:
            if self.area.get_realized():
                self.area.make_current()
            self.player.destroy()
            self.player = None

    def _set(self, name, value):
        if self.player is not None:
            self.player.set(name, value)

    def toggle_pause(self):
        if self.player is not None:
            if self.props.get("eof-reached"):
                self.player.command("seek", "0", "absolute")
                self._set("pause", False)
            else:
                self.player.command("cycle", "pause")

    def seek(self, delta: float):
        if self.player is not None:
            self.player.command("seek", str(delta), "relative", "exact")

    def change_volume(self, delta: float):
        v = max(0.0, min(130.0, (self.props.get("volume") or 100) + delta))
        self._set("volume", round(v))
        if self.props.get("mute"):
            self._set("mute", False)

    def toggle_mute(self):
        if self.player is not None:
            self.player.command("cycle", "mute")

    def _loops(self) -> bool:
        """GIF всегда крутится по кругу, остальное — по настройке «Повторять видео»."""
        return bool(self.win.app.settings.get("loop_video")) or self._ext == "gif"

    def set_loop(self, on: bool):
        self._set("loop-file", "inf" if on or self._ext == "gif" else "no")

    def _seek_changed(self, scale, scroll, value):
        if self.player is not None:
            self.player.command("seek", f"{max(0.0, value):.3f}", "absolute")
        return False

    # ------------------------------------------------------------------ события mpv

    def _on_event(self, name, value):
        if name == "error":
            self.error = f"Не удалось воспроизвести видео: {value}"
            self.win._video_error(self.error)
            return
        if name in ("end-file", "file-loaded"):
            return
        self.props[name] = value
        if name in ("time-pos", "duration"):
            self._update_labels()
        elif name == "pause":
            self.btn_play.set_icon_name("media-playback-start-symbolic" if value
                                        else "media-playback-pause-symbolic")
        elif name == "volume" and value is not None:
            self.vol.set_value(value)
            self.win.app.settings.data["volume"] = round(value)
        elif name == "mute":
            self.btn_mute.set_icon_name("audio-volume-muted-symbolic" if value
                                        else "audio-volume-high-symbolic")
            self.win.app.settings.data["mute"] = bool(value)
        elif name == "eof-reached" and value:
            self.btn_play.set_icon_name("media-playback-start-symbolic")
            self.win._video_finished()
        elif name in ("width", "height", "video-params/rotate"):
            self.win._update_title()

    def _update_labels(self):
        pos, dur = self.props.get("time-pos"), self.props.get("duration")
        self.lbl_pos.set_text(fmt_time(pos))
        self.lbl_dur.set_text(fmt_time(dur))
        if dur:
            adj = self.scale.get_adjustment()
            if abs(adj.get_upper() - dur) > 0.01:
                adj.set_upper(dur)
        self.scale.set_value(pos or 0)

    # ------------------------------------------------------------------ ввод

    def _clicked(self, g, n, x, y):
        self.area.grab_focus()
        W = self.area.get_width()
        edge = EDGE_CLICK if W > 4 * EDGE_CLICK else W // 5
        if x <= edge or x >= W - edge:
            if n == 1:
                self.win.step(-1 if x <= edge else 1)
            return
        if n == 1:
            self.toggle_pause()
        elif n == 2:
            self.toggle_pause()  # второй клик двойного — отменить паузу первого
            self.win.activate_action("win.fullscreen", None)

    def _scroll(self, ctl, dx, dy):
        self.change_volume(-5 * dy)
        return True
