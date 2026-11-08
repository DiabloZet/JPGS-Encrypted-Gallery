"""Окно «Поиск по смыслу (ИИ)»: модели (скачать/удалить), библиотеки, индексация."""

from __future__ import annotations

import os
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from . import ai as A  # noqa: E402

INSTALL_HINT = ("Arch: sudo pacman -S python-onnxruntime python-numpy python-tokenizers\n"
                "Debian/Ubuntu: pip install --user onnxruntime numpy tokenizers")


def _mb(n: int) -> str:
    return f"{n / 1e6:.0f} МБ"


class AISettings:
    def __init__(self, win):
        self.win = win
        self.app = win.app
        self.downloads: dict[str, threading.Event] = win._ai_downloads
        self.dialog = Adw.Dialog(title="Поиск по смыслу (ИИ)", content_width=520,
                                 content_height=640)
        tv = Adw.ToolbarView()
        tv.add_top_bar(Adw.HeaderBar())
        self.page = Adw.PreferencesPage()
        tv.set_content(self.page)
        self.dialog.set_child(tv)
        self.rows: dict[str, Adw.ActionRow] = {}
        self._build()
        self._tick = GLib.timeout_add(500, self._refresh)
        self.dialog.connect("closed", lambda *_: GLib.source_remove(self._tick))

    def present(self):
        self.dialog.present(self.win)

    def _build(self):
        g0 = Adw.PreferencesGroup(
            description="Модели работают на этом компьютере, без интернета: картинки никуда не "
                        "отправляются. Теги и «смысл» каждой картинки сохраняются в самом файле "
                        ".jpgs — в зашифрованном виде. Индексация идёт в фоне, только пока открыта "
                        "программа, и останавливается вместе с ней.")
        self.page.add(g0)
        missing = A.missing_libs(("onnxruntime", "numpy", "tokenizers"))
        if missing:
            row = Adw.ActionRow(title="Не установлены библиотеки: " + ", ".join(missing),
                                subtitle=INSTALL_HINT)
            row.set_subtitle_selectable(True)
            row.add_prefix(Gtk.Image(icon_name="dialog-warning-symbolic"))
            g0.add(row)

        g1 = Adw.PreferencesGroup(title="Модели")
        self.page.add(g1)
        for name, spec in A.MODELS.items():
            row = Adw.ActionRow(title=spec["title"])
            btn = Gtk.Button(valign=Gtk.Align.CENTER)
            btn.connect("clicked", lambda _b, n=name: self._toggle(n))
            row.add_suffix(btn)
            row.btn = btn
            self.rows[name] = row
            g1.add(row)

        g2 = Adw.PreferencesGroup(title="Индексация")
        self.page.add(g2)
        sw = Adw.SwitchRow(title="Индексировать картинки этой папки",
                           subtitle="В фоне, с низким приоритетом",
                           active=bool(self.app.settings.get("ai_enabled")))
        sw.connect("notify::active", self._enable_changed)
        g2.add(sw)
        cpu = os.cpu_count() or 2
        th = Adw.SpinRow.new_with_range(1, max(1, cpu), 1)
        th.set_title("Потоков процессора")
        th.set_subtitle("Больше — быстрее, но сильнее нагружает компьютер")
        th.set_value(int(self.app.settings.get("ai_threads") or 2))
        th.connect("notify::value", self._threads_changed)
        g2.add(th)
        self.status = Adw.ActionRow(title="Эта папка")
        g2.add(self.status)
        self._refresh()

    def _refresh(self):
        for name, row in self.rows.items():
            spec = A.MODELS[name]
            size = _mb(A.model_size(name))
            if name in self.downloads:
                done = self.win._ai_dl_progress.get(name, 0)
                row.set_subtitle(f"Скачивание… {done * 100 // max(1, A.model_size(name))}% из {size}")
                row.btn.set_label("Отмена")
                row.btn.remove_css_class("suggested-action")
            elif A.model_installed(name):
                row.set_subtitle(f"{spec['about']}\nУстановлена · {size}")
                row.btn.set_label("Удалить")
                row.btn.remove_css_class("suggested-action")
            else:
                row.set_subtitle(f"{spec['about']}\nНе скачана · {size}")
                row.btn.set_label("Скачать")
                row.btn.add_css_class("suggested-action")
        d, t, running = self.win._ai_state
        if not A.installed_models():
            self.status.set_subtitle("Скачайте хотя бы одну модель")
        elif t:
            self.status.set_subtitle(f"Проиндексировано {d} из {t}" + (" · идёт индексация" if running else ""))
        else:
            self.status.set_subtitle("Откройте папку с файлами .jpgs / .vids")
        return True

    def _toggle(self, name):
        if name in self.downloads:
            self.downloads[name].set()
            return
        if A.model_installed(name):
            self.win.indexer.stop(wait=5)
            A.remove_model(name)
            self.win._ai_engine_reset()
            self.win.toast("Модель удалена")
            self._refresh()
            return
        cancel = threading.Event()
        self.downloads[name] = cancel
        self.win._ai_dl_progress[name] = 0

        def prog(done, total):
            self.win._ai_dl_progress[name] = done

        def work():
            try:
                A.download_model(name, prog, cancel)
                err = None
            except Exception as e:  # noqa: BLE001
                err = e
            GLib.idle_add(lambda: finished(err) and False)

        def finished(err):
            self.downloads.pop(name, None)
            if err is None:
                self.win.toast(f"Модель «{A.MODELS[name]['title']}» установлена")
                self.win._ai_engine_reset()
                self.win._start_indexer()
            elif not cancel.is_set():
                self.win.toast(f"Не удалось скачать: {err}")
            self._refresh()
        threading.Thread(target=work, daemon=True).start()
        self._refresh()

    def _enable_changed(self, row, _p):
        self.app.settings.set("ai_enabled", row.get_active())
        if row.get_active():
            self.win._start_indexer()
        else:
            self.win.indexer.stop()

    def _threads_changed(self, row, _p):
        self.app.settings.set("ai_threads", int(row.get_value()))
        self.win._ai_engine_reset()
        self.win._start_indexer()
