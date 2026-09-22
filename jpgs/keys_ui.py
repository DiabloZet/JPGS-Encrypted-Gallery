"""Интерфейс управления ключами: список ключей, добавление/удаление/переименование,
выбор активного, необязательный пароль на программу и перешифровка файлов другим ключом.

Отделён от viewer.py по образцу video_ui.py, чтобы не раздувать основной модуль.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .crypto import Cipher, fingerprint_material, generate_key, material_for  # noqa: E402
from .keystore import get_keystore  # noqa: E402


def _focus_later(widget):
    """Один раз перевести фокус после показа диалога.

    Важно вернуть False: grab_focus() возвращает True, и если отдать это значение из
    idle-колбэка, источник не снимется — фокус будет возвращаться назад при каждом
    простое (не дать перейти в соседнее поле, а выделение текста будет затирать ввод).
    """
    def once():
        widget.grab_focus()
        return False
    GLib.idle_add(once)


# --------------------------------------------------------------------------- пароль при запуске

def unlock_dialog(app, win, then: Optional[Callable[[], None]] = None):
    """Спросить пароль и разблокировать хранилище. При успехе пересобрать шифр и вызвать then."""
    ks = get_keystore()
    d = Adw.AlertDialog(heading="Требуется пароль",
                        body="Список ключей защищён паролем. Введите его, чтобы открывать файлы.")
    lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
    entry = Adw.PasswordEntryRow(title="Пароль")
    lst.append(entry)
    d.set_extra_child(lst)
    d.add_response("cancel", "Отмена")
    d.add_response("ok", "Разблокировать")
    d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response("ok")
    d.set_close_response("cancel")

    def resp(_d, r):
        if r != "ok":
            return
        if ks.unlock(entry.get_text()):
            try:
                app.cipher = Cipher()
            except Exception:  # noqa: BLE001
                app.cipher = None
            _reopen(app)
            if then:
                then()
        else:
            err = Adw.AlertDialog(heading="Неверный пароль", body="Попробуйте ещё раз.")
            err.add_response("ok", "ОК")
            err.connect("response", lambda *_: unlock_dialog(app, win, then))
            err.present(win)
    d.connect("response", resp)
    d.present(win)
    _focus_later(entry)


# --------------------------------------------------------------------------- добавление ключа

def add_key_dialog(app, win, on_done: Optional[Callable[[], None]] = None):
    ks = get_keystore()
    d = Adw.AlertDialog(heading="Новый ключ",
                        body="Ключ — это слово или фраза. Файлы, зашифрованные им, "
                             "открываются только этим же ключом.")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
    name = Adw.EntryRow(title="Имя ключа")
    e1 = Adw.PasswordEntryRow(title="Ключ")
    e2 = Adw.PasswordEntryRow(title="Повторите ключ")
    for w in (name, e1, e2):
        lst.append(w)
    box.append(lst)
    gen = Gtk.Button(label="Сгенерировать случайный ключ", css_classes=["pill"],
                     halign=Gtk.Align.CENTER)
    legacy = Gtk.CheckButton(label="Ключ из прежних версий JPGS (без усиления)")
    legacy.set_tooltip_text("Отметьте, если этим словом уже зашифрованы файлы старой версией "
                            "программы — иначе они не откроются")
    info = Gtk.Label(wrap=True, selectable=True, css_classes=["caption"], xalign=0.5)
    box.append(gen)
    box.append(legacy)
    box.append(info)
    d.set_extra_child(box)
    d.add_response("cancel", "Отмена")
    d.add_response("save", "Добавить")
    d.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response("save")
    d.set_close_response("cancel")
    d.set_response_enabled("save", False)

    def changed(*_):
        k1, k2 = e1.get_text(), e2.get_text()
        ok = bool(k1) and k1 == k2
        d.set_response_enabled("save", ok)
        if info.get_text().startswith("Сгенерирован"):
            return
        if ok:
            kind = "raw" if legacy.get_active() else "derived"
            warn = ("  ⚠ короче 16 символов — ненадёжно"
                    if len(k1.encode()) < 16 and kind == "raw" else "")
            info.set_text(f"Отпечаток: {fingerprint_material(material_for(k1, kind))}{warn}")
        elif k1 and k2:
            info.set_text("Ключи не совпадают")
        else:
            info.set_text("")
    e1.connect("changed", changed)
    e2.connect("changed", changed)
    legacy.connect("toggled", changed)

    def do_gen(_b):
        k = generate_key()
        kind = "raw" if legacy.get_active() else "derived"
        info.set_text(f"Сгенерирован ключ (сохраните его, без него файлы не открыть):\n{k}\n"
                      f"Отпечаток: {fingerprint_material(material_for(k, kind))}")
        e1.set_text(k)
        e2.set_text(k)
    gen.connect("clicked", do_gen)

    def resp(_d, r):
        if r != "save":
            return
        key = e1.get_text()
        if not key:
            return
        kind = "raw" if legacy.get_active() else "derived"
        try:
            ks.add(name.get_text().strip() or "Ключ", key, kind=kind)
            app.cipher = Cipher()
        except Exception as ex:  # noqa: BLE001
            _toast(win, f"Не удалось добавить ключ: {ex}")
            return
        _toast(win, f"Ключ добавлен · отпечаток {fingerprint_material(material_for(key, kind))}")
        _reopen(app)
        if on_done:
            on_done()
    d.connect("response", resp)
    d.present(win)
    _focus_later(name)


# --------------------------------------------------------------------------- пароль на программу

def password_dialog(app, win, on_done: Optional[Callable[[], None]] = None):
    ks = get_keystore()
    has = ks.is_encrypted()
    d = Adw.AlertDialog(
        heading="Сменить пароль" if has else "Пароль на программу",
        body=("Пароль защищает список ключей: без него программа не откроет файлы. "
              "Сам пароль на диск не записывается — хранится только проверка. "
              "Если забыть пароль, ключи не восстановить."))
    lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
    e1 = Adw.PasswordEntryRow(title="Новый пароль")
    e2 = Adw.PasswordEntryRow(title="Повторите пароль")
    lst.append(e1)
    lst.append(e2)
    d.set_extra_child(lst)
    d.add_response("cancel", "Отмена")
    if has:
        d.add_response("remove", "Снять пароль")
        d.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
    d.add_response("save", "Сменить пароль" if has else "Установить")
    d.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response("save")
    d.set_close_response("cancel")

    def resp(_d, r):
        if r == "remove":
            ks.set_password(None)
            _toast(win, "Пароль снят")
            if on_done:
                on_done()
            return
        if r != "save":
            return
        p1, p2 = e1.get_text(), e2.get_text()
        if not p1:
            _toast(win, "Пустой пароль")
            return
        if p1 != p2:
            _toast(win, "Пароли не совпадают")
            return
        ks.set_password(p1)
        _toast(win, "Пароль установлен · список ключей теперь зашифрован")
        if on_done:
            on_done()
    d.connect("response", resp)
    d.present(win)
    _focus_later(e1)


# --------------------------------------------------------------------------- менеджер ключей

class KeyManager:
    def __init__(self, app, win):
        self.app = app
        self.win = win
        self.dialog = Adw.Dialog(title="Ключи шифрования", content_width=460, content_height=560)
        tv = Adw.ToolbarView()
        hb = Adw.HeaderBar()
        tv.add_top_bar(hb)
        self.scroller = Gtk.ScrolledWindow(vexpand=True)
        self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16,
                               margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self.scroller.set_child(self.content)
        tv.set_content(self.scroller)
        self.dialog.set_child(tv)
        self._rebuild()

    def present(self):
        self.dialog.present(self.win)

    def _rebuild(self):
        child = self.content.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.content.remove(child)
            child = nxt
        ks = get_keystore()

        group = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        entries = ks.entries() if ks.is_unlocked() else []
        if not entries:
            row = Adw.ActionRow(title="Ключей пока нет",
                                subtitle="Добавьте ключ, чтобы шифровать и открывать файлы")
            group.append(row)
        for e in entries:
            raw = e["kind"] == "raw"
            note = "  ·  старый формат" if raw else ""
            if raw and e["weak"]:
                note += "  ⚠ короткий"
            row = Adw.ActionRow(title=e["name"], subtitle=e["fingerprint"] + note)
            check = Gtk.Image(icon_name="object-select-symbolic")
            check.set_visible(e["active"])
            row.add_prefix(check)
            row.set_activatable(True)
            row.connect("activated", lambda _r, kid=e["id"]: self._set_active(kid))
            if raw:
                up = Gtk.Button(icon_name="security-high-symbolic", css_classes=["flat"],
                                valign=Gtk.Align.CENTER,
                                tooltip_text="Усилить ключ (то же слово, стойкий ключ)")
                up.connect("clicked", lambda _b, kid=e["id"]: self._upgrade(kid))
                row.add_suffix(up)
            ren = Gtk.Button(icon_name="document-edit-symbolic", css_classes=["flat"],
                             valign=Gtk.Align.CENTER, tooltip_text="Переименовать")
            ren.connect("clicked", lambda _b, kid=e["id"], nm=e["name"]: self._rename(kid, nm))
            row.add_suffix(ren)
            if len(entries) > 1:
                dele = Gtk.Button(icon_name="user-trash-symbolic", css_classes=["flat"],
                                  valign=Gtk.Align.CENTER, tooltip_text="Удалить ключ")
                dele.connect("clicked", lambda _b, kid=e["id"], nm=e["name"]: self._delete(kid, nm))
                row.add_suffix(dele)
            group.append(row)
        self.content.append(group)

        add = Gtk.Button(label="Добавить ключ", css_classes=["pill", "suggested-action"],
                         halign=Gtk.Align.CENTER)
        add.connect("clicked", lambda *_: add_key_dialog(self.app, self.win, self._rebuild))
        self.content.append(add)

        # --- пароль
        pw_group = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        has_pw = ks.is_encrypted()
        pw_row = Adw.ActionRow(
            title="Пароль на программу",
            subtitle="Установлен — список ключей зашифрован" if has_pw
            else "Не задан — можно защитить список ключей паролем")
        btn = Gtk.Button(label="Сменить" if has_pw else "Установить",
                         valign=Gtk.Align.CENTER, css_classes=["flat"])
        btn.connect("clicked", lambda *_: password_dialog(self.app, self.win, self._rebuild))
        pw_row.add_suffix(btn)
        pw_row.set_activatable_widget(btn)
        pw_group.append(pw_row)
        self.content.append(pw_group)

        text = ("Активный ключ (✓) используется для новых файлов и при открытии. "
                "Чтобы перешифровать уже готовый файл другим ключом, откройте его и выберите "
                "«Сменить ключ файла…» в меню.")
        if any(e["kind"] == "raw" for e in entries):
            text += ("\n\nКлючи «старого формата» достались от прежних версий: там слово "
                     "становилось ключом напрямую, поэтому короткое слово подбирается быстро. "
                     "Кнопка со щитом усиливает ключ, оставляя то же слово.")
        hint = Gtk.Label(wrap=True, xalign=0, css_classes=["caption", "dim-label"], label=text)
        self.content.append(hint)

    def _set_active(self, kid):
        ks = get_keystore()
        ks.set_active(kid)
        try:
            self.app.cipher = Cipher()
        except Exception:  # noqa: BLE001
            pass
        _reopen(self.app)
        self._rebuild()

    def _upgrade(self, kid):
        """Усилить ключ старого формата и предложить сразу перешифровать открытую папку."""
        ks = get_keystore()
        d = Adw.AlertDialog(
            heading="Усилить ключ?",
            body="Слово останется тем же, но ключ будет выведен из него стойким способом "
                 "(PBKDF2, 300 000 итераций) — подобрать его словарём станет несоизмеримо "
                 "дороже.\n\nСтарый ключ останется в списке: им открываются уже существующие "
                 "файлы, пока вы их не перешифруете новым.")
        d.add_response("cancel", "Отмена")
        d.add_response("ok", "Усилить")
        d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("ok")
        d.set_close_response("cancel")

        def resp(_d, r):
            if r != "ok":
                return
            try:
                new_id = ks.upgrade(kid)
            except (KeyError, ValueError) as ex:
                _toast(self.win, f"Не удалось усилить ключ: {ex}")
                return
            self._rebuild()
            _toast(self.win, "Создан усиленный ключ")
            self._offer_rekey(new_id)
        d.connect("response", resp)
        d.present(self.win)

    def _offer_rekey(self, new_id):
        """После усиления — предложить перевести файлы открытой папки на новый ключ."""
        win = self.win
        if not getattr(win, "files", None) or not getattr(win, "folder", None):
            info = Adw.AlertDialog(
                heading="Файлы пока на старом ключе",
                body="Откройте папку с зашифрованными файлами и выберите «Сменить ключ у всех "
                     "файлов папки…», чтобы перевести их на усиленный ключ.")
            info.add_response("ok", "Понятно")
            info.present(win)
            return
        d = Adw.AlertDialog(
            heading="Перешифровать файлы сейчас?",
            body=f"Файлы в «{os.path.basename(win.folder)}» будут перешифрованы усиленным "
                 "ключом. Содержимое не меняется, на диск ничего не расшифровывается. "
                 "Файлы, зашифрованные другим ключом, пропускаются.")
        d.add_response("later", "Позже")
        d.add_response("go", "Перешифровать")
        d.set_response_appearance("go", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("go")
        d.set_close_response("later")

        def resp(_d, r):
            if r == "go":
                self.dialog.close()
                win.rekey_folder_to(new_id)
        d.connect("response", resp)
        d.present(win)

    def _rename(self, kid, cur):
        entry = Gtk.Entry(text=cur, activates_default=True)
        d = Adw.AlertDialog(heading="Переименовать ключ", body="")
        d.set_extra_child(entry)
        d.add_response("cancel", "Отмена")
        d.add_response("ok", "Сохранить")
        d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("ok")
        d.set_close_response("cancel")

        def resp(_d, r):
            if r == "ok":
                get_keystore().rename(kid, entry.get_text().strip())
                self._rebuild()
        d.connect("response", resp)
        d.present(self.win)
        _focus_later(entry)

    def _delete(self, kid, name):
        d = Adw.AlertDialog(
            heading=f"Удалить ключ «{name}»?",
            body="Файлы, зашифрованные этим ключом, без него больше не открыть. "
                 "Убедитесь, что он вам не нужен.")
        d.add_response("cancel", "Отмена")
        d.add_response("del", "Удалить")
        d.set_response_appearance("del", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_close_response("cancel")

        def resp(_d, r):
            if r != "del":
                return
            get_keystore().remove(kid)
            try:
                self.app.cipher = Cipher()
            except Exception:  # noqa: BLE001
                self.app.cipher = None
            _reopen(self.app)
            self._rebuild()
        d.connect("response", resp)
        d.present(self.win)


# --------------------------------------------------------------------------- выбор ключа (перешифровка)

def choose_key_dialog(app, win, heading: str, body: str, on_choose: Callable[[str], None],
                      exclude_active: bool = False):
    ks = get_keystore()
    entries = ks.entries() if ks.is_unlocked() else []
    active = ks.active_id() if ks.is_unlocked() else None
    if exclude_active:
        entries = [e for e in entries if e["id"] != active]
    if not entries:
        _toast(win, "Нет другого ключа. Сначала добавьте ключ в «Ключи шифрования…».")
        return
    d = Adw.AlertDialog(heading=heading, body=body)
    lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, css_classes=["boxed-list"])
    rows = []
    for e in entries:
        row = Adw.ActionRow(
            title=e["name"],
            subtitle=e["fingerprint"] + ("  ·  старый формат" if e["kind"] == "raw" else ""))
        lst.append(row)
        rows.append((row, e["id"]))
    if rows:
        lst.select_row(rows[0][0])
    d.set_extra_child(lst)
    d.add_response("cancel", "Отмена")
    d.add_response("ok", "Продолжить")
    d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response("ok")
    d.set_close_response("cancel")

    def resp(_d, r):
        if r != "ok":
            return
        sel = lst.get_selected_row()
        kid = next((i for row, i in rows if row is sel), rows[0][1])
        on_choose(kid)
    d.connect("response", resp)
    d.present(win)


# --------------------------------------------------------------------------- helpers

def _toast(win, text):
    if hasattr(win, "toast"):
        win.toast(text)


def _reopen(app):
    for w in app.get_windows():
        if hasattr(w, "files") and w.files:
            w.open_path(w.files[w.fi].path)
