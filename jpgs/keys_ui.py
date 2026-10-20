"""Интерфейс управления ключами: список ключей, добавление/удаление/переименование,
выбор активного, необязательный пароль на программу (и сколько его помнить) и
перешифровка файлов другим ключом.

Отделён от viewer.py по образцу video_ui.py, чтобы не раздувать основной модуль.
Всё медленное (scrypt — доли секунды и 128 МиБ памяти) считается в фоновом потоке,
чтобы окно не замирало.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable, Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .crypto import (DEFAULT_KIND, fingerprint_material, generate_key, key_strength,  # noqa: E402
                     material_for)
from .keystore import get_keystore, unlock_cache_available  # noqa: E402

KIND_LABELS = (
    ("scrypt", "Новый ключ (scrypt) — рекомендуется"),
    ("derived", "Ключ из JPGS 2.4 (PBKDF2)"),
    ("raw", "Ключ из старых версий JPGS (без усиления)"),
)
KIND_SHORT = {"raw": "старый формат", "derived": "PBKDF2", "scrypt": "scrypt"}

REMEMBER = ((0, "Не помнить"), (5, "5 минут"), (15, "15 минут"), (60, "1 час"),
            (480, "8 часов"), (1440, "Сутки"))

# задержка после неверного пароля растёт: перебор вручную или скриптом по окну бессмыслен
_fails = {"n": 0, "until": 0.0}


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


def _in_thread(work: Callable, done: Callable):
    """work() в фоне, done(результат, ошибка) — в главном потоке."""
    def job():
        try:
            res, err = work(), None
        except Exception as e:  # noqa: BLE001
            res, err = None, e
        GLib.idle_add(lambda: done(res, err) and False)
    threading.Thread(target=job, daemon=True).start()


# --------------------------------------------------------------------------- пароль при запуске

def unlock_dialog(app, win, then: Optional[Callable[[], None]] = None):
    """Спросить пароль и разблокировать хранилище. При успехе пересобрать ключи и вызвать then."""
    ks = get_keystore()
    d = Adw.AlertDialog(heading="Требуется пароль",
                        body="Список ключей защищён паролем. Введите его, чтобы открывать файлы.")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
    entry = Adw.PasswordEntryRow(title="Пароль")
    lst.append(entry)
    box.append(lst)
    status = Gtk.Label(wrap=True, css_classes=["caption", "dim-label"])
    box.append(status)
    d.set_extra_child(box)
    d.add_response("cancel", "Отмена")
    d.add_response("ok", "Разблокировать")
    d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response("ok")
    d.set_close_response("cancel")
    d.set_response_enabled("ok", False)

    def wait_tick():
        left = _fails["until"] - time.time()
        if left > 0:
            status.set_text(f"Неверный пароль. Повторить можно через {int(left) + 1} с")
            d.set_response_enabled("ok", False)
            return True
        status.set_text("Неверный пароль. Попробуйте ещё раз." if _fails["n"] else "")
        d.set_response_enabled("ok", bool(entry.get_text()))
        return False

    entry.connect("changed", lambda *_: wait_tick())
    if _fails["until"] > time.time():
        GLib.timeout_add(250, wait_tick)
    wait_tick()

    def resp(_d, r):
        if r != "ok":
            return
        pw = entry.get_text()
        busy = Adw.AlertDialog(heading="Проверка пароля…", body="Это занимает около секунды.")
        busy.present(win)

        def done(ok, _err):
            busy.force_close()
            if ok:
                _fails["n"] = 0
                _fails["until"] = 0.0
                app.reload_keys()
                _reopen(app)
                if then:
                    then()
                return
            _fails["n"] += 1
            _fails["until"] = time.time() + min(30, 2 ** (_fails["n"] - 1))
            unlock_dialog(app, win, then)
        _in_thread(lambda: ks.unlock(pw), done)
    d.connect("response", resp)
    d.present(win)
    _focus_later(entry)


# --------------------------------------------------------------------------- добавление ключа

def add_key_dialog(app, win, on_done: Optional[Callable[[], None]] = None):
    ks = get_keystore()
    d = Adw.AlertDialog(heading="Новый ключ",
                        body="Ключ — это фраза, которую знаете только вы. Файлы, зашифрованные им, "
                             "открываются только этим же ключом. Лучше всего — 4–5 случайных слов "
                             "или сгенерированный ключ.")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
    name = Adw.EntryRow(title="Имя ключа")
    e1 = Adw.PasswordEntryRow(title="Ключ")
    e2 = Adw.PasswordEntryRow(title="Повторите ключ")
    kind_row = Adw.ComboRow(title="Тип", model=Gtk.StringList.new([t for _k, t in KIND_LABELS]))
    for w in (name, e1, e2, kind_row):
        lst.append(w)
    box.append(lst)
    gen = Gtk.Button(label="Сгенерировать случайный ключ", css_classes=["pill"],
                     halign=Gtk.Align.CENTER)
    info = Gtk.Label(wrap=True, selectable=True, css_classes=["caption"], xalign=0.5)
    box.append(gen)
    box.append(info)
    d.set_extra_child(box)
    d.add_response("cancel", "Отмена")
    d.add_response("save", "Добавить")
    d.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response("save")
    d.set_close_response("cancel")
    d.set_response_enabled("save", False)
    generated = {"key": None}

    def kind():
        return KIND_LABELS[kind_row.get_selected()][0]

    def changed(*_):
        k1, k2 = e1.get_text(), e2.get_text()
        if generated["key"] is not None and k1 != generated["key"]:
            generated["key"] = None
        if not k1:
            info.set_text("")
            d.set_response_enabled("save", False)
            return
        if k1 != k2:
            info.set_text("Ключи не совпадают" if k2 else "")
            d.set_response_enabled("save", False)
            return
        strong, why = key_strength(k1)
        if kind() == "scrypt" and not strong:
            # новый ключ должен быть стойким; слабые допускаются только для старых файлов
            info.set_text(f"⚠ {why}")
            d.set_response_enabled("save", False)
            return
        if kind() != "scrypt":
            why = ("Тип для уже существующих файлов. Новые файлы лучше шифровать новым ключом: "
                   "его подбор в сотни раз дороже." + ("" if strong else "  ⚠ Ключ слабый."))
        if generated["key"]:
            why = ("Сгенерирован ключ — сохраните его в надёжном месте, без него файлы не открыть:\n"
                   f"{generated['key']}")
        info.set_text(why)
        d.set_response_enabled("save", True)
    e1.connect("changed", changed)
    e2.connect("changed", changed)
    kind_row.connect("notify::selected", changed)

    def do_gen(_b):
        k = generate_key()
        kind_row.set_selected(0)
        generated["key"] = k
        e1.set_text(k)
        e2.set_text(k)
        changed()
    gen.connect("clicked", do_gen)

    def resp(_d, r):
        if r != "save":
            return
        key, kd = e1.get_text(), kind()
        if not key:
            return
        nm = name.get_text().strip() or "Ключ"
        busy = Adw.AlertDialog(heading="Создание ключа…",
                               body="Ключ выводится из фразы стойким способом — это занимает "
                                    "около секунды.")
        busy.present(win)

        def done(fp, err):
            busy.force_close()
            if err is not None:
                _toast(win, f"Не удалось добавить ключ: {err}")
                return
            app.reload_keys()
            _toast(win, f"Ключ добавлен · отпечаток {fp}")
            _reopen(app)
            if on_done:
                on_done()

        def work():
            mat = material_for(key, kd)
            ks.add(nm, key, kind=kd, material=mat)
            return fingerprint_material(mat)
        _in_thread(work, done)
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
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
    e1 = Adw.PasswordEntryRow(title="Новый пароль")
    e2 = Adw.PasswordEntryRow(title="Повторите пароль")
    lst.append(e1)
    lst.append(e2)
    box.append(lst)
    info = Gtk.Label(wrap=True, css_classes=["caption"])
    box.append(info)
    d.set_extra_child(box)
    d.add_response("cancel", "Отмена")
    if has:
        d.add_response("remove", "Снять пароль")
        d.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
    d.add_response("save", "Сменить пароль" if has else "Установить")
    d.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response("save")
    d.set_close_response("cancel")
    d.set_response_enabled("save", False)

    def changed(*_):
        p1, p2 = e1.get_text(), e2.get_text()
        strong, why = key_strength(p1) if p1 else (False, "")
        if p1 and p2 and p1 != p2:
            why, strong = "Пароли не совпадают", False
        elif p1 and not p2:
            strong = False
        info.set_text(("" if strong or not p1 else "⚠ ") + why)
        d.set_response_enabled("save", strong)
    e1.connect("changed", changed)
    e2.connect("changed", changed)

    def resp(_d, r):
        if r == "remove":
            ks.set_password(None)
            _toast(win, "Пароль снят")
            if on_done:
                on_done()
            return
        if r != "save":
            return
        p1 = e1.get_text()
        busy = Adw.AlertDialog(heading="Установка пароля…", body="")
        busy.present(win)

        def done(_r, err):
            busy.force_close()
            if err is not None:
                _toast(win, f"Не удалось: {err}")
                return
            _toast(win, "Пароль установлен · список ключей теперь зашифрован")
            if on_done:
                on_done()
        _in_thread(lambda: ks.set_password(p1), done)
    d.connect("response", resp)
    d.present(win)
    _focus_later(e1)


def upgrade_word_dialog(win, kid: str, name: str, on_word: Callable[[str], None]):
    """У ключа PBKDF2 слово не хранится — для усиления его нужно ввести."""
    d = Adw.AlertDialog(heading=f"Усилить «{name}»",
                        body="Введите слово этого ключа: из него будет выведен ключ scrypt. "
                             "Слово проверяется — чужое не подойдёт.")
    lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
    e = Adw.PasswordEntryRow(title="Слово ключа")
    lst.append(e)
    d.set_extra_child(lst)
    d.add_response("cancel", "Отмена")
    d.add_response("ok", "Усилить")
    d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response("ok")
    d.set_close_response("cancel")
    d.connect("response", lambda _d, r: r == "ok" and e.get_text() and on_word(e.get_text()))
    d.present(win)
    _focus_later(e)


# --------------------------------------------------------------------------- менеджер ключей

class KeyManager:
    def __init__(self, app, win):
        self.app = app
        self.win = win
        self.dialog = Adw.Dialog(title="Ключи шифрования", content_width=480, content_height=600)
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
            kind = e["kind"]
            note = f"  ·  {KIND_SHORT.get(kind, kind)}"
            if e["weak"]:
                note += "  ⚠ слабый"
            row = Adw.ActionRow(title=e["name"], subtitle=e["fingerprint"] + note)
            check = Gtk.Image(icon_name="object-select-symbolic")
            check.set_visible(e["active"])
            check.set_tooltip_text("Активный: им шифруются новые файлы")
            row.add_prefix(check)
            row.set_activatable(True)
            row.connect("activated", lambda _r, kid=e["id"]: self._set_active(kid))
            if kind != "scrypt":
                up = Gtk.Button(icon_name="security-high-symbolic", css_classes=["flat"],
                                valign=Gtk.Align.CENTER,
                                tooltip_text="Усилить ключ (то же слово, ключ scrypt)")
                up.connect("clicked", lambda _b, kid=e["id"], k=kind, nm=e["name"]:
                           self._upgrade(kid, k, nm))
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
        if has_pw:
            remember = Adw.ComboRow(title="Помнить пароль",
                                    model=Gtk.StringList.new([t for _m, t in REMEMBER]))
            cur = int(self.app.settings.get("unlock_minutes") or 0)
            idx = next((i for i, (m, _t) in enumerate(REMEMBER) if m == cur), 0)
            remember.set_selected(idx)
            if not unlock_cache_available():
                remember.set_sensitive(False)
                remember.set_subtitle("Недоступно в этой системе (нет XDG_RUNTIME_DIR)")
            else:
                exp = ks.unlock_expires()
                remember.set_subtitle(
                    ("Запомнен до " + time.strftime("%H:%M", time.localtime(exp))) if exp
                    else "Пароль хранится только в памяти сеанса (не на диске)")
            remember.connect("notify::selected", self._remember_changed)
            pw_group.append(remember)
            lock_row = Adw.ActionRow(title="Заблокировать сейчас",
                                     subtitle="Забыть пароль и закрыть файлы (Ctrl+L)")
            lock_btn = Gtk.Button(icon_name="system-lock-screen-symbolic", valign=Gtk.Align.CENTER,
                                  css_classes=["flat"])
            lock_btn.connect("clicked", lambda *_: (self.dialog.close(), self.app.lock()))
            lock_row.add_suffix(lock_btn)
            lock_row.set_activatable_widget(lock_btn)
            pw_group.append(lock_row)
        self.content.append(pw_group)

        text = ("Файлы открываются любым ключом из списка — программа сама подбирает нужный. "
                "Активный ключ (✓) используется для новых файлов. Сменить ключ уже готового "
                "файла: правый клик → «Сменить ключ файла…».")
        if any(e["kind"] != "scrypt" for e in entries):
            text += ("\n\nКлючи «старого формата» и PBKDF2 достались от прежних версий и "
                     "подбираются заметно быстрее. Кнопка со щитом создаёт из того же слова "
                     "ключ scrypt — затем перешифруйте им файлы.")
        hint = Gtk.Label(wrap=True, xalign=0, css_classes=["caption", "dim-label"], label=text)
        self.content.append(hint)

    def _remember_changed(self, row, _p):
        mins = REMEMBER[row.get_selected()][0]
        self.app.settings.set("unlock_minutes", mins)
        ks = get_keystore()
        if mins:
            ks._remember()  # запомнить сразу, раз пароль уже введён
        else:
            from .keystore import forget_unlock
            forget_unlock()
        self._rebuild()

    def _set_active(self, kid):
        ks = get_keystore()
        ks.set_active(kid)
        self.app.reload_keys()
        self._rebuild()

    def _upgrade(self, kid, kind, name):
        """Усилить ключ (старый формат или PBKDF2 → scrypt) и предложить перешифровать папку."""
        ks = get_keystore()

        def run(word: Optional[str]):
            busy = Adw.AlertDialog(heading="Усиление ключа…", body="")
            busy.present(self.win)

            def done(new_id, err):
                busy.force_close()
                if err is not None:
                    _toast(self.win, f"Не удалось усилить ключ: {err}")
                    return
                self.app.reload_keys()
                self._rebuild()
                _toast(self.win, "Создан ключ scrypt")
                self._offer_rekey(new_id)
            _in_thread(lambda: ks.upgrade(kid, word=word, activate=True), done)

        if kind == "derived":
            upgrade_word_dialog(self.win, kid, name, run)
            return
        d = Adw.AlertDialog(
            heading="Усилить ключ?",
            body="Слово останется тем же, но ключ будет выведен из него через scrypt — "
                 "подобрать его станет несоизмеримо дороже. Новый ключ станет активным.\n\n"
                 "Старый ключ останется в списке: им открываются уже существующие "
                 "файлы, пока вы их не перешифруете новым.")
        d.add_response("cancel", "Отмена")
        d.add_response("ok", "Усилить")
        d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("ok")
        d.set_close_response("cancel")
        d.connect("response", lambda _d, r: r == "ok" and run(None))
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
                 "Файлы, к которым не подходит ни один ключ, пропускаются.")
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
                self.app.reload_keys()
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
            self.app.reload_keys()
            _reopen(self.app)
            self._rebuild()
        d.connect("response", resp)
        d.present(self.win)


# --------------------------------------------------------------------------- выбор ключа (перешифровка)

def choose_key_dialog(app, win, heading: str, body: str, on_choose: Callable[[str], None],
                      exclude_active: bool = False, exclude_material: Optional[bytes] = None):
    ks = get_keystore()
    entries = ks.entries() if ks.is_unlocked() else []
    active = ks.active_id() if ks.is_unlocked() else None
    if exclude_active:
        entries = [e for e in entries if e["id"] != active]
    if exclude_material is not None:
        entries = [e for e in entries if ks.material_by_id(e["id"]) != exclude_material]
    if not entries:
        _toast(win, "Нет другого ключа. Сначала добавьте ключ в «Ключи шифрования…».")
        return
    d = Adw.AlertDialog(heading=heading, body=body)
    lst = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, css_classes=["boxed-list"])
    rows = []
    for e in entries:
        row = Adw.ActionRow(
            title=e["name"] + ("  ✓" if e["id"] == active else ""),
            subtitle=e["fingerprint"] + f"  ·  {KIND_SHORT.get(e['kind'], e['kind'])}")
        lst.append(row)
        rows.append((row, e["id"]))
    first = next((r for r, i in rows if i == active), rows[0][0])
    lst.select_row(first)
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


__all__ = ["unlock_dialog", "add_key_dialog", "password_dialog", "KeyManager",
           "choose_key_dialog", "DEFAULT_KIND"]
