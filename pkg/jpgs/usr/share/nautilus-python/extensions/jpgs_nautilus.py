"""Пункты JPGS в контекстном меню Nautilus (нужен пакет python-nautilus)."""
import subprocess

from gi.repository import GObject, Nautilus

JPGS = "/usr/bin/jpgs"
IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp",
              ".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".wmv", ".flv", ".3gp", ".ts",
              ".mts", ".m2ts", ".mpg", ".mpeg", ".ogv")


def _paths(files):
    return [f.get_location().get_path() for f in files if f.get_location() and f.get_location().get_path()]


class JpgsMenu(GObject.GObject, Nautilus.MenuProvider):
    def _item(self, name, label, args, files):
        item = Nautilus.MenuItem(name=f"JPGS::{name}", label=label)
        item.connect("activate", lambda *_: subprocess.Popen([JPGS, *args, *_paths(files)],
                                                             start_new_session=True))
        return item

    def get_file_items(self, *args):
        files = args[-1]
        if not files or any(f.get_uri_scheme() != "file" or f.is_directory() for f in files):
            return []
        names = [f.get_name().lower() for f in files]
        if all(n.endswith((".jpgs", ".vids")) for n in names):
            return [self._item("open", "Открыть в JPGS", [], files),
                    self._item("decrypt", "Расшифровать сюда", ["decrypt"], files)]
        if all(n.endswith(IMAGE_EXTS) for n in names):
            return [self._item("encrypt", "Зашифровать (.jpgs / .vids)", ["--encrypt"], files)]
        return []

    def get_background_items(self, *args):
        return []
