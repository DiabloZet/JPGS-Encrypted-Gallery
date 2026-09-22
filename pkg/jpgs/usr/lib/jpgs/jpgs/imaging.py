"""Декодирование в текстуру нужного размера.

Для просмотра изображение декодируется сразу под размер экрана: libjpeg умеет
распаковывать в 1/2, 1/4, 1/8 разрешения (DCT-масштабирование), поэтому снимок
6000×4000 на экране 2560×1440 занимает ~11 МБ вместо ~96 МБ и декодируется в разы
быстрее. Полное разрешение подгружается только при увеличении.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import gi

gi.require_version("GdkPixbuf", "2.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, GdkPixbuf, GLib  # noqa: E402

ROTATED_ORIENTATIONS = ("5", "6", "7", "8")


class DecodeError(Exception):
    pass


@dataclass
class Decoded:
    pixels: GLib.Bytes
    width: int          # размер текстуры
    height: int
    stride: int
    alpha: bool
    orig_w: int         # полный размер изображения (с учётом EXIF-поворота)
    orig_h: int

    @property
    def full(self) -> bool:
        return self.width >= self.orig_w and self.height >= self.orig_h

    @property
    def nbytes(self) -> int:
        return self.stride * self.height

    def texture(self) -> Gdk.Texture:
        fmt = Gdk.MemoryFormat.R8G8B8A8 if self.alpha else Gdk.MemoryFormat.R8G8B8
        return Gdk.MemoryTexture.new(self.width, self.height, fmt, self.pixels, self.stride)


def decode(data: bytes, max_side: Optional[int] = None) -> Decoded:
    """max_side — ограничение по длинной стороне (None — полное разрешение)."""
    loader = GdkPixbuf.PixbufLoader()
    info = {}

    def prepared(ld, w, h):
        info["w"], info["h"] = w, h
        if max_side:
            s = max_side / max(w, h)
            if s < 1:
                ld.set_size(max(1, round(w * s)), max(1, round(h * s)))

    loader.connect("size-prepared", prepared)
    try:
        loader.write(data)
        loader.close()
    except GLib.Error as e:
        try:
            loader.close()
        except GLib.Error:
            pass
        raise DecodeError(e.message) from None
    pb = loader.get_pixbuf()
    if pb is None or "w" not in info:
        raise DecodeError("Не удалось распознать изображение")
    orient = pb.get_option("orientation")
    ow, oh = info["w"], info["h"]
    if orient in ROTATED_ORIENTATIONS:
        ow, oh = oh, ow
    pb = pb.apply_embedded_orientation() or pb
    return Decoded(pb.read_pixel_bytes(), pb.get_width(), pb.get_height(),
                   pb.get_rowstride(), pb.get_has_alpha(), ow, oh)
