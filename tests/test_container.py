import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["JPGS_KEY"] = "test-key-for-unit-tests-only-123"

import gi  # noqa: E402

gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf  # noqa: E402

from jpgs import container as C  # noqa: E402
from jpgs.crypto import Cipher  # noqa: E402


def make_jpeg(w, h, color=0x3366AAFF, quality=90) -> bytes:
    pb = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, False, 8, w, h)
    pb.fill(color)
    ok, buf = pb.save_to_bufferv("jpeg", ["quality"], [str(quality)])
    return bytes(buf)


def with_exif_thumbnail(jpeg: bytes, thumb: bytes) -> bytes:
    """Вставляет APP1 с вложенным JPEG (как у фото с камер) — ловушка для наивного поиска FFD9."""
    payload = b"Exif\0\0" + b"MM\0*\0\0\0\x08" + b"\0" * 16 + thumb
    app1 = b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    return jpeg[:2] + app1 + jpeg[2:]


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.d = self.t.name
        self.c = Cipher()

    def tearDown(self):
        self.t.cleanup()

    def enc(self, name, data):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(self.c.encrypt(data))
        return p

    def test_backends_match(self):
        data = os.urandom(1000)
        a = Cipher(backend=None)
        b = Cipher(backend="openssl")
        self.assertEqual(a.encrypt(data), b.encrypt(data))
        self.assertEqual(b.decrypt(a.encrypt(data)), data)

    def test_single_and_exif_thumbnail(self):
        big = with_exif_thumbnail(make_jpeg(640, 480), make_jpeg(64, 48, 0xFF0000FF))
        p = self.enc("a.jpgs", big)
        f = C.JpgsFile(p, self.c)
        self.assertEqual(f.count(), 1)
        self.assertEqual(f.read_image(0), big)
        self.assertEqual(f.read_first(), big)

    def test_merged(self):
        imgs = [make_jpeg(300 + i * 10, 200) for i in range(3)]
        imgs[1] = with_exif_thumbnail(imgs[1], make_jpeg(32, 32))
        parts = [self.enc(f"{i}.jpgs", im) for i, im in enumerate(imgs)]
        dest = os.path.join(self.d, "merged.jpgs")
        C.merge_files(parts, dest)
        f = C.JpgsFile(dest, self.c)
        self.assertEqual(f.count(), 3)
        for i, im in enumerate(imgs):
            self.assertEqual(f.read_image(i), im)

    def test_large_crosses_chunks(self):
        # данные больше блока чтения, маркеры на стыках
        noise = os.urandom(3 * C.CHUNK).replace(b"\xff", b"\xfe")
        body = make_jpeg(64, 64)
        # вставим «шум» как APP-сегменты (каждый < 64К)
        segs = b"".join(b"\xff\xe2" + struct.pack(">H", 60002) + noise[i:i + 60000]
                        for i in range(0, len(noise), 60000))
        img = body[:2] + segs + body[2:]
        p = self.enc("big.jpgs", img + img)
        f = C.JpgsFile(p, self.c)
        self.assertEqual(f.count(), 2)
        self.assertEqual(f.read_image(1), img)

    def test_png_fallback_and_decrypt(self):
        pb = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, True, 8, 20, 20)
        pb.fill(0x00FF0080)
        png = os.path.join(self.d, "x.png")
        pb.savev(png, "png", [], [])
        out = C.encrypt_file(png, self.d, self.c)
        f = C.JpgsFile(out, self.c)
        self.assertEqual(f.count(), 1)
        self.assertTrue(C.is_real_jpeg(f.read_image(0)))
        files = C.decrypt_to_dir(out, os.path.join(self.d, "out"), self.c)
        self.assertEqual(len(files), 1)
        GdkPixbuf.Pixbuf.new_from_file(files[0])

    def test_wrong_key(self):
        p = self.enc("k.jpgs", make_jpeg(50, 50))
        f = C.JpgsFile(p, Cipher("other-key"))
        rs = f.ranges()
        # мусор: либо ничего похожего на JPEG, либо «целиком» — но не валидный JPEG
        self.assertFalse(any(C.is_real_jpeg(f.read_image(i)) for i in range(len(rs))))

    def test_truncated_recovery(self):
        img = make_jpeg(400, 300)
        p = self.enc("t.jpgs", img)
        with open(p, "r+b") as fh:
            fh.truncate(os.path.getsize(p) - 37)
        with C.DecryptingReader(p, self.c) as r:
            rs = C.scan_images(r, tolerant=True)
        self.assertEqual(len(rs), 1)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.d = self.t.name
        self.c = Cipher()
        self.imgs = [make_jpeg(100 + 10 * i, 80, 0x112233FF * (i + 1) & 0xFFFFFFFF) for i in range(4)]
        self.path = os.path.join(self.d, "a.jpgs")
        with open(self.path, "wb") as f:
            f.write(self.c.encrypt(self.imgs[0]))

    def tearDown(self):
        self.t.cleanup()

    def frames(self, p=None):
        jf = C.JpgsFile(p or self.path, self.c)
        return [jf.read_image(i) for i in range(jf.count())]

    def test_append_image_and_jpgs(self):
        src = os.path.join(self.d, "x.jpg")
        with open(src, "wb") as f:
            f.write(self.imgs[1])
        other = os.path.join(self.d, "b.jpgs")
        with open(other, "wb") as f:
            f.write(self.c.encrypt(self.imgs[2]) + self.c.encrypt(self.imgs[3]))
        n = C.append_frames(self.path, [src, other, self.path], self.c)
        self.assertEqual(n, 3)
        self.assertEqual(self.frames(), self.imgs)
        self.assertTrue(os.path.exists(src))  # оригинал не трогаем, копий не создаём
        self.assertEqual(sorted(os.listdir(self.d)), ["a.jpgs", "b.jpgs", "x.jpg"])

    def test_append_wrong_key_rejected(self):
        other = os.path.join(self.d, "b.jpgs")
        with open(other, "wb") as f:
            f.write(Cipher("another-key-xxxxxxxxxx").encrypt(self.imgs[1]))
        with self.assertRaises(C.ArchiveError):
            C.append_frames(self.path, [other], self.c)
        self.assertEqual(self.frames(), self.imgs[:1])

    def test_rewrite_and_extract(self):
        with open(self.path, "ab") as f:
            for im in self.imgs[1:]:
                f.write(self.c.encrypt(im))
        C.rewrite_frames(self.path, [3, 0, 2], self.c)
        self.assertEqual(self.frames(), [self.imgs[3], self.imgs[0], self.imgs[2]])
        out = C.extract_frames(self.path, [1], self.c)
        self.assertEqual(self.frames(out[0]), [self.imgs[0]])
        with self.assertRaises(C.ArchiveError):
            C.rewrite_frames(self.path, [], self.c)


if __name__ == "__main__":
    unittest.main()
