"""Архив v2: видео и картинки вперемешку, заметки, совместимость со старым форматом."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jpgs import container as C  # noqa: E402
from jpgs.crypto import Cipher, KeyRing  # noqa: E402


def fake_jpeg(tag: bytes, size: int = 3000) -> bytes:
    """Структурно правильный JPEG (сканер находит его границы), пиксели не важны."""
    body = (tag * (size // max(1, len(tag)) + 1))[:size].replace(b"\xff", b"\xfe")
    return (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + body + b"\xff\xd9")


def fake_video(size: int) -> bytes:
    head = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00isomiso2mp41"
    return head + os.urandom(size - len(head))


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.d = self.t.name
        self.c = Cipher(material=b"A" * 32)
        self.c2 = Cipher(material=b"B" * 32)

    def tearDown(self):
        self.t.cleanup()

    def p(self, name):
        return os.path.join(self.d, name)

    def write(self, name, data):
        with open(self.p(name), "wb") as f:
            f.write(data)
        return self.p(name)

    def legacy_jpgs(self, name, imgs, cipher=None):
        cipher = cipher or self.c
        return self.write(name, b"".join(cipher.encrypt(i) for i in imgs))

    # ------------------------------------------------------------------ старый формат

    def test_legacy_archive_unchanged(self):
        imgs = [fake_jpeg(b"a"), fake_jpeg(b"b", 5000)]
        p = self.legacy_jpgs("old.jpgs", imgs)
        jf = C.JpgsFile(p, self.c)
        self.assertFalse(jf.is_v2)
        self.assertEqual([jf.read_image(i) for i in range(2)], imgs)
        self.assertEqual(jf.kind(0), "image")
        self.assertTrue(C.verify_media(p, self.c))
        self.assertFalse(C.verify_media(p, self.c2))

    def test_build_images_only_stays_legacy(self):
        a = self.write("a.jpg", fake_jpeg(b"a"))
        b = self.write("b.jpg", fake_jpeg(b"b"))
        out = C.build_archive([a, b], self.p("x.jpgs"), self.c)
        self.assertFalse(C.has_index(out))
        with open(out, "rb") as f:
            raw = f.read()
        self.assertEqual(raw, self.c.encrypt(fake_jpeg(b"a")) + self.c.encrypt(fake_jpeg(b"b")))

    # ------------------------------------------------------------------ v2

    def test_mixed_archive_roundtrip(self):
        img = fake_jpeg(b"i")
        vid = fake_video(3 * C.CHUNK + 123)
        a = self.write("a.jpg", img)
        v = self.write("v.mp4", vid)
        out = C.build_archive([a, v], self.p("mix.jpgs"), self.c)
        self.assertTrue(C.has_index(out))
        jf = C.JpgsFile(out, self.c)
        self.assertEqual([e.kind for e in jf.entries()], ["image", "video"])
        self.assertEqual(jf.read_image(0), img)
        with jf.open_entry(1) as f:
            self.assertEqual(f.size, len(vid))
            f.seek(C.CHUNK - 5)
            self.assertEqual(f.read(100), vid[C.CHUNK - 5:C.CHUNK + 95])
            f.seek(0)
            self.assertEqual(f.read(), vid)
        self.assertEqual(jf.video_ext(1), "mp4")
        self.assertTrue(C.verify_media(out, self.c))
        self.assertFalse(C.verify_media(out, self.c2))
        # чужой ключ: записей нет, а не мусор
        self.assertEqual(C.JpgsFile(out, self.c2).entries(), [])
        with self.assertRaises(C.WrongKey):
            C.load_index(out, self.c2)

    def test_append_video_to_legacy_keeps_old_bytes(self):
        imgs = [fake_jpeg(b"a"), fake_jpeg(b"b")]
        p = self.legacy_jpgs("old.jpgs", imgs)
        with open(p, "rb") as f:
            before = f.read()
        vid = fake_video(50000)
        v = self.write("v.webm", b"\x1a\x45\xdf\xa3" + vid[4:])
        n = C.append_frames(p, [v], self.c)
        self.assertEqual(n, 1)
        with open(p, "rb") as f:
            after = f.read()
        self.assertTrue(after.startswith(before))   # данные не перезаписаны
        jf = C.JpgsFile(p, self.c)
        self.assertTrue(jf.is_v2)
        self.assertEqual([e.kind for e in jf.entries()], ["image", "image", "video"])
        self.assertEqual(jf.read_image(1), imgs[1])
        self.assertEqual(jf.video_ext(2), "webm")
        # прежние версии видят в файле те же картинки
        with C.DecryptingReader(p, self.c) as r:
            ranges = C.scan_images(r)
            self.assertEqual([r.read(s, e - s) for s, e in ranges[:2]], imgs)

    def test_append_jpeg_to_legacy_stays_legacy(self):
        p = self.legacy_jpgs("old.jpgs", [fake_jpeg(b"a")])
        b = self.write("b.jpg", fake_jpeg(b"b"))
        C.append_frames(p, [b], self.c)
        self.assertFalse(C.has_index(p))
        self.assertEqual(C.JpgsFile(p, self.c).count(), 2)

    def test_append_refuses_wrong_key_and_rolls_back(self):
        p = self.legacy_jpgs("old.jpgs", [fake_jpeg(b"a")])
        b = self.write("b.jpg", fake_jpeg(b"b"))
        with self.assertRaises(C.WrongKey):
            C.append_frames(p, [b], self.c2)
        size = os.path.getsize(p)
        bad = self.write("bad.png", b"not an image")
        with self.assertRaises(C.ArchiveError):
            C.append_frames(p, [b, bad], self.c)
        self.assertEqual(os.path.getsize(p), size)

    def test_append_other_key_archive_reencrypts(self):
        p = self.legacy_jpgs("a.jpgs", [fake_jpeg(b"a")])
        other = self.legacy_jpgs("b.jpgs", [fake_jpeg(b"b"), fake_jpeg(b"c")], self.c2)
        ring = KeyRing(self.c, [self.c2])
        C.append_frames(p, [other], self.c, ring)
        jf = C.JpgsFile(p, self.c)
        self.assertEqual([jf.read_image(i) for i in range(3)],
                         [fake_jpeg(b"a"), fake_jpeg(b"b"), fake_jpeg(b"c")])
        with self.assertRaises(C.ArchiveError):  # без связки чужой файл не читается
            C.append_frames(p, [other], self.c)

    def test_notes_small_and_large(self):
        p = self.legacy_jpgs("n.jpgs", [fake_jpeg(b"a"), fake_jpeg(b"b")])
        C.set_note(p, 1, "  Заметка ✓  ", self.c)
        jf = C.JpgsFile(p, self.c)
        self.assertEqual(jf.note(1), "Заметка ✓")
        self.assertEqual(jf.note(0), "")
        C.set_note(p, 1, "", self.c)
        self.assertFalse(C.has_index(p))  # без заметок — снова старый формат
        # большой файл: индекс дописывается, данные не копируются
        old = C.SMALL_FILE
        C.SMALL_FILE = 1000
        try:
            v = self.write("v.mp4", fake_video(200000))
            vids = C.encrypt_stream(v, self.d, self.c)
            with open(vids, "rb") as f:
                before = f.read()
            C.set_note(vids, 0, "первая", self.c)
            C.set_note(vids, 0, "вторая", self.c)
            with open(vids, "rb") as f:
                after = f.read()
            self.assertTrue(after.startswith(before))
            jv = C.VidsFile(vids, self.c)
            self.assertEqual(jv.note(0), "вторая")
            self.assertEqual(jv.entry(0).length, 200000)
            dec = C.decrypt_video_to(vids, self.p("out"), self.c)
            with open(dec, "rb") as f, open(v, "rb") as g:
                self.assertEqual(f.read(), g.read())
            with open(self.p("out/" + os.path.basename(vids)[:-5] + ".txt"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "вторая")
        finally:
            C.SMALL_FILE = old

    def test_rewrite_order_delete_rekey_extract(self):
        img = [fake_jpeg(bytes([65 + i])) for i in range(3)]
        srcs = [self.write(f"{i}.jpg", d) for i, d in enumerate(img)]
        v = self.write("v.mp4", fake_video(70000))
        p = C.build_archive(srcs[:2] + [v] + srcs[2:], self.p("m.jpgs"), self.c)
        C.set_note(p, 2, "видео", self.c)
        C.rewrite_entries(p, [2, 0, 3], self.c)
        jf = C.JpgsFile(p, self.c)
        self.assertEqual([e.kind for e in jf.entries()], ["video", "image", "image"])
        self.assertEqual(jf.note(0), "видео")
        self.assertEqual(jf.read_image(2), img[2])
        C.reencrypt_media(p, self.c, self.c2)
        self.assertFalse(C.verify_media(p, self.c))
        jf2 = C.JpgsFile(p, self.c2)
        self.assertEqual(jf2.read_image(1), img[0])
        with self.assertRaises(C.WrongKey):
            C.reencrypt_media(p, self.c, self.c2)  # старым ключом файл уже не открыть
        out = C.extract_frames(p, [0, 1], self.c2)
        self.assertTrue(out[0].endswith(".vids") and out[1].endswith(".jpgs"))
        self.assertEqual(C.VidsFile(out[0], self.c2).note(0), "видео")
        self.assertFalse(C.has_index(out[1]))

    def test_merge_media_mixed_keys(self):
        a = self.legacy_jpgs("a.jpgs", [fake_jpeg(b"a")])
        b = self.legacy_jpgs("b.jpgs", [fake_jpeg(b"b")], self.c2)
        v = self.write("v.mp4", fake_video(30000))
        vids = C.encrypt_stream(v, self.d, self.c2)
        ring = KeyRing(self.c, [self.c2])
        out = C.merge_media([a, b, vids], self.p("all.jpgs"), ring)
        jf = C.JpgsFile(out, self.c)
        self.assertEqual([e.kind for e in jf.entries()], ["image", "image", "video"])
        self.assertEqual(jf.read_image(1), fake_jpeg(b"b"))
        # только старые .jpgs одним ключом — быстрая склейка без индекса
        a2 = self.legacy_jpgs("a2.jpgs", [fake_jpeg(b"z")])
        out2 = C.merge_media([a, a2], self.p("simple.jpgs"), ring)
        self.assertFalse(C.has_index(out2))
        self.assertEqual(C.JpgsFile(out2, self.c).count(), 2)

    def test_merge_files_rejects_corrupt(self):
        a = self.legacy_jpgs("a.jpgs", [fake_jpeg(b"a")])
        bad = self.write("bad.jpgs", b"x" * 33)
        with self.assertRaises(C.ArchiveError):
            C.merge_files([a, bad], self.p("m.jpgs"))

    def test_keyring_picks_key(self):
        a = self.legacy_jpgs("a.jpgs", [fake_jpeg(b"a")], self.c2)
        v = self.write("v.mp4", fake_video(5000))
        vids = C.encrypt_stream(v, self.d, self.c2)
        mix = C.build_archive([v, self.write("i.jpg", fake_jpeg(b"i"))], self.p("mix.jpgs"), self.c2)
        ring = KeyRing(self.c, [self.c2])
        for p in (a, vids, mix):
            self.assertEqual(ring.cipher_for(p), self.c2, p)
        self.assertIsNone(KeyRing(self.c).cipher_for(a))

    def test_decrypt_to_dir_mixed(self):
        img = fake_jpeg(b"q")
        vid = fake_video(9000)
        out = C.build_archive([self.write("q.jpg", img), self.write("v.mp4", vid)],
                              self.p("mix.jpgs"), self.c)
        C.set_note(out, 0, "привет", self.c)
        files = C.decrypt_to_dir(out, self.p("dec"), self.c)
        self.assertEqual([os.path.splitext(f)[1] for f in files], [".jpg", ".mp4"])
        with open(files[1], "rb") as f:
            self.assertEqual(f.read(), vid)
        self.assertTrue(os.path.exists(self.p("dec/mix_1.txt")))

    def test_tampered_index_detected(self):
        out = C.build_archive([self.write("v.mp4", fake_video(5000))], self.p("t.jpgs"), self.c)
        with open(out, "r+b") as f:
            f.seek(-80, os.SEEK_END)
            b = f.read(1)
            f.seek(-80, os.SEEK_END)
            f.write(bytes([b[0] ^ 1]))
        self.assertFalse(C.verify_media(out, self.c))
        self.assertEqual(C.JpgsFile(out, self.c).entries(), [])

    def test_strict_signatures(self):
        # 1 из 256 случайных блоков начинается с 0x47 — раньше этого хватало, чтобы
        # принять чужой ключ за верный для .vids
        self.assertFalse(C.plausible_video_head(b"\x47" + os.urandom(400)))
        self.assertFalse(C.plausible_image_head(b"\xff\xd8\x00" + os.urandom(20)))
        self.assertFalse(C.plausible_image_head(b"BM" + b"\x01" * 20))

    @unittest.skipUnless(shutil.which("ffmpeg"), "нет ffmpeg")
    def test_video_entry_frame_grab(self):
        import importlib.util
        if importlib.util.find_spec("av") is None:
            self.skipTest("нет PyAV")
        import subprocess
        src = self.p("clip.webm")
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i",
                        "testsrc2=size=160x120:rate=10", "-t", "2", "-c:v", "libvpx-vp9", src],
                       check=True)
        out = C.build_archive([self.write("a.jpg", fake_jpeg(b"a")), src], self.p("m.jpgs"), self.c)
        from jpgs.video import grab_frame
        jf = C.JpgsFile(out, self.c)
        _d, w, h, _s, info = grab_frame(out, self.c, 64, entry=jf.entry(1))
        self.assertEqual((info.width, info.height), (160, 120))



@unittest.skipUnless(shutil.which("ffmpeg"), "нет ffmpeg")
class TranscodeTests(unittest.TestCase):
    def setUp(self):
        import subprocess
        self.t = tempfile.TemporaryDirectory()
        self.d = self.t.name
        self.c = Cipher(material=b"T" * 32)
        self.src = os.path.join(self.d, "src.mp4")
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i",
                        "testsrc2=size=320x240:rate=25", "-f", "lavfi", "-i", "sine=f=300",
                        "-t", "3", "-c:v", "libx264", "-c:a", "aac", "-shortest", self.src],
                       check=True)

    def tearDown(self):
        self.t.cleanup()

    def test_video_in_archive_replace_keeps_note_and_no_plaintext_left(self):
        from jpgs import transcode as T
        img = os.path.join(self.d, "i.jpg")
        with open(img, "wb") as f:
            f.write(fake_jpeg(b"i"))
        arch = C.build_archive([img, self.src], os.path.join(self.d, "a.jpgs"), self.c)
        C.set_note(arch, 1, "видео", self.c)
        before = set(os.listdir(self.d))
        jf = C.JpgsFile(arch, self.c)
        r = T.transcode_video(jf, 1, T.VideoOpts(fmt="mp4-h264", max_height=120, fps=10,
                                                 start=0.5, end=2.5), True, T.Job())
        self.assertTrue(r.replaced)
        self.assertEqual(set(os.listdir(self.d)), before)  # ни временных, ни открытых файлов
        jf = C.JpgsFile(arch, self.c)
        self.assertEqual(jf.note(1), "видео")
        self.assertEqual(jf.read_image(0), fake_jpeg(b"i"))
        import importlib.util
        if importlib.util.find_spec("av"):
            from jpgs.video import grab_frame
            _d, _w, _h, _s, info = grab_frame(arch, self.c, 64, entry=jf.entry(1))
            self.assertEqual(info.height, 120)
            self.assertAlmostEqual(info.duration, 2.0, delta=0.3)

    def test_cancel_leaves_file_intact(self):
        import threading
        from jpgs import transcode as T
        vids = C.encrypt_stream(self.src, self.d, self.c)
        with open(vids, "rb") as f:
            orig = f.read()
        job = T.Job()
        threading.Timer(0.2, job.cancel).start()
        with self.assertRaises(T.TranscodeError):
            T.transcode_video(C.VidsFile(vids, self.c), 0,
                              T.VideoOpts(fmt="webm-vp9", quality="high"), True, job)
        with open(vids, "rb") as f:
            self.assertEqual(f.read(), orig)
        self.assertEqual(len(os.listdir(self.d)), 2)  # src.mp4 + .vids

    def test_source_server_requires_token(self):
        import urllib.error
        import urllib.request
        from jpgs import transcode as T
        vids = C.encrypt_stream(self.src, self.d, self.c)
        with T._SourceServer(vids, self.c, None) as srv:
            base = srv.url.rsplit("/", 1)[0]
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(base + "/wrong", timeout=5)
            req = urllib.request.Request(srv.url, headers={"Range": "bytes=4-11"})
            with urllib.request.urlopen(req, timeout=5) as r:
                self.assertEqual(r.status, 206)
                self.assertEqual(r.read(), b"ftypisom")

    def test_image_resize_png(self):
        import subprocess
        from jpgs import transcode as T
        img = os.path.join(self.d, "big.jpg")
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i",
                        "testsrc2=size=800x600", "-frames:v", "1", img], check=True)
        arch = C.build_archive([img], os.path.join(self.d, "p.jpgs"), self.c)
        r = T.transcode_image(C.JpgsFile(arch, self.c), 0, T.ImageOpts(fmt="png", max_side=200),
                              True, T.Job())
        jf = C.JpgsFile(arch, self.c)
        self.assertEqual(jf.entry(0).ext, "png")
        self.assertTrue(jf.read_image(0).startswith(b"\x89PNG"))
        self.assertLess(r.after, 200 * 200 * 4)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.d = self.t.name
        self.env = {k: os.environ.get(k) for k in ("JPGS_KEY", "XDG_CONFIG_HOME")}
        os.environ["JPGS_KEY"] = "cli-test-key-123456"
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.d, "cfg")
        import jpgs.keystore as K
        K._INSTANCE = None

    def tearDown(self):
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.t.cleanup()

    def run_cli(self, *args):
        import contextlib
        import io
        from jpgs.cli import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = main(list(args))
        return rc, out.getvalue()

    def test_pack_note_info_decrypt(self):
        img = os.path.join(self.d, "a.jpg")
        vid = os.path.join(self.d, "v.mp4")
        with open(img, "wb") as f:
            f.write(fake_jpeg(b"a"))
        with open(vid, "wb") as f:
            f.write(fake_video(20000))
        arch = os.path.join(self.d, "x.jpgs")
        rc, out = self.run_cli("pack", arch, img, vid, "--remove")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(img) or os.path.exists(vid))  # проверено и удалено
        rc, out = self.run_cli("note", arch, "2", "моё видео")
        self.assertEqual(rc, 0, out)
        rc, out = self.run_cli("info", arch)
        self.assertIn("1 изображение, 1 видео", out)
        self.assertIn("заметок: 1", out)
        rc, out = self.run_cli("decrypt", arch, "-o", os.path.join(self.d, "out"))
        self.assertEqual(rc, 0, out)
        self.assertEqual(sorted(os.listdir(os.path.join(self.d, "out"))),
                         ["x_1.jpg", "x_2.mp4", "x_2.txt"])

    def test_encrypt_to_new_folder_and_remove(self):
        src = os.path.join(self.d, "p.jpg")
        with open(src, "wb") as f:
            f.write(fake_jpeg(b"p"))
        out_dir = os.path.join(self.d, "нет", "такой")
        rc, out = self.run_cli("encrypt", src, "-o", out_dir, "--remove")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(src))
        self.assertEqual(len(os.listdir(out_dir)), 1)

    def test_weak_new_key_rejected(self):
        os.environ.pop("JPGS_KEY")
        import io
        import sys
        old = sys.stdin
        sys.stdin = io.StringIO("123456\n")
        try:
            rc, out = self.run_cli("keys", "add", "--stdin")
        finally:
            sys.stdin = old
        self.assertEqual(rc, 1)
        self.assertIn("не принят", out)


if __name__ == "__main__":
    unittest.main()
