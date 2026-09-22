import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["JPGS_KEY"] = "test-key-for-unit-tests-only-123"

from jpgs import container as C  # noqa: E402
from jpgs.crypto import Cipher  # noqa: E402


class VideoContainerTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.d = self.t.name
        self.c = Cipher()

    def tearDown(self):
        self.t.cleanup()

    def test_stream_encrypt_equals_whole_and_random_access(self):
        for size in (0, 15, 16, C.CHUNK, C.CHUNK + 1, 3 * C.CHUNK + 777):
            data = os.urandom(size)
            src = os.path.join(self.d, f"v{size}.mp4")
            with open(src, "wb") as f:
                f.write(data)
            out = C.encrypt_stream(src, self.d, self.c)
            with open(out, "rb") as f:
                enc = f.read()
            self.assertEqual(enc, self.c.encrypt(data), size)
            df = C.DecryptedFile(out, self.c)
            self.assertEqual(df.size, size)
            rnd = random.Random(size)
            for _ in range(50):
                a = rnd.randrange(0, size + 1)
                n = rnd.randrange(0, 200000)
                df.seek(a)
                self.assertEqual(df.read(n), data[a:a + n])
            df.close()

    def test_sniff(self):
        self.assertEqual(C.sniff_video_ext(b"\0\0\0\x20ftypisom" + b"\0" * 50), "mp4")
        self.assertEqual(C.sniff_video_ext(b"\x1a\x45\xdf\xa3" + b"webm" + b"\0" * 50), "webm")
        self.assertEqual(C.sniff_video_ext(b"\x1a\x45\xdf\xa3" + b"matroska" + b"\0" * 50), "mkv")

    @unittest.skipUnless(shutil.which("ffmpeg"), "нет ffmpeg")
    def test_decrypt_roundtrip_and_frame(self):
        src = os.path.join(self.d, "clip.mp4")
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i",
                        "testsrc2=size=320x240:rate=25", "-t", "4", "-c:v", "libx264",
                        "-pix_fmt", "yuv420p", src], check=True)
        out = C.encrypt_stream(src, self.d, self.c)
        dec = C.decrypt_video_to(out, os.path.join(self.d, "out"), self.c)
        self.assertTrue(dec.endswith(".mp4"))
        with open(dec, "rb") as a, open(src, "rb") as b:
            self.assertEqual(a.read(), b.read())
        import importlib.util
        if importlib.util.find_spec("av") is None:
            self.skipTest("нет PyAV")
        from jpgs.video import grab_frame
        data, w, h, stride, info = grab_frame(out, self.c, 128)
        self.assertEqual((info.width, info.height), (320, 240))
        self.assertAlmostEqual(info.duration, 4.0, delta=0.2)
        self.assertEqual(w, 128)
        self.assertGreaterEqual(len(data), stride * h)


if __name__ == "__main__":
    unittest.main()
