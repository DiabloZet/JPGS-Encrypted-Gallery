"""ИИ-поиск: логика ранжирования и тегов (без моделей) и, если модели скачаны, настоящий
прогон (JPGS_MODELS_DIR=папка с моделями)."""

import importlib.util
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NP = importlib.util.find_spec("numpy") is not None


@unittest.skipUnless(HAVE_NP, "нет numpy")
class AILogicTests(unittest.TestCase):
    def setUp(self):
        import numpy as np
        from jpgs import ai as A
        self.A, self.np = A, np
        self.vecs = list(np.eye(64, dtype=np.float32)[:5])  # ортогональные: сходство 0 или 1

    def ai(self, k, tags=(), n=(), r="general"):
        return {"v": 1, "m": {"siglip2": 1}, "e": self.A.pack_vec(self.vecs[k]),
                "t": [[t, 90] for t in tags], "n": list(n), "r": r}

    def test_pack_unpack_keeps_direction(self):
        v = self.vecs[0]
        u = self.A.unpack_vec(self.A.pack_vec(v))
        self.assertGreater(float(self.np.dot(u, v)), 0.999)
        self.assertLess(len(self.A.pack_vec(self.np.ones(768))), 1100)  # ~1 КБ на запись

    def test_labels_ru(self):
        a = self.ai(0, tags=["1girl", "swimsuit", "unknown_tag"],
                    n=["FEMALE_BREAST_EXPOSED", "FEET_COVERED"], r="explicit")
        lab = self.A.labels_ru(a)
        self.assertIn("обнажённая натура", lab)
        self.assertIn("обнажённая грудь", lab)
        self.assertNotIn("ноги в обуви", lab)        # служебный класс не показываем
        self.assertIn("эротика 18+", lab)
        self.assertIn("купальник", lab)
        self.assertIn("unknown tag", lab)             # без перевода — как есть

    def test_tag_search_russian_forms(self):
        a = self.ai(0, tags=["swimsuit", "beach"])
        self.assertEqual(self.A.tag_matches("в купальнике на пляже", a), 2)
        self.assertEqual(self.A.tag_matches("swimsuit", a), 1)
        self.assertEqual(self.A.tag_matches("кошка", a), 0)

    def test_rank_semantic_threshold_and_tags(self):
        items = [(k, self.ai(k)) for k in range(5)]
        q = self.vecs[2] * 0.2 + self.vecs[0] * 0.0
        q = q / self.np.linalg.norm(q)
        res, exact = self.A.rank("запрос", items, q)
        self.assertTrue(exact)
        self.assertEqual(res[0][0], 2)
        # без совпадений выше порога — «похожие», не больше 5
        res, exact = self.A.rank("запрос", items, -q)
        self.assertFalse(exact)
        self.assertLessEqual(len(res), 5)
        # без SigLIP — только записи, где есть ВСЕ слова запроса
        items = [(0, self.ai(0, tags=["swimsuit"])), (1, self.ai(1, tags=["swimsuit", "beach"]))]
        res, _e = self.A.rank("купальник пляж", items, None)
        self.assertEqual([k for k, _s in res], [1])

    def test_similar(self):
        items = [(k, self.ai(k)) for k in range(5)]
        res = self.A.similar(items, self.vecs[1], exclude=1)
        self.assertNotIn(1, [k for k, _s in res])
        self.assertGreaterEqual(len(res), 4)

    def test_needs_analysis(self):
        avail = {"siglip2": 1, "wd": 1}
        self.assertEqual(self.A.needs_analysis(None, avail), {"siglip2", "wd"})
        self.assertEqual(self.A.needs_analysis({"m": {"siglip2": 1}}, avail), {"wd"})
        self.assertEqual(self.A.needs_analysis({"m": {"siglip2": 1, "wd": 1}}, avail), set())

    def test_digest_check(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "f")
        with open(p, "wb") as f:
            f.write(b"hello\n")
        self.assertTrue(self.A._digest_ok(p, "git:ce013625030ba8dba906f756967f9e9ca394464a"))
        self.assertTrue(self.A._digest_ok(
            p, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"))
        self.assertFalse(self.A._digest_ok(p, "0" * 64))


MODELS = os.environ.get("JPGS_MODELS_DIR")


@unittest.skipUnless(MODELS and HAVE_NP and importlib.util.find_spec("onnxruntime"),
                     "модели не скачаны (JPGS_MODELS_DIR) или нет onnxruntime")
class AIModelTests(unittest.TestCase):
    def test_index_and_search_real_models(self):
        import gi
        gi.require_version("GdkPixbuf", "2.0")
        from gi.repository import GdkPixbuf
        from jpgs import ai as A
        from jpgs import container as C
        from jpgs.ai_index import Indexer
        from jpgs.crypto import Cipher
        if not A.installed_models():
            self.skipTest("модели не установлены")
        d = tempfile.mkdtemp()
        c = Cipher(material=b"m" * 32)
        paths = []
        for i, col in enumerate((0xFF0000FF, 0x0000FFFF)):
            pb = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, False, 8, 256, 256)
            pb.fill(col)
            src = os.path.join(d, f"{i}.jpg")
            pb.savev(src, "jpeg", [], [])
            paths.append(C.encrypt_file(src, d, c))
        ix = Indexer(2)
        ix.start([(p, c) for p in paths])
        ix._thread.join(120)
        self.assertEqual((ix.done, ix.total), (2, 2))
        items = [(p, C.JpgsFile(p, c).entry(0).ai) for p in paths]
        self.assertTrue(all(a and a.get("m") for _p, a in items))
        if A.model_installed("siglip2") and importlib.util.find_spec("tokenizers"):
            eng = A.Engine(2)
            res, _exact = A.rank("красный цвет", items, eng.embed_text("красный цвет"))
            self.assertEqual(res[0][0], paths[0])
            res, _exact = A.rank("синий цвет", items, eng.embed_text("синий цвет"))
            self.assertEqual(res[0][0], paths[1])


if __name__ == "__main__":
    unittest.main()
