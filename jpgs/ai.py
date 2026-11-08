"""Локальный ИИ: смысловые векторы и теги изображений, поиск по-русски.

Всё работает на процессоре через ONNX Runtime, без интернета (интернет нужен только один
раз — скачать модели). Модели:
  * SigLIP2 (Google, многоязычная, понимает русский): вектор смысла картинки и запроса —
    поиск фразой «девушка на пляже в красном купальнике»;
  * WD-Tagger v3 (SmilingWolf): ~10 000 тегов Danbooru и рейтинг — лучше всего для аниме
    и артов, понимает откровенный контент;
  * NudeNet 3: что обнажено на фото (18 классов) — для реальных фотографий.

Результат анализа одной картинки — небольшой словарь (≈1–2 КБ), который хранится в
зашифрованном индексе самого файла .jpgs/.vids (поле "ai" записи, см. container.Entry).

Файлы моделей скачиваются в ~/.local/share/jpgs/models с закреплённой версии
репозитория и проверяются по SHA-256: подменить модель по дороге нельзя.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import threading
import urllib.request
from typing import Callable, Optional

from .ai_tags_ru import (NUDENET_HIDDEN, NUDENET_LABELS, NUDENET_NUDE, NUDENET_RU, RATING_RU,
                         wd_ru)

AI_FORMAT = 1
_HF = "https://huggingface.co/{repo}/resolve/{rev}/{path}"

# Модели: файлы с закреплённой ревизии и их SHA-256 (для мелких не-LFS файлов — git blob SHA-1).
MODELS = {
    "siglip2": {
        "title": "Смысловой поиск (SigLIP2)",
        "about": "Поиск фразой по-русски: «кошка на диване», «пляж на закате». Фото и арты.",
        "repo": "onnx-community/siglip2-base-patch16-224-ONNX",
        "rev": "ba1f3b0843f24bc5417d38e19c37b287d719b2f4",
        "files": {
            "vision.onnx": ("onnx/vision_model_quantized.onnx", 94553333,
                            "5f2b401c1a4fc095702a5d45348e17ad46c4f87064085365b43c6e8eaa5c0070"),
            "text.onnx": ("onnx/text_model_quantized.onnx", 283438275,
                          "3a0603d3a00c05a80a6ded4743c16aaac7b1e62cdcc7e362e7ce418659b96400"),
            "tokenizer.json": ("tokenizer.json", 34363039,
                               "cb9140fae3ac5122c972d37adf83e1248471a38147ad76f8215c8872c6fd8322"),
        },
    },
    "wd": {
        "title": "Теги аниме и артов (WD-Tagger v3)",
        "about": "Подробные теги Danbooru: персонажи, одежда, позы, откровенность.",
        "repo": "SmilingWolf/wd-swinv2-tagger-v3",
        "rev": "627aef95638667ddcaa3ac8ae625e88ea5b02f51",
        "files": {
            "model.onnx": ("model.onnx", 467460978,
                           "e6774bff34d43bd49f75a47db4ef217dce701c9847b546523eb85ff6dbba1db1"),
            "selected_tags.csv": ("selected_tags.csv", 308468,
                                  "git:a2a653a5c89c8e387765eb1de9cfd2aedc92ee8d"),
        },
    },
    "nudenet": {
        "title": "Откровенный контент на фото (NudeNet)",
        "about": "Что обнажено на фотографии: грудь, ягодицы, интимные зоны и т.п.",
        "repo": "deepghs/nudenet_onnx",
        "rev": "44956a0587943016350c7815f9e0dec089d45cae",
        "files": {
            "320n.onnx": ("320n.onnx", 12150158,
                          "c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f"),
        },
    },
}

WD_GENERAL_T = 0.35
WD_CHARACTER_T = 0.85
NUDENET_T = 0.40
MAX_TAGS = 40


class AIError(Exception):
    pass


# --------------------------------------------------------------------------- окружение

def models_dir() -> str:
    base = os.environ.get("JPGS_MODELS_DIR")
    if base:
        return base
    data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(data, "jpgs", "models")


def missing_libs(names=("onnxruntime", "numpy")) -> list[str]:
    import importlib.util
    return [n for n in names if importlib.util.find_spec(n) is None]


def model_size(name: str) -> int:
    return sum(f[1] for f in MODELS[name]["files"].values())


def model_installed(name: str) -> bool:
    d = os.path.join(models_dir(), name)
    return all(os.path.isfile(os.path.join(d, f)) and os.path.getsize(os.path.join(d, f)) == spec[1]
               for f, spec in MODELS[name]["files"].items())


def installed_models() -> list[str]:
    return [n for n in MODELS if model_installed(n)]


def remove_model(name: str):
    d = os.path.join(models_dir(), name)
    for f in MODELS[name]["files"]:
        try:
            os.unlink(os.path.join(d, f))
        except OSError:
            pass


def _digest_ok(path: str, want: str) -> bool:
    if want.startswith("git:"):  # маленький не-LFS файл: git blob SHA-1
        with open(path, "rb") as f:
            data = f.read()
        h = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
        return h == want[4:]
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest() == want


def download_model(name: str, progress: Optional[Callable[[int, int], None]] = None,
                   cancel: Optional[threading.Event] = None) -> None:
    """Скачать файлы модели (с закреплённой ревизии) и проверить SHA-256."""
    spec = MODELS[name]
    d = os.path.join(models_dir(), name)
    os.makedirs(d, exist_ok=True)
    total = model_size(name)
    done = 0
    for local, (remote, size, digest) in spec["files"].items():
        dest = os.path.join(d, local)
        if os.path.isfile(dest) and os.path.getsize(dest) == size:
            done += size
            continue
        url = _HF.format(repo=spec["repo"], rev=spec["rev"], path=remote)
        tmp = dest + ".part"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "JPGS"})
            with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
                while True:
                    if cancel is not None and cancel.is_set():
                        raise AIError("отменено")
                    b = r.read(1 << 20)
                    if not b:
                        break
                    f.write(b)
                    done += len(b)
                    if progress:
                        progress(done, total)
            if os.path.getsize(tmp) != size or not _digest_ok(tmp, digest):
                raise AIError(f"{local}: файл повреждён или подменён (контрольная сумма не совпала)")
            os.replace(tmp, dest)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    if progress:
        progress(total, total)


# --------------------------------------------------------------------------- картинка → массив

def decode_rgb(data: bytes, max_side: int = 1024):
    """Байты изображения → numpy uint8 (H, W, 3) с учётом EXIF-поворота, прозрачность — на белом."""
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf, GLib
    loader = GdkPixbuf.PixbufLoader()

    def prepared(ld, w, h):
        k = max_side / max(w, h)
        if k < 1:
            ld.set_size(max(1, round(w * k)), max(1, round(h * k)))
    loader.connect("size-prepared", prepared)
    try:
        loader.write(data)
        loader.close()
    except GLib.Error as e:
        raise AIError(f"не удалось прочитать изображение: {e.message}") from None
    pb = loader.get_pixbuf()
    pb = pb.apply_embedded_orientation() or pb
    return pixbuf_to_rgb(pb)


def pixbuf_to_rgb(pb):
    import gi
    import numpy as np
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf
    if pb.get_has_alpha():
        w, h = pb.get_width(), pb.get_height()
        bg = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, False, 8, w, h)
        bg.fill(0xFFFFFFFF)
        pb.composite(bg, 0, 0, w, h, 0, 0, 1, 1, GdkPixbuf.InterpType.NEAREST, 255)
        pb = bg
    w, h, rs, nc = pb.get_width(), pb.get_height(), pb.get_rowstride(), pb.get_n_channels()
    buf = np.frombuffer(pb.read_pixel_bytes().get_data(), dtype=np.uint8)
    rows = np.lib.stride_tricks.as_strided(buf, shape=(h, w, nc), strides=(rs, nc, 1))
    return np.ascontiguousarray(rows[:, :, :3])


def _resize(rgb, w: int, h: int):
    """Масштабирование через GdkPixbuf (билинейно) — без зависимости от Pillow/OpenCV."""
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf, GLib
    ih, iw = rgb.shape[:2]
    pb = GdkPixbuf.Pixbuf.new_from_bytes(GLib.Bytes.new(rgb.tobytes()), GdkPixbuf.Colorspace.RGB,
                                         False, 8, iw, ih, iw * 3)
    pb = pb.scale_simple(w, h, GdkPixbuf.InterpType.BILINEAR)
    return pixbuf_to_rgb(pb)


def _pad_square(rgb, fill: int, center: bool):
    import numpy as np
    h, w = rgb.shape[:2]
    s = max(h, w)
    out = np.full((s, s, 3), fill, dtype=np.uint8)
    y, x = ((s - h) // 2, (s - w) // 2) if center else (0, 0)
    out[y:y + h, x:x + w] = rgb
    return out


# --------------------------------------------------------------------------- векторы

def pack_vec(v) -> str:
    """Нормированный вектор → int8 → base64 (768 чисел ≈ 1 КБ)."""
    import numpy as np
    v = np.asarray(v, dtype=np.float32)
    m = float(np.abs(v).max()) or 1.0
    return base64.b64encode(np.round(v / m * 127).astype(np.int8).tobytes()).decode("ascii")


def unpack_vec(s: str):
    import numpy as np
    v = np.frombuffer(base64.b64decode(s), dtype=np.int8).astype(np.float32)
    n = float(np.linalg.norm(v)) or 1.0
    return v / n


# --------------------------------------------------------------------------- движок

class Engine:
    """Сессии ONNX Runtime загружаются лениво; один экземпляр на программу."""

    def __init__(self, threads: int = 2):
        self.threads = max(1, int(threads))
        self._s: dict[str, object] = {}
        self._wd_tags = None
        self._tok = None
        self._lock = threading.Lock()

    def _session(self, key: str, path: str):
        s = self._s.get(key)
        if s is None:
            import onnxruntime as ort
            o = ort.SessionOptions()
            o.intra_op_num_threads = self.threads
            o.inter_op_num_threads = 1
            o.log_severity_level = 3
            s = ort.InferenceSession(path, sess_options=o, providers=["CPUExecutionProvider"])
            self._s[key] = s
        return s

    def _path(self, model: str, f: str) -> str:
        return os.path.join(models_dir(), model, f)

    def models(self) -> dict[str, int]:
        """Какие части анализа доступны (и их версии) — сравнивается с индексом записи."""
        return {m: AI_FORMAT for m in installed_models()}

    def can_search(self) -> bool:
        return model_installed("siglip2")

    # ---- анализ картинки

    def analyze(self, rgb, want: Optional[set] = None, prev: Optional[dict] = None) -> dict:
        """Вектор и теги для изображения (numpy RGB). want — какие модели прогнать
        (по умолчанию все установленные); prev — уже посчитанное раньше (дополняется)."""
        out = dict(prev or {})
        done = dict(out.get("m") or {})
        want = set(want) if want is not None else set(installed_models())
        with self._lock:
            if "siglip2" in want and model_installed("siglip2"):
                out["e"] = pack_vec(self._siglip_image(rgb))
                done["siglip2"] = AI_FORMAT
            if "wd" in want and model_installed("wd"):
                tags, rating = self._wd(rgb)
                out["t"] = tags
                out["r"] = rating
                done["wd"] = AI_FORMAT
            if "nudenet" in want and model_installed("nudenet"):
                out["n"] = self._nudenet(rgb)
                done["nudenet"] = AI_FORMAT
        out["v"] = AI_FORMAT
        out["m"] = done
        return out

    def _siglip_image(self, rgb):
        import numpy as np
        x = _resize(rgb, 224, 224).astype(np.float32) / 255.0
        x = (x - 0.5) / 0.5
        x = x.transpose(2, 0, 1)[None]
        s = self._session("siglip_v", self._path("siglip2", "vision.onnx"))
        v = s.run(["pooler_output"], {"pixel_values": x})[0][0]
        return v / (np.linalg.norm(v) or 1.0)

    def _wd_load_tags(self):
        if self._wd_tags is None:
            import csv
            with open(self._path("wd", "selected_tags.csv"), encoding="utf-8") as f:
                rows = list(csv.reader(f))[1:]
            self._wd_tags = [(r[1], int(r[2])) for r in rows]
        return self._wd_tags

    def _wd(self, rgb):
        import numpy as np
        x = _resize(_pad_square(rgb, 255, True), 448, 448).astype(np.float32)
        x = x[:, :, ::-1][None]  # модель ждёт BGR 0..255, NHWC
        s = self._session("wd", self._path("wd", "model.onnx"))
        p = s.run(None, {s.get_inputs()[0].name: np.ascontiguousarray(x)})[0][0]
        names = self._wd_load_tags()
        rating, best = "general", -1.0
        tags = []
        for (name, cat), prob in zip(names, p):
            prob = float(prob)
            if cat == 9:
                if prob > best:
                    rating, best = name, prob
            elif (cat == 0 and prob >= WD_GENERAL_T) or (cat == 4 and prob >= WD_CHARACTER_T):
                tags.append([name, int(round(prob * 100))])
        tags.sort(key=lambda t: -t[1])
        return tags[:MAX_TAGS], rating

    def _nudenet(self, rgb):
        import numpy as np
        x = _resize(_pad_square(rgb, 0, False), 320, 320).astype(np.float32) / 255.0
        x = x.transpose(2, 0, 1)[None]
        s = self._session("nudenet", self._path("nudenet", "320n.onnx"))
        out = s.run(None, {s.get_inputs()[0].name: x})[0][0]  # (4 + 18, N)
        scores = out[4:4 + len(NUDENET_LABELS)].max(axis=1)
        return [NUDENET_LABELS[i] for i in np.argsort(-scores) if scores[i] >= NUDENET_T]

    # ---- запрос

    def embed_text(self, text: str):
        import numpy as np
        if self._tok is None:
            from tokenizers import Tokenizer
            self._tok = Tokenizer.from_file(self._path("siglip2", "tokenizer.json"))
            self._pad = self._tok.token_to_id("<pad>") or 0
        ids = self._tok.encode(text.lower()).ids[:64]
        ids = ids + [self._pad] * (64 - len(ids))
        with self._lock:
            s = self._session("siglip_t", self._path("siglip2", "text.onnx"))
            v = s.run(["pooler_output"], {"input_ids": np.array([ids], dtype=np.int64)})[0][0]
        return v / (np.linalg.norm(v) or 1.0)


# --------------------------------------------------------------------------- теги для людей

def labels_ru(ai: Optional[dict]) -> list[str]:
    """Человекочитаемые теги записи (по-русски, где есть перевод)."""
    if not ai:
        return []
    out = []
    n = ai.get("n") or []
    if any(x in NUDENET_NUDE for x in n):
        out.append("обнажённая натура")
    out += [NUDENET_RU.get(x, x) for x in n if x not in NUDENET_HIDDEN]
    r = ai.get("r")
    if r and r != "general":
        out.append(RATING_RU.get(r, r))
    out += [wd_ru(t[0]) for t in ai.get("t") or []]
    seen, res = set(), []
    for t in out:
        if t not in seen:
            seen.add(t)
            res.append(t)
    return res


def needs_analysis(ai: Optional[dict], available: dict[str, int]) -> set:
    """Какие модели ещё не прогнаны для записи (новая модель — дополнить индекс)."""
    done = (ai or {}).get("m") or {}
    return {m for m, ver in available.items() if done.get(m) != ver}


# --------------------------------------------------------------------------- поиск

_WORD = re.compile(r"[\wё]+", re.IGNORECASE)


def _norm(s: str) -> str:
    return s.lower().replace("ё", "е")


def _stem(w: str) -> str:
    """Грубая основа русского/английского слова: «купальнике» и «купальник» совпадут."""
    return w[:max(4, len(w) - 2)] if len(w) > 4 else w


def query_words(query: str) -> list[str]:
    return [_stem(w) for w in _WORD.findall(_norm(query)) if len(w) >= 3]


def tag_matches(query: str, ai: dict) -> int:
    """Сколько слов запроса нашлось в тегах записи (русских и английских)."""
    words = query_words(query)
    if not words:
        return 0
    hay = [_norm(t) for t in labels_ru(ai)]
    hay += [_norm(t[0].replace("_", " ")) for t in ai.get("t") or []]
    toks = {_stem(w) for t in hay for w in _WORD.findall(t)}
    # основы обрезаются по-разному («купальни-ке» / «купальн-ик»): совпадение — если одна
    # начинается с другой и общая часть не короче 4 букв
    return sum(1 for w in words
               if any((t.startswith(w) or w.startswith(t)) and min(len(t), len(w)) >= 4
                      or t == w for t in toks))


SEM_MIN = 0.075   # ниже — у SigLIP2 обычно «не то» (подобрано на тестовых фото)
SEM_SPREAD = 0.05


def rank(query: str, items: list[tuple[object, dict]], qvec=None, limit: int = 300):
    """items: [(ключ, ai)] → ([(ключ, оценка)] по убыванию, точные ли это совпадения).

    Оценка — косинус вектора запроса и картинки (SigLIP2) плюс прибавка за совпавшие
    слова в тегах. Без SigLIP — только совпадения тегов. Если ничего не прошло порог,
    возвращаются несколько самых похожих (exact=False) — интерфейс так и пишет.
    """
    import numpy as np
    nwords = len(query_words(query))
    scored = []
    for key, ai in items:
        sem = 0.0
        if qvec is not None and ai.get("e"):
            sem = float(np.dot(qvec, unpack_vec(ai["e"])))
        hits = tag_matches(query, ai)
        full = bool(nwords) and hits == nwords  # все слова запроса есть в тегах
        if qvec is None and not full:
            continue
        scored.append((key, sem + 0.06 * hits, sem, full))
    if not scored:
        return [], True
    scored.sort(key=lambda t: -t[1])
    if qvec is None:
        return [(k, sc) for k, sc, _s, _b in scored[:limit]], True
    # порог — по смысловой оценке; совпадения тегов только поднимают выше в списке
    cut = max(max(t[2] for t in scored) - SEM_SPREAD, SEM_MIN)
    good = [t for t in scored if t[2] >= cut or t[3]]
    if good:
        return [(k, sc) for k, sc, _s, _b in good[:limit]], True
    return [(k, sc) for k, sc, _s, _b in scored[:5]], False


def similar(items: list[tuple[object, dict]], vec, exclude=None, limit: int = 60):
    """Похожие картинки по вектору другой картинки: [(ключ, сходство)] по убыванию.

    У картинок между собой сходство по SigLIP высокое даже у несвязанных (0,6–0,8),
    поэтому порог относительный: всё, что не намного хуже лучшего совпадения.
    """
    import numpy as np
    scored = [(k, float(np.dot(vec, unpack_vec(a["e"])))) for k, a in items
              if k != exclude and a.get("e")]
    if not scored:
        return []
    scored.sort(key=lambda t: -t[1])
    cut = scored[0][1] - 0.12
    out = [t for t in scored if t[1] >= cut]
    return (out if len(out) >= 5 else scored[:5])[:limit]
