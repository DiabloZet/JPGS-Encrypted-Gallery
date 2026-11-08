"""Фоновая ИИ-индексация папки — только пока работает JPGS.

Поток с наименьшим приоритетом проходит по файлам открытой папки, для каждой картинки
(и кадра из каждого видео) считает теги и вектор смысла (jpgs.ai) и дописывает их в
зашифрованный индекс самого файла. При смене папки или закрытии программы поток
останавливается; на следующем запуске продолжит с непроиндексированных записей.
"""

from __future__ import annotations

import os
import threading
import traceback
from typing import Callable, Optional

from . import ai as A
from . import container as C

FLUSH_EVERY = 20  # записей одного файла между записями индекса на диск


class Indexer:
    def __init__(self, threads: int = 2,
                 on_progress: Optional[Callable[[int, int, bool], None]] = None,
                 on_file: Optional[Callable[[str], None]] = None):
        """on_progress(готово, всего, идёт ли) и on_file(путь) вызываются из фонового потока."""
        self.threads = threads
        self.on_progress = on_progress
        self.on_file = on_file
        self.engine: Optional[A.Engine] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.done = self.total = 0
        self.running = False

    # ---- управление

    def start(self, files: list[tuple[str, object]]):
        """Начать (заново) индексацию: files — [(путь, ключ)]. Предыдущий проход прерывается."""
        self.stop()
        if not files or A.missing_libs() or not A.installed_models():
            return
        if self.engine is None or self.engine.threads != self.threads:
            self.engine = A.Engine(self.threads)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(list(files), self._stop),
                                        name="jpgs-ai-index", daemon=True)
        self._thread.start()

    def stop(self, wait: float = 0):
        self._stop.set()
        t = self._thread
        if t is not None and wait:
            t.join(wait)

    # ---- поток

    def _report(self, running: bool):
        if self.on_progress:
            try:
                self.on_progress(self.done, self.total, running)
            except Exception:  # noqa: BLE001
                traceback.print_exc()

    def _run(self, files, stop: threading.Event):
        try:  # самый низкий приоритет: просмотр и видео не должны тормозить
            os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 19)
        except (AttributeError, OSError):
            pass
        eng = self.engine
        avail = eng.models()
        self.running = True
        self.done = self.total = 0
        plan = []
        try:
            for path, cipher in files:
                if stop.is_set():
                    return
                try:
                    jf = C.open_media(path, cipher)
                    es = jf.entries()
                except Exception:  # noqa: BLE001 — чужой ключ, повреждение: пропускаем
                    continue
                todo = []
                for i, e in enumerate(es):
                    self.total += 1
                    need = A.needs_analysis(e.ai, avail)
                    if need:
                        todo.append((i, e, need))
                    else:
                        self.done += 1
                if todo:
                    plan.append((path, cipher, todo))
            self._report(True)
            for path, cipher, todo in plan:
                if stop.is_set():
                    return
                self._index_file(path, cipher, todo, stop)
        finally:
            self.running = False
            self._report(False)

    def _index_file(self, path, cipher, todo, stop):
        jf = C.open_media(path, cipher)
        updates: dict[int, dict] = {}
        expect: dict[int, tuple[int, int]] = {}

        def flush():
            if not updates:
                return
            try:
                C.set_ai(path, dict(updates), cipher, dict(expect))
                if self.on_file:
                    self.on_file(path)
            except (FileNotFoundError, C.WrongKey):
                pass  # файл удалили, переименовали или перешифровали, пока шёл анализ
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            updates.clear()
            expect.clear()

        for i, e, need in todo:
            if stop.is_set():
                break
            try:
                rgb = self._pixels(jf, i, e)
                ai = self.engine.analyze(rgb, need, e.ai)
            except Exception:  # noqa: BLE001
                # не читается/не декодируется: пометить как обработанную, чтобы не
                # пытаться снова при каждом запуске
                ai = dict(e.ai or {})
                ai.update({"v": A.AI_FORMAT, "x": 1,
                           "m": {**(ai.get("m") or {}), **{m: A.AI_FORMAT for m in need}}})
            updates[i] = ai
            expect[i] = (e.start, e.length)
            self.done += 1
            self._report(True)
            if len(updates) >= FLUSH_EVERY:
                flush()
        flush()

    @staticmethod
    def _pixels(jf, i, e):
        import numpy as np
        if e.is_video:
            from .video import grab_frame
            data, w, h, stride, _info = grab_frame(jf.path, jf.cipher, 640,
                                                   entry=None if jf.is_video else e)
            rows = np.frombuffer(data, dtype=np.uint8)[:stride * h].reshape(h, stride)
            return np.ascontiguousarray(rows[:, :w * 3].reshape(h, w, 3))
        return A.decode_rgb(jf.read_image(i))
