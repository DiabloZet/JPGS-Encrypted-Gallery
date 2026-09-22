"""Настройка glibc malloc: крупные буферы пикселей сразу возвращаются системе.

По умолчанию glibc после освобождения большого блока поднимает порог mmap, и
следующие мегабайтные буферы остаются в куче процесса — RSS растёт при листании.
Фиксируем порог и ограничиваем число арен (потоки-загрузчики иначе заводят свои).
"""

import ctypes
import ctypes.util

M_TRIM_THRESHOLD = -1
M_MMAP_THRESHOLD = -3
M_ARENA_MAX = -8

_libc = None


def tune() -> None:
    global _libc
    try:
        _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
        _libc.mallopt(M_MMAP_THRESHOLD, 256 * 1024)
        _libc.mallopt(M_TRIM_THRESHOLD, 1024 * 1024)
        _libc.mallopt(M_ARENA_MAX, 2)
    except (OSError, AttributeError):
        _libc = None


def trim() -> None:
    if _libc is not None:
        try:
            _libc.malloc_trim(0)
        except AttributeError:
            pass
