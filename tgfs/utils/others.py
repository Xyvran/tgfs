from typing import Iterable, Optional, TypeVar

T = TypeVar("T")


def exclude_none(iterable: Iterable[Optional[T]]) -> Iterable[T]:
    return (item for item in iterable if item is not None)


def is_big_file(size: int) -> bool:
    return size > 10 * 1024 * 1024  # 10 MB


def flood_wait_seconds(ex: BaseException) -> Optional[int]:
    """How long Telegram asks us to wait, or ``None`` for other errors.

    Retrying a flood error on our own schedule is what turns a short
    throttle into a long one, so the wait Telegram names has to win over
    any backoff we would pick. Telethon calls the field ``seconds`` and
    Pyrogram calls it ``value``; probing the attribute keeps this free of
    an import of either library.
    """
    if "flood" not in type(ex).__name__.lower():
        return None
    for attr in ("seconds", "value"):
        if isinstance(value := getattr(ex, attr, None), int):
            return value
    return None
