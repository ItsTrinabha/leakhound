"""Output formats. Every reporter exposes ``render(result, ...) -> str``."""

from __future__ import annotations

from typing import Callable

from . import console, json_report, sarif

FORMATS: dict[str, Callable[..., str]] = {
    "console": console.render,
    "json": json_report.render,
    "sarif": sarif.render,
}

__all__ = ["FORMATS"]
