# -*- coding: utf-8 -*-
"""G-LOCK · El lock ancla y comprueba. (H-06) Delega en `core.lock`, que es donde vive la regla."""

from __future__ import annotations

from core.lock import verify
from core.model import HIGH

GATE_ID = "G-LOCK"
TITLE = "Lock criptográfico del origen"


def run(ctx):
    result = verify(ctx.workspace, ctx.lock, check_remote=not ctx.offline)
    result.id, result.name, result.severity = GATE_ID, TITLE, HIGH
    return result
