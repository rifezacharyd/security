"""Async file tailer — follows a log file and yields new lines as they appear.

Designed for cowrie.json under T-Pot, which rotates daily; we handle
truncation and rotation by detecting inode changes.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path


async def tail(path: Path, *, poll_seconds: float = 0.5) -> AsyncIterator[str]:
    """Yield newly appended lines from `path` forever."""
    while True:
        try:
            fd = open(path, "r", encoding="utf-8", errors="replace")  # noqa: SIM115
        except FileNotFoundError:
            await asyncio.sleep(poll_seconds * 4)
            continue

        try:
            fd.seek(0, os.SEEK_END)
            inode = os.fstat(fd.fileno()).st_ino
            buffer = ""
            while True:
                chunk = fd.read()
                if chunk:
                    buffer += chunk
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        yield line
                else:
                    await asyncio.sleep(poll_seconds)

                # Rotation detection: stat the path and compare inodes.
                try:
                    if os.stat(path).st_ino != inode:
                        break
                except FileNotFoundError:
                    break
        finally:
            fd.close()
