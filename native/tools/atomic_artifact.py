"""Same-directory replacement for host build artifacts; I/O failures stay visible."""

import os
from pathlib import Path
import tempfile
import time


_WINDOWS_DELAYS = (0.005, 0.01, 0.02, 0.04, 0.08, 0.08, 0.08)


def _file_operation(operation):
    for attempt in range(len(_WINDOWS_DELAYS) + 1):
        try:
            return operation()
        except OSError as error:
            if (os.name != "nt" or getattr(error, "winerror", None) not in (5, 32, 33) or
                    attempt == len(_WINDOWS_DELAYS)):
                raise
            time.sleep(_WINDOWS_DELAYS[attempt])


def remove_artifact(path: Path) -> None:
    _file_operation(lambda: path.unlink(missing_ok=True))


def atomic_write(path: Path, data: bytes) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        _file_operation(lambda: os.replace(temporary, path))
    finally:
        if temporary is not None:
            remove_artifact(temporary)
