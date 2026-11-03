"""Real Windows sharing handles and bounded host-operation failure behavior."""

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import sys
import tempfile
import threading
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import atomic_artifact as artifact


def require_error(operation, expected):
    try:
        operation()
    except OSError as error:
        assert error is expected
    else:
        raise AssertionError("failed host operation was silently accepted")


def check_budget():
    for code in (5, 32, 33, 2, None):
        error = PermissionError("controlled file-operation failure")
        error.winerror = code
        calls = []
        def fail():
            calls.append(1)
            raise error
        with patch.object(artifact.time, "sleep") as sleep:
            require_error(lambda: artifact._file_operation(fail), error)
        retryable = os.name == "nt" and code in (5, 32, 33)
        assert len(calls) == (8 if retryable else 1)
        assert sleep.call_count == (7 if retryable else 0)
        assert sum(call.args[0] for call in sleep.call_args_list) <= 0.316


def windows_handles(directory):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    target = directory / "artifact.hpp"
    before, after = b"old verified artifact", b"new verified artifact"
    artifact.atomic_write(target, before)
    def hold():
        handle = kernel.CreateFileW(str(target), 0x80000000, 1, None, 3, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle
    def close(handle):
        if not kernel.CloseHandle(handle): raise ctypes.WinError(ctypes.get_last_error())
    for operation in ("replace", "remove"):
        artifact.atomic_write(target, before)
        handle = hold()
        observed, release = threading.Event(), threading.Event()
        failures = []
        def close_later():
            if not release.wait(5): failures.append("file operation did not reach its shared-handle refusal")
            try: close(handle)
            except OSError as error: failures.append(str(error))
        worker = threading.Thread(target=close_later)
        worker.start()
        def record_sleep(delay):
            # The real first operation has already failed while the handle is held.
            if not observed.is_set():
                assert target.read_bytes() == before
                observed.set()
                release.set()
            threading.Event().wait(delay)
        try:
            with patch.object(artifact.time, "sleep", record_sleep):
                if operation == "replace": artifact.atomic_write(target, after)
                else: artifact.remove_artifact(target)
        finally:
            release.set(); worker.join(6)
        assert observed.is_set() and not worker.is_alive() and not failures
        assert (target.read_bytes() == after) if operation == "replace" else not target.exists()
    artifact.atomic_write(target, before)
    handle = hold()
    try:
        try:
            artifact.atomic_write(target, after)
        except OSError as error:
            assert error.winerror in (5, 32, 33)
        else:
            raise AssertionError("persistent shared handle accepted a replacement")
        assert target.read_bytes() == before
        assert {path.name for path in directory.iterdir()} == {target.name}
    finally:
        close(handle)
    # A later valid request succeeds with the persistent failure removed.
    artifact.atomic_write(target, after)
    assert target.read_bytes() == after
    with patch.object(artifact.os, "replace", side_effect=OSError("unexpected replacement error")):
        try: artifact.atomic_write(target, before)
        except OSError as error: assert str(error) == "unexpected replacement error"
        else: raise AssertionError("unexpected error became stale success")
    assert target.read_bytes() == after and {path.name for path in directory.iterdir()} == {target.name}


def main():
    check_budget()
    parent = Path(sys.argv[1])
    with tempfile.TemporaryDirectory(dir=parent) as temporary:
        directory = Path(temporary)
        if os.name == "nt": windows_handles(directory)
        else:
            target = directory / "artifact"
            artifact.atomic_write(target, b"data")
            assert target.read_bytes() == b"data"
            artifact.remove_artifact(target)
    print("host artifacts: known Windows sharing recovery, persistent-lock/unknown-error preservation, cleanup and bounded8-attempt policy passed")


if __name__ == "__main__":
    main()
