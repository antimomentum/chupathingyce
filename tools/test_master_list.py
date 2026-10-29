"""Runs the C tests of the server browser's reading of OpenCE's master
servers (port/linux/src/master_list.c, with p2p_crypto.c's signatures) with
the build machine's C compiler: masters.txt's lines, the official master, a
list's signature, key and freshness checks, and its entries. The unit needs
no SDL or game: the platform headers are left out, and the two functions it
calls from them are declared ahead."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def compiler():
    """the first of clang, cc and gcc found, or None"""
    for name in ("clang", "cc", "gcc"):
        path = shutil.which(name)
        if path:
            return path
    return None


def test_master_list(tmp_path):
    """Builds master_list.c with its tests, warnings as errors, and runs them."""
    cc = compiler()
    if not cc:
        pytest.skip("no C compiler")
    prelude = tmp_path / "prelude.h"
    prelude.write_text("void posix_random_bytes(void *buffer, unsigned long size);\n"
                       "void platform_log(const char *format, ...);\n")
    binary = tmp_path / "master_list_test"
    monocypher = ROOT / "port" / "third_party" / "monocypher"
    build = subprocess.run(
        [cc, "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror", "-O1",
         "-D__HALO_LINUX_PLATFORM_H", "-D__HALO_LINUX_POSIX_H", "-include", str(prelude),
         "-I", str(ROOT / "port" / "linux" / "src"), "-I", str(monocypher),
         str(ROOT / "port" / "linux" / "tests" / "master_list_test.c"),
         str(ROOT / "port" / "linux" / "src" / "master_list.c"),
         str(ROOT / "port" / "linux" / "src" / "p2p_crypto.c"),
         str(monocypher / "monocypher.c"), str(monocypher / "monocypher-ed25519.c"),
         "-o", str(binary)],
        capture_output=True, text=True,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout
