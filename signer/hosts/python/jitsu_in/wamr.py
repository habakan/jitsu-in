"""WAMR's classic interpreter through ctypes, enough to drive parser.wasm and signer.wasm.

libiwasm is the one native piece, and it is the interpreter the device runs. Nothing here is compiled:
the bindings are plain ctypes, so a SeedSigner OS image needs only the shared library.
"""

import ctypes
import os
from ctypes import POINTER, c_bool, c_char_p, c_int32, c_uint8, c_uint32, c_uint64, c_void_p


def _load(path=None):
    path = path or os.environ.get("JITSU_IN_LIBIWASM") or "libiwasm" + (".dylib" if os.uname().sysname == "Darwin" else ".so")
    lib = ctypes.CDLL(path)
    for name, res, args in [
        ("wasm_runtime_init", c_bool, []),
        ("wasm_runtime_load", c_void_p, [POINTER(c_uint8), c_uint32, c_char_p, c_uint32]),
        ("wasm_runtime_get_import_count", c_int32, [c_void_p]),
        ("wasm_runtime_instantiate", c_void_p, [c_void_p, c_uint32, c_uint32, c_char_p, c_uint32]),
        ("wasm_runtime_create_exec_env", c_void_p, [c_void_p, c_uint32]),
        ("wasm_runtime_lookup_function", c_void_p, [c_void_p, c_char_p]),
        ("wasm_runtime_call_wasm", c_bool, [c_void_p, c_void_p, c_uint32, POINTER(c_uint32)]),
        ("wasm_runtime_get_exception", c_char_p, [c_void_p]),
        ("wasm_runtime_get_default_memory", c_void_p, [c_void_p]),
        ("wasm_memory_get_cur_page_count", c_uint64, [c_void_p]),
        ("wasm_memory_get_bytes_per_page", c_uint64, [c_void_p]),
        ("wasm_memory_get_base_address", c_void_p, [c_void_p]),
    ]:
        f = getattr(lib, name)
        f.restype, f.argtypes = res, args
    if not lib.wasm_runtime_init():
        raise RuntimeError("WAMR initialization failed")
    return lib


_lib = None


class Instance:
    """One instance of a module with no imports. `memory` is a writable memoryview of its linear
    memory, valid for the instance's life because neither module can grow it."""

    def __init__(self, wasm: bytes, lib_path=None):
        global _lib
        _lib = _lib or _load(lib_path)
        # WAMR keeps pointers into these bytes, so they live as long as the instance
        self._bytes = (c_uint8 * len(wasm)).from_buffer_copy(wasm)
        err = ctypes.create_string_buffer(256)
        self._module = _lib.wasm_runtime_load(self._bytes, len(wasm), err, 256)
        if not self._module:
            raise RuntimeError(err.value.decode() or "WAMR could not load the module")
        if _lib.wasm_runtime_get_import_count(self._module):
            raise RuntimeError("the module must have no imports")
        self._inst = _lib.wasm_runtime_instantiate(self._module, 16384, 0, err, 256)
        if not self._inst:
            raise RuntimeError(err.value.decode() or "WAMR instantiation failed")
        self._env = _lib.wasm_runtime_create_exec_env(self._inst, 16384)
        mem = _lib.wasm_runtime_get_default_memory(self._inst)
        size = _lib.wasm_memory_get_cur_page_count(mem) * _lib.wasm_memory_get_bytes_per_page(mem)
        self.memory = memoryview((c_uint8 * size).from_address(_lib.wasm_memory_get_base_address(mem))).cast("B")
        self._funcs = {}

    def __getattr__(self, name):
        """An export as a function of i32 arguments returning a signed i32."""
        f = self._funcs.get(name)
        if f is None:
            f = _lib.wasm_runtime_lookup_function(self._inst, name.encode())
            if not f:
                raise AttributeError(f"no export {name}")
            self._funcs[name] = f

        def call(*args):
            argv = (c_uint32 * max(len(args), 1))(*(a & 0xFFFFFFFF for a in args))
            if not _lib.wasm_runtime_call_wasm(self._env, f, len(args), argv):
                raise RuntimeError((_lib.wasm_runtime_get_exception(self._inst) or b"WAMR call failed").decode())
            return c_int32(argv[0]).value

        return call
