from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import ctypes as ct
from ctypes import wintypes
import os

from .models import canonical_json


class WalletCustodyProvider(ABC):
    backend_id: str

    @abstractmethod
    def protect(self, plaintext: bytes, *, context: dict[str, object]) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def unprotect(self, protected_blob: bytes, *, context: dict[str, object]) -> bytes:
        raise NotImplementedError

    def status(self) -> dict[str, object]:
        return {
            "backend_id": self.backend_id,
            "available": True,
        }


class PlaintextCustodyProvider(WalletCustodyProvider):
    backend_id = "plaintext"

    def protect(self, plaintext: bytes, *, context: dict[str, object]) -> bytes:
        return bytes(plaintext)

    def unprotect(self, protected_blob: bytes, *, context: dict[str, object]) -> bytes:
        return bytes(protected_blob)

    def status(self) -> dict[str, object]:
        status = super().status()
        status["warning"] = "Plaintext custody is intended only for explicit insecure development mode."
        return status


class _DataBlob(ct.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ct.POINTER(ct.c_byte)),
    ]


class WindowsDpapiCustodyProvider(WalletCustodyProvider):
    backend_id = "windows_dpapi"
    _CRYPTPROTECT_UI_FORBIDDEN = 0x1
    _CRYPTPROTECT_LOCAL_MACHINE = 0x4

    def __init__(self, *, scope: str = "current_user"):
        if os.name != "nt":
            raise ValueError("Windows DPAPI custody is only available on Windows.")
        normalized_scope = scope.strip().lower()
        if normalized_scope not in {"current_user", "local_machine"}:
            raise ValueError("DPAPI custody scope must be 'current_user' or 'local_machine'.")
        self.scope = normalized_scope
        self._crypt32 = ct.WinDLL("crypt32", use_last_error=True)
        self._kernel32 = ct.WinDLL("kernel32", use_last_error=True)
        self._crypt32.CryptProtectData.argtypes = [
            ct.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ct.POINTER(_DataBlob),
            ct.c_void_p,
            ct.c_void_p,
            wintypes.DWORD,
            ct.POINTER(_DataBlob),
        ]
        self._crypt32.CryptProtectData.restype = wintypes.BOOL
        self._crypt32.CryptUnprotectData.argtypes = [
            ct.POINTER(_DataBlob),
            ct.POINTER(wintypes.LPWSTR),
            ct.POINTER(_DataBlob),
            ct.c_void_p,
            ct.c_void_p,
            wintypes.DWORD,
            ct.POINTER(_DataBlob),
        ]
        self._crypt32.CryptUnprotectData.restype = wintypes.BOOL
        self._kernel32.LocalFree.argtypes = [ct.c_void_p]
        self._kernel32.LocalFree.restype = ct.c_void_p

    def protect(self, plaintext: bytes, *, context: dict[str, object]) -> bytes:
        data_in = self._blob_from_bytes(plaintext)
        entropy = self._blob_from_bytes(self._entropy_bytes(context))
        data_out = _DataBlob()
        flags = self._CRYPTPROTECT_UI_FORBIDDEN
        if self.scope == "local_machine":
            flags |= self._CRYPTPROTECT_LOCAL_MACHINE
        if not self._crypt32.CryptProtectData(
            ct.byref(data_in),
            "qr-chain-wallet-state",
            ct.byref(entropy),
            None,
            None,
            flags,
            ct.byref(data_out),
        ):
            raise OSError(ct.get_last_error(), "CryptProtectData failed.")
        try:
            return self._bytes_from_blob(data_out)
        finally:
            self._free_blob(data_out)

    def unprotect(self, protected_blob: bytes, *, context: dict[str, object]) -> bytes:
        data_in = self._blob_from_bytes(protected_blob)
        entropy = self._blob_from_bytes(self._entropy_bytes(context))
        data_out = _DataBlob()
        description = wintypes.LPWSTR()
        if not self._crypt32.CryptUnprotectData(
            ct.byref(data_in),
            ct.byref(description),
            ct.byref(entropy),
            None,
            None,
            self._CRYPTPROTECT_UI_FORBIDDEN,
            ct.byref(data_out),
        ):
            raise OSError(ct.get_last_error(), "CryptUnprotectData failed.")
        try:
            return self._bytes_from_blob(data_out)
        finally:
            if description:
                self._kernel32.LocalFree(description)
            self._free_blob(data_out)

    def status(self) -> dict[str, object]:
        status = super().status()
        status["scope"] = self.scope
        return status

    @staticmethod
    def _blob_from_bytes(data: bytes) -> _DataBlob:
        blob = _DataBlob()
        if not data:
            blob.cbData = 0
            blob.pbData = ct.cast(None, ct.POINTER(ct.c_byte))
            return blob
        buffer = (ct.c_byte * len(data)).from_buffer_copy(data)
        blob.cbData = len(data)
        blob.pbData = ct.cast(buffer, ct.POINTER(ct.c_byte))
        blob._buffer = buffer  # keep alive for call lifetime
        return blob

    @staticmethod
    def _bytes_from_blob(blob: _DataBlob) -> bytes:
        if not blob.pbData or blob.cbData == 0:
            return b""
        return bytes(ct.string_at(blob.pbData, blob.cbData))

    def _free_blob(self, blob: _DataBlob) -> None:
        if blob.pbData:
            self._kernel32.LocalFree(blob.pbData)

    @staticmethod
    def _entropy_bytes(context: dict[str, object]) -> bytes:
        return canonical_json(context).encode("utf-8")


@dataclass(frozen=True)
class WalletCustodyConfig:
    mode: str = "auto"
    scope: str = "current_user"


def build_wallet_custody_provider(config: WalletCustodyConfig) -> WalletCustodyProvider:
    mode = config.mode.strip().lower()
    if mode == "auto":
        if os.name == "nt":
            return WindowsDpapiCustodyProvider(scope=config.scope)
        return PlaintextCustodyProvider()
    if mode == "windows_dpapi":
        return WindowsDpapiCustodyProvider(scope=config.scope)
    if mode == "plaintext":
        return PlaintextCustodyProvider()
    raise ValueError(
        "Unsupported wallet custody mode. Expected one of: auto, windows_dpapi, plaintext."
    )
