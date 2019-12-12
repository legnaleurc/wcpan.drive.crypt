from typing import AsyncIterator
import contextlib

import numpy

from wcpan.drive.core.types import Node
from wcpan.drive.core.abc import ReadableFile, WritableFile, Hasher
from wcpan.drive.core.exceptions import DriveError


class InvalidCryptVersion(DriveError):

    pass


class DecryptReadableFile(ReadableFile):

    def __init__(self, stream: ReadableFile) -> None:
        self._stream = stream
        self._raii = None

    async def __aenter__(self) -> ReadableFile:
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(self._stream)
            self._raii = stack.pop_all()
        return self

    async def __aexit__(self, et, e, tb) -> bool:
        await self._raii.aclose()
        self._raii = None

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield decrypt(chunk)

    async def read(self, length: int) -> bytes:
        chunk = await self._stream.read(length)
        return decrypt(chunk)

    async def seek(self, offset: int) -> None:
        await self._stream.seek(offset)

    async def node(self) -> Node:
        return await self._stream.node()


class EncryptWritableFile(WritableFile):

    def __init__(self, stream: WritableFile) -> None:
        self._stream = stream
        self._raii = None

    async def __aenter__(self) -> WritableFile:
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(self._stream)
            self._raii = stack.pop_all()
        return self

    async def __aexit__(self, et, ev, tb) -> bool:
        await self._raii.aclose()
        self._raii = None

    async def tell(self) -> int:
        return await self._stream.tell()

    async def seek(self, offset: int) -> None:
        await self._stream.seek(offset)

    async def write(self, chunk: bytes) -> int:
        crypted = encrypt(chunk)
        return await self._stream.write(crypted)

    async def node(self) -> Node:
        return await self._stream.node()


class EncryptHasher(Hasher):

    def __init__(self, hasher: Hasher) -> None:
        self._hasher = hasher

    def update(self, data: bytes) -> None:
        self._hasher.update(encrypt(data))

    def digest(self) -> bytes:
        return self._hasher.digest()

    def hexdigest(self) -> str:
        return self._hasher.hexdigest()

    def copy(self) -> Hasher:
        return EncryptHasher(self._hasher.copy())


def encrypt(chunk: bytes) -> bytes:
    buffer = numpy.frombuffer(chunk, dtype=numpy.uint8)
    buffer = numpy.bitwise_not(buffer)
    return buffer.tobytes()


def decrypt(chunk: bytes) -> bytes:
    buffer = numpy.frombuffer(chunk, dtype=numpy.uint8)
    buffer = numpy.bitwise_not(buffer)
    return buffer.tobytes()


def encrypt_name(name: str) -> str:
    bname = name.encode('utf-8')
    bname = encrypt(bname)
    return ''.join(('%02x' % c for c in bname))


def decrypt_name(name: str) -> str:
    hex_list = (name[i:i+2] for i in range(0, len(name), 2))
    bname = bytes((int(c, 16) for c in hex_list))
    bname = decrypt(bname)
    return bname.decode('utf-8')
