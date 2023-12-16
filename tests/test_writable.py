from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock
from typing import cast

from wcpan.drive.crypt._lib import EncryptWritableFile, encrypt
from wcpan.drive.core.types import WritableFile

from ._lib import aexpect


class EncryptWritableFileTestCase(IsolatedAsyncioTestCase):
    async def testTell(self):
        mock = cast(WritableFile, AsyncMock(spec=WritableFile))

        fout = EncryptWritableFile(mock)
        await fout.tell()

        aexpect(mock.tell).assert_awaited_once_with()

    async def testSeek(self):
        mock = cast(WritableFile, AsyncMock(spec=WritableFile))

        fout = EncryptWritableFile(mock)
        await fout.seek(123)

        aexpect(mock.seek).assert_awaited_once_with(123)

    async def testWrite(self):
        content = b"xyz456"
        mock = cast(WritableFile, AsyncMock(spec=WritableFile))

        fout = EncryptWritableFile(mock)
        await fout.write(content)

        content = encrypt(content)
        aexpect(mock.write).assert_awaited_once_with(content)

    async def testNode(self):
        mock = cast(WritableFile, AsyncMock(spec=WritableFile))

        fout = EncryptWritableFile(mock)
        await fout.node()

        aexpect(mock.node).assert_awaited_once_with()
