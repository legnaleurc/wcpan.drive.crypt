from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock
from typing import cast

from wcpan.drive.crypt.lib import EncryptHasher, encrypt
from wcpan.drive.core.types import Hasher

from ._lib import aexpect


class HasherTestCase(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._mock = cast(Hasher, AsyncMock(spec=Hasher))
        self._hasher = EncryptHasher(self._mock)

    async def testUpdate(self):
        chunk = b"1234abcd"
        await self._hasher.update(chunk)
        chunk = encrypt(chunk)
        aexpect(self._mock.update).assert_awaited_once_with(chunk)

    async def testDigest(self):
        await self._hasher.digest()
        aexpect(self._mock.digest).assert_awaited_once_with()

    async def testHexdigest(self):
        await self._hasher.hexdigest()
        aexpect(self._mock.hexdigest).assert_awaited_once_with()

    async def testCopy(self):
        clone = await self._hasher.copy()
        aexpect(self._mock.copy).assert_awaited_once_with()
        self.assertIsInstance(clone, EncryptHasher)
