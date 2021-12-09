#-*- coding: utf-8 -*-

import datetime
import re
import unittest
from unittest.mock import Mock, AsyncMock

from wcpan.drive.crypt.util import (
    DecryptReadableFile,
    EncryptHasher,
    EncryptWritableFile,
    decrypt,
    decrypt_name,
    encrypt,
    encrypt_name,
)
from wcpan.drive.crypt.middleware import CryptMiddleware, InvalidCryptVersion
from wcpan.drive.core.types import Node


class TestCrypt(unittest.TestCase):

    def testBinaryCrypt(self):
        binary = bytes(range(255))

        encoded = encrypt(binary)
        self.assertNotEqual(encoded, binary)
        self.assertEqual(len(encoded), len(binary))

        decoded = decrypt(encoded)
        self.assertEqual(binary, decoded)

    def testNameCrypt(self):
        text = (
            '1234567890'
            'abcdefghijklmnopqrstuvwxyz'
            '().~@-[]{}:,'
            'レオナルド・ディ・セル・ピエーロ・ダ・ヴィンチ'
        )

        encoded = encrypt_name(text)
        self.assertNotEqual(encoded, text)
        matched = re.match(r'^[a-z0-9]+$', encoded)
        self.assertIsNotNone(matched)

        decoded = decrypt_name(encoded)
        self.assertEqual(text, decoded)


class TestHasher(unittest.TestCase):

    def setUp(self):
        self._mock = Mock()
        self._hasher = EncryptHasher(self._mock)

    def tearDown(self):
        self._hasher = None
        self._mock = None

    def testUpdate(self):
        chunk = b'1234abcd'
        self._hasher.update(chunk)
        chunk = encrypt(chunk)
        self._mock.update.assert_called_once_with(chunk)

    def testDigest(self):
        self._hasher.digest()
        self._mock.digest.assert_called_once_with()

    def testHexdigest(self):
        self._hasher.hexdigest()
        self._mock.hexdigest.assert_called_once_with()

    def testCopy(self):
        clone = self._hasher.copy()
        self._mock.copy.assert_called_once_with()
        self.assertIsInstance(clone, EncryptHasher)


class TestDecryptReadableFile(unittest.IsolatedAsyncioTestCase):

    async def testContextManager(self):
        mock = AsyncMock()
        async with DecryptReadableFile(mock) as dummy_fin:
            pass
        mock.__aenter__.assert_awaited_once_with(mock)
        mock.__aexit__.assert_awaited_once_with(mock, None, None, None)

    async def testIterable(self):
        content_list = [
            b'xyz',
            b'123',
        ]
        async def fake_iterator(self):
            for content in content_list:
                yield encrypt(content)

        mock = AsyncMock()
        mock.__aiter__ = fake_iterator

        async with DecryptReadableFile(mock) as fin:
            chunk_list = [chunk async for chunk in fin]

        self.assertEqual(chunk_list, content_list)

    async def testRead(self):
        content = b'789abc'
        mock = AsyncMock()
        mock.read = AsyncMock(return_value=encrypt(content))
        async with DecryptReadableFile(mock) as fin:
            chunk = await fin.read(123)

        mock.read.assert_awaited_once_with(123)
        self.assertEqual(content, chunk)

    async def testSeek(self):
        mock = AsyncMock()
        async with DecryptReadableFile(mock) as fin:
            await fin.seek(123)
        mock.seek.assert_awaited_once_with(123)

    async def testNode(self):
        mock = AsyncMock()
        async with DecryptReadableFile(mock) as fin:
            await fin.node()
        mock.node.assert_awaited_once_with()


class TestEncryptWritableFile(unittest.IsolatedAsyncioTestCase):

    async def testContextManager(self):
        mock = AsyncMock()
        async with EncryptWritableFile(mock) as dummy_fout:
            pass
        mock.__aenter__.assert_awaited_once_with(mock)
        mock.__aexit__.assert_awaited_once_with(mock, None, None, None)

    async def testTell(self):
        mock = AsyncMock()
        async with EncryptWritableFile(mock) as fout:
            await fout.tell()
        mock.tell.assert_awaited_once_with()

    async def testSeek(self):
        mock = AsyncMock()
        async with EncryptWritableFile(mock) as fout:
            await fout.seek(123)
        mock.seek.assert_awaited_once_with(123)

    async def testWrite(self):
        content = b'xyz456'
        mock = AsyncMock()
        async with EncryptWritableFile(mock) as fout:
            await fout.write(content)

        content = encrypt(content)
        mock.write.assert_awaited_once_with(content)

    async def testNode(self):
        mock = AsyncMock()
        async with EncryptWritableFile(mock) as fout:
            await fout.node()
        mock.node.assert_awaited_once_with()


class TestMiddleware(unittest.IsolatedAsyncioTestCase):

    async def testFetchChanges(self):
        context = Mock()
        driver = AsyncMock()
        middleware = CryptMiddleware(context, driver)

        async def fake_fetch_changes(dummy):
            yield '1', [
                {
                    'removed': True,
                    'id': 1,
                },
                {
                    'removed': False,
                    'node': {
                        'name': 'name',
                        'private': None,
                    },
                },
                {
                    'removed': False,
                    'node': {
                        'name': encrypt_name('name'),
                        'private': {
                            'crypt': '1',
                        },
                    },
                },
            ]
        driver.fetch_changes = fake_fetch_changes

        async for dummy, changes in middleware.fetch_changes('1'):
            # should not touch remove changes
            self.assertEqual(changes[0], {
                'removed': True,
                'id': 1,
            })

            # should not touch normal files
            self.assertEqual(changes[1], {
                'removed': False,
                'node': {
                    'name': 'name',
                    'private': None,
                },
            })

            # should decrypt the name
            self.assertEqual(changes[1]['node']['name'], 'name')

        async def fake_fetch_changes_2(dummy):
            yield '1', [
                {
                    'removed': False,
                    'node': {
                        'name': 'name',
                        'private': {
                            'crypt': '-1',
                        },
                    },
                },
            ]
        driver.fetch_changes = fake_fetch_changes_2

        # should not accept invalid crypt version
        with self.assertRaises(InvalidCryptVersion):
            async for dummy, changes in middleware.fetch_changes('1'):
                pass

    async def testRenameNode(self):
        context = Mock()
        driver = AsyncMock()
        middleware = CryptMiddleware(context, driver)

        # should not touch normal files
        node = create_node('name_1', None)
        new_parent = create_node('name_2', None)
        await middleware.rename_node(node, new_parent=new_parent, new_name='new_name')
        driver.rename_node.assert_awaited_once_with(node, new_parent, 'new_name')
        driver.rename_node.reset_mock()

        # should not accept invalid crypt version
        node = create_node('name_1', {
            'crypt': '-1',
        })
        new_parent = create_node('name_2', None)
        with self.assertRaises(InvalidCryptVersion):
            await middleware.rename_node(node, new_parent=new_parent, new_name='new_name')
        driver.rename_node.reset_mock()

        # should encrypt the name
        node = create_node('name_1', {
            'crypt': '1',
        })
        new_parent = create_node('name_2', None)
        await middleware.rename_node(node, new_parent=new_parent, new_name='new_name')
        new_name = encrypt_name('new_name')
        driver.rename_node.assert_awaited_once_with(node, new_parent, new_name)
        driver.rename_node.reset_mock()

    async def testCreateFolder(self):
        context = Mock()
        driver = AsyncMock()
        middleware = CryptMiddleware(context, driver)

        # should not accept invalid crypt version
        node = create_node('name', None)
        with self.assertRaises(InvalidCryptVersion):
            await middleware.create_folder(
                node,
                'new_name',
                exist_ok=False,
                private={
                    'crypt': '-1',
                }
            )
        driver.create_folder.reset_mock()

        # should create encrypted file by default
        node = create_node('name', None)
        await middleware.create_folder(
            node,
            'new_name',
            exist_ok=False,
            private=None,
        )
        new_name = encrypt_name('new_name')
        driver.create_folder.assert_awaited_once_with(
            parent_node=node,
            folder_name=new_name,
            private={
                'crypt': '1',
            },
            exist_ok=False,
        )
        driver.create_folder.reset_mock()

    async def testDownload(self):
        context = Mock()
        driver = AsyncMock()
        middleware = CryptMiddleware(context, driver)

        # should not accept invalid crypt version
        node = create_node('name', {
            'crypt': '-1',
        })
        with self.assertRaises(InvalidCryptVersion):
            await middleware.download(node)
        driver.download.reset_mock()

        # should not touch normal file
        node = create_node('name', None)
        rv = await middleware.download(node)
        driver.download.assert_awaited_once_with(node)
        self.assertNotIsInstance(rv, DecryptReadableFile)
        driver.download.reset_mock()

        # should create decrypt stream
        node = create_node('name', {
            'crypt': '1',
        })
        rv = await middleware.download(node)
        driver.download.assert_awaited_once_with(node)
        self.assertIsInstance(rv, DecryptReadableFile)
        driver.download.reset_mock()

    async def testUpload(self):
        context = Mock()
        driver = AsyncMock()
        middleware = CryptMiddleware(context, driver)

        # should not accept invalid crypt version
        node = create_node('name', None)
        with self.assertRaises(InvalidCryptVersion):
            await middleware.upload(
                parent_node=node,
                file_name='new_name',
                file_size=None,
                mime_type=None,
                media_info=None,
                private={
                    'crypt': '-1',
                },
            )
        driver.upload.reset_mock()

        # should create encrypted file by default
        node = create_node('name', None)
        rv = await middleware.upload(
            node,
            'new_name',
            file_size=None,
            mime_type=None,
            media_info=None,
            private={
                'crypt': '1',
            },
        )
        new_name = encrypt_name('new_name')
        driver.upload.assert_awaited_once_with(
            node,
            new_name,
            file_size=None,
            mime_type=None,
            media_info=None,
            private={
                'crypt': '1',
            },
        )
        self.assertIsInstance(rv, EncryptWritableFile)
        driver.upload.reset_mock()

    async def testGetHahser(self):
        context = Mock()
        driver = AsyncMock()
        middleware = CryptMiddleware(context, driver)

        # should just create the encrypted hasher
        rv = await middleware.get_hasher()
        driver.get_hasher.assert_awaited_once_with()
        self.assertIsInstance(rv, EncryptHasher)


def create_node(name, private):
    dict_ = {
        'id': name,
        'name': name,
        'trashed': False,
        'created': get_utc_now(),
        'modified': get_utc_now(),
        'is_folder': True,
        'mime_type': None,
        'hash': None,
        'size': None,
        'image': None,
        'video': None,
        'private': private,
    }
    return Node.from_dict(dict_)


def get_utc_now():
    return datetime.datetime.now(datetime.timezone.utc)
