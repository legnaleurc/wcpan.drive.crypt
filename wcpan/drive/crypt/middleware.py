from typing import Optional, AsyncGenerator, Tuple, List
import contextlib

from wcpan.drive.core.types import (
    ChangeDict,
    MediaInfo,
    Node,
    NodeDict,
    PrivateDict,
    ReadOnlyContext,
)
from wcpan.drive.core.abc import (
    ReadableFile,
    WritableFile,
    Middleware,
    Hasher,
    RemoteDriver,
)

from .util import (
    DecryptReadableFile,
    EncryptHasher,
    EncryptWritableFile,
    InvalidCryptVersion,
    decrypt_name,
    encrypt_name,
)


class CryptMiddleware(Middleware):

    @classmethod
    def get_version_range(cls):
        return (1, 1)

    def __init__(self, context: ReadOnlyContext, driver: RemoteDriver):
        self._context = context
        self._driver = driver
        self._raii = None

    async def __aenter__(self) -> Middleware:
        async with contextlib.AsyncExitStack() as stack:
            self._driver = await stack.enter_async_context(self._driver)
            self._raii = stack.pop_all()
        return self

    async def __aexit__(self, et, ev, tb) -> bool:
        await self._raii.aclose()
        self._raii = None

    async def get_initial_check_point(self) -> str:
        return await self._driver.get_initial_check_point()

    async def fetch_root_node(self) -> Node:
        return await self._driver.fetch_root_node()

    async def trash_node(self, node: Node) -> None:
        return await self._driver.trash_node(node)

    async def fetch_changes(self,
        check_point: str,
    ) -> AsyncGenerator[Tuple[str, List[ChangeDict]], None]:
        async for check_point, changes in self._driver.fetch_changes(check_point):
            decoded = [decode_change(change) for change in changes]
            yield check_point, decoded

    async def rename_node(self,
        node: Node,
        new_parent: Optional[Node],
        new_name: Optional[str],
    ) -> Node:
        private = node.private
        if not private:
            return await self._driver.rename_node(node, new_parent, new_name)
        if 'crypt' not in private:
            return await self._driver.rename_node(node, new_parent, new_name)
        if private['crypt'] != '1':
            raise InvalidCryptVersion()

        if node.name is not None:
            name = encrypt_name(node.name)
            node = node.clone(name=name)
        if new_name is not None:
            new_name = encrypt_name(new_name)

        return await self._driver.rename_node(node, new_parent, new_name)

    async def download(self, node: Node) -> ReadableFile:
        private = node.private
        if not private:
            return await self._driver.download(node)
        if 'crypt' not in private:
            return await self._driver.download(node)
        if private['crypt'] != '1':
            raise InvalidCryptVersion()

        readable = await self._driver.download(node)
        return DecryptReadableFile(readable)

    async def upload(self,
        parent_node: Node,
        file_name: str,
        file_size: Optional[int],
        mime_type: Optional[str],
        media_info: Optional[MediaInfo],
        private: Optional[PrivateDict],
    ) -> WritableFile:
        if private is None:
            private = {}
        if 'crypt' not in private:
            private['crypt'] = '1'
        if private['crypt'] != '1':
            raise InvalidCryptVersion()

        file_name = encrypt_name(file_name)

        writable = await self._driver.upload(
            parent_node,
            file_name,
            file_size=file_size,
            mime_type=mime_type,
            media_info=media_info,
            private=private,
        )
        return EncryptWritableFile(writable)

    async def create_folder(self,
        parent_node: Node,
        folder_name: str,
        private: Optional[PrivateDict],
        exist_ok: bool,
    ) -> Node:
        if private is None:
            private = {}
        if 'crypt' not in private:
            private['crypt'] = '1'
        if private['crypt'] != '1':
            raise InvalidCryptVersion()

        folder_name = encrypt_name(folder_name)
        return await self._driver.create_folder(
            parent_node=parent_node,
            folder_name=folder_name,
            private=private,
            exist_ok=exist_ok,
        )

    async def get_hasher(self) -> Hasher:
        hasher = await self._driver.get_hasher()
        return EncryptHasher(hasher)


def decode_change(change: ChangeDict) -> ChangeDict:
    if change['removed']:
        return change

    dict_ = change['node']
    if dict_['name'] is None:
        return change

    private = dict_.get('private', None)
    if not private:
        return change
    if 'crypt' not in private:
        return change
    if private['crypt'] != '1':
        raise InvalidCryptVersion()

    name = decrypt_name(dict_['name'])
    dict_['name'] = name
    return change
