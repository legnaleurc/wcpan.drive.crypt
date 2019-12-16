from typing import Optional

from wcpan.drive.core.types import (
    CreateFolderFunction,
    DownloadFunction,
    GetHasherFunction,
    MediaInfo,
    Node,
    NodeDict,
    PrivateDict,
    RenameNodeFunction,
    UploadFunction,
)
from wcpan.drive.core.abc import ReadableFile, WritableFile, Middleware, Hasher

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

    async def decode_dict(self, dict_: NodeDict) -> NodeDict:
        if dict_['name'] is None:
            return dict_

        private = dict_.get('private', None)
        if not private:
            return dict_
        if 'crypt' not in private:
            return dict_
        if private['crypt'] != '1':
            raise InvalidCryptVersion()

        name = decrypt_name(dict_['name'])
        dict_['name'] = name
        return dict_

    async def rename_node(self,
        fn: RenameNodeFunction,
        node: Node,
        new_parent: Optional[Node],
        new_name: Optional[str],
    ) -> Node:
        private = node.private
        if not private:
            return await fn(node, new_parent, new_name)
        if 'crypt' not in private:
            return await fn(node, new_parent, new_name)
        if private['crypt'] != '1':
            raise InvalidCryptVersion()

        if node.name is not None:
            name = encrypt_name(node.name)
            node = node.clone(name=name)
        if new_name is not None:
            new_name = encrypt_name(new_name)

        return await fn(node, new_parent, new_name)

    async def download(self, fn: DownloadFunction, node: Node) -> ReadableFile:
        private = node.private
        if not private:
            return await fn(node)
        if 'crypt' not in private:
            return await fn(node)
        if private['crypt'] != '1':
            raise InvalidCryptVersion()

        readable = await fn(node)
        return DecryptReadableFile(readable)

    async def upload(self,
        fn: UploadFunction,
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

        writable = await fn(
            parent_node,
            file_name,
            file_size=file_size,
            mime_type=mime_type,
            media_info=media_info,
            private=private,
        )
        return EncryptWritableFile(writable)

    async def create_folder(self,
        fn: CreateFolderFunction,
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
        return await fn(parent_node, folder_name, private, exist_ok)

    async def get_hasher(self, fn: GetHasherFunction) -> Hasher:
        hasher = await fn()
        return EncryptHasher(hasher)
