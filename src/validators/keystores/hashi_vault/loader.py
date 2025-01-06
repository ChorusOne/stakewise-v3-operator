import abc
import asyncio
import itertools
import logging
from dataclasses import dataclass
from typing import Iterator

from eth_typing import HexStr
from eth_utils import add_0x_prefix
from web3 import Web3

from src.validators.keystores.local import Keys, LocalKeystore
from src.validators.typings import BLSPrivkey

from .client import HashiVaultClient
from .config import HashiVaultConfiguration

logger = logging.getLogger(__name__)


@dataclass
class HashiVaultKeysLoader(metaclass=abc.ABCMeta):
    config: HashiVaultConfiguration
    input_iter: Iterator[str]

    @staticmethod
    def merge_keys_responses(keys_responses: list[Keys], merged_keys: Keys) -> None:
        """Merge keys objects, proactively searching for duplicate keys to prevent
        potential slashing."""
        for keys in keys_responses:
            for pk, sk in keys.items():
                if pk in merged_keys:
                    logger.error('Duplicate validator key %s found in hashi vault', pk)
                    raise RuntimeError('Found duplicate key in path')
                merged_keys[pk] = sk

    @abc.abstractmethod
    async def load(self, client: HashiVaultClient, merged_keys: Keys) -> None:
        """Populate merged_keys structure with validator keys from given loader."""
        raise NotImplementedError


class HashiVaultBundledKeysLoader(HashiVaultKeysLoader):
    async def load(self, client: HashiVaultClient, merged_keys: Keys) -> None:
        """Load all the key bundles from input locations."""
        while key_chunk := list(itertools.islice(self.input_iter, self.config.parallelism)):
            keys_responses = await asyncio.gather(
                *[
                    self._load_bundled_hashi_vault_keys(
                        client=client,
                        secret_url=self.config.secret_url(key_path),
                    )
                    for key_path in key_chunk
                ]
            )
            self.merge_keys_responses(keys_responses, merged_keys)

    @staticmethod
    async def _load_bundled_hashi_vault_keys(client: HashiVaultClient, secret_url: str) -> Keys:
        """
        Load public and private keys from hashi vault
        K/V secret engine.

        All public and private keys must be stored as hex string  with or without 0x prefix.
        """
        keys = []
        logger.info('Will load validator keys from %s', secret_url)

        response = await client.request(
            secret_url,
            method='GET',
        )
        for pk, sk in response['data'].items():
            sk_bytes = Web3.to_bytes(hexstr=sk)
            keys.append((add_0x_prefix(HexStr(pk)), BLSPrivkey(sk_bytes)))
        validator_keys = Keys(dict(keys))
        return validator_keys


class HashiVaultPrefixedKeysLoader(HashiVaultKeysLoader):
    async def load(self, client: HashiVaultClient, merged_keys: Keys) -> None:
        """Discover all the keys under given prefix. Then, load the keys into merged structure."""
        prefix_leaf_location_tuples = []
        while prefix_chunk := list(itertools.islice(self.input_iter, self.config.parallelism)):
            prefix_leaf_location_tuples += await asyncio.gather(
                *[
                    self._find_prefixed_hashi_vault_keys(
                        client=client,
                        prefix=prefix_path,
                        prefix_url=self.config.prefix_url(prefix_path),
                    )
                    for prefix_path in prefix_chunk
                ]
            )

        # Flattened list of prefix, pubkey tuples
        keys_paired_with_prefix: list[tuple[str, str]] = sum(
            prefix_leaf_location_tuples,
            [],
        )
        prefixed_keys_iter = iter(keys_paired_with_prefix)
        while prefixed_chunk := list(itertools.islice(prefixed_keys_iter, self.config.parallelism)):
            keys_responses = await asyncio.gather(
                *[
                    self._load_prefixed_hashi_vault_key(
                        client=client,
                        secret_url=self.config.secret_url(f'{key_prefix}/{key_path}'),
                    )
                    for (key_prefix, key_path) in prefixed_chunk
                ]
            )
            self.merge_keys_responses(keys_responses, merged_keys)

    @staticmethod
    async def _find_prefixed_hashi_vault_keys(
        client: HashiVaultClient, prefix: str, prefix_url: str
    ) -> list[tuple[str, str]]:
        """
        Discover public keys under prefix in hashi vault K/V secret engine

        All public keys must be a final chunk of the secret path without 0x prefix,
        all secret keys are stored under these paths with arbitrary secret dictionary
        key, and secret value with or without 0x prefix.
        """
        logger.info('Will discover validator keys in %s', prefix_url)
        response = await client.request(method='LIST', url=prefix_url)
        discovered_keys = response['keys']
        return list(zip([prefix] * len(discovered_keys), discovered_keys))

    @staticmethod
    async def _load_prefixed_hashi_vault_key(client: HashiVaultClient, secret_url: str) -> Keys:
        logger.info('Will load keys from %s', secret_url)
        response = await client.request(
            method='GET',
            url=secret_url,
        )
        # Last chunk of URL is a public key
        pk = add_0x_prefix(HexStr(secret_url.strip('/').split('/')[-1]))
        if len(response['data']) > 1:
            raise RuntimeError(
                f'Invalid multi-value secret at path {secret_url}, '
                'should only contain single value',
            )
        sk = list(response['data'].values())[0]
        sk_bytes = Web3.to_bytes(hexstr=sk)
        return Keys({pk: BLSPrivkey(sk_bytes)})


class HashiVaultKeystore(LocalKeystore):
    @staticmethod
    async def load() -> 'HashiVaultKeystore':
        """Extracts private keys from the keystores."""
        hashi_vault_config = HashiVaultConfiguration.from_settings()
        merged_keys = Keys({})

        for loader_class, input_list in {
            HashiVaultBundledKeysLoader: hashi_vault_config.key_paths,
            HashiVaultPrefixedKeysLoader: hashi_vault_config.key_prefixes,
        }.items():
            if len(input_list) == 0:
                continue
            input_iter = iter(input_list)
            loader = loader_class(
                config=hashi_vault_config,
                input_iter=input_iter,
            )
            client = await HashiVaultClient.from_hashi_vault_config(hashi_vault_config)
            await loader.load(client, merged_keys)

        return HashiVaultKeystore(merged_keys)
