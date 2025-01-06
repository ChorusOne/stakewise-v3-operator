import pytest

from src.config.settings import settings
from src.validators.keystores.hashi_vault.client import HashiVaultClient
from src.validators.keystores.hashi_vault.config import HashiVaultConfiguration
from src.validators.keystores.hashi_vault.loader import (
    HashiVaultBundledKeysLoader,
    HashiVaultKeystore,
    HashiVaultPrefixedKeysLoader,
)


class TestHashiVault:
    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_bundled_keystores_loading(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        config = HashiVaultConfiguration.from_settings()
        client = await HashiVaultClient.from_hashi_vault_config(config)
        keystore = await HashiVaultBundledKeysLoader._load_bundled_hashi_vault_keys(
            client=client,
            secret_url=config.secret_url('ethereum/signing/keystores'),
        )

        assert len(keystore) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_prefixed_keystores_finding(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        config = HashiVaultConfiguration.from_settings()
        client = await HashiVaultClient.from_hashi_vault_config(config)

        keystores_prefixes = await HashiVaultPrefixedKeysLoader._find_prefixed_hashi_vault_keys(
            client=client,
            prefix='ethereum/signing/prefixed1',
            prefix_url=config.prefix_url('ethereum/signing/prefixed1'),
        )
        assert len(keystores_prefixes) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_prefixed_keystores_loading(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        config = HashiVaultConfiguration.from_settings()
        client = await HashiVaultClient.from_hashi_vault_config(config)
        keystore = await HashiVaultPrefixedKeysLoader._load_prefixed_hashi_vault_key(
            client=client,
            secret_url=config.secret_url(
                'ethereum/signing/prefixed1/8b09379ca969e8283a42a09285f430e8bd58c70bb33b44397ae81dac01b1403d0f631f156d211b6931a1c6284e2e469c',
            ),
        )
        assert list(keystore.keys()) == [
            '0x8b09379ca969e8283a42a09285f430e8bd58c70bb33b44397ae81dac01b1403d0f631f156d211b6931a1c6284e2e469c'
        ]

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_not_configured(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = None
        settings.hashi_vault_key_path = None
        settings.hashi_vault_parallelism = 1

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        with pytest.raises(
            RuntimeError,
            match='All three of URL, key path or prefix, and either token or OIDC config for it, must be specified for hashi vault',
        ):
            await HashiVaultConfiguration.from_settings()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_bundled_keystores_inaccessible(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_path = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        config = HashiVaultConfiguration.from_settings()
        with pytest.raises(RuntimeError, match='Can not retrieve key data from hashi vault'):
            client = await HashiVaultClient.from_hashi_vault_config(config)
            await HashiVaultBundledKeysLoader._load_bundled_hashi_vault_keys(
                client=client,
                secret_url=config.secret_url('ethereum/inaccessible/keystores'),
            )

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_bundled_keystores_parallel(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/other/keystores',
        ]
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 2

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        config = HashiVaultConfiguration.from_settings()
        client = await HashiVaultClient.from_hashi_vault_config(config)
        loader = HashiVaultBundledKeysLoader(
            config=config,
            input_iter=iter(settings.hashi_vault_key_paths),
        )
        keys = {}
        await loader.load(client, keys)

        assert len(keys) == 4

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_bundled_keystores_sequential(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/other/keystores',
        ]
        settings.hashi_vault_parallelism = 1

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        config = HashiVaultConfiguration.from_settings()
        client = await HashiVaultClient.from_hashi_vault_config(config)

        loader = HashiVaultBundledKeysLoader(
            config=config,
            input_iter=iter(settings.hashi_vault_key_paths),
        )
        keys = {}
        await loader.load(client, keys)

        assert len(keys) == 4

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_duplicates_parallel(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/same/keystores',
        ]
        settings.hashi_vault_parallelism = 2

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        keystore = HashiVaultKeystore({})
        with pytest.raises(RuntimeError, match='Found duplicate key in path'):
            await keystore.load()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_loading_custom_engine_name(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'custom'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_parallelism = 1

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        config = HashiVaultConfiguration.from_settings()
        client = await HashiVaultClient.from_hashi_vault_config(config)
        keystore = await HashiVaultBundledKeysLoader._load_bundled_hashi_vault_keys(
            client=client,
            secret_url=config.secret_url('ethereum/signing/keystores'),
        )

        assert len(keystore) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_prefixed_loader(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        settings.hashi_vault_auth_mount = None
        settings.hashi_vault_auth_role = None
        settings.hashi_vault_jwt_file = None

        config = HashiVaultConfiguration.from_settings()
        client = await HashiVaultClient.from_hashi_vault_config(config)

        loader = HashiVaultPrefixedKeysLoader(
            config=config, input_iter=iter(['ethereum/signing/prefixed1'])
        )
        keystore = {}
        await loader.load(client, keystore)

        assert len(keystore) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_load_bundled_and_prefixed(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/other/keystores',
        ]
        settings.hashi_vault_key_prefixes = [
            'ethereum/signing/prefixed1',
            'ethereum/signing/prefixed2',
        ]
        settings.hashi_vault_parallelism = 2

        keystore = HashiVaultKeystore({})
        keys = await keystore.load()
        assert len(keys) == 8

    @pytest.mark.usefixtures('mocked_hashi_vault_oidc_auth')
    async def test_hashi_vault_oidc_auth_success(
        self,
        hashi_vault_url: str,
        mocked_jwt_auth_file: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = None
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
        ]
        settings.hashi_vault_key_prefixes = [
            'ethereum/signing/prefixed1',
        ]
        settings.hashi_vault_parallelism = 2

        settings.hashi_vault_auth_mount = 'kubernetes'
        settings.hashi_vault_auth_role = 'GoodIAM'
        settings.hashi_vault_jwt_file = mocked_jwt_auth_file

        keystore = HashiVaultKeystore({})
        keys = await keystore.load()
        assert len(keys) == 4

    @pytest.mark.usefixtures('mocked_hashi_vault_oidc_auth')
    async def test_hashi_vault_oidc_auth_error(
        self,
        hashi_vault_url: str,
        mocked_jwt_auth_file: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = None
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
        ]
        settings.hashi_vault_key_prefixes = [
            'ethereum/signing/prefixed1',
        ]
        settings.hashi_vault_parallelism = 2

        settings.hashi_vault_auth_mount = 'kubernetes_error'
        settings.hashi_vault_auth_role = 'BadIAM'
        settings.hashi_vault_jwt_file = mocked_jwt_auth_file

        keystore = HashiVaultKeystore({})
        with pytest.raises(
            RuntimeError, match='Can not authenticate with Hashi Vault via OID connect'
        ):
            await keystore.load()

    @pytest.mark.usefixtures('mocked_hashi_vault_oidc_auth')
    async def test_hashi_vault_oidc_auth_reauth_success(
        self,
        hashi_vault_url: str,
        mocked_jwt_auth_file: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = None
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
        ]
        settings.hashi_vault_key_prefixes = [
            'ethereum/signing/prefixed2',
        ]
        settings.hashi_vault_parallelism = 2

        # Special endpoint where token stale check is always true
        settings.hashi_vault_auth_mount = 'kubernetes_reauth'
        settings.hashi_vault_auth_role = 'ReauthIAM'
        settings.hashi_vault_jwt_file = mocked_jwt_auth_file

        keystore = HashiVaultKeystore({})
        keys = await keystore.load()
        assert len(keys) == 4

    @pytest.mark.usefixtures('mocked_hashi_vault_oidc_auth')
    async def test_hashi_vault_oidc_auth_reauth_error(
        self,
        hashi_vault_url: str,
        mocked_jwt_auth_file: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = None
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
        ]
        settings.hashi_vault_key_prefixes = [
            'ethereum/signing/prefixed2',
        ]
        settings.hashi_vault_parallelism = 2

        # Special endpoint where token stale check is always false
        settings.hashi_vault_auth_mount = 'kubernetes'
        settings.hashi_vault_auth_role = 'ReauthIAM'
        settings.hashi_vault_jwt_file = mocked_jwt_auth_file

        keystore = HashiVaultKeystore({})
        with pytest.raises(RuntimeError, match='Can not retrieve key data from hashi vault'):
            await keystore.load()
