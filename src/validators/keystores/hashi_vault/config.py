import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from src.config.settings import settings


@dataclass
class HashiVaultConfiguration:  # pylint: disable=too-many-instance-attributes
    token: str | None

    jwt_file: Path | None
    auth_role: str | None
    mount_point: str | None

    url: str
    engine_name: str
    key_paths: list[str]
    key_prefixes: list[str]
    parallelism: int

    @classmethod
    def from_settings(cls) -> 'HashiVaultConfiguration':
        if not (
            settings.hashi_vault_url is not None
            and (
                settings.hashi_vault_token is not None
                or (
                    settings.hashi_vault_auth_role is not None
                    and settings.hashi_vault_auth_mount is not None
                    and settings.hashi_vault_jwt_file is not None
                )
            )
            and (
                settings.hashi_vault_key_paths is not None
                or settings.hashi_vault_key_prefixes is not None
            )
        ):
            raise RuntimeError(
                'All three of URL, key path or prefix, '
                'and either token or OIDC config for it, '
                'must be specified for hashi vault'
            )
        return cls(
            url=settings.hashi_vault_url,
            engine_name=settings.hashi_vault_engine_name,
            key_paths=settings.hashi_vault_key_paths or [],
            key_prefixes=settings.hashi_vault_key_prefixes or [],
            parallelism=settings.hashi_vault_parallelism,
            # Static auth token
            token=settings.hashi_vault_token,
            # OID connect auth params
            jwt_file=settings.hashi_vault_jwt_file,
            auth_role=settings.hashi_vault_auth_role,
            mount_point=settings.hashi_vault_auth_mount,
        )

    def secret_url(self, key_path: str, location: str = 'data') -> str:
        return urllib.parse.urljoin(
            self.url,
            f'/v1/{self.engine_name}/{location}/{key_path}',
        )

    def prefix_url(self, keys_prefix: str) -> str:
        """An URL for Vault secrets engine location that holds prefixes for keys."""
        keys_prefix = keys_prefix.strip('/')
        # URL is used for listing, so it lists metadata
        return self.secret_url(keys_prefix, location='metadata')
