import logging
from calendar import timegm
from dataclasses import dataclass
from datetime import datetime, timezone

from aiohttp.client import ClientSession, ClientTimeout

from src.config.settings import HASHI_VAULT_OIDC_LOGIN_TIMEOUT, HASHI_VAULT_TIMEOUT

from .config import HashiVaultConfiguration

logger = logging.getLogger(__name__)


def utc_timestamp() -> int:
    return timegm(datetime.now(tz=timezone.utc).timetuple())


@dataclass
class HashiVaultToken:
    value: str
    valid_until: int

    def is_stale(self) -> bool:
        """Check if supposed lease duration end is later than current time."""
        return self.valid_until != -1 and self.valid_until <= utc_timestamp()

    def session(self) -> ClientSession:
        return ClientSession(
            timeout=ClientTimeout(HASHI_VAULT_TIMEOUT),
            headers={'X-Vault-Token': self.value},
        )


async def acquire_vault_token(config: HashiVaultConfiguration) -> HashiVaultToken:
    """Acquires Vault token, either from static config or dynamically via OIDC"""
    if config.token is not None:
        return HashiVaultToken(
            value=config.token,
            valid_until=-1,
        )

    if (
        config.auth_role is not None
        and config.jwt_file is not None
        and config.mount_point is not None
    ):
        if not config.jwt_file.exists() or not config.jwt_file.is_file():
            raise RuntimeError(
                f'JWT token file path {config.jwt_file} must point to an existing file'
            )
        login_url = f'{config.url}/v1/auth/{config.mount_point}/login'
        async with ClientSession(
            timeout=ClientTimeout(total=HASHI_VAULT_OIDC_LOGIN_TIMEOUT),
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
        ) as session:
            now = utc_timestamp()
            jwt = config.jwt_file.read_text(encoding='utf-8').strip()
            params = {
                'role': config.auth_role,
                'jwt': jwt,
            }
            response = await session.post(url=login_url, json=params)

            if response.status != 200:
                try:
                    token_data = await response.json()
                except ValueError:
                    # Non-json response
                    logger.error('Non-JSON response on auth, not logging error for safety')
                    raise
                for error in token_data.get('errors', []):
                    logger.debug('Got Hashi Vault error when authenticating: %s', error)
                raise RuntimeError('Can not authenticate with Hashi Vault via OID connect')

            token_data = await response.json()
            client_token = token_data['auth']['client_token']
            lease_duration = token_data['auth']['lease_duration']
            return HashiVaultToken(
                valid_until=now + lease_duration,
                value=client_token,
            )

    raise RuntimeError('Invalid Hashi Vault auth config')
