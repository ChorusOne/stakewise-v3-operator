import logging
from asyncio import Event, ensure_future
from dataclasses import dataclass

from aiohttp.client import ClientSession

from .auth import HashiVaultToken, acquire_vault_token
from .config import HashiVaultConfiguration

HASHI_VAULT_AUTH_MAX_RETRIES = 3
logger = logging.getLogger(__name__)


@dataclass
class HashiVaultClient:
    """Client instance with automated token refresh."""

    config: HashiVaultConfiguration
    token: HashiVaultToken
    has_auth: Event
    session: ClientSession

    @classmethod
    async def from_hashi_vault_config(cls, config: HashiVaultConfiguration) -> 'HashiVaultClient':
        hashi_vault_config = HashiVaultConfiguration.from_settings()
        token = await acquire_vault_token(hashi_vault_config)
        has_auth = Event()
        # After token is acquired, event is not initially guarding anything
        # It will be used only in case of 403
        has_auth.set()
        return cls(
            config=config,
            token=token,
            has_auth=has_auth,
            session=token.session(),
        )

    async def request(self, url: str, method: str) -> dict:
        """Perform Vault request and parse errors."""
        retry = 0
        while retry < HASHI_VAULT_AUTH_MAX_RETRIES:
            if not self.has_auth.is_set():
                # Parallel authentication
                await self.has_auth.wait()
            response = await self.session.request(
                method=method,
                url=url,
            )
            if response.status == 403 and self.token.is_stale():
                # Attempt to re-authenticate via OIDC
                # This will not work with static token,
                # we assume if static gets 403 response then
                # fail
                if not self.has_auth.is_set():
                    self.has_auth.clear()
                    self.token = await acquire_vault_token(self.config)
                    await self.session.close()
                    self.session = self.token.session()
                    self.has_auth.set()
                else:
                    # Already authenticating from parallel request,
                    # wait until its done
                    await self.has_auth.wait()
                continue

            response_data = await response.json()
            # Common response format handling
            if 'data' not in response_data or response.status != 200:
                logger.error('Failed to discover keys in hashi vault')
                errors = response_data.get('errors', [])
                if not isinstance(errors, list):
                    errors = [
                        errors,
                    ]
                for error in errors:
                    logger.error('hashi vault error: %s', error)
                raise RuntimeError('Can not retrieve key data from hashi vault')

            return response_data['data']

        raise RuntimeError(
            'Failed authenticating with '
            f'Hashi Vault more than {HASHI_VAULT_AUTH_MAX_RETRIES} times'
        )

    def __del__(self) -> None:
        # Cleanup session when client is not used any more
        ensure_future(self.session.close())
