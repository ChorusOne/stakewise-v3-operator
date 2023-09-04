import asyncio
from dataclasses import dataclass
from pathlib import Path

import click
import milagro_bls_binding as bls
from eth_typing import BLSSignature, HexAddress, HexStr
from sw_utils import ValidatorStatus
from sw_utils.consensus import EXITED_STATUSES
from sw_utils.exceptions import AiohttpRecoveredErrors
from sw_utils.signing import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.clients import consensus_client
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import AVAILABLE_NETWORKS, NETWORKS, settings
from src.validators.typings import BLSPrivkey, ValidatorKeys
from src.validators.utils import load_validator_keys


@dataclass
class ExitKeyMaterial:
    private_key: BLSPrivkey
    public_key: HexStr
    index: int


EXITING_STATUSES = [ValidatorStatus.ACTIVE_EXITING] + EXITED_STATUSES


@click.option(
    '--network',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
    envvar='NETWORK',
    help='The network of the vault. Default is the network specified at "init" command.',
)
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data is placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--count',
    help='The number of validators to exit.',
    type=click.IntRange(min=1),
)
@click.option(
    '--consensus-endpoints',
    help='Comma separated list of API endpoints for consensus nodes',
    prompt='Enter the comma separated list of API endpoints for consensus nodes',
    envvar='CONSENSUS_ENDPOINTS',
    type=str,
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--hashicorp-vault-addr',
    callback=validate_eth_address,
    envvar='HASHICORP_VAULT_ADDR',
    help='Address of the vault to register validators for.',
)
@click.option(
    '--hashicorp-vault-token',
    envvar='HASHICORP_VAULT_TOKEN',
    help='Token for accessing Hashicopr vault.',
)
@click.option(
    '--hashicorp-vault-key',
    envvar='HASHICORP_VAULT_KEY',
    help='Key of the secret where signing keys are stored. Compatible with format recognized by Web3Signer',
)
@click.command(help='Performs a voluntary exit for active vault validators.')
# pylint: disable-next=too-many-arguments
def validators_exit(
    network: str,
    vault: HexAddress,
    count: int | None,
    consensus_endpoints: str,
    data_dir: str,
    verbose: bool,
    hashicorp_vault_addr: str | None,
    hashicorp_vault_token: str | None,
    hashicorp_vault_key: str | None,
) -> None:
    # pylint: disable=duplicate-code
    vault_config = VaultConfig(vault, Path(data_dir))
    if network is None:
        vault_config.load()
        network = vault_config.network

    settings.set(
        vault=vault,
        network=network,
        vault_dir=vault_config.vault_dir,
        consensus_endpoints=consensus_endpoints,
        verbose=verbose,
        hashicorp_vault_addr=hashicorp_vault_addr,
        hashicorp_vault_key=hashicorp_vault_key,
        hashicorp_vault_token=hashicorp_vault_token,
    )
    try:
        asyncio.run(main(count))
    except Exception as e:
        log_verbose(e)


async def main(count: int | None) -> None:
    keystores = load_validator_keys()
    if not keystores:
        raise click.ClickException('Keystores not found.')
    fork = await consensus_client.get_consensus_fork()

    exit_keystores = await _get_exit_key_material(keystores)
    if not exit_keystores:
        raise click.ClickException('There are no active validators.')

    exit_keystores.sort(key=lambda x: x.index)

    if count:
        exit_keystores = exit_keystores[:count]

    click.confirm(
        f'Are you sure you want to exit {len(exit_keystores)} validators '
        f'with indexes: {", ".join(str(x.index) for x in exit_keystores)}?',
        abort=True,
    )
    exited_indexes = []
    for keystore in exit_keystores:
        try:
            exit_signature = _get_exit_signature(
                validator_index=keystore.index,
                private_key=keystore.private_key,
                fork=fork,
                network=settings.network,
            )
            await consensus_client.submit_voluntary_exit(
                validator_index=keystore.index,
                signature=Web3.to_hex(exit_signature),
                epoch=fork.epoch,
            )
            exited_indexes.append(keystore.index)
        except AiohttpRecoveredErrors as e:
            raise click.ClickException(f'Consensus client error: {e}')
    if exited_indexes:
        click.secho(
            f'Validators {", ".join(str(index) for index in exited_indexes)} '
            f'exits successfully initiated',
            bold=True,
            fg='green',
        )


def _get_exit_signature(
    validator_index: int,
    private_key: BLSPrivkey,
    fork: ConsensusFork,
    network: str,
) -> BLSSignature:
    """Generates exit signature"""
    message = get_exit_message_signing_root(
        validator_index=validator_index,
        genesis_validators_root=NETWORKS[network].GENESIS_VALIDATORS_ROOT,
        fork=fork,
    )
    exit_signature = bls.Sign(private_key, message)
    return exit_signature


async def _get_exit_key_material(validator_keys: ValidatorKeys) -> list[ExitKeyMaterial]:
    """Fetches validators consensus info."""
    results = []
    public_keys = list(validator_keys.keys())
    exited_statuses = [x.value for x in EXITING_STATUSES]

    for i in range(0, len(public_keys), settings.validators_fetch_chunk_size):
        validators = await consensus_client.get_validators_by_ids(
            public_keys[i : i + settings.validators_fetch_chunk_size]
        )
        for beacon_validator in validators['data']:
            if beacon_validator.get('status') in exited_statuses:
                continue

            results.append(
                ExitKeyMaterial(
                    public_key=beacon_validator['validator']['pubkey'],
                    private_key=validator_keys[beacon_validator['validator']['pubkey']],
                    index=int(beacon_validator['index']),
                )
            )
    return results
