from dataclasses import dataclass


@dataclass
class HashicorpVaultSettings:
    addr: str
    key: str
    token: str
