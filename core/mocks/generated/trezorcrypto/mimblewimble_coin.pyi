from typing import *
from enum import IntEnum, IntFlag
from trezorcrypto.bip32 import HDNode
from apps.mimblewimble_coin.coins import CoinInfo
from trezor.enums import MimbleWimbleCoinSwitchType


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
class AddressDerivationType(IntEnum):
    """
    Address derivation type
    """
    MWC_ADDRESS_DERIVATION = 0
    GRIN_ADDRESS_DERIVATION = 1


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
class PaymentProofMessageType(IntEnum):
    """
    Payment proof message type
    """
    ASCII_PAYMENT_PROOF_MESSAGE = 0
    BINARY_PAYMENT_PROOF_MESSAGE = 1


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
class PaymentProofAddressType(IntFlag):
    """
    Payment proof address type
    """
    MQS_PAYMENT_PROOF_ADDRESS = 1 << 0
    TOR_PAYMENT_PROOF_ADDRESS = 1 << 1
    SLATEPACK_PAYMENT_PROOF_ADDRESS = 1 << 2


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
class SlateEncryptionType(IntFlag):
    """
    Slate encryption type
    """
    MQS_SLATE_ENCRYPTION = 1 << 0
    TOR_SLATE_ENCRYPTION = 1 << 1
    SLATEPACK_SLATE_ENCRYPTION = 1 << 2


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
def getRootPublicKey(extendedPrivateKey: HDNode) -> bytes:
    """
    Get root public key
    """


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
def getMqsAddress(extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int) -> str:
    """
    Get MQS address
    """


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
def getTorAddress(extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int) -> str:
    """
    Get Tor address
    """


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
def getSlatepackAddress(extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int) -> str:
    """
    Get Slatepack address
    """


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
def getSeedCookie(extendedPrivateKey: HDNode) -> bytes:
    """
    Get seed cookie
    """


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
def getCommitment(extendedPrivateKey: HDNode, value: int, identifier: bytes, switchType: MimbleWimbleCoinSwitchType) -> bytes:
    """
    Get commitment
    """


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
def getBulletproofComponents(extendedPrivateKey: HDNode, value: int, identifier: bytes, switchType: MimbleWimbleCoinSwitchType, updateProgress: Callable[[int], None] | None) -> tuple[bytes, bytes, bytes]:
    """
    Get Bulletproof components
    """


# extmod/modtrezorcrypto/modtrezorcrypto-mimblewimble_coin.h
def getMqsChallengeSignature(extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int, challenge: str) -> bytes:
    """
    Get MQS challenge signature
    """
