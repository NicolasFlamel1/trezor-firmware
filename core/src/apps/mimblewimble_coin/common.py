# Imports
from typing import TYPE_CHECKING
from micropython import const

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.crypto.bip32 import HDNode
	from .coins import CoinInfo


# Constants

# MimbleWimble Coin curve name
MIMBLEWIMBLE_COIN_CURVE_NAME = const("secp256k1-mimblewimble-coin")

# BIP44 purpose
BIP44_PURPOSE = const(44)


# Supporting function implementation

# Get extended private key
async def getExtendedPrivateKey(context: Context, coinInfo: CoinInfo, account: int) -> HDNode:

	# Imports
	from apps.common.paths import AlwaysMatchingSchema, HARDENED
	from apps.common.keychain import get_keychain
	
	# Get keychain
	keychain = await get_keychain(context, MIMBLEWIMBLE_COIN_CURVE_NAME, [AlwaysMatchingSchema])
	
	# Derive node at BIP44 path
	node = keychain.derive([
	
		# Purpose
		BIP44_PURPOSE | HARDENED,
		
		# Coin type
		coinInfo.slip44 | HARDENED,
		
		# Account
		account | HARDENED,
		
		# Change
		0,
		
		# Address index
		0
	])
	
	# Return node
	return node
