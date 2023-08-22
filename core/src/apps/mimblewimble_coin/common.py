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

# Uint32 max
UINT32_MAX = const(0xFFFFFFFF)

# Uint64 max
UINT64_MAX = const(0xFFFFFFFFFFFFFFFF)

# Native uint64 pack format
NATIVE_UINT64_PACK_FORMAT = const("@Q")


# Supporting function implementation

# Get extended private key
async def getExtendedPrivateKey(context: Context, coinInfo: CoinInfo, account: int) -> HDNode:

	# Imports
	from apps.common.paths import AlwaysMatchingSchema, HARDENED
	from apps.common.keychain import get_keychain
	from trezor.wire import ProcessError
	
	# Try
	try:
	
		# Get keychain
		keychain = await get_keychain(context, MIMBLEWIMBLE_COIN_CURVE_NAME, [AlwaysMatchingSchema], progress_bar = False)
		
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
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
	
	# Return node
	return node
