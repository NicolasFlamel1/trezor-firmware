# Imports
from typing import TYPE_CHECKING
from micropython import const

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.crypto.bip32 import HDNode
	from .coins import CoinInfo


# Constants

# MimbleWimble Coin curve name
MIMBLEWIMBLE_COIN_CURVE_NAME = const("secp256k1-mimblewimble-coin")

# BIP44 purpose
BIP44_PURPOSE = const(44)

# Uint8 max
UINT8_MAX = const(0xFF)

# Uint32 max
UINT32_MAX = const(0xFFFFFFFF)

# Uint64 max
UINT64_MAX = const(0xFFFFFFFFFFFFFFFF)

# Native uint64 pack format
NATIVE_UINT64_PACK_FORMAT = const("@Q")

# Milliseconds in a second
MILLISECONDS_IN_A_SECOND = const(1000)

# Seconds in a minute
SECONDS_IN_A_MINUTE = const(60)

# Minutes in an hour
MINUTES_IN_AN_HOUR = const(60)

# Hours in a day
HOURS_IN_A_DAY = const(24)

# Days on a week
DAYS_IN_A_WEEK = const(7)

# Maximum timestamp
MAXIMUM_TIMESTAMP = const(UINT32_MAX * MINUTES_IN_AN_HOUR * SECONDS_IN_A_MINUTE * MILLISECONDS_IN_A_SECOND + MILLISECONDS_IN_A_SECOND - 1)

# Minimum time zone offset
MINIMUM_TIME_ZONE_OFFSET = const(-13 * MINUTES_IN_AN_HOUR)

# Maximum time zone offset
MAXIMUM_TIME_ZONE_OFFSET = const(15 * MINUTES_IN_AN_HOUR)


# Supporting function implementation

# Get extended private key
async def getExtendedPrivateKey(coinInfo: CoinInfo, account: int) -> HDNode:

	# Imports
	from apps.common.paths import AlwaysMatchingSchema, HARDENED
	from apps.common.keychain import get_keychain
	from trezor.wire import ProcessError
	
	# Try
	try:
	
		# Get keychain
		keychain = await get_keychain(MIMBLEWIMBLE_COIN_CURVE_NAME, [AlwaysMatchingSchema], progress_bar = False)
		
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
