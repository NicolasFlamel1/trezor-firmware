# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinGetSeedCookie, MimbleWimbleCoinSeedCookie


# Supporting function implementation

# Get seed cookie
async def get_seed_cookie(context: Context, message: MimbleWimbleCoinGetSeedCookie) -> MimbleWimbleCoinSeedCookie:

	# Imports
	from trezor.messages import MimbleWimbleCoinSeedCookie
	from storage.device import is_initialized
	from apps.base import unlock_device
	from trezor.wire import NotInitialized, ProcessError
	from trezor.crypto import mimblewimble_coin
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey
	
	# Check if not initialized
	if not is_initialized():
	
		# Raise not initialized error
		raise NotInitialized("")
	
	# Unlock device
	await unlock_device()
	
	# TODO Initialize storage
	
	# TODO Get session
	
	# TODO Clear session
	
	# Get coin info
	coinInfo = getCoinInfo(message.coin_type, message.network_type)
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(context, coinInfo, message.account)
	
	# Try
	try:
	
		# Get seed cookie
		seedCookie = mimblewimble_coin.getSeedCookie(extendedPrivateKey)
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
	
	# Return seed cookie
	return MimbleWimbleCoinSeedCookie(seed_cookie = seedCookie)
