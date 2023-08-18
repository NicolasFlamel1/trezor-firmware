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
	from apps.common.seed import derive_and_store_roots
	from storage.cache import delete, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.crypto import mimblewimble_coin
	from apps.common.paths import HARDENED
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey
	
	# Check if not initialized
	if not is_initialized():
	
		# Raise not initialized error
		raise NotInitialized("")
	
	# Unlock device
	await unlock_device()
	
	# Cache seed
	await derive_and_store_roots(context, False)
	
	# TODO Initialize storage
	
	# Clear session
	delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get coin info
	coinInfo = getCoinInfo(message.coin_type, message.network_type)
	
	# Check if account is invalid
	if message.account >= HARDENED:
	
		# Raise data error
		raise DataError("")
	
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
