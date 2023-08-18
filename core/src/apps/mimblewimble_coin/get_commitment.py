# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinGetCommitment, MimbleWimbleCoinCommitment


# Supporting function implementation

# Get commitment
async def get_commitment(context: Context, message: MimbleWimbleCoinGetCommitment) -> MimbleWimbleCoinCommitment:

	# Imports
	from trezor.messages import MimbleWimbleCoinCommitment
	from storage.device import is_initialized
	from apps.base import unlock_device
	from storage.cache import delete, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.crypto import mimblewimble_coin
	from trezor.enums import MimbleWimbleCoinSwitchType
	from apps.common.paths import HARDENED
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey, UINT64_MAX
	
	# Check if not initialized
	if not is_initialized():
	
		# Raise not initialized error
		raise NotInitialized("")
	
	# Unlock device
	await unlock_device()
	
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
	
	# Check if identifier is invalid
	if len(message.identifier) != mimblewimble_coin.IDENTIFIER_SIZE:
	
		# Raise data error
		raise DataError("")
	
	# Check if identifier depth is invalid
	if message.identifier[mimblewimble_coin.IDENTIFIER_DEPTH_INDEX] > mimblewimble_coin.MAXIMUM_IDENTIFIER_DEPTH:
	
		# Raise data error
		raise DataError("")
	
	# Check if value is invalid
	if message.value == 0 or message.value > UINT64_MAX:
	
		# Raise data error
		raise DataError("")
	
	# Check if switch type is invalid
	if message.switch_type != MimbleWimbleCoinSwitchType.REGULAR:
	
		# Raise data error
		raise DataError("")
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(context, coinInfo, message.account)
	
	# Try
	try:
	
		# Get commitment
		commitment = mimblewimble_coin.getCommitment(extendedPrivateKey, message.value, message.identifier, message.switch_type)
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
	
	# Return commitment
	return MimbleWimbleCoinCommitment(commitment = commitment)
