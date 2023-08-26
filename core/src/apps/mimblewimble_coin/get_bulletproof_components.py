# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinGetBulletproofComponents, MimbleWimbleCoinBulletproofComponents


# Supporting function implementation

# Get Bulletproof components
async def get_bulletproof_components(message: MimbleWimbleCoinGetBulletproofComponents) -> MimbleWimbleCoinBulletproofComponents:

	# Imports
	from trezor.messages import MimbleWimbleCoinBulletproofComponents
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer, close_others
	from storage.cache import delete, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.crypto import mimblewimble_coin
	from trezor.enums import MimbleWimbleCoinSwitchType, MimbleWimbleCoinMessageType
	from trezor.ui.layouts.progress import progress
	from trezor.utils import DISABLE_ANIMATION
	from apps.common.paths import HARDENED
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey, UINT64_MAX
	from .storage import initializeStorage
	
	# Refresh idle timer
	idle_timer.touch()
	
	# Check if not initialized
	if not is_initialized():
	
		# Raise not initialized error
		raise NotInitialized("")
	
	# Unlock device
	await unlock_device()
	
	# Cache seed
	await derive_and_store_roots(False)
	
	# Initialize storage
	initializeStorage()
	
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
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, message.account)
	
	# Check if animation isn't disabled
	if not DISABLE_ANIMATION:
	
		# Close running layout
		close_others()
		
		# Check if message type is sending transaction
		if message.message_type == MimbleWimbleCoinMessageType.SENDING_TRANSACTION:
		
			# Display progress
			displayProgress = progress("Sending Transaction")
		
		# Otherwise check if message type is receiving transaction
		elif message.message_type == MimbleWimbleCoinMessageType.RECEIVING_TRANSACTION:
		
			# Display progress
			displayProgress = progress("Receiving Transaction")
		
		# Otherwise check if message type is creating coinbase
		elif message.message_type == MimbleWimbleCoinMessageType.CREATING_COINBASE:
		
			# Display progress
			displayProgress = progress("Creating Coinbase")
	
	# Try
	try:
	
		# Get Bulletproof components
		tauX, tOne, tTwo = mimblewimble_coin.getBulletproofComponents(extendedPrivateKey, message.value, message.identifier, message.switch_type, None if DISABLE_ANIMATION else displayProgress.report)
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
	
	# Return Bulletproof components
	return MimbleWimbleCoinBulletproofComponents(tau_x = tauX, t_one = tOne, t_two = tTwo)
