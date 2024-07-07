# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinVerifyRootPublicKey, Success


# Supporting function implementation

# Verify root public key
async def verify_root_public_key(message: MimbleWimbleCoinVerifyRootPublicKey) -> Success:

	# Imports
	from trezor.messages import Success
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer
	from storage.cache import delete, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.ui.layouts import confirm_action, confirm_blob, show_warning
	from trezor.enums import ButtonRequestType
	from trezor.crypto import mimblewimble_coin
	from apps.common.paths import HARDENED
	from trezor.utils import UI_LAYOUT
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey
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
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, message.account)
	
	# Try
	try:
	
		# Get root public key
		rootPublicKey = mimblewimble_coin.getRootPublicKey(extendedPrivateKey)
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
	
	# Try
	try:
	
		# Show prompt
		await confirm_action("", coinInfo.name, action = "Verify root public key.", verb = "Next")
		
		# Check if UI layout is mercury
		if UI_LAYOUT == "MERCURY":
		
			# Show prompt
			await show_warning("", "".join(f"{i:02x}" for i in rootPublicKey), "Valid", "Root Public Key", ButtonRequestType.Other, allow_cancel = True, value_text_mono = True)
		
		# Otherwise
		else:
		
			# Show prompt
			await confirm_blob("", "Root Public Key", rootPublicKey, verb = "Valid".upper())
	
	# Finally
	finally:
	
		# Clear root public key
		for i in range(len(rootPublicKey)):
			rootPublicKey[i] = 0
	
	# Return success
	return Success()
