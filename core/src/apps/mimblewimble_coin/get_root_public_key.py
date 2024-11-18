# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinGetRootPublicKey, MimbleWimbleCoinRootPublicKey


# Supporting function implementation

# Get root public key
async def get_root_public_key(message: MimbleWimbleCoinGetRootPublicKey) -> MimbleWimbleCoinRootPublicKey:

	# Imports
	from trezor.messages import MimbleWimbleCoinRootPublicKey
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer
	from storage.cache import delete, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.ui.layouts import confirm_action, confirm_value, show_warning, confirm_text
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
	
	# Check if UI layout is mercury
	if UI_LAYOUT == "MERCURY":
	
		# Show prompt
		await confirm_value(coinInfo.name, "", "Export root public key?", "", verb = "Next")
		
	# Otherwise
	else:
	
		# Show prompt
		await confirm_action("", coinInfo.name, action = "Export root public key?", verb = "Next")
	
	# Show prompt
	await confirm_value("Account Index", str(message.account), "", "", verb = "Next")
	
	# Check if UI layout is TR
	if UI_LAYOUT == "TR":
	
		# Show prompt
		await confirm_text("", "Warning", "The host will be able to view the account's transactions.", verb = "Approve")
	
	# Otherwise check if UI layout is TT
	elif UI_LAYOUT == "TT":
	
		# Show prompt
		await show_warning("", "The host will be able to view the account's transactions.", button = "Approve", br_code = ButtonRequestType.Other, left_is_small = True)
	
	# Otherwise
	else:
	
		# Show prompt
		await show_warning("", "The host will be able to view the account's transactions.", "Approve", "Warning", br_code = ButtonRequestType.Other, allow_cancel = True)
	
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
	
	# Return root public key
	return MimbleWimbleCoinRootPublicKey(root_public_key = rootPublicKey)
