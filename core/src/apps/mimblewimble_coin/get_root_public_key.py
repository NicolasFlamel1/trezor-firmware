# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinGetRootPublicKey, MimbleWimbleCoinRootPublicKey


# Supporting function implementation

# Get root public key
async def get_root_public_key(context: Context, message: MimbleWimbleCoinGetRootPublicKey) -> MimbleWimbleCoinRootPublicKey:

	# Imports
	from trezor.messages import MimbleWimbleCoinRootPublicKey
	from storage.device import is_initialized
	from apps.base import unlock_device
	from storage.cache import delete, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError
	from trezor.workflow import close_others
	from trezor.ui.layouts import confirm_action, confirm_value, show_warning
	from trezor.enums import ButtonRequestType
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
	
	# Clear session
	delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get coin info
	coinInfo = getCoinInfo(message.coin_type, message.network_type)
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(context, coinInfo, message.account)
	
	# Show prompt
	await confirm_action(context, "", coinInfo.name, action = "Export root public key?", verb = "Next")
	
	# Show prompt
	await confirm_value(context, "Account Index", str(message.account), "", "", verb = "Next")
	
	# Show prompt
	await show_warning(context, "", "The host will be able to view the account's transactions.", button = "Approve", br_code = ButtonRequestType.Other)
	
	# Close running layout
	close_others()
	
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
