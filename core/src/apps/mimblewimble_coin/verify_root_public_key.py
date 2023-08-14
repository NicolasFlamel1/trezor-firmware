# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinVerifyRootPublicKey, Success


# Supporting function implementation

# Verify root public key
async def verify_root_public_key(context: Context, message: MimbleWimbleCoinVerifyRootPublicKey) -> Success:

	# Imports
	from trezor.messages import Success
	from storage.device import is_initialized
	from apps.base import unlock_device
	from trezor.wire import NotInitialized, ProcessError
	from trezor.workflow import close_others
	from trezor.ui.layouts import confirm_action, confirm_blob
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
	
		# Get root public key
		rootPublicKey = mimblewimble_coin.getRootPublicKey(extendedPrivateKey)
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
	
	# Show prompt
	await confirm_action(context, "", coinInfo.name, action = "Verify root public key.", verb = "Next")
	
	# Show prompt
	await confirm_blob(context, "", "Root Public Key", rootPublicKey, verb = "Valid".upper())
	
	# Close running layout
	close_others()
	
	# Return success
	return Success()
