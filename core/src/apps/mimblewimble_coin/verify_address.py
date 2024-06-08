# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinVerifyAddress, Success


# Supporting function implementation

# Verify address
async def verify_address(message: MimbleWimbleCoinVerifyAddress) -> Success:

	# Imports
	from trezor.messages import Success
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer
	from storage.cache import delete, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.ui.layouts import confirm_action, confirm_blob
	from trezor.crypto import mimblewimble_coin
	from trezor.enums import MimbleWimbleCoinAddressType
	from apps.common.paths import HARDENED
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey, UINT32_MAX
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
	
	# Check if index is invalid
	if message.index > UINT32_MAX:
	
		# Raise data error
		raise DataError("")
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, message.account)
	
	# Check if address type is MQS
	if message.address_type == MimbleWimbleCoinAddressType.MQS:
	
		# Check if currency doesn't allow MQS addresses
		if not coinInfo.enableMqsAddress:
		
			# Raise data error
			raise DataError("")
		
		# Try
		try:
		
			# Get MQS address
			address = mimblewimble_coin.getMqsAddress(extendedPrivateKey, coinInfo, message.index)
		
		# Catch errors
		except:
		
			# Raise process error
			raise ProcessError("")
		
		# Show prompt
		await confirm_action("", coinInfo.name, action = f"Verify {coinInfo.mqsName} address.", verb = "Next")
		
		# Show prompt
		await confirm_blob("", f"{coinInfo.mqsName} Address", address, verb = "Valid".upper())
	
	# Otherwise check if address type is Tor
	elif message.address_type == MimbleWimbleCoinAddressType.TOR:
	
		# Check if currency doesn't allow Tor addresses
		if not coinInfo.enableTorAddress:
		
			# Raise data error
			raise DataError("")
		
		# Try
		try:
		
			# Get Tor address
			address = mimblewimble_coin.getTorAddress(extendedPrivateKey, coinInfo, message.index)
		
		# Catch errors
		except:
		
			# Raise process error
			raise ProcessError("")
		
		# Show prompt
		await confirm_action("", coinInfo.name, action = "Verify Tor address.", verb = "Next")
		
		# Show prompt
		await confirm_blob("", "Tor Address", address, verb = "Valid".upper())
	
	# Otherwise check if address type is Slatepack
	elif message.address_type == MimbleWimbleCoinAddressType.SLATEPACK:
	
		# Check if currency doesn't allow Slatepack addresses
		if not coinInfo.enableSlatepackAddress:
		
			# Raise data error
			raise DataError("")
		
		# Try
		try:
		
			# Get Slatepack address
			address = mimblewimble_coin.getSlatepackAddress(extendedPrivateKey, coinInfo, message.index)
		
		# Catch errors
		except:
		
			# Raise process error
			raise ProcessError("")
		
		# Show prompt
		await confirm_action("", coinInfo.name, action = "Verify Slatepack address.", verb = "Next")
		
		# Show prompt
		await confirm_blob("", "Slatepack Address", address, verb = "Valid".upper())
	
	# Return success
	return Success()
