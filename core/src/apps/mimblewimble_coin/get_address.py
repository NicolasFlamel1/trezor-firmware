# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinGetAddress, MimbleWimbleCoinAddress


# Supporting function implementation

# Get address
async def get_address(context: Context, message: MimbleWimbleCoinGetAddress) -> MimbleWimbleCoinAddress:

	# Imports
	from trezor.messages import MimbleWimbleCoinAddress
	from storage.device import is_initialized
	from apps.base import unlock_device
	from storage.cache import delete, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.crypto import mimblewimble_coin
	from trezor.enums import MimbleWimbleCoinAddressType
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey, UINT32_MAX
	
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
	
	# Check if index is invalid
	if message.index > UINT32_MAX:
	
		# Raise data error
		raise DataError("")
	
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
	
	# Return address
	return MimbleWimbleCoinAddress(address = address)
