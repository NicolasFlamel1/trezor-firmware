# Imports
from typing import TYPE_CHECKING
from .common import UINT8_MAX

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinStartEncryptingSlate, MimbleWimbleCoinEncryptedSlateNonceAndSalt


# Constants

# Maximum recipient address size
MAXIMUM_RECIPIENT_ADDRESS_SIZE = UINT8_MAX - 8


# Supporting function implementation

# Start encrypting slate
async def start_encrypting_slate(message: MimbleWimbleCoinStartEncryptingSlate) -> MimbleWimbleCoinEncryptedSlateNonceAndSalt:

	# Imports
	from trezor.messages import MimbleWimbleCoinEncryptedSlateNonceAndSalt
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer
	from storage.cache import delete, get_memory_view, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.crypto import mimblewimble_coin
	from apps.common.paths import HARDENED
	from uctypes import struct, addressof, UINT8, UINT32
	from .coins import getCoinInfo, SlateEncryptionType
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
	
	# Get session's encryption and decryption context
	encryptionAndDecryptionContext = get_memory_view(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
	# Get session's encryption and decryption context's structure
	encryptionAndDecryptionContextStructure = struct(addressof(encryptionAndDecryptionContext), {
	
		# Coin type
		"coinType": mimblewimble_coin.ENCRYPTION_AND_DECRYPTION_CONTEXT_COIN_TYPE_OFFSET | UINT8,
		
		# Network type
		"networkType": mimblewimble_coin.ENCRYPTION_AND_DECRYPTION_CONTEXT_NETWORK_TYPE_OFFSET | UINT8,
		
		# Account
		"account": mimblewimble_coin.ENCRYPTION_AND_DECRYPTION_CONTEXT_ACCOUNT_OFFSET | UINT32
	})
	
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
	
	# Check if recipient address is invalid
	if len(message.recipient_address) > MAXIMUM_RECIPIENT_ADDRESS_SIZE:
	
		# Raise data error
		raise DataError("")
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, message.account)
	
	# Get address components
	addressComponents = message.recipient_address.split(b"@", 1)
	
	# Check if address is an MQS address
	if len(addressComponents[0]) == mimblewimble_coin.MQS_ADDRESS_SIZE:
	
		# Check if currency doesn't allow MQS addresses or doesn't support MQS slate encryption
		if not coinInfo.enableMqsAddress or (coinInfo.supportedSlateEncryptionTypes & SlateEncryptionType.MQS_SLATE_ENCRYPTION) == 0:
		
			# Raise data error
			raise DataError("")
		
		# Check if address has a domain
		if len(addressComponents) > 1:
		
			# Check if address domain isn't a valid MQS address domain
			if not mimblewimble_coin.isValidMqsAddressDomain(addressComponents[1]):
			
				# Raise data error
				raise DataError("")
		
		# Check if recipient address isn't a valid MQS address
		if not mimblewimble_coin.isValidMqsAddress(addressComponents[0], coinInfo):
		
			# Raise data error
			raise DataError("")
		
		# Try
		try:
		
			# Start MQS encryption
			nonce, salt = mimblewimble_coin.startMqsEncryption(encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message.index, addressComponents[0], addressComponents[1] if len(addressComponents) > 1 else None)
		
		# Catch errors
		except:
		
			# Raise process error
			raise ProcessError("")
	
	# Otherwise check if address is a TOR address
	elif len(addressComponents[0]) == mimblewimble_coin.TOR_ADDRESS_SIZE:
	
		# Check if currency doesn't allow Tor addresses or doesn't support Tor slate encryption
		if not coinInfo.enableTorAddress or (coinInfo.supportedSlateEncryptionTypes & SlateEncryptionType.TOR_SLATE_ENCRYPTION) == 0:
		
			# Raise data error
			raise DataError("")
		
		# Check if address has a domain
		if len(addressComponents) > 1:
		
			# Raise data error
			raise DataError("")
		
		# Check if recipient address isn't a valid Tor address
		if not mimblewimble_coin.isValidTorAddress(addressComponents[0]):
		
			# Raise data error
			raise DataError("")
		
		# Try
		try:
		
			# Start Tor encryption
			nonce = mimblewimble_coin.startTorEncryption(encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message.index, addressComponents[0])
			salt = None
			
		# Catch errors
		except:
		
			# Raise process error
			raise ProcessError("")
	
	# Otherwise
	else:
	
		# Raise data error
		raise DataError("")
	
	# Set session's encryption and decryption context's coin type
	encryptionAndDecryptionContextStructure.coinType = message.coin_type
	
	# Set session's encryption and decryption context's network type
	encryptionAndDecryptionContextStructure.networkType = message.network_type
	
	# Set session's encryption and decryption context's account
	encryptionAndDecryptionContextStructure.account = message.account
	
	# Return encrypted slate nonce and salt
	return MimbleWimbleCoinEncryptedSlateNonceAndSalt(nonce = nonce, salt = salt)
