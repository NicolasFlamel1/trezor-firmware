# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinStartDecryptingSlate, Success


# Supporting function implementation

# Start decrypting slate
async def start_decrypting_slate(message: MimbleWimbleCoinStartDecryptingSlate) -> Success:

	# Imports
	from trezor.messages import Success
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer
	from storage.cache_common import APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.wire.context import cache_delete, cache_get_memory_view
	from trezor.crypto import mimblewimble_coin
	from apps.common.paths import HARDENED
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
	cache_delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	cache_delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get session's encryption and decryption context
	encryptionAndDecryptionContext = cache_get_memory_view(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
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
	
	# Check if nonce is invalid
	if len(message.nonce) != mimblewimble_coin.CHACHA20_NONCE_SIZE:
	
		# Raise data error
		raise DataError("")
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, message.account)
	
	# Check if sender address or ephemeral X25519 public key is an MQS address
	if len(message.sender_address_or_ephemeral_x25519_public_key) == mimblewimble_coin.MQS_ADDRESS_SIZE:
	
		# Check if currency doesn't allow MQS addresses or doesn't support MQS slate encryption
		if not coinInfo.enableMqsAddress or (coinInfo.supportedSlateEncryptionTypes & SlateEncryptionType.MQS_SLATE_ENCRYPTION) == 0:
		
			# Raise data error
			raise DataError("")
		
		# Check if sender address or ephemeral X25519 public key isn't a valid MQS address
		if not mimblewimble_coin.isValidMqsAddress(message.sender_address_or_ephemeral_x25519_public_key, coinInfo):
		
			# Raise data error
			raise DataError("")
		
		# Check if salt or encrypted file key is invalid
		if message.salt_or_encrypted_file_key is None or len(message.salt_or_encrypted_file_key) != mimblewimble_coin.MQS_ENCRYPTION_SALT_SIZE:
		
			# Raise data error
			raise DataError("")
		
		# Check if payload nonce exists
		if message.payload_nonce is not None:
		
			# Raise data error
			raise DataError("")
		
		# Try
		try:
		
			# Start MQS decryption
			mimblewimble_coin.startMqsDecryption(encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message.index, message.sender_address_or_ephemeral_x25519_public_key, message.nonce, message.salt_or_encrypted_file_key)
		
		# Catch errors
		except:
		
			# Raise process error
			raise ProcessError("")
	
	# Otherwise check if sender address or ephemeral X25519 public key is a Tor address
	elif len(message.sender_address_or_ephemeral_x25519_public_key) == mimblewimble_coin.TOR_ADDRESS_SIZE:
	
		# Check if currency doesn't allow Tor addresses or doesn't support Tor slate encryption
		if not coinInfo.enableTorAddress or (coinInfo.supportedSlateEncryptionTypes & SlateEncryptionType.TOR_SLATE_ENCRYPTION) == 0:
		
			# Raise data error
			raise DataError("")
		
		# Check if sender address or ephemeral X25519 public key isn't a valid Tor address
		if not mimblewimble_coin.isValidTorAddress(message.sender_address_or_ephemeral_x25519_public_key):
		
			# Raise data error
			raise DataError("")
		
		# Check if salt or encrypted file key exists
		if message.salt_or_encrypted_file_key is not None:
		
			# Raise data error
			raise DataError("")
		
		# Check if payload nonce exists
		if message.payload_nonce is not None:
		
			# Raise data error
			raise DataError("")
		
		# Try
		try:
		
			# Start Tor decryption
			mimblewimble_coin.startTorDecryption(encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message.index, message.sender_address_or_ephemeral_x25519_public_key, message.nonce)
			
		# Catch errors
		except:
		
			# Raise process error
			raise ProcessError("")
	
	# Otherwise check if sender address or ephemeral X25519 public key is an X25519 public key size
	elif len(message.sender_address_or_ephemeral_x25519_public_key) == mimblewimble_coin.X25519_PUBLIC_KEY_SIZE:
	
		# Check if currency doesn't allow Slatepack addresses or doesn't support Slatepack slate encryption
		if not coinInfo.enableSlatepackAddress or (coinInfo.supportedSlateEncryptionTypes & SlateEncryptionType.SLATEPACK_SLATE_ENCRYPTION) == 0:
		
			# Raise data error
			raise DataError("")
		
		# Check if sender address or ephemeral X25519 public key isn't a valid X25519 public key
		if not mimblewimble_coin.isValidX25519PublicKey(message.sender_address_or_ephemeral_x25519_public_key):
		
			# Raise data error
			raise DataError("")
		
		# Check if salt or encrypted file key is invalid
		if message.salt_or_encrypted_file_key is None or len(message.salt_or_encrypted_file_key) != mimblewimble_coin.SLATEPACK_ENCRYPTION_ENCRYPTED_FILE_KEY_SIZE:
		
			# Raise data error
			raise DataError("")
		
		# Check if payload nonce is invalid
		if message.payload_nonce is None or len(message.payload_nonce) != mimblewimble_coin.AGE_PAYLOAD_NONCE_SIZE:
		
			# Raise data error
			raise DataError("")
		
		# Try
		try:
		
			# Start Slatepack decryption
			mimblewimble_coin.startSlatepackDecryption(encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message.index, message.sender_address_or_ephemeral_x25519_public_key, message.nonce, message.salt_or_encrypted_file_key, message.payload_nonce)
			
		# Catch errors
		except:
		
			# Raise process error
			raise ProcessError("")
	
	# Otherwise
	else:
	
		# Raise data error
		raise DataError("")
	
	# Return success
	return Success()
