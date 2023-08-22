# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinContinueDecryptingSlate, MimbleWimbleCoinDecryptedSlateData


# Supporting function implementation

# Continue decrypting slate
async def continue_decrypting_slate(context: Context, message: MimbleWimbleCoinContinueDecryptingSlate) -> MimbleWimbleCoinDecryptedSlateData:

	# Imports
	from trezor.messages import MimbleWimbleCoinDecryptedSlateData
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from storage.cache import delete, get_memory_view, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError, InvalidSession
	from trezor.crypto import mimblewimble_coin
	from uctypes import struct, addressof, UINT8
	from .storage import initializeStorage
	
	# Check if not initialized
	if not is_initialized():
	
		# Raise not initialized error
		raise NotInitialized("")
	
	# Unlock device
	await unlock_device()
	
	# Cache seed
	await derive_and_store_roots(context, False)
	
	# Initialize storage
	initializeStorage()
	
	# Clear unrelated session
	delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get session's encryption and decryption context
	encryptionAndDecryptionContext = get_memory_view(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
	# Get session's encryption and decryption context's structure
	encryptionAndDecryptionContextStructure = struct(addressof(encryptionAndDecryptionContext), {
	
		# Decrypting state
		"decryptingState": mimblewimble_coin.ENCRYPTION_AND_DECRYPTION_CONTEXT_DECRYPTING_STATE_OFFSET | UINT8
	})
	
	# Check if encrypted data is invalid
	if len(message.encrypted_data) == 0 or len(message.encrypted_data) > mimblewimble_coin.CHACHA20_BLOCK_SIZE:
	
		# Raise data error
		raise DataError("")
	
	# Check if session's encryption and decryption context's decrypting state isn't ready or active
	if encryptionAndDecryptionContextStructure.decryptingState != mimblewimble_coin.EncryptingOrDecryptingState.READY_STATE and encryptionAndDecryptionContextStructure.decryptingState != mimblewimble_coin.EncryptingOrDecryptingState.ACTIVE_STATE:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Try
	try:
	
		# Decrypt data
		data = mimblewimble_coin.decryptData(encryptionAndDecryptionContext, message.encrypted_data)
	
	# Catch errors
	except:
	
		# Clear session's encryption and decryption context
		delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
		# Raise process error
		raise ProcessError("")
	
	# Return decrypted slate data
	return MimbleWimbleCoinDecryptedSlateData(data = data)
