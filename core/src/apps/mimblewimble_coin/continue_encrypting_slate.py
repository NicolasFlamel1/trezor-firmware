# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinContinueEncryptingSlate, MimbleWimbleCoinEncryptedSlateData


# Supporting function implementation

# Continue encrypting slate
async def continue_encrypting_slate(context: Context, message: MimbleWimbleCoinContinueEncryptingSlate) -> MimbleWimbleCoinEncryptedSlateData:

	# Imports
	from trezor.messages import MimbleWimbleCoinEncryptedSlateData
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from storage.cache import delete, get_memory_view, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError, InvalidSession
	from trezor.crypto import mimblewimble_coin
	from uctypes import struct, addressof, INT
	
	# Check if not initialized
	if not is_initialized():
	
		# Raise not initialized error
		raise NotInitialized("")
	
	# Unlock device
	await unlock_device()
	
	# Cache seed
	await derive_and_store_roots(context, False)
	
	# TODO Initialize storage
	
	# Clear unrelated session
	delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get session's encryption and decryption context
	encryptionAndDecryptionContext = get_memory_view(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
	# Get session's encryption and decryption context's structure
	encryptionAndDecryptionContextStructure = struct(addressof(encryptionAndDecryptionContext), {
	
		# Encrypting state
		"encryptingState": mimblewimble_coin.ENCRYPTION_AND_DECRYPTION_CONTEXT_ENCRYPTING_STATE_OFFSET | INT
	})
	
	# Check if data is invalid
	if len(message.data) == 0:
	
		# Raise data error
		raise DataError("")
	
	# Check if session's encryption and decryption context's encrypting state isn't ready or active
	if encryptionAndDecryptionContextStructure.encryptingState != mimblewimble_coin.EncryptingOrDecryptingState.READY_STATE and encryptionAndDecryptionContextStructure.encryptingState != mimblewimble_coin.EncryptingOrDecryptingState.ACTIVE_STATE:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Try
	try:
	
		# Encrypt data
		encryptedData = mimblewimble_coin.encryptData(encryptionAndDecryptionContext, message.data)
	
	# Catch errors
	except:
	
		# Clear session's encryption and decryption context
		delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
		# Raise process error
		raise ProcessError("")
	
	# Return encrypted slate data
	return MimbleWimbleCoinEncryptedSlateData(encrypted_data = encryptedData)
