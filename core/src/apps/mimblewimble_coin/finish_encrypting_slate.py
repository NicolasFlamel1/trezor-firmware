# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinFinishEncryptingSlate, MimbleWimbleCoinEncryptedSlateTagAndSignature


# Supporting function implementation

# Finish encrypting slate
async def finish_encrypting_slate(message: MimbleWimbleCoinFinishEncryptingSlate) -> MimbleWimbleCoinEncryptedSlateTagAndSignature:

	# Imports
	from trezor.messages import MimbleWimbleCoinEncryptedSlateTagAndSignature
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from storage.cache import delete, get_memory_view, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, InvalidSession
	from trezor.crypto import mimblewimble_coin
	from uctypes import struct, addressof, UINT8, UINT32
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey
	from .storage import initializeStorage
	
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
	
	# Clear unrelated session
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
		"account": mimblewimble_coin.ENCRYPTION_AND_DECRYPTION_CONTEXT_ACCOUNT_OFFSET | UINT32,
		
		# Encrypting state
		"encryptingState": mimblewimble_coin.ENCRYPTION_AND_DECRYPTION_CONTEXT_ENCRYPTING_STATE_OFFSET | UINT8
	})
	
	# Check if session's encryption and decryption context's encrypting state isn't active or complete
	if encryptionAndDecryptionContextStructure.encryptingState != mimblewimble_coin.EncryptingOrDecryptingState.ACTIVE_STATE and encryptionAndDecryptionContextStructure.encryptingState != mimblewimble_coin.EncryptingOrDecryptingState.COMPLETE_STATE:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Try
	try:
	
		# Get coin info
		coinInfo = getCoinInfo(encryptionAndDecryptionContextStructure.coinType, encryptionAndDecryptionContextStructure.networkType)
	
	# Catch errors
	except:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, encryptionAndDecryptionContextStructure.account)
	
	# Try
	try:
	
		# Finish encryption
		tag, mqsMessageSignature = mimblewimble_coin.finishEncryption(encryptionAndDecryptionContext, extendedPrivateKey, coinInfo)
	
	# Catch errors
	except:
	
		# Clear session's encryption and decryption context
		delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
		# Raise process error
		raise ProcessError("")
	
	# Clear session's encryption and decryption context
	delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
	# Return encrypted slate tag and signature
	return MimbleWimbleCoinEncryptedSlateTagAndSignature(tag = tag, mqs_message_signature = mqsMessageSignature)
