# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinContinueTransactionApplyOffset, MimbleWimbleCoinTransactionSecretNonceIndex


# Supporting function implementation

# Continue transaction apply offset
async def continue_transaction_apply_offset(message: MimbleWimbleCoinContinueTransactionApplyOffset) -> MimbleWimbleCoinTransactionSecretNonceIndex:

	# Imports
	from trezor.messages import MimbleWimbleCoinTransactionSecretNonceIndex
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer
	from storage.cache_common import APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError, InvalidSession
	from trezor.wire.context import cache_delete, cache_get_memory_view
	from trezor.crypto import mimblewimble_coin
	from uctypes import struct, addressof, UINT8, ARRAY
	from struct import unpack, calcsize
	from .common import NATIVE_UINT64_PACK_FORMAT
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
	
	# Clear unrelated session
	cache_delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
	# Get session's transaction context
	transactionContext = cache_get_memory_view(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get session's transaction context's structure
	transactionContextStructure = struct(addressof(transactionContext), {
	
		# Remaining output
		"remainingOutput": (mimblewimble_coin.TRANSACTION_CONTEXT_REMAINING_OUTPUT_OFFSET | ARRAY, calcsize(NATIVE_UINT64_PACK_FORMAT) | UINT8),
		
		# Remaining input
		"remainingInput": (mimblewimble_coin.TRANSACTION_CONTEXT_REMAINING_INPUT_OFFSET | ARRAY, calcsize(NATIVE_UINT64_PACK_FORMAT) | UINT8),
		
		# Started
		"started": mimblewimble_coin.TRANSACTION_CONTEXT_STARTED_OFFSET | UINT8,
		
		# Offset applied
		"offsetApplied": mimblewimble_coin.TRANSACTION_CONTEXT_OFFSET_APPLIED_OFFSET | UINT8,
		
		# Message signed
		"messageSigned": mimblewimble_coin.TRANSACTION_CONTEXT_MESSAGE_SIGNED_OFFSET | UINT8
	})
	
	# Check if offset is invalid
	if not mimblewimble_coin.isValidSecp256k1PrivateKey(message.offset):
	
		# Raise data error
		raise DataError("")
	
	# Check if session's transaction context hasn't been started
	if transactionContextStructure.started == 0:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Check if session's transaction context has remaining output or input
	remainingOutput = unpack(NATIVE_UINT64_PACK_FORMAT, transactionContextStructure.remainingOutput)[0]
	remainingInput = unpack(NATIVE_UINT64_PACK_FORMAT, transactionContextStructure.remainingInput)[0]
	if remainingOutput != 0 or remainingInput != 0:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Check if an offset was already applied to the session's transaction context
	if transactionContextStructure.offsetApplied != 0:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Check if a message was signed for the session's transaction context
	if transactionContextStructure.messageSigned != 0:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Try
	try:
	
		# Apply offset to the transaction
		secretNonceIndex = mimblewimble_coin.applyOffsetToTransaction(transactionContext, message.offset)
	
	# Catch errors
	except:
	
		# Clear session's transaction context
		cache_delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
		
		# Raise process error
		raise ProcessError("")
	
	# Return transaction secret nonce index
	return MimbleWimbleCoinTransactionSecretNonceIndex(secret_nonce_index = secretNonceIndex)
