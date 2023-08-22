# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinContinueTransactionIncludeOutput, Success


# Supporting function implementation

# Continue transaction include output
async def continue_transaction_include_output(message: MimbleWimbleCoinContinueTransactionIncludeOutput) -> Success:

	# Imports
	from trezor.messages import Success
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from storage.cache import delete, get_memory_view, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError, InvalidSession
	from trezor.crypto import mimblewimble_coin
	from trezor.enums import MimbleWimbleCoinSwitchType
	from uctypes import struct, addressof, UINT8, UINT32, ARRAY
	from struct import unpack, calcsize
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey, UINT64_MAX, NATIVE_UINT64_PACK_FORMAT
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
	delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
	# Get session's transaction context
	transactionContext = get_memory_view(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get session's transaction context's structure
	transactionContextStructure = struct(addressof(transactionContext), {
	
		# Coin type
		"coinType": mimblewimble_coin.TRANSACTION_CONTEXT_COIN_TYPE_OFFSET | UINT8,
		
		# Network type
		"networkType": mimblewimble_coin.TRANSACTION_CONTEXT_NETWORK_TYPE_OFFSET | UINT8,
		
		# Account
		"account": mimblewimble_coin.TRANSACTION_CONTEXT_ACCOUNT_OFFSET | UINT32,
		
		# Remaining output
		"remainingOutput": (mimblewimble_coin.TRANSACTION_CONTEXT_REMAINING_OUTPUT_OFFSET | ARRAY, calcsize(NATIVE_UINT64_PACK_FORMAT) | UINT8),
		
		# Started
		"started": mimblewimble_coin.TRANSACTION_CONTEXT_STARTED_OFFSET | UINT8
	})
	
	# Check if identifier is invalid
	if len(message.identifier) != mimblewimble_coin.IDENTIFIER_SIZE:
	
		# Raise data error
		raise DataError("")
	
	# Check if identifier depth is invalid
	if message.identifier[mimblewimble_coin.IDENTIFIER_DEPTH_INDEX] > mimblewimble_coin.MAXIMUM_IDENTIFIER_DEPTH:
	
		# Raise data error
		raise DataError("")
	
	# Check if value is invalid
	if message.value == 0 or message.value > UINT64_MAX:
	
		# Raise data error
		raise DataError("")
	
	# Check if switch type is invalid
	if message.switch_type != MimbleWimbleCoinSwitchType.REGULAR:
	
		# Raise data error
		raise DataError("")
	
	# Check if session's transaction context hasn't been started
	if transactionContextStructure.started == 0:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Try
	try:
	
		# Get coin info
		coinInfo = getCoinInfo(transactionContextStructure.coinType, transactionContextStructure.networkType)
	
	# Catch errors
	except:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Check if session's transaction context has no more remaining output
	remainingOutput = unpack(NATIVE_UINT64_PACK_FORMAT, transactionContextStructure.remainingOutput)[0]
	if remainingOutput == 0:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Check if value is too big for the session's transaction context's remaining output
	if message.value > remainingOutput:
	
		# Raise data error
		raise DataError("")
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, transactionContextStructure.account)
	
	# Try
	try:
	
		# Include the output in the transaction
		mimblewimble_coin.includeOutputInTransaction(transactionContext, extendedPrivateKey, message.value, message.identifier, message.switch_type)
	
	# Catch errors
	except:
	
		# Clear session's transaction context
		delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
		
		# Raise process error
		raise ProcessError("")
	
	# Return success
	return Success()
