# Imports
from typing import TYPE_CHECKING
from .common import UINT8_MAX

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinContinueTransactionGetMessageSignature, MimbleWimbleCoinTransactionMessageSignature


# Constants

# Maximum message size
MAXIMUM_MESSAGE_SIZE = UINT8_MAX


# Supporting function implementation

# Continue transaction get message signature
async def continue_transaction_get_message_signature(context: Context, message: MimbleWimbleCoinContinueTransactionGetMessageSignature) -> MimbleWimbleCoinTransactionMessageSignature:

	# Imports
	from trezor.messages import MimbleWimbleCoinTransactionMessageSignature
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from storage.cache import delete, get_memory_view, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError, InvalidSession
	from trezor.crypto import mimblewimble_coin
	from uctypes import struct, addressof, UINT8, ARRAY
	from struct import unpack, calcsize
	from .common import NATIVE_UINT64_PACK_FORMAT
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
	delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	
	# Get session's transaction context
	transactionContext = get_memory_view(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get session's transaction context's structure
	transactionContextStructure = struct(addressof(transactionContext), {
	
		# Send
		"send": (mimblewimble_coin.TRANSACTION_CONTEXT_SEND_OFFSET | ARRAY, calcsize(NATIVE_UINT64_PACK_FORMAT) | UINT8),
		
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
	
	# Check if message is invalid
	if len(message.message) == 0 or len(message.message) > MAXIMUM_MESSAGE_SIZE:
	
		# Raise data error
		raise DataError("")
	
	# Try
	try:
	
		# Go through all characters in the message as a UTF-8 string
		for character in message.message.decode():
		
			# Check if character is a non-printable ASCII character
			if (character < " " and character != "\t" and character != "\n" and character != "\r") or character == "\x7F":
			
				# Raise data error
				raise DataError("")
	
	# Catch Unicode errors
	except UnicodeError:
	
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
	
	# Check if session's transaction context is sending and offset wasn't applied
	send = unpack(NATIVE_UINT64_PACK_FORMAT, transactionContextStructure.send)[0]
	if send != 0 and transactionContextStructure.offsetApplied == 0:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Check if a message was signed for the session's transaction context
	if transactionContextStructure.messageSigned != 0:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Try
	try:
	
		# Get the transaction's message signature
		messageSignature = mimblewimble_coin.getTransactionMessageSignature(transactionContext, message.message)
	
	# Catch errors
	except:
	
		# Clear session's transaction context
		delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
		
		# Raise process error
		raise ProcessError("")
	
	# Return transaction message signature
	return MimbleWimbleCoinTransactionMessageSignature(message_signature = messageSignature)
