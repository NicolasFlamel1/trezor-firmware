# Imports
from typing import TYPE_CHECKING
from .common import MINUTES_IN_AN_HOUR, HOURS_IN_A_DAY, DAYS_IN_A_WEEK

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinFinishTransaction, MimbleWimbleCoinTransactionSignatureAndPaymentProof


# Constants

# Maximum relative height
MAXIMUM_RELATIVE_HEIGHT = DAYS_IN_A_WEEK * HOURS_IN_A_DAY * MINUTES_IN_AN_HOUR


# Supporting function implementation

# Finish transaction
async def finish_transaction(message: MimbleWimbleCoinFinishTransaction) -> MimbleWimbleCoinTransactionSignatureAndPaymentProof:

	# Imports
	from trezor.messages import MimbleWimbleCoinTransactionSignatureAndPaymentProof
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer
	from storage.cache import delete, get_memory_view, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError, InvalidSession, ActionCancelled
	from trezor.ui.layouts import confirm_action, confirm_value, confirm_blob, show_warning
	from trezor.enums import ButtonRequestType
	from trezor.crypto import mimblewimble_coin
	from trezor.enums import MimbleWimbleCoinAddressType
	from trezor.strings import format_amount
	from uctypes import struct, addressof, UINT8, UINT32, ARRAY
	from struct import unpack, calcsize
	from .coins import getCoinInfo, PaymentProofAddressType
	from .common import getExtendedPrivateKey, NATIVE_UINT64_PACK_FORMAT
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
		
		# Send
		"send": (mimblewimble_coin.TRANSACTION_CONTEXT_SEND_OFFSET | ARRAY, calcsize(NATIVE_UINT64_PACK_FORMAT) | UINT8),
		
		# Receive
		"receive": (mimblewimble_coin.TRANSACTION_CONTEXT_RECEIVE_OFFSET | ARRAY, calcsize(NATIVE_UINT64_PACK_FORMAT) | UINT8),
		
		# Fee
		"fee": (mimblewimble_coin.TRANSACTION_CONTEXT_FEE_OFFSET | ARRAY, calcsize(NATIVE_UINT64_PACK_FORMAT) | UINT8),
		
		# Remaining output
		"remainingOutput": (mimblewimble_coin.TRANSACTION_CONTEXT_REMAINING_OUTPUT_OFFSET | ARRAY, calcsize(NATIVE_UINT64_PACK_FORMAT) | UINT8),
		
		# Remaining input
		"remainingInput": (mimblewimble_coin.TRANSACTION_CONTEXT_REMAINING_INPUT_OFFSET | ARRAY, calcsize(NATIVE_UINT64_PACK_FORMAT) | UINT8),
		
		# Started
		"started": mimblewimble_coin.TRANSACTION_CONTEXT_STARTED_OFFSET | UINT8,
		
		# Offset applied
		"offsetApplied": mimblewimble_coin.TRANSACTION_CONTEXT_OFFSET_APPLIED_OFFSET | UINT8,
		
		# Address
		"address": (mimblewimble_coin.TRANSACTION_CONTEXT_ADDRESS_OFFSET | ARRAY, mimblewimble_coin.TRANSACTION_CONTEXT_ADDRESS_SIZE | UINT8)
	})
	
	# Check if public nonce is invalid
	if not mimblewimble_coin.isValidSecp256k1PublicKey(message.public_nonce):
	
		# Raise data error
		raise DataError("")
	
	# Check if public key is invalid
	if not mimblewimble_coin.isValidSecp256k1PublicKey(message.public_key):
	
		# Raise data error
		raise DataError("")
	
	# Check if kernel information is invalid
	if len(message.kernel_information) == 0:
	
		# Raise data error
		raise DataError("")
	
	# Check if kernel information's features is plain or coinbase features
	if message.kernel_information[0] == mimblewimble_coin.KernelFeatures.PLAIN_FEATURES or message.kernel_information[0] == mimblewimble_coin.KernelFeatures.COINBASE_FEATURES:
	
		# Check if kernel information is invalid
		if len(message.kernel_information) != calcsize("<B"):
		
			# Raise data error
			raise DataError("")
	
	# Otherwise check if kernel information's features is height locked features
	elif message.kernel_information[0] == mimblewimble_coin.KernelFeatures.HEIGHT_LOCKED_FEATURES:
	
		# Check if kernel information is invalid
		if len(message.kernel_information) != calcsize("<BQ"):
		
			# Raise data error
			raise DataError("")
	
	# Otherwise check if kernel information's features is no recent duplicate features
	elif message.kernel_information[0] == mimblewimble_coin.KernelFeatures.NO_RECENT_DUPLICATE_FEATURES:
	
		# Check if kernel information is invalid
		if len(message.kernel_information) != calcsize("<BH"):
		
			# Raise data error
			raise DataError("")
		
		# Get relative height from kernel information
		relativeHeight = unpack("<BH", message.kernel_information)[1]
		
		# Check if relative height is invalid
		if relativeHeight == 0 or relativeHeight > MAXIMUM_RELATIVE_HEIGHT:
		
			# Raise data error
			raise DataError("")
	
	# Otherwise
	else:
	
		# Raise data error
		raise DataError("")
	
	# Check if kernel commitment is invalid
	if message.kernel_commitment is not None and not mimblewimble_coin.isValidCommitment(message.kernel_commitment):
	
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
	
	# Check if address type is MQS
	if message.address_type == MimbleWimbleCoinAddressType.MQS:
	
		# Check if currency doesn't allow MQS addresses or doesn't support MQS payment proof addresses
		if not coinInfo.enableMqsAddress or (coinInfo.supportedPaymentProofAddressTypes & PaymentProofAddressType.MQS_PAYMENT_PROOF_ADDRESS) == 0:
		
			# Raise data error
			raise DataError("")
	
	# Otherwise check if address type is Tor
	elif message.address_type == MimbleWimbleCoinAddressType.TOR:
	
		# Check if currency doesn't allow Tor addresses or doesn't support Tor payment proof addresses
		if not coinInfo.enableTorAddress or (coinInfo.supportedPaymentProofAddressTypes & PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS) == 0:
		
			# Raise data error
			raise DataError("")
	
	# Otherwise check if address type is Slatepack
	elif message.address_type == MimbleWimbleCoinAddressType.SLATEPACK:
	
		# Check if currency doesn't allow Slatepack addresses or doesn't support Slatepack payment proof addresses
		if not coinInfo.enableSlatepackAddress or (coinInfo.supportedPaymentProofAddressTypes & PaymentProofAddressType.SLATEPACK_PAYMENT_PROOF_ADDRESS) == 0:
		
			# Raise data error
			raise DataError("")
	
	# Check if kernel information's features is coinbase features
	send = unpack(NATIVE_UINT64_PACK_FORMAT, transactionContextStructure.send)[0]
	if message.kernel_information[0] == mimblewimble_coin.KernelFeatures.COINBASE_FEATURES:
	
		# Check if session's transaction context is sending
		if send != 0:
		
			# Raise data error
			raise DataError("")
		
		# Check if session's transaction context has an address
		if transactionContextStructure.address[0] != 0:
		
			# Raise data error
			raise DataError("")
	
	# Otherwise check if kernel information's features is no recent duplicate features
	elif message.kernel_information[0] == mimblewimble_coin.KernelFeatures.NO_RECENT_DUPLICATE_FEATURES:
	
		# Check if currency doesn't allow no recent duplicate kernels
		if not coinInfo.enableNoRecentDuplicateKernels:
		
			# Raise data error
			raise DataError("")
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, transactionContextStructure.account)
	
	# Check if session's transaction context is sending
	if send != 0:
	
		# Check if a kernel commitment exists
		if message.kernel_commitment is not None:
		
			# Check if session's transaction context doesn't have an address
			if transactionContextStructure.address[0] == 0:
			
				# Raise data error
				raise DataError("")
			
			# Check if a payment proof doesn't exist
			if message.payment_proof is None:
			
				# Raise data error
				raise DataError("")
			
			# Check if verifying transaction payment proof failed
			if not mimblewimble_coin.verifyTransactionPaymentProof(transactionContext, extendedPrivateKey, coinInfo, message.address_type, message.kernel_commitment, message.payment_proof):
			
				# Raise data error
				raise DataError("")
		
		# Otherwise check if a payment proof exists
		elif message.payment_proof is not None:
		
			# Raise data error
			raise DataError("")
		
		# Check if an offset wasn't applied to the session's transaction context
		if transactionContextStructure.offsetApplied == 0:
		
			# Raise invalid session
			raise InvalidSession("")
	
	# Otherwise
	else:
	
		# Check if a kernel commitment exists but session's transaction context doesn't have an address
		if message.kernel_commitment is not None and transactionContextStructure.address[0] == 0:
		
			# Raise data error
			raise DataError("")
		
		# Check if a payment proof exists
		if message.payment_proof is not None:
		
			# Raise data error
			raise DataError("")
	
	# Check if session's transaction context has remaining output or input
	remainingOutput = unpack(NATIVE_UINT64_PACK_FORMAT, transactionContextStructure.remainingOutput)[0]
	remainingInput = unpack(NATIVE_UINT64_PACK_FORMAT, transactionContextStructure.remainingInput)[0]
	if remainingOutput != 0 or remainingInput != 0:
	
		# Raise invalid session
		raise InvalidSession("")
	
	# Try
	try:
	
		# Show prompt
		await confirm_action("", coinInfo.name, action = "Send transaction?" if send != 0 else "Receive transaction?", verb = "Next")
		
		# Show prompt
		await confirm_value("Account Index", str(transactionContextStructure.account), "", "", verb = "Next")
		
		# Show prompt
		receive = unpack(NATIVE_UINT64_PACK_FORMAT, transactionContextStructure.receive)[0]
		await confirm_value("Amount", format_amount(send if send != 0 else receive, coinInfo.fractionalDigits, useGrouping = False), "", "", verb = "Next")
		
		# Show prompt
		fee = unpack(NATIVE_UINT64_PACK_FORMAT, transactionContextStructure.fee)[0]
		await confirm_value("Fee", format_amount(fee, coinInfo.fractionalDigits, useGrouping = False), "", "", verb = "Next")
		
		# Check kernel information's features is plain features
		if message.kernel_information[0] == mimblewimble_coin.KernelFeatures.PLAIN_FEATURES:
		
			# Show prompt
			await confirm_action("", "Kernel Features", action = "Plain", verb = "Next")
		
		# Otherwise check kernel information's features is coinbase features
		elif message.kernel_information[0] == mimblewimble_coin.KernelFeatures.COINBASE_FEATURES:
		
			# Show prompt
			await confirm_action("", "Kernel Features", action = "Coinbase", verb = "Next")
		
		# Otherwise check kernel information's features is height locked features
		elif message.kernel_information[0] == mimblewimble_coin.KernelFeatures.HEIGHT_LOCKED_FEATURES:
		
			# Show prompt
			await confirm_action("", "Kernel Features", action = "Height locked", verb = "Next")
			
			# Get lock height from kernel information
			lockHeight = unpack("<BQ", message.kernel_information)[1]
			
			# Show prompt
			await confirm_value("Lock Height", str(lockHeight), "", "", verb = "Next")
		
		# Otherwise check kernel information's features is no recent duplicate features
		elif message.kernel_information[0] == mimblewimble_coin.KernelFeatures.NO_RECENT_DUPLICATE_FEATURES:
		
			# Show prompt
			await confirm_action("", "Kernel Features", action = "No recent duplicate", verb = "Next")
			
			# Get relative height from kernel information
			relativeHeight = unpack("<BH", message.kernel_information)[1]
			
			# Show prompt
			await confirm_value("Relative Height", str(relativeHeight), "", "", verb = "Next")
		
		# Check if kernel commitment exists
		if message.kernel_commitment is not None:
		
			# Show prompt
			await confirm_blob("", "Proof Address", bytes(transactionContextStructure.address).split(b"\0", 1)[0].decode(), verb = "Approve".upper())
			
		# Otherwise
		else:
		
			# Show prompt
			await show_warning("", "No payment proof.", button = "Approve", br_code = ButtonRequestType.Other, left_is_small = True)
	
	# Catch action cancelled errors
	except ActionCancelled:
	
		# Clear session's transaction context
		delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
		
		# Raise error
		raise
	
	# Try
	try:
	
		# Finish transaction
		signature, paymentProof = mimblewimble_coin.finishTransaction(transactionContext, extendedPrivateKey, coinInfo, message.address_type, message.public_nonce, message.public_key, message.kernel_information, message.kernel_commitment)
	
	# Catch errors
	except:
	
		# Clear session's transaction context
		delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
		
		# Raise process error
		raise ProcessError("")
	
	# Clear session's transaction context
	delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Return transaction signature and payment proof
	return MimbleWimbleCoinTransactionSignatureAndPaymentProof(signature = signature, payment_proof = paymentProof)
