# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinStartTransaction, Success


# Supporting function implementation

# Start transaction
async def start_transaction(message: MimbleWimbleCoinStartTransaction) -> Success:

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
	from uctypes import struct, addressof, UINT8, UINT32
	from .coins import getCoinInfo, PaymentProofAddressType
	from .common import UINT32_MAX, UINT64_MAX
	from .storage import initializeStorage, getTransactionSecretNonce, NUMBER_OF_TRANSACTION_SECRET_NONCES
	
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
	
	# Get session's transaction context
	transactionContext = cache_get_memory_view(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get session's transaction context's structure
	transactionContextStructure = struct(addressof(transactionContext), {
	
		# Coin type
		"coinType": mimblewimble_coin.TRANSACTION_CONTEXT_COIN_TYPE_OFFSET | UINT8,
		
		# Network type
		"networkType": mimblewimble_coin.TRANSACTION_CONTEXT_NETWORK_TYPE_OFFSET | UINT8,
		
		# Account
		"account": mimblewimble_coin.TRANSACTION_CONTEXT_ACCOUNT_OFFSET | UINT32
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
	
	# Check if output is invalid
	if message.output > UINT64_MAX:
	
		# Raise data error
		raise DataError("")
	
	# Check if input is invalid
	if message.input > UINT64_MAX:
	
		# Raise data error
		raise DataError("")
	
	# Check if fee is invalid
	if message.fee > UINT64_MAX:
	
		# Raise data error
		raise DataError("")
	
	# Check if an address is provided
	if message.address is not None:
	
		# Check if address is an MQS address
		if len(message.address) == mimblewimble_coin.MQS_ADDRESS_SIZE:
		
			# Check if currency doesn't allow MQS addresses or doesn't support MQS payment proof addresses
			if not coinInfo.enableMqsAddress or (coinInfo.supportedPaymentProofAddressTypes & PaymentProofAddressType.MQS_PAYMENT_PROOF_ADDRESS) == 0:
			
				# Raise data error
				raise DataError("")
			
			# Check if address isn't a valid MQS address
			if not mimblewimble_coin.isValidMqsAddress(message.address, coinInfo):
			
				# Raise data error
				raise DataError("")
		
		# Otherwise check if address is a Tor address
		elif len(message.address) == mimblewimble_coin.TOR_ADDRESS_SIZE:
		
			# Check if currency doesn't allow Tor addresses or doesn't support Tor payment proof addresses
			if not coinInfo.enableTorAddress or (coinInfo.supportedPaymentProofAddressTypes & PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS) == 0:
			
				# Raise data error
				raise DataError("")
			
			# Check if address isn't a valid Tor address
			if not mimblewimble_coin.isValidTorAddress(message.address):
			
				# Raise data error
				raise DataError("")
		
		# Otherwise check if address is a Slatepack address
		elif len(message.address) == mimblewimble_coin.SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + len(coinInfo.slatepackAddressHumanReadablePart):
		
			# Check if currency doesn't allow Slatepack addresses or doesn't support Slatepack payment proof addresses
			if not coinInfo.enableSlatepackAddress or (coinInfo.supportedPaymentProofAddressTypes & PaymentProofAddressType.SLATEPACK_PAYMENT_PROOF_ADDRESS) == 0:
			
				# Raise data error
				raise DataError("")
			
			# Check if address isn't a valid Slatepack address
			if not mimblewimble_coin.isValidSlatepackAddress(message.address, coinInfo):
			
				# Raise data error
				raise DataError("")
		
		# Otherwise
		else:
		
			# Raise data error
			raise DataError("")
	
	# Check if input exists
	if message.input != 0:
	
		# Check if input is invalid
		if message.input <= message.output:
		
			# Raise data error
			raise DataError("")
		
		# Check if fee is invalid or will overflow
		if message.fee == 0 or message.fee > coinInfo.maximumFee or UINT64_MAX - message.input < message.fee:
		
			# Raise data error
			raise DataError("")
		
		# Check if secret nonce index is invalid
		if message.secret_nonce_index > NUMBER_OF_TRANSACTION_SECRET_NONCES:
		
			# Raise data error
			raise DataError("")
		
		# Check if secret nonce index exists
		if message.secret_nonce_index != 0:
		
			# Check if getting transaction secret nonce at the index from storage failed
			transactionSecretNonce = getTransactionSecretNonce(message.secret_nonce_index - 1)
			if transactionSecretNonce is False:
			
				# Raise process error
				raise ProcessError("")
			
			# Check if transaction secret nonce is invalid
			if mimblewimble_coin.isZero(transactionSecretNonce):
			
				# Raise data error
				raise DataError("")
	
	# Otherwise
	else:
	
		# Check if output is invalid
		if message.output == 0:
		
			# Raise data error
			raise DataError("")
		
		# Check if secret nonce index is invalid
		if message.secret_nonce_index != 0:
		
			# Raise data error
			raise DataError("")
	
	# Try
	try:
	
		# Start transaction
		mimblewimble_coin.startTransaction(transactionContext, message.index, message.output, message.input, message.fee, message.secret_nonce_index, message.address)
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
	
	# Set session's transaction context's coin type
	transactionContextStructure.coinType = message.coin_type
	
	# Set session's transaction context's network type
	transactionContextStructure.networkType = message.network_type
	
	# Set session's transaction context's account
	transactionContextStructure.account = message.account
	
	# Return success
	return Success()
