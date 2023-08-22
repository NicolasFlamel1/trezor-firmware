# Imports
from micropython import const


# Constants

# Number of transaction secret nonces
NUMBER_OF_TRANSACTION_SECRET_NONCES = const(30)

# Current transaction secret nonce index storage key
CURRENT_TRANSACTION_SECRET_NONCE_INDEX_STORAGE_KEY = const(1)

# Transaction secret nonce start storage key
TRANSACTION_SECRET_NONCE_START_STORAGE_KEY = const(2)


# Supporting function implementation

# Get current transaction secret nonce index
def getCurrentTransactionSecretNonceIndex() -> int | bool:

	# Imports
	from storage.common import get_uint8, APP_MIMBLEWIMBLE_COIN
	
	# Try
	try:
	
		# Get current transaction secret nonce index from storage
		currentTransactionSecretNonceIndex = get_uint8(APP_MIMBLEWIMBLE_COIN, CURRENT_TRANSACTION_SECRET_NONCE_INDEX_STORAGE_KEY)
		if currentTransactionSecretNonceIndex is None:
			currentTransactionSecretNonceIndex = 0
	
	# Catch errors
	except:
	
		# Return false
		return False
	
	# Return current transaction secret nonce index
	return currentTransactionSecretNonceIndex

# Increment current transaction secret nonce index
def incrementCurrentTransactionSecretNonceIndex() -> bool:

	# Imports
	from storage.common import set_uint8, APP_MIMBLEWIMBLE_COIN
	
	# Try
	try:
	
		# Check if getting current transaction secret nonce failed
		currentTransactionSecretNonce = getCurrentTransactionSecretNonceIndex()
		if currentTransactionSecretNonce is False:
		
			# Return false
			return False
	
		# Increment current transaction secret nonce index in storage
		set_uint8(APP_MIMBLEWIMBLE_COIN, CURRENT_TRANSACTION_SECRET_NONCE_INDEX_STORAGE_KEY, (currentTransactionSecretNonce + 1) % NUMBER_OF_TRANSACTION_SECRET_NONCES)
	
	# Catch errors
	except:
	
		# Return false
		return False
	
	# Return true
	return True

# Get transaction secret nonce
def getTransactionSecretNonce(index: int) -> bytes | bool:

	# Imports
	from storage.common import get, APP_MIMBLEWIMBLE_COIN
	from trezor.crypto import mimblewimble_coin
	
	# Try
	try:
	
		# Get transaction secret nonce at the index from storage
		transactionSecretNonce = get(APP_MIMBLEWIMBLE_COIN, TRANSACTION_SECRET_NONCE_START_STORAGE_KEY + index)
		if transactionSecretNonce is None:
			transactionSecretNonce = b"\0" * mimblewimble_coin.ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE
	
	# Catch errors
	except:
	
		# Return false
		return False
	
	# Return transaction sexret nonce
	return transactionSecretNonce

# Set transaction secret nonce
def setTransactionSecretNonce(transactionSecretNonce: bytes, index: int) -> bool:

	# Imports
	from storage.common import set, APP_MIMBLEWIMBLE_COIN
	
	# Try
	try:
	
		# Set transaction secret nonce at the index in storage
		set(APP_MIMBLEWIMBLE_COIN, TRANSACTION_SECRET_NONCE_START_STORAGE_KEY + index, transactionSecretNonce)
	
	# Catch errors
	except:
	
		# Return false
		return False
	
	# Return true
	return True

# Clear transaction secret nonce
def clearTransactionSecretNonce(index: int) -> bool:

	# Imports
	from trezor.crypto import mimblewimble_coin

	# Return if setting transaction secret nonce was successful
	return setTransactionSecretNonce(b"\0" * mimblewimble_coin.ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE, index)

# Initialize storage
def initializeStorage() -> None:

	# Imports
	from trezor.wire import ProcessError
	from storage.common import set_uint8, APP_MIMBLEWIMBLE_COIN
	
	# Try
	try:
	
		# Check if getting current transaction secret nonce failed
		currentTransactionSecretNonce = getCurrentTransactionSecretNonceIndex()
		if currentTransactionSecretNonce is False:
		
			# Raise process error
			raise ProcessError("")
	
		# Check if current transaction secret nonce index is invalid
		if currentTransactionSecretNonce >= NUMBER_OF_TRANSACTION_SECRET_NONCES:
		
			# Reset current transaction secret nonce index in storage
			set_uint8(APP_MIMBLEWIMBLE_COIN, CURRENT_TRANSACTION_SECRET_NONCE_INDEX_STORAGE_KEY, 0)
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
