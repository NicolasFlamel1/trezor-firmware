# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinGetLoginChallengeSignature, MimbleWimbleCoinLoginChallengeSignature


# Supporting function implementation

# Get login challenge signature
async def get_login_challenge_signature(message: MimbleWimbleCoinGetLoginChallengeSignature) -> MimbleWimbleCoinLoginChallengeSignature:

	# Imports
	from trezor.messages import MimbleWimbleCoinLoginChallengeSignature
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer
	from storage.cache import delete, APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.ui.layouts import confirm_action, confirm_value
	from trezor.crypto import mimblewimble_coin
	from apps.common.paths import HARDENED
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey, UINT32_MAX, MILLISECONDS_IN_A_SECOND, SECONDS_IN_A_MINUTE, MINUTES_IN_AN_HOUR, MAXIMUM_TIMESTAMP, MINIMUM_TIME_ZONE_OFFSET, MAXIMUM_TIME_ZONE_OFFSET
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
	delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get coin info
	coinInfo = getCoinInfo(message.coin_type, message.network_type)
	
	# Check if account is invalid
	if message.account >= HARDENED:
	
		# Raise data error
		raise DataError("")
	
	# Check if timestamp is invalid
	if message.timestamp > MAXIMUM_TIMESTAMP:
	
		# Raise data error
		raise DataError("")
	
	# Check if time zone offset is invalid
	if message.time_zone_offset <= MINIMUM_TIME_ZONE_OFFSET or message.time_zone_offset >= MAXIMUM_TIME_ZONE_OFFSET:
	
		# Raise data error
		raise DataError("")
	
	# Show prompt
	await confirm_action("", coinInfo.name, action = "Login with wallet?", verb = "Next")
	
	# Show prompt
	await confirm_value("Account Index", str(message.account), "", "", verb = "Next")
	
	# Get timestamp from timestamp
	timestamp = message.timestamp // MILLISECONDS_IN_A_SECOND
	
	# Get time zone offset
	timeZoneOffset = 0 if message.time_zone_offset * SECONDS_IN_A_MINUTE > timestamp else message.time_zone_offset
	
	# Apply time zone offset to timestamp
	timestamp -= timeZoneOffset * SECONDS_IN_A_MINUTE
	
	# Show prompt
	time = mimblewimble_coin.getTimestampComponents(timestamp)
	await confirm_action("", "Time And Date", action = f"{time[3]:02d}:{time[4]:02d}:{time[5]:02d} on {time[0]}-{time[1]:02d}-{time[2]:02d} UTC{'-' if timeZoneOffset > 0 else '+'}{abs(timeZoneOffset) // MINUTES_IN_AN_HOUR:02d}:{abs(timeZoneOffset) % MINUTES_IN_AN_HOUR:02d}", verb = "Approve")
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, message.account)
	
	# Try
	try:
	
		# Get login challenge signature
		loginPublicKey, loginChallengeSignature = mimblewimble_coin.getLoginChallengeSignature(extendedPrivateKey, str(message.timestamp))
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
	
	# Return login challenge signature and login public key
	return MimbleWimbleCoinLoginChallengeSignature(login_public_key = loginPublicKey, login_challenge_signature = loginChallengeSignature)
