# Imports
from typing import TYPE_CHECKING
from micropython import const
from .common import UINT32_MAX

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinGetMqsChallengeSignature, MimbleWimbleCoinMqsChallengeSignature


# Constants

# Milliseconds in a second
MILLISECONDS_IN_A_SECOND = const(1000)

# Seconds in a minute
SECONDS_IN_A_MINUTE = const(60)

# Minutes in an hour
MINUTES_IN_AN_HOUR = const(60)

# Maximum timestamp
MAXIMUM_TIMESTAMP = const(UINT32_MAX * MINUTES_IN_AN_HOUR * SECONDS_IN_A_MINUTE * MILLISECONDS_IN_A_SECOND + MILLISECONDS_IN_A_SECOND - 1)

# Minimum time zone offset
MINIMUM_TIME_ZONE_OFFSET = const(-13 * MINUTES_IN_AN_HOUR)

# Maximum time zone offset
MAXIMUM_TIME_ZONE_OFFSET = const(15 * MINUTES_IN_AN_HOUR)


# Supporting function implementation

# Get MQS challenge signature
async def get_mqs_challenge_signature(context: Context, message: MimbleWimbleCoinGetMqsChallengeSignature) -> MimbleWimbleCoinMqsChallengeSignature:

	# Imports
	from trezor.messages import MimbleWimbleCoinMqsChallengeSignature
	from storage.device import is_initialized
	from apps.base import unlock_device
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.workflow import close_others
	from trezor.ui.layouts import confirm_action, confirm_value, show_warning
	from trezor.enums import ButtonRequestType
	from trezor.crypto import mimblewimble_coin
	from utime import gmtime2000
	from trezor.strings import _SECONDS_1970_TO_2000
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey
	
	# Check if not initialized
	if not is_initialized():
	
		# Raise not initialized error
		raise NotInitialized("")
	
	# Unlock device
	await unlock_device()
	
	# TODO Initialize storage
	
	# TODO Get session
	
	# TODO Clear session
	
	# Get coin info
	coinInfo = getCoinInfo(message.coin_type, message.network_type)
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(context, coinInfo, message.account)
	
	# Check if currency doesn't allow MQS addresses
	if not coinInfo.enableMqsAddress:
	
		# Raise data error
		raise DataError("")
	
	# Check if index is invalid
	if message.index > UINT32_MAX:
	
		# Raise data error
		raise DataError("")
	
	# Check if timestamp is provided and it is invalid
	if message.timestamp is not None and (message.time_zone_offset is None or message.timestamp // MILLISECONDS_IN_A_SECOND < _SECONDS_1970_TO_2000 or message.timestamp > MAXIMUM_TIMESTAMP):
	
		# Raise data error
		raise DataError("")
	
	# Check if time zone offset is provided and it is invalid
	if message.time_zone_offset is not None and (message.timestamp is None or message.time_zone_offset <= MINIMUM_TIME_ZONE_OFFSET or message.time_zone_offset >= MAXIMUM_TIME_ZONE_OFFSET):
	
		# Raise data error
		raise DataError("")
	
	# Show prompt
	await confirm_action(context, "", coinInfo.name, action = f"Sign {coinInfo.mqsName} challenge?", verb = "Next")
	
	# Show prompt
	await confirm_value(context, "Account Index", f"{str(message.account)}", "", "", verb = "Next")
	
	# Check if a timestamp is provided
	if message.timestamp is not None:
	
		# Get timestamp from timestamp
		timestamp = message.timestamp // MILLISECONDS_IN_A_SECOND - _SECONDS_1970_TO_2000
		
		# Get time zone offset
		timeZoneOffset = 0 if message.time_zone_offset * SECONDS_IN_A_MINUTE > timestamp else message.time_zone_offset
		
		# Apply time zone offset to timestamp
		timestamp -= timeZoneOffset * SECONDS_IN_A_MINUTE
		
		# Show prompt
		time = gmtime2000(timestamp)
		await confirm_value(context, "Time And Date", f"{time[3]:02d}:{time[4]:02d}:{time[5]:02d} on {time[0]}-{time[1]:02d}-{time[2]:02d} UTC{'-' if timeZoneOffset > 0 else '+'}{abs(timeZoneOffset) // MINUTES_IN_AN_HOUR:02d}:{abs(timeZoneOffset) % MINUTES_IN_AN_HOUR:02d}", "", "", verb = "Next")
		
	# Otherwise
	else:
	
		# Show prompt
		await confirm_value(context, "Default Challenge", mimblewimble_coin.DEFAULT_MQS_CHALLENGE, "", "", verb = "Next")
	
	# Show prompt
	await show_warning(context, "", f"The host will be able to listen for the account's {coinInfo.mqsName} transactions.", button = "Approve", br_code = ButtonRequestType.Other)
	
	# Close running layout
	close_others()
	
	# Try
	try:
	
		# Get MQS challenge signature
		mqsChallengeSignature = mimblewimble_coin.getMqsChallengeSignature(extendedPrivateKey, coinInfo, message.index, mimblewimble_coin.DEFAULT_MQS_CHALLENGE if message.timestamp is None else str(message.timestamp))
	
	# Catch errors
	except:
	
		# Raise process error
		raise ProcessError("")
	
	# Return MQS challenge signature
	return MimbleWimbleCoinMqsChallengeSignature(mqs_challenge_signature = mqsChallengeSignature)
