# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.messages import MimbleWimbleCoinGetMqsChallengeSignature, MimbleWimbleCoinMqsChallengeSignature


# Supporting function implementation

# Get MQS challenge signature
async def get_mqs_challenge_signature(message: MimbleWimbleCoinGetMqsChallengeSignature) -> MimbleWimbleCoinMqsChallengeSignature:

	# Imports
	from trezor.messages import MimbleWimbleCoinMqsChallengeSignature
	from storage.device import is_initialized
	from apps.base import unlock_device
	from apps.common.seed import derive_and_store_roots
	from trezor.workflow import idle_timer
	from storage.cache_common import APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT, APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT
	from trezor.wire import NotInitialized, ProcessError, DataError
	from trezor.wire.context import cache_delete
	from trezor.ui.layouts import confirm_action, confirm_value, confirm_blob, show_warning, confirm_text
	from trezor.enums import ButtonRequestType
	from trezor.crypto import mimblewimble_coin
	from apps.common.paths import HARDENED
	from trezor.utils import UI_LAYOUT
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
	cache_delete(APP_MIMBLEWIMBLE_COIN_ENCRYPTION_AND_DECRYPTION_CONTEXT)
	cache_delete(APP_MIMBLEWIMBLE_COIN_TRANSACTION_CONTEXT)
	
	# Get coin info
	coinInfo = getCoinInfo(message.coin_type, message.network_type)
	
	# Check if currency doesn't allow MQS addresses
	if not coinInfo.enableMqsAddress:
	
		# Raise data error
		raise DataError("")
	
	# Check if account is invalid
	if message.account >= HARDENED:
	
		# Raise data error
		raise DataError("")
	
	# Check if index is invalid
	if message.index > UINT32_MAX:
	
		# Raise data error
		raise DataError("")
	
	# Check if timestamp is provided and it is invalid
	if message.timestamp is not None and (message.time_zone_offset is None or message.timestamp > MAXIMUM_TIMESTAMP):
	
		# Raise data error
		raise DataError("")
	
	# Check if time zone offset is provided and it is invalid
	if message.time_zone_offset is not None and (message.timestamp is None or message.time_zone_offset <= MINIMUM_TIME_ZONE_OFFSET or message.time_zone_offset >= MAXIMUM_TIME_ZONE_OFFSET):
	
		# Raise data error
		raise DataError("")
	
	# Check if UI layout is delizia
	if UI_LAYOUT == "DELIZIA":
	
		# Show prompt
		await confirm_value(coinInfo.name, f"Sign {coinInfo.mqsName} challenge?", "", "", verb = "Next", is_data = False)
		
	# Otherwise
	else:
	
		# Show prompt
		await confirm_action("", coinInfo.name, action = f"Sign {coinInfo.mqsName} challenge?", verb = "Next")
	
	# Show prompt
	await confirm_value("Account Index", str(message.account), "", "", verb = "Next")
	
	# Check if a timestamp is provided
	if message.timestamp is not None:
	
		# Get timestamp from timestamp
		timestamp = message.timestamp // MILLISECONDS_IN_A_SECOND
		
		# Get time zone offset
		timeZoneOffset = 0 if message.time_zone_offset * SECONDS_IN_A_MINUTE > timestamp else message.time_zone_offset
		
		# Apply time zone offset to timestamp
		timestamp -= timeZoneOffset * SECONDS_IN_A_MINUTE
		
		# Get timestamp components
		time = mimblewimble_coin.getTimestampComponents(timestamp)
		
		# Check if UI layout is caesar
		if UI_LAYOUT == "CAESAR":
		
			# Show prompt
			await confirm_value("Time And Date", f"{time[3]:02d}:{time[4]:02d}:{time[5]:02d} on {time[0]}-{time[1]:02d}-{time[2]:02d} UTC{'-' if timeZoneOffset > 0 else '+'}{abs(timeZoneOffset) // MINUTES_IN_AN_HOUR:02d}:{abs(timeZoneOffset) % MINUTES_IN_AN_HOUR:02d}", "", "", verb = "Next")
			
		# Otherwise check if UI layout is bolt
		elif UI_LAYOUT == "BOLT":
		
			# Show prompt
			await confirm_action("", "Time And Date", action = f"{time[3]:02d}:{time[4]:02d}:{time[5]:02d} on {time[0]}-{time[1]:02d}-{time[2]:02d} UTC{'-' if timeZoneOffset > 0 else '+'}{abs(timeZoneOffset) // MINUTES_IN_AN_HOUR:02d}:{abs(timeZoneOffset) % MINUTES_IN_AN_HOUR:02d}", verb = "Next")
		
		# Otherwise
		else:
		
			# Show prompt
			await confirm_value("Time And Date", f"{time[3]:02d}:{time[4]:02d}:{time[5]:02d} on {time[0]}-{time[1]:02d}-{time[2]:02d} UTC{'-' if timeZoneOffset > 0 else '+'}{abs(timeZoneOffset) // MINUTES_IN_AN_HOUR:02d}:{abs(timeZoneOffset) % MINUTES_IN_AN_HOUR:02d}", "", "", verb = "Next", is_data = False)
	
	# Otherwise
	else:
	
		# Show prompt
		await confirm_blob("", "Default Challenge", mimblewimble_coin.DEFAULT_MQS_CHALLENGE, verb = "Next".upper(), prompt_screen = False, info = False)
	
	# Check if UI layout is caesar
	if UI_LAYOUT == "CAESAR":
	
		# Show prompt
		await confirm_text("", "Warning", f"The host will be able to listen for the account's {coinInfo.mqsName} transactions.", verb = "Approve")
	
	# Otherwise check if UI layout is bolt
	elif UI_LAYOUT == "BOLT":
	
		# Show prompt
		await show_warning("", f"The host will be able to listen for the account's {coinInfo.mqsName} transactions.", button = "Approve", br_code = ButtonRequestType.Other, left_is_small = True)
	
	# Otherwise
	else:
	
		# Show prompt
		await show_warning("", f"The host will be able to listen for the account's {coinInfo.mqsName} transactions.", "Approve", "Warning", br_code = ButtonRequestType.Other, allow_cancel = True)
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(coinInfo, message.account)
	
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
