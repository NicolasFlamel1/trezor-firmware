// Header files
#include <time.h>
#include <stdio.h>


// Definitions

// Uint16 buffer size
#define MIMBLEWIMBLE_COIN_UINT16_BUFFER_SIZE (sizeof("65535") - sizeof((char)'\0'))

// Uint32 buffer size
#define MIMBLEWIMBLE_COIN_UINT32_BUFFER_SIZE (sizeof("4294967295") - sizeof((char)'\0'))

// BIP44 purpose
#define MIMBLEWIMBLE_COIN_BIP44_PURPOSE 44

// Row length
#define MIMBLEWIMBLE_COIN_ROW_LENGTH 18

// Milliseconds in a second
#define MIMBLEWIMBLE_COIN_MILLISECONDS_IN_A_SECOND 1000

// Seconds in a minute
#define MIMBLEWIMBLE_COIN_SECONDS_IN_A_MINUTE 60

// Minutes in an hour
#define MIMBLEWIMBLE_COIN_MINUTES_IN_AN_HOUR 60

// Hours in a day
#define MIMBLEWIMBLE_COIN_HOURS_IN_A_DAY 24

// Days in a week
#define MIMBLEWIMBLE_COIN_DAYS_IN_A_WEEK 7

// Maximum timestamp
#define MIMBLEWIMBLE_COIN_MAXIMUM_TIMESTAMP ((uint64_t)UINT32_MAX * MIMBLEWIMBLE_COIN_MINUTES_IN_AN_HOUR * MIMBLEWIMBLE_COIN_SECONDS_IN_A_MINUTE * MIMBLEWIMBLE_COIN_MILLISECONDS_IN_A_SECOND + MIMBLEWIMBLE_COIN_MILLISECONDS_IN_A_SECOND - 1)

// Minimum time zone offset
#define MIMBLEWIMBLE_COIN_MINIMUM_TIME_ZONE_OFFSET (-13 * MIMBLEWIMBLE_COIN_MINUTES_IN_AN_HOUR)

// Maximum time zone offset
#define MIMBLEWIMBLE_COIN_MAXIMUM_TIME_ZONE_OFFSET (15 * MIMBLEWIMBLE_COIN_MINUTES_IN_AN_HOUR)

// Maximum relative height
#define MIMBLEWIMBLE_COIN_MAXIMUM_RELATIVE_HEIGHT (MIMBLEWIMBLE_COIN_DAYS_IN_A_WEEK * MIMBLEWIMBLE_COIN_HOURS_IN_A_DAY * MIMBLEWIMBLE_COIN_MINUTES_IN_AN_HOUR)


// Function prototypes

// Get extended private key
static HDNode *mimbleWimbleCoinGetExtendedPrivateKey(const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t account);

// Initialize storage
static bool mimbleWimbleCoinInitializeStorage(void);


// Supporting function implementation

// Get root public key
void fsm_msgMimbleWimbleCoinGetRootPublicKey(const MimbleWimbleCoinGetRootPublicKey *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinRootPublicKey);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show prompt
	layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _(coinInfo->name), _("Export root public"), _("key?"), NULL, NULL, NULL, NULL, FONT_STANDARD);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Get account as a string
	char accountBuffer[MIMBLEWIMBLE_COIN_UINT32_BUFFER_SIZE + sizeof((char)'\0')];
	bn_format_uint64(message->account, NULL, NULL, 0, 0, false, 0, accountBuffer, sizeof(accountBuffer));
	
	// Show prompt
	layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Account Index"), accountBuffer, NULL, NULL, NULL, NULL, NULL, FONT_FIXED);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show prompt
	layoutDialogSwipeEx(&bmp_icon_warning, _("Deny"), _("Approve"), NULL, _("The host will be able"), _("to view the account's"), _("transactions."), NULL, NULL, NULL, FONT_STANDARD);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show home
	layoutHome();
	
	// Check if getting extended private key failed
	HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Set response's root public key to the extended private key's public key
	resp->root_public_key.size = sizeof(extendedPrivateKey->public_key);
	memcpy(resp->root_public_key.bytes, extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Clear extended private key's public key
	memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Send root public key response
	msg_write(MessageType_MessageType_MimbleWimbleCoinRootPublicKey, resp);
	
	// Show home
	layoutHome();
}

// Get address
void fsm_msgMimbleWimbleCoinGetAddress(const MimbleWimbleCoinGetAddress *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinAddress);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if address type is invalid
	if(message->address_type > _MimbleWimbleCoinAddressType_MAX) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check address type
	switch(message->address_type) {
	
		// MQS
		case MimbleWimbleCoinAddressType_MQS:
		
			// Check if currency doesn't allow MQS addresses
			if(!coinInfo->enableMqsAddress) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if getting MQS address failed
			if(!mimbleWimbleCoinGetMqsAddress(resp->address, extendedPrivateKey, coinInfo, message->index)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
		
			// Break
			break;
		
		// Tor
		case MimbleWimbleCoinAddressType_TOR:
		
			// Check if currency doesn't allow Tor addresses
			if(!coinInfo->enableTorAddress) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if getting Tor address failed
			if(!mimbleWimbleCoinGetTorAddress(resp->address, extendedPrivateKey, coinInfo, message->index)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// Slatepack
		case MimbleWimbleCoinAddressType_SLATEPACK:
		
			// Check if currency doesn't allow Slatepack addresses
			if(!coinInfo->enableSlatepackAddress) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if getting Slatepack address failed
			if(!mimbleWimbleCoinGetSlatepackAddress(resp->address, extendedPrivateKey, coinInfo, message->index)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
	}
	
	// Send address response
	msg_write(MessageType_MessageType_MimbleWimbleCoinAddress, resp);
	
	// Show home
	layoutHome();
}

// Get seed cookie
void fsm_msgMimbleWimbleCoinGetSeedCookie(const MimbleWimbleCoinGetSeedCookie *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinSeedCookie);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Get seed cookie
	resp->seed_cookie.size = sizeof(resp->seed_cookie.bytes);
	mimbleWimbleCoinGetSeedCookie(resp->seed_cookie.bytes, extendedPrivateKey);
	
	// Clear extended private key's public key
	memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Send seed cookie response
	msg_write(MessageType_MessageType_MimbleWimbleCoinSeedCookie, resp);
	
	// Show home
	layoutHome();
}

// Get commitment
void fsm_msgMimbleWimbleCoinGetCommitment(const MimbleWimbleCoinGetCommitment *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinCommitment);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if identifier is invalid
	if(message->identifier.size != sizeof(message->identifier.bytes)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if identifier depth is invalid
	if(message->identifier.bytes[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX] > MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if value is invalid
	if(!message->value) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if switch type is invalid
	if(message->switch_type != MimbleWimbleCoinSwitchType_REGULAR) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if getting commitment failed
	resp->commitment.size = sizeof(resp->commitment.bytes);
	if(!mimbleWimbleCoinGetCommitment(resp->commitment.bytes, extendedPrivateKey, message->value, message->identifier.bytes, message->switch_type)) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send commitment response
	msg_write(MessageType_MessageType_MimbleWimbleCoinCommitment, resp);
	
	// Show home
	layoutHome();
}

// Get Bulletproof components
void fsm_msgMimbleWimbleCoinGetBulletproofComponents(const MimbleWimbleCoinGetBulletproofComponents *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinBulletproofComponents);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if message type is invalid
	if(message->message_type > _MimbleWimbleCoinMessageType_MAX) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if identifier is invalid
	if(message->identifier.size != sizeof(message->identifier.bytes)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if identifier depth is invalid
	if(message->identifier.bytes[0] > MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if value is invalid
	if(!message->value) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if switch type is invalid
	if(message->switch_type != MimbleWimbleCoinSwitchType_REGULAR) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check message type
	char *displayMessage = NULL;
	switch(message->message_type) {
	
		// Sending transaction
		case MimbleWimbleCoinMessageType_SENDING_TRANSACTION:
		
			// Set display message
			displayMessage = _("Sending Transaction");
			
			// Break
			break;
		
		// Receiving transaction
		case MimbleWimbleCoinMessageType_RECEIVING_TRANSACTION:
		
			// Set display message
			displayMessage =_("Receiving Transaction");
			
			// Break
			break;
		
		// Creating coinbase
		case MimbleWimbleCoinMessageType_CREATING_COINBASE:
		
			// Set display message
			displayMessage =_("Creating Coinbase");
			
			// Break
			break;
	}
	
	// Show progress
	layoutProgressSwipe(displayMessage, 0);
	
	// Check if getting Bulletproof components failed
	resp->tau_x.size = sizeof(resp->tau_x.bytes);
	resp->t_one.size = sizeof(resp->t_one.bytes);
	resp->t_two.size = sizeof(resp->t_two.bytes);
	if(!mimbleWimbleCoinGetBulletproofComponents(resp->tau_x.bytes, resp->t_one.bytes, resp->t_two.bytes, extendedPrivateKey, message->value, message->identifier.bytes, message->switch_type, displayMessage)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear extended private key's public key
	memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Send Bulletproof components response
	msg_write(MessageType_MessageType_MimbleWimbleCoinBulletproofComponents, resp);
	
	// Show home
	layoutHome();
}

// Verify root public key
void fsm_msgMimbleWimbleCoinVerifyRootPublicKey(const MimbleWimbleCoinVerifyRootPublicKey *message) {

	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show prompt
	layoutDialogSwipeEx(&bmp_icon_question, _("Invalid"), _("Next"), _(coinInfo->name), _("Verify root public"), _("key."), NULL, NULL, NULL, NULL, FONT_STANDARD);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show prompt
	char hexString[sizeof(extendedPrivateKey->public_key) * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE];
	mimbleWimbleCoinToHexString(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key), hexString);
	const char **splitMessage = split_message((const uint8_t *)hexString, sizeof(hexString), MIMBLEWIMBLE_COIN_ROW_LENGTH);
	layoutDialogSwipeEx(&bmp_icon_question, _("Invalid"), _("Valid"), _("Root Public Key"), splitMessage[0], splitMessage[1], splitMessage[2], splitMessage[3], NULL, NULL, FONT_FIXED);
	
	// Clear extended private key's public key
	memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Clear split message
		split_message(NULL, 0, 0);
		
		// Clear hex string
		memzero(hexString, sizeof(hexString));
		
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear split message
	split_message(NULL, 0, 0);
	
	// Clear hex string
	memzero(hexString, sizeof(hexString));
	
	// Send success response
	fsm_sendSuccess(NULL);
	
	// Show home
	layoutHome();
}

// Verify address
void fsm_msgMimbleWimbleCoinVerifyAddress(const MimbleWimbleCoinVerifyAddress *message) {

	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if address type is invalid
	if(message->address_type > _MimbleWimbleCoinAddressType_MAX) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check address type
	switch(message->address_type) {
	
		// MQS
		case MimbleWimbleCoinAddressType_MQS: {
		
			// Check if currency doesn't allow MQS addresses
			if(!coinInfo->enableMqsAddress) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if getting MQS address failed
			char address[MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE + sizeof((char)'\0')];
			if(!mimbleWimbleCoinGetMqsAddress(address, extendedPrivateKey, coinInfo, message->index)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Show prompt
			char verifyAddressMessage[sizeof(_("Verify ")) - sizeof((char)'\0') + strlen(_(coinInfo->mqsName)) + sizeof(_(" address."))];
			strcpy(verifyAddressMessage, _("Verify "));
			strcat(verifyAddressMessage, _(coinInfo->mqsName));
			if(strlen(_(coinInfo->mqsName)) < 5) {
				strcat(verifyAddressMessage, _(" address."));
			}
			layoutDialogSwipeEx(&bmp_icon_question, _("Invalid"), _("Next"), _(coinInfo->name), verifyAddressMessage, (strlen(_(coinInfo->mqsName)) < 5) ? NULL : _("address."), NULL, NULL, NULL, NULL, FONT_STANDARD);
			
			// Check if user denied prompt
			if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			
				// Send action canceled response
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Show prompt
			char addressTypeMessage[strlen(_(coinInfo->mqsName)) + sizeof(_(" Address"))];
			strcpy(addressTypeMessage, _(coinInfo->mqsName));
			strcat(addressTypeMessage, _(" Address"));
			const char **splitMessage = split_message((const uint8_t *)address, sizeof(address) - sizeof((char)'\0'), MIMBLEWIMBLE_COIN_ROW_LENGTH);
			layoutDialogSwipeEx(&bmp_icon_question, _("Invalid"), _("Valid"), addressTypeMessage, splitMessage[0], splitMessage[1], splitMessage[2], splitMessage[3], NULL, NULL, FONT_FIXED);
			
			// Check if user denied prompt
			if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			
				// Send action canceled response
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
		
			// Break
			break;
		}
		
		// Tor
		case MimbleWimbleCoinAddressType_TOR: {
		
			// Check if currency doesn't allow Tor addresses
			if(!coinInfo->enableTorAddress) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if getting Tor address failed
			char address[MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE + sizeof((char)'\0')];
			if(!mimbleWimbleCoinGetTorAddress(address, extendedPrivateKey, coinInfo, message->index)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Show prompt
			layoutDialogSwipeEx(&bmp_icon_question, _("Invalid"), _("Next"), _(coinInfo->name), _("Verify Tor address."), NULL, NULL, NULL, NULL, NULL, FONT_STANDARD);
			
			// Check if user denied prompt
			if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			
				// Send action canceled response
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Show prompt
			const char **splitMessage = split_message((const uint8_t *)address, sizeof(address) - sizeof((char)'\0'), MIMBLEWIMBLE_COIN_ROW_LENGTH);
			layoutDialogSwipeEx(&bmp_icon_question, _("Invalid"), _("Valid"), _("Tor Address"), splitMessage[0], splitMessage[1], splitMessage[2], splitMessage[3], NULL, NULL, FONT_FIXED);
			
			// Check if user denied prompt
			if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			
				// Send action canceled response
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		}
		
		// Slatepack
		case MimbleWimbleCoinAddressType_SLATEPACK: {
		
			// Check if currency doesn't allow Slatepack addresses
			if(!coinInfo->enableSlatepackAddress) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if getting Slatepack address failed
			char address[MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + strlen(coinInfo->slatepackAddressHumanReadablePart) + sizeof((char)'\0')];
			if(!mimbleWimbleCoinGetSlatepackAddress(address, extendedPrivateKey, coinInfo, message->index)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Show prompt
			layoutDialogSwipeEx(&bmp_icon_question, _("Invalid"), _("Next"), _(coinInfo->name), _("Verify Slatepack"), _("address."), NULL, NULL, NULL, NULL, FONT_STANDARD);
			
			// Check if user denied prompt
			if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			
				// Send action canceled response
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Show prompt
			const char **splitMessage = split_message((const uint8_t *)address, sizeof(address) - sizeof((char)'\0'), MIMBLEWIMBLE_COIN_ROW_LENGTH);
			layoutDialogSwipeEx(&bmp_icon_question, _("Invalid"), _("Valid"), _("Slatepack Address"), splitMessage[0], splitMessage[1], splitMessage[2], splitMessage[3], NULL, NULL, FONT_FIXED);
			
			// Check if user denied prompt
			if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			
				// Send action canceled response
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		}
	}
	
	// Send success response
	fsm_sendSuccess(NULL);
	
	// Show home
	layoutHome();
}

// Start encrypting slate
void fsm_msgMimbleWimbleCoinStartEncryptingSlate(const MimbleWimbleCoinStartEncryptingSlate *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinEncryptedSlateNonceAndSalt);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Get address domain
	const char *addressDomain = memchr(message->recipient_address.bytes, '@', message->recipient_address.size);
	
	// Check address length
	switch(addressDomain ? addressDomain - (const char *)message->recipient_address.bytes : message->recipient_address.size) {
	
		// MQS address size
		case MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE:
		
			// Check if currency doesn't allow MQS addresses or doesn't support MQS slate encryption
			if(!coinInfo->enableMqsAddress || !(coinInfo->supportedSlateEncryptionTypes & MimbleWimbleCoinSlateEncryptionType_MQS_SLATE_ENCRYPTION)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if address has a domain
			if(addressDomain) {
			
				// Check if address domain isn't a valid MQS address domain
				if(!mimbleWimbleCoinIsValidMqsAddressDomain(&addressDomain[sizeof((char)'@')], message->recipient_address.size - (addressDomain - (const char *)message->recipient_address.bytes + sizeof((char)'@')))) {
				
					// Send data error response
					fsm_sendFailure(FailureType_Failure_DataError, NULL);
					
					// Show home
					layoutHome();
					
					// Return
					return;
				}
			}
			
			// Check if recipient address isn't a valid MQS address
			if(!mimbleWimbleCoinIsValidMqsAddress((const char *)message->recipient_address.bytes, coinInfo, MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if starting MQS encryption failed
			resp->nonce.size = sizeof(resp->nonce.bytes);
			resp->has_salt = true;
			resp->salt.size = sizeof(resp->salt.bytes);
			if(!mimbleWimbleCoinStartMqsEncryption(resp->nonce.bytes, resp->salt.bytes, &session->encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message->index, (const char *)message->recipient_address.bytes, addressDomain ? &addressDomain[sizeof((char)'@')] : NULL, addressDomain ? message->recipient_address.size - (addressDomain - (const char *)message->recipient_address.bytes + sizeof((char)'@')) : 0)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// Tor address size
		case MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE:
		
			// Check if currency doesn't allow Tor addresses or doesn't support Tor slate encryption
			if(!coinInfo->enableTorAddress || !(coinInfo->supportedSlateEncryptionTypes & MimbleWimbleCoinSlateEncryptionType_TOR_SLATE_ENCRYPTION)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if address has a domain
			if(addressDomain) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if recipient address isn't a valid Tor address
			if(!mimbleWimbleCoinIsValidTorAddress((const char *)message->recipient_address.bytes, message->recipient_address.size)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if starting Tor encryption failed
			resp->nonce.size = sizeof(resp->nonce.bytes);
			resp->has_salt = false;
			resp->salt.size = 0;
			if(!mimbleWimbleCoinStartTorEncryption(resp->nonce.bytes, &session->encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message->index, (const char *)message->recipient_address.bytes)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// Default
		default:
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
	}
	
	// Set session's encryption and decryption context's coin type
	session->encryptionAndDecryptionContext.coinType = message->coin_type;
	
	// Set session's encryption and decryption context's network type
	session->encryptionAndDecryptionContext.networkType = message->network_type;
	
	// Set session's encryption and decryption context's account
	session->encryptionAndDecryptionContext.account = message->account;
	
	// Send encrypted slate nonce and salt response
	msg_write(MessageType_MessageType_MimbleWimbleCoinEncryptedSlateNonceAndSalt, resp);
	
	// Show home
	layoutHome();
}

// Continue encrypting slate
void fsm_msgMimbleWimbleCoinContinueEncryptingSlate(const MimbleWimbleCoinContinueEncryptingSlate *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinEncryptedSlateData);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->transactionContext, sizeof(session->transactionContext));
	
	// Check if data is invalid
	if(!message->data.size) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's encryption and decryption context's encrypting state isn't ready or active
	if(session->encryptionAndDecryptionContext.encryptingState != MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE && session->encryptionAndDecryptionContext.encryptingState != MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if encrypting data failed
	resp->encrypted_data.size = message->data.size;
	if(!mimbleWimbleCoinEncryptData(resp->encrypted_data.bytes, &session->encryptionAndDecryptionContext, message->data.bytes, message->data.size)) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send encrypted slate data response
	msg_write(MessageType_MessageType_MimbleWimbleCoinEncryptedSlateData, resp);
	
	// Show home
	layoutHome();
}

// Finish encrypting slate
void fsm_msgMimbleWimbleCoinFinishEncryptingSlate(__attribute__((unused)) const MimbleWimbleCoinFinishEncryptingSlate *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinEncryptedSlateTagAndSignature);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->transactionContext, sizeof(session->transactionContext));
	
	// Check if session's encryption and decryption context's encrypting state isn't active or complete
	if(session->encryptionAndDecryptionContext.encryptingState != MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE && session->encryptionAndDecryptionContext.encryptingState != MimbleWimbleCoinEncryptingOrDecryptingState_COMPLETE_STATE) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(session->encryptionAndDecryptionContext.coinType, session->encryptionAndDecryptionContext.networkType);
	if(!coinInfo) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, session->encryptionAndDecryptionContext.account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if finishing encryption failed
	resp->tag.size = sizeof(resp->tag.bytes);
	resp->has_mqs_message_signature = session->encryptionAndDecryptionContext.messageHashContextInitialized;
	resp->mqs_message_signature.size = mimbleWimbleCoinFinishEncryption(resp->tag.bytes, resp->mqs_message_signature.bytes, &session->encryptionAndDecryptionContext, extendedPrivateKey, coinInfo);
	if(!resp->mqs_message_signature.size) {
	
		// Clear session
		memzero(session, sizeof(*session));
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Send encrypted slate tag and signature response
	msg_write(MessageType_MessageType_MimbleWimbleCoinEncryptedSlateTagAndSignature, resp);
	
	// Show home
	layoutHome();
}

// Start decrypting slate
void fsm_msgMimbleWimbleCoinStartDecryptingSlate(const MimbleWimbleCoinStartDecryptingSlate *message) {

	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if nonce is invalid
	if(message->nonce.size != sizeof(message->nonce.bytes)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check sender address or ephemeral X25519 public key length
	switch(message->sender_address_or_ephemeral_x25519_public_key.size) {
	
		// MQS address size
		case MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE:
		
			// Check if currency doesn't allow MQS addresses or doesn't support MQS slate encryption
			if(!coinInfo->enableMqsAddress || !(coinInfo->supportedSlateEncryptionTypes & MimbleWimbleCoinSlateEncryptionType_MQS_SLATE_ENCRYPTION)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if sender address or ephemeral X25519 public key isn't a valid MQS address
			if(!mimbleWimbleCoinIsValidMqsAddress((const char *)message->sender_address_or_ephemeral_x25519_public_key.bytes, coinInfo, message->sender_address_or_ephemeral_x25519_public_key.size)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if salt or encrypted file key is invalid
			if(!message->has_salt_or_encrypted_file_key || message->salt_or_encrypted_file_key.size != MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if payload nonce exists
			if(message->has_payload_nonce) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if starting MQS decryption failed
			if(!mimbleWimbleCoinStartMqsDecryption(&session->encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message->index, (const char *)message->sender_address_or_ephemeral_x25519_public_key.bytes, message->nonce.bytes, message->salt_or_encrypted_file_key.bytes)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// Tor address size
		case MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE:
		
			// Check if currency doesn't allow Tor addresses or doesn't support Tor slate encryption
			if(!coinInfo->enableTorAddress || !(coinInfo->supportedSlateEncryptionTypes & MimbleWimbleCoinSlateEncryptionType_TOR_SLATE_ENCRYPTION)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if sender address or ephemeral X25519 public key isn't a valid Tor address
			if(!mimbleWimbleCoinIsValidTorAddress((const char *)message->sender_address_or_ephemeral_x25519_public_key.bytes, message->sender_address_or_ephemeral_x25519_public_key.size)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if salt or encrypted file key exists
			if(message->has_salt_or_encrypted_file_key) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if payload nonce exists
			if(message->has_payload_nonce) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if starting Tor decryption failed
			if(!mimbleWimbleCoinStartTorDecryption(&session->encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message->index, (const char *)message->sender_address_or_ephemeral_x25519_public_key.bytes, message->nonce.bytes)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// X25519 public key size
		case MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE:
		
			// Check if currency doesn't allow Slatepack addresses or doesn't support Slatepack slate encryption
			if(!coinInfo->enableSlatepackAddress || !(coinInfo->supportedSlateEncryptionTypes & MimbleWimbleCoinSlateEncryptionType_SLATEPACK_SLATE_ENCRYPTION)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if sender address or ephemeral X25519 public key isn't a valid X25519 public key
			if(!mimbleWimbleCoinIsValidX25519PublicKey(message->sender_address_or_ephemeral_x25519_public_key.bytes, message->sender_address_or_ephemeral_x25519_public_key.size)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if salt or encrypted file key is invalid
			if(!message->has_salt_or_encrypted_file_key || message->salt_or_encrypted_file_key.size != sizeof(message->salt_or_encrypted_file_key.bytes)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if payload nonce is invalid
			if(!message->has_payload_nonce || message->payload_nonce.size != sizeof(message->payload_nonce.bytes)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if starting Slatepack decryption failed
			if(!mimbleWimbleCoinStartSlatepackDecryption(&session->encryptionAndDecryptionContext, extendedPrivateKey, coinInfo, message->index, message->sender_address_or_ephemeral_x25519_public_key.bytes, message->nonce.bytes, message->salt_or_encrypted_file_key.bytes, message->payload_nonce.bytes)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// Default
		default:
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
	}
	
	// Send success response
	fsm_sendSuccess(NULL);
	
	// Show home
	layoutHome();
}

// Continue decrypting slate
void fsm_msgMimbleWimbleCoinContinueDecryptingSlate(const MimbleWimbleCoinContinueDecryptingSlate *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinDecryptedSlateData);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->transactionContext, sizeof(session->transactionContext));
	
	// Check if encrypted data is invalid
	if(!message->encrypted_data.size) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's encryption and decryption context's decrypting state isn't ready or active
	if(session->encryptionAndDecryptionContext.decryptingState != MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE && session->encryptionAndDecryptionContext.decryptingState != MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if decrypting data failed
	resp->data.size = mimbleWimbleCoinDecryptData(resp->data.bytes, &session->encryptionAndDecryptionContext, message->encrypted_data.bytes, message->encrypted_data.size);
	if(!resp->data.size) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send decrypted slate data response
	msg_write(MessageType_MessageType_MimbleWimbleCoinDecryptedSlateData, resp);
	
	// Show home
	layoutHome();
}

// Finish decrypting slate
void fsm_msgMimbleWimbleCoinFinishDecryptingSlate(const MimbleWimbleCoinFinishDecryptingSlate *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinDecryptedSlateAesKey);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->transactionContext, sizeof(session->transactionContext));
	
	// Check if tag is invalid
	if(message->tag.size != sizeof(message->tag.bytes)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's encryption and decryption context's decrypting state isn't active or complete
	if(session->encryptionAndDecryptionContext.decryptingState != MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE && session->encryptionAndDecryptionContext.decryptingState != MimbleWimbleCoinEncryptingOrDecryptingState_COMPLETE_STATE) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if finishing decrypting failed
	resp->aes_key.size = sizeof(resp->aes_key.bytes);
	if(!mimbleWimbleCoinFinishDecryption(resp->aes_key.bytes, &session->encryptionAndDecryptionContext, message->tag.bytes)) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Send decrypted slate AES key response
	msg_write(MessageType_MessageType_MimbleWimbleCoinDecryptedSlateAesKey, resp);
	
	// Show home
	layoutHome();
}

// Start transaction
void fsm_msgMimbleWimbleCoinStartTransaction(const MimbleWimbleCoinStartTransaction *message) {

	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if an address is provided
	if(message->has_address) {
	
		// Check address size
		switch(message->address.size) {
		
			// MQS address size
			case MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE:
			
				// Check if currency doesn't allow MQS addresses or doesn't support MQS payment proof addresses
				if(!coinInfo->enableMqsAddress || !(coinInfo->supportedPaymentProofAddressTypes & MimbleWimbleCoinPaymentProofAddressType_MQS_PAYMENT_PROOF_ADDRESS)) {
				
					// Send data error response
					fsm_sendFailure(FailureType_Failure_DataError, NULL);
					
					// Show home
					layoutHome();
					
					// Return
					return;
				}
				
				// Check if address isn't a valid MQS address
				if(!mimbleWimbleCoinIsValidMqsAddress((const char *)message->address.bytes, coinInfo, message->address.size)) {
				
					// Send data error response
					fsm_sendFailure(FailureType_Failure_DataError, NULL);
					
					// Show home
					layoutHome();
					
					// Return
					return;
				}
				
				// Break
				break;
			
			// Tor address size
			case MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE:
			
				// Check if currency doesn't allow Tor addresses or doesn't support Tor payment proof addresses
				if(!coinInfo->enableTorAddress || !(coinInfo->supportedPaymentProofAddressTypes & MimbleWimbleCoinPaymentProofAddressType_TOR_PAYMENT_PROOF_ADDRESS)) {
				
					// Send data error response
					fsm_sendFailure(FailureType_Failure_DataError, NULL);
					
					// Show home
					layoutHome();
					
					// Return
					return;
				}
				
				// Check if address isn't a valid Tor address
				if(!mimbleWimbleCoinIsValidTorAddress((const char *)message->address.bytes, message->address.size)) {
				
					// Send data error response
					fsm_sendFailure(FailureType_Failure_DataError, NULL);
					
					// Show home
					layoutHome();
					
					// Return
					return;
				}
				
				// Break
				break;
			
			// Default
			default:
			
				// Check if address size is Slatepack address size
				if(message->address.size == MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + strlen(coinInfo->slatepackAddressHumanReadablePart)) {
				
					// Check if currency doesn't allow Slatepack addresses or doesn't support Slatepack payment proof addresses
					if(!coinInfo->enableSlatepackAddress || !(coinInfo->supportedPaymentProofAddressTypes & MimbleWimbleCoinPaymentProofAddressType_SLATEPACK_PAYMENT_PROOF_ADDRESS)) {
					
						// Send data error response
						fsm_sendFailure(FailureType_Failure_DataError, NULL);
						
						// Show home
						layoutHome();
						
						// Return
						return;
					}
					
					// Check if address isn't a valid Slatepack address
					if(!mimbleWimbleCoinIsValidSlatepackAddress((const char *)message->address.bytes, coinInfo, message->address.size)) {
					
						// Send data error response
						fsm_sendFailure(FailureType_Failure_DataError, NULL);
						
						// Show home
						layoutHome();
						
						// Return
						return;
					}
				}
				
				// Otherwise
				else {
				
					// Send data error response
					fsm_sendFailure(FailureType_Failure_DataError, NULL);
					
					// Show home
					layoutHome();
					
					// Return
					return;
				}
			
				// Break
				break;
		}
	}
	
	// Check if an input exists
	if(message->input) {
	
		// Check if input is invalid
		if(message->input <= message->output) {
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
		}
	
		// Check if fee is invalid or will overflow
		if(!message->fee || message->fee > coinInfo->maximumFee || UINT64_MAX - message->input < message->fee) {
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
		}
		
		// Check if secret nonce index is invalid
		if(message->secret_nonce_index > MIMBLEWIMBLE_COIN_NUMBER_OF_TRANSACTION_SECRET_NONCES) {
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
		}
		
		// Check if secret nonce index exists
		if(message->secret_nonce_index) {
		
			// Check if getting transaction secret nonce at the index from storage failed
			uint8_t transactionSecretNonce[MIMBLEWIMBLE_COIN_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE];
			if(!config_getMimbleWimbleCoinTransactionSecretNonce(transactionSecretNonce, message->secret_nonce_index - 1)) {
			
				// Send process error response
				fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if transaction secret nonce is invalid
			if(mimbleWimbleCoinIsZero(transactionSecretNonce, sizeof(transactionSecretNonce))) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
		}
	}
	
	// Otherwise
	else {
	
		// Check if output is invalid
		if(!message->output) {
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
		}
		
		// Check if secret nonce index is invalid
		if(message->secret_nonce_index) {
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
		}
	}
	
	// Check if starting transaction failed
	if(!mimbleWimbleCoinStartTransaction(&session->transactionContext, message->index, message->output, message->input, message->fee, message->secret_nonce_index, message->has_address ? (const char *)message->address.bytes : NULL, message->has_address ? message->address.size : 0)) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Set session's transaction context's coin type
	session->transactionContext.coinType = message->coin_type;
	
	// Set session's transaction context's network type
	session->transactionContext.networkType = message->network_type;
	
	// Set session's transaction context's account
	session->transactionContext.account = message->account;
	
	// Send success response
	fsm_sendSuccess(NULL);
	
	// Show home
	layoutHome();
}

// Continue transaction include output
void fsm_msgMimbleWimbleCoinContinueTransactionIncludeOutput(const MimbleWimbleCoinContinueTransactionIncludeOutput *message) {

	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->encryptionAndDecryptionContext, sizeof(session->encryptionAndDecryptionContext));
	
	// Check if identifier is invalid
	if(message->identifier.size != sizeof(message->identifier.bytes)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if identifier depth is invalid
	if(message->identifier.bytes[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX] > MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if value is invalid
	if(!message->value) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if switch type is invalid
	if(message->switch_type != MimbleWimbleCoinSwitchType_REGULAR) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context hasn't been started
	if(!session->transactionContext.started) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(session->transactionContext.coinType, session->transactionContext.networkType);
	if(!coinInfo) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context has no more remaining output
	if(!session->transactionContext.remainingOutput) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if value is too big for the session's transaction context's remaining output
	if(message->value > session->transactionContext.remainingOutput) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, session->transactionContext.account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if including the output in the transaction failed
	if(!mimbleWimbleCoinIncludeOutputInTransaction(&session->transactionContext, extendedPrivateKey, message->value, message->identifier.bytes, message->switch_type)) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send success response
	fsm_sendSuccess(NULL);
	
	// Show home
	layoutHome();
}

// Continue transaction include input
void fsm_msgMimbleWimbleCoinContinueTransactionIncludeInput(const MimbleWimbleCoinContinueTransactionIncludeInput *message) {

	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->encryptionAndDecryptionContext, sizeof(session->encryptionAndDecryptionContext));
	
	// Check if identifier is invalid
	if(message->identifier.size != sizeof(message->identifier.bytes)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if identifier depth is invalid
	if(message->identifier.bytes[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX] > MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if value is invalid
	if(!message->value) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if switch type is invalid
	if(message->switch_type != MimbleWimbleCoinSwitchType_REGULAR) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context hasn't been started
	if(!session->transactionContext.started) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(session->transactionContext.coinType, session->transactionContext.networkType);
	if(!coinInfo) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context has no more remaining input
	if(!session->transactionContext.remainingInput) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if value is too big for the session's transaction context's remaining input
	if(message->value > session->transactionContext.remainingInput) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, session->transactionContext.account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if including the input in the transaction failed
	if(!mimbleWimbleCoinIncludeInputInTransaction(&session->transactionContext, extendedPrivateKey, message->value, message->identifier.bytes, message->switch_type)) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send success response
	fsm_sendSuccess(NULL);
	
	// Show home
	layoutHome();
}

// Continue transaction apply offset
void fsm_msgMimbleWimbleCoinContinueTransactionApplyOffset(const MimbleWimbleCoinContinueTransactionApplyOffset *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinTransactionSecretNonceIndex);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->encryptionAndDecryptionContext, sizeof(session->encryptionAndDecryptionContext));
	
	// Check if offset is invalid
	if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(message->offset.bytes, message->offset.size)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context hasn't been started
	if(!session->transactionContext.started) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context has remaining output or input
	if(session->transactionContext.remainingOutput || session->transactionContext.remainingInput) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if an offset was already applied to the session's transaction context
	if(session->transactionContext.offsetApplied) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if a message was signed for the session's transaction context
	if(session->transactionContext.messageSigned) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if applying offset to the transaction failed
	resp->has_secret_nonce_index = session->transactionContext.send && !session->transactionContext.secretNonceIndex;
	resp->secret_nonce_index = mimbleWimbleCoinApplyOffsetToTransaction(&session->transactionContext, message->offset.bytes);
	if(!resp->secret_nonce_index) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send transaction secret nonce index response
	msg_write(MessageType_MessageType_MimbleWimbleCoinTransactionSecretNonceIndex, resp);
	
	// Show home
	layoutHome();
}

// Continue transaction get public key
void fsm_msgMimbleWimbleCoinContinueTransactionGetPublicKey(__attribute__((unused)) const MimbleWimbleCoinContinueTransactionGetPublicKey *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinTransactionPublicKey);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->encryptionAndDecryptionContext, sizeof(session->encryptionAndDecryptionContext));
	
	// Check if session's transaction context hasn't been started
	if(!session->transactionContext.started) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context has remaining output or input
	if(session->transactionContext.remainingOutput || session->transactionContext.remainingInput) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context is sending and offset wasn't applied
	if(session->transactionContext.send && !session->transactionContext.offsetApplied) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting the transaction's public key failed
	resp->public_key.size = sizeof(resp->public_key.bytes);
	if(!mimbleWimbleCoinGetTransactionPublicKey(resp->public_key.bytes, &session->transactionContext)) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send transaction public key response
	msg_write(MessageType_MessageType_MimbleWimbleCoinTransactionPublicKey, resp);
	
	// Show home
	layoutHome();
}

// Continue transaction get public nonce
void fsm_msgMimbleWimbleCoinContinueTransactionGetPublicNonce(__attribute__((unused)) const MimbleWimbleCoinContinueTransactionGetPublicNonce *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinTransactionPublicNonce);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->encryptionAndDecryptionContext, sizeof(session->encryptionAndDecryptionContext));
	
	// Check if session's transaction context hasn't been started
	if(!session->transactionContext.started) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context has remaining output or input
	if(session->transactionContext.remainingOutput || session->transactionContext.remainingInput) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context is sending and offset wasn't applied
	if(session->transactionContext.send && !session->transactionContext.offsetApplied) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting the transaction's public nonce failed
	resp->public_nonce.size = sizeof(resp->public_nonce.bytes);
	if(!mimbleWimbleCoinGetTransactionPublicNonce(resp->public_nonce.bytes, &session->transactionContext)) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send transaction public nonce response
	msg_write(MessageType_MessageType_MimbleWimbleCoinTransactionPublicNonce, resp);
	
	// Show home
	layoutHome();
}

// Continue transaction get message signature
void fsm_msgMimbleWimbleCoinContinueTransactionGetMessageSignature(const MimbleWimbleCoinContinueTransactionGetMessageSignature *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinTransactionMessageSignature);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->encryptionAndDecryptionContext, sizeof(session->encryptionAndDecryptionContext));
	
	// Check if message is invalid
	if(!message->message.size || !mimbleWimbleCoinisValidUtf8String((const char *)message->message.bytes, message->message.size)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context hasn't been started
	if(!session->transactionContext.started) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context has remaining output or input
	if(session->transactionContext.remainingOutput || session->transactionContext.remainingInput) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context is sending and offset wasn't applied
	if(session->transactionContext.send && !session->transactionContext.offsetApplied) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if a message was signed for the session's transaction context
	if(session->transactionContext.messageSigned) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting the transaction's message signature failed
	resp->message_signature.size = sizeof(resp->message_signature.bytes);
	if(!mimbleWimbleCoinGetTransactionMessageSignature(resp->message_signature.bytes, &session->transactionContext, (const char *)message->message.bytes, message->message.size)) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send transaction message signature response
	msg_write(MessageType_MessageType_MimbleWimbleCoinTransactionMessageSignature, resp);
	
	// Show home
	layoutHome();
}

// Finish transaction
void fsm_msgMimbleWimbleCoinFinishTransaction(const MimbleWimbleCoinFinishTransaction *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinTransactionSignatureAndPaymentProof);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear unrelated session
	memzero(&session->encryptionAndDecryptionContext, sizeof(session->encryptionAndDecryptionContext));
	
	// Check if address type is invalid
	if(message->address_type > _MimbleWimbleCoinAddressType_MAX) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if public nonce is invalid
	if(!mimbleWimbleCoinIsValidSecp256k1PublicKey(message->public_nonce.bytes, message->public_nonce.size)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if public key is invalid
	if(!mimbleWimbleCoinIsValidSecp256k1PublicKey(message->public_key.bytes, message->public_key.size)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if kernel information is invalid
	if(!message->kernel_information.size) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check kernel information's features
	switch(message->kernel_information.bytes[0]) {
	
		// Plain or coinbase features
		case MimbleWimbleCoinKernelFeatures_PLAIN_FEATURES:
		case MimbleWimbleCoinKernelFeatures_COINBASE_FEATURES:
		
			// Check if kernel information is invalid
			if(message->kernel_information.size != sizeof(message->kernel_information.bytes[0])) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// Height locked features
		case MimbleWimbleCoinKernelFeatures_HEIGHT_LOCKED_FEATURES:
		
			// Check if kernel information is invalid
			if(message->kernel_information.size != sizeof(message->kernel_information.bytes[0]) + sizeof(uint64_t)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// No recent duplicate features
		case MimbleWimbleCoinKernelFeatures_NO_RECENT_DUPLICATE_FEATURES: {
		
			// Check if kernel information is invalid
			if(message->kernel_information.size != sizeof(message->kernel_information.bytes[0]) + sizeof(uint16_t)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Get relative height from kernel information
			uint16_t relativeHeight;
			memcpy(&relativeHeight, &message->kernel_information.bytes[sizeof(message->kernel_information.bytes[0])], sizeof(relativeHeight));

			// Check if big endian
			#if BYTE_ORDER == BIG_ENDIAN

				// Make relative height big endian
				REVERSE16(relativeHeight, relativeHeight);
			#endif
			
			// Check if relative height is invalid
			if(!relativeHeight || relativeHeight > MIMBLEWIMBLE_COIN_MAXIMUM_RELATIVE_HEIGHT) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		}
		
		// Default
		default:
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
	}
	
	// Check if kernel commitment is invalid
	if(message->has_kernel_commitment && !mimbleWimbleCoinIsValidCommitment(message->kernel_commitment.bytes, message->kernel_commitment.size)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if session's transaction context hasn't been started
	if(!session->transactionContext.started) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(session->transactionContext.coinType, session->transactionContext.networkType);
	if(!coinInfo) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check address type
	switch(message->address_type) {
	
		// MQS
		case MimbleWimbleCoinAddressType_MQS:
		
			// Check if currency doesn't allow MQS addresses or doesn't support MQS payment proof addresses
			if(!coinInfo->enableMqsAddress || !(coinInfo->supportedPaymentProofAddressTypes & MimbleWimbleCoinPaymentProofAddressType_MQS_PAYMENT_PROOF_ADDRESS)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
		
			// Break
			break;
		
		// Tor
		case MimbleWimbleCoinAddressType_TOR:
		
			// Check if currency doesn't allow Tor addresses or doesn't support Tor payment proof addresses
			if(!coinInfo->enableTorAddress || !(coinInfo->supportedPaymentProofAddressTypes & MimbleWimbleCoinPaymentProofAddressType_TOR_PAYMENT_PROOF_ADDRESS)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// Slatepack
		case MimbleWimbleCoinAddressType_SLATEPACK:
		
			// Check if currency doesn't allow Slatepack addresses or doesn't support Slatepack payment proof addresses
			if(!coinInfo->enableSlatepackAddress || !(coinInfo->supportedPaymentProofAddressTypes & MimbleWimbleCoinPaymentProofAddressType_SLATEPACK_PAYMENT_PROOF_ADDRESS)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
	}
	
	// Check kernel information's features
	switch(message->kernel_information.bytes[0]) {
	
		// Coinbase features
		case MimbleWimbleCoinKernelFeatures_COINBASE_FEATURES:
		
			// Check if session's transaction context is sending
			if(session->transactionContext.send) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if session's transaction context has an address
			if(session->transactionContext.address[0]) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		
		// No recent duplicate features
		case MimbleWimbleCoinKernelFeatures_NO_RECENT_DUPLICATE_FEATURES:
		
			// Check if currency doesn't allow no recent duplicate kernels
			if(!coinInfo->enableNoRecentDuplicateKernels) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
	}
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, session->transactionContext.account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if session's transaction context is sending
	if(session->transactionContext.send) {
	
		// Check if a kernel commitment exists
		if(message->has_kernel_commitment) {
		
			// Check if session's transaction context doesn't have an address
			if(!session->transactionContext.address[0]) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if a payment proof doesn't exist
			if(!message->has_payment_proof) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Check if verifying transaction payment proof failed
			if(!mimbleWimbleCoinVerifyTransactionPaymentProof(&session->transactionContext, extendedPrivateKey, coinInfo, message->address_type, message->kernel_commitment.bytes, message->payment_proof.bytes, message->payment_proof.size)) {
			
				// Send data error response
				fsm_sendFailure(FailureType_Failure_DataError, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
		}
		
		// Otherwise check if a payment proof exists
		else if(message->has_payment_proof) {
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
		}
		
		// Check if an offset wasn't applied to the session's transaction context
		if(!session->transactionContext.offsetApplied) {
		
			// Send invalid session response
			fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
		}
	}
	
	// Otherwise
	else {
	
		// Check if a kernel commitment exists but session's transaction context doesn't have an address
		if(message->has_kernel_commitment && !session->transactionContext.address[0]) {
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
		}
		
		// Check if a payment proof exists
		if(message->has_payment_proof) {
		
			// Send data error response
			fsm_sendFailure(FailureType_Failure_DataError, NULL);
			
			// Show home
			layoutHome();
			
			// Return
			return;
		}
	}
	
	// Check if session's transaction context has remaining output or input
	if(session->transactionContext.remainingOutput || session->transactionContext.remainingInput) {
	
		// Send invalid session response
		fsm_sendFailure(FailureType_Failure_InvalidSession, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show prompt
	layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _(coinInfo->name), session->transactionContext.send ? _("Send transaction?") : _("Receive transaction?"), NULL, NULL, NULL, NULL, NULL, FONT_STANDARD);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Get session's transaction context's account as a string
	char accountBuffer[MIMBLEWIMBLE_COIN_UINT32_BUFFER_SIZE + sizeof((char)'\0')];
	bn_format_uint64(session->transactionContext.account, NULL, NULL, 0, 0, false, 0, accountBuffer, sizeof(accountBuffer));
	
	// Show prompt
	layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Account Index"), accountBuffer, NULL, NULL, NULL, NULL, NULL, FONT_FIXED);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Get session's transaction context's amount as a string
	char amountBuffer[MIMBLEWIMBLE_COIN_UINT64_BUFFER_SIZE + sizeof((char)'.') + sizeof((char)'\0')];
	bn_format_uint64(session->transactionContext.send ? session->transactionContext.send : session->transactionContext.receive, NULL, NULL, coinInfo->fractionalDigits, 0, false, 0, amountBuffer, sizeof(amountBuffer));
	const char **splitMessage = split_message((const uint8_t *)amountBuffer, strlen(amountBuffer), MIMBLEWIMBLE_COIN_ROW_LENGTH);
	
	// Show prompt
	layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Amount"), splitMessage[0], splitMessage[1], splitMessage[2], splitMessage[3], NULL, NULL, FONT_FIXED);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Get session's transaction context's fee as a string
	char feeBuffer[MIMBLEWIMBLE_COIN_UINT64_BUFFER_SIZE + sizeof((char)'.') + sizeof((char)'\0')];
	bn_format_uint64(session->transactionContext.fee, NULL, NULL, coinInfo->fractionalDigits, 0, false, 0, feeBuffer, sizeof(feeBuffer));
	splitMessage = split_message((const uint8_t *)feeBuffer, strlen(feeBuffer), MIMBLEWIMBLE_COIN_ROW_LENGTH);
	
	// Show prompt
	layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Fee"), splitMessage[0], splitMessage[1], splitMessage[2], splitMessage[3], NULL, NULL, FONT_FIXED);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check kernel information's features
	switch(message->kernel_information.bytes[0]) {
	
		// Plain features
		case MimbleWimbleCoinKernelFeatures_PLAIN_FEATURES:
		
			// Show prompt
			layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Kernel Features"), _("Plain"), NULL, NULL, NULL, NULL, NULL, FONT_FIXED);
			
			// Break
			break;
	
		// Coinbase features
		case MimbleWimbleCoinKernelFeatures_COINBASE_FEATURES:
		
			// Show prompt
			layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Kernel Features"), _("Coinbase"), NULL, NULL, NULL, NULL, NULL, FONT_FIXED);
			
			// Break
			break;
		
		// Height locked features
		case MimbleWimbleCoinKernelFeatures_HEIGHT_LOCKED_FEATURES:
		
			// Show prompt
			layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Kernel Features"), _("Height locked"), NULL, NULL, NULL, NULL, NULL, FONT_FIXED);
			
			// Break
			break;
		
		// No recent duplicate features
		case MimbleWimbleCoinKernelFeatures_NO_RECENT_DUPLICATE_FEATURES:
		
			// Show prompt
			layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Kernel Features"), _("No recent duplicate"), NULL, NULL, NULL, NULL, NULL, FONT_FIXED);
			
			// Break
			break;
	}
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check kernel information's features
	switch(message->kernel_information.bytes[0]) {
	
		// Height locked features
		case MimbleWimbleCoinKernelFeatures_HEIGHT_LOCKED_FEATURES: {
		
			// Get lock height from kernel information
			uint64_t lockHeight;
			memcpy(&lockHeight, &message->kernel_information.bytes[sizeof(message->kernel_information.bytes[0])], sizeof(lockHeight));

			// Check if big endian
			#if BYTE_ORDER == BIG_ENDIAN

				// Make lock height big endian
				REVERSE64(lockHeight, lockHeight);
			#endif
		
			// Get lock height as a string
			char lockHeightBuffer[MIMBLEWIMBLE_COIN_UINT64_BUFFER_SIZE + sizeof((char)'\0')];
			bn_format_uint64(lockHeight, NULL, NULL, 0, 0, false, 0, lockHeightBuffer, sizeof(lockHeightBuffer));
			splitMessage = split_message((const uint8_t *)lockHeightBuffer, strlen(lockHeightBuffer), MIMBLEWIMBLE_COIN_ROW_LENGTH);
		
			// Show prompt
			layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Lock Height"), splitMessage[0], splitMessage[1], splitMessage[2], splitMessage[3], NULL, NULL, FONT_FIXED);
			
			// Check if user denied prompt
			if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			
				// Send action canceled response
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		}
		
		// No recent duplicate features
		case MimbleWimbleCoinKernelFeatures_NO_RECENT_DUPLICATE_FEATURES: {
		
			// Get relative height from kernel information
			uint16_t relativeHeight;
			memcpy(&relativeHeight, &message->kernel_information.bytes[sizeof(message->kernel_information.bytes[0])], sizeof(relativeHeight));

			// Check if big endian
			#if BYTE_ORDER == BIG_ENDIAN

				// Make relative height big endian
				REVERSE16(relativeHeight, relativeHeight);
			#endif
			
			// Get relative height as a string
			char relativeHeightBuffer[MIMBLEWIMBLE_COIN_UINT16_BUFFER_SIZE + sizeof((char)'\0')];
			bn_format_uint64(relativeHeight, NULL, NULL, 0, 0, false, 0, relativeHeightBuffer, sizeof(relativeHeightBuffer));
			
			// Show prompt
			layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Relative Height"), relativeHeightBuffer, NULL, NULL, NULL, NULL, NULL, FONT_FIXED);
			
			// Check if user denied prompt
			if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			
				// Send action canceled response
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				
				// Show home
				layoutHome();
				
				// Return
				return;
			}
			
			// Break
			break;
		}
	}
	
	// Check if kernel commitment exists
	if(message->has_kernel_commitment) {
	
		// Show prompt
		splitMessage = split_message((const uint8_t *)session->transactionContext.address, strlen(session->transactionContext.address), MIMBLEWIMBLE_COIN_ROW_LENGTH);
		layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Approve"), _("Proof Address"), splitMessage[0], splitMessage[1], splitMessage[2], splitMessage[3], NULL, NULL, FONT_FIXED);
	}
	
	// Otherwise
	else {
	
		// Show prompt
		layoutDialogSwipeEx(&bmp_icon_warning, _("Deny"), _("Approve"), NULL, _("No payment proof."), NULL, NULL, NULL, NULL, NULL, FONT_STANDARD);
	}
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {

		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show home
	layoutHome();
	
	// Check if finishing transaction failed
	resp->signature.size = sizeof(resp->signature.bytes);
	resp->has_payment_proof = session->transactionContext.receive && message->has_kernel_commitment;
	resp->payment_proof.size = mimbleWimbleCoinFinishTransaction(resp->signature.bytes, resp->payment_proof.bytes, &session->transactionContext, extendedPrivateKey, coinInfo, message->address_type, message->public_nonce.bytes, message->public_key.bytes, message->kernel_information.bytes, message->has_kernel_commitment ? message->kernel_commitment.bytes : NULL);
	if(!resp->payment_proof.size) {
	
		// Clear session
		memzero(session, sizeof(*session));
		
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Send transaction signature and payment proof response
	msg_write(MessageType_MessageType_MimbleWimbleCoinTransactionSignatureAndPaymentProof, resp);
	
	// Show home
	layoutHome();
}

// Get MQS challenge signature
void fsm_msgMimbleWimbleCoinGetMqsChallengeSignature(const MimbleWimbleCoinGetMqsChallengeSignature *message) {

	// Initialize response
	RESP_INIT(MimbleWimbleCoinMqsChallengeSignature);
	
	// Require initialized
	CHECK_INITIALIZED
	
	// Require pin
	CHECK_PIN
	
	// Check if caching seed failed
	if(!config_getSeed()) {
	
		// Return
		return;
	}
	
	// Check if initializing storage failed
	if(!mimbleWimbleCoinInitializeStorage()) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if getting session failed
	MimbleWimbleCoinSession *session = config_getMimbleWimbleCoinSession();
	if(!session) {
	
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Clear session
	memzero(session, sizeof(*session));
	
	// Check if getting coin info failed
	const MimbleWimbleCoinCoinInfo *coinInfo = getMimbleWimbleCoinCoinInfo(message->coin_type, message->network_type);
	if(!coinInfo) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if currency doesn't allow MQS addresses
	if(!coinInfo->enableMqsAddress) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if account is invalid
	if(message->account > PATH_UNHARDEN_MASK) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if timestamp is provided and it is invalid
	if(message->has_timestamp && (!message->has_time_zone_offset || message->timestamp > MIMBLEWIMBLE_COIN_MAXIMUM_TIMESTAMP)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if time zone offset is provided and it is invalid
	if(message->has_time_zone_offset && (!message->has_timestamp || message->time_zone_offset <= MIMBLEWIMBLE_COIN_MINIMUM_TIME_ZONE_OFFSET || message->time_zone_offset >= MIMBLEWIMBLE_COIN_MAXIMUM_TIME_ZONE_OFFSET)) {
	
		// Send data error response
		fsm_sendFailure(FailureType_Failure_DataError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show prompt
	char signChallengeMessage[sizeof(_("Sign ")) - sizeof((char)'\0') + strlen(_(coinInfo->mqsName)) + sizeof(_(" challenge?"))];
	strcpy(signChallengeMessage, _("Sign "));
	strcat(signChallengeMessage, _(coinInfo->mqsName));
	if(strlen(_(coinInfo->mqsName)) < 7) {
		strcat(signChallengeMessage, _(" challenge?"));
	}
	layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _(coinInfo->name), signChallengeMessage, (strlen(_(coinInfo->mqsName)) < 7) ? NULL : _("challenge?"), NULL, NULL, NULL, NULL, FONT_STANDARD);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Get account as a string
	char accountBuffer[MIMBLEWIMBLE_COIN_UINT32_BUFFER_SIZE + sizeof((char)'\0')];
	bn_format_uint64(message->account, NULL, NULL, 0, 0, false, 0, accountBuffer, sizeof(accountBuffer));
	
	// Show prompt
	layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Account Index"), accountBuffer, NULL, NULL, NULL, NULL, NULL, FONT_FIXED);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Check if a timestamp is provided
	if(message->has_timestamp) {
	
		// Get timestamp from timestamp
		time_t timestamp = message->timestamp / MIMBLEWIMBLE_COIN_MILLISECONDS_IN_A_SECOND;
		
		// Get time zone offset
		const int16_t timeZoneOffset = (message->time_zone_offset * MIMBLEWIMBLE_COIN_SECONDS_IN_A_MINUTE > timestamp) ? 0 : message->time_zone_offset;
		
		// Apply time zone offset to timestamp
		timestamp -= timeZoneOffset * MIMBLEWIMBLE_COIN_SECONDS_IN_A_MINUTE;
		
		// Get timestamp parts as a strings
		const struct tm *time = gmtime(&timestamp);
		char timestampTimeBuffer[sizeof(_("HH:MM:SS on"))];
		snprintf(timestampTimeBuffer, sizeof(timestampTimeBuffer), _("%02d:%02d:%02d on"), time->tm_hour, time->tm_min, time->tm_sec);
		char timestampDateBuffer[sizeof(_("YYYYYY-mm-dd"))];
		snprintf(timestampDateBuffer, sizeof(timestampDateBuffer), _("%d-%02d-%02d"), (unsigned)time->tm_year + 1900, (unsigned)time->tm_mon + 1, time->tm_mday);
		char timestampOffsetBuffer[sizeof(_("UTC+00:00")) + 1/*The +1 satisfies -Werror=format-truncation= despite it not being necessary*/];
		snprintf(timestampOffsetBuffer, sizeof(timestampOffsetBuffer), _("UTC%c%02d:%02d"), (timeZoneOffset > 0) ? '-' : '+', abs(timeZoneOffset) / MIMBLEWIMBLE_COIN_MINUTES_IN_AN_HOUR, abs(timeZoneOffset) % MIMBLEWIMBLE_COIN_MINUTES_IN_AN_HOUR);
		
		// Show prompt
		layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Time And Date"), timestampTimeBuffer, timestampDateBuffer, timestampOffsetBuffer, NULL, NULL, NULL, FONT_FIXED);
	}
	
	// Otherwises
	else {
	
		// Show prompt
		const char **splitMessage = split_message((const uint8_t *)MIMBLEWIMBLE_COIN_DEFAULT_MQS_CHALLENGE, sizeof(MIMBLEWIMBLE_COIN_DEFAULT_MQS_CHALLENGE) - sizeof((char)'\0'), MIMBLEWIMBLE_COIN_ROW_LENGTH);
		layoutDialogSwipeEx(&bmp_icon_question, _("Deny"), _("Next"), _("Default Challenge"), splitMessage[0], splitMessage[1], splitMessage[2], splitMessage[3], NULL, NULL, FONT_FIXED);
	}
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show prompt
	char transactionTypeMessage[sizeof(_("account's ")) + strlen(_(coinInfo->mqsName))];
	strcpy(transactionTypeMessage, _("account's "));
	strcat(transactionTypeMessage, _(coinInfo->mqsName));
	layoutDialogSwipeEx(&bmp_icon_warning, _("Deny"), _("Approve"), NULL, _("The host will be able"), _("to listen for the"), transactionTypeMessage, _("transactions."), NULL, NULL, FONT_STANDARD);
	
	// Check if user denied prompt
	if(!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
	
		// Send action canceled response
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Show home
	layoutHome();
	
	// Check if getting extended private key failed
	const HDNode *extendedPrivateKey = mimbleWimbleCoinGetExtendedPrivateKey(coinInfo, message->account);
	if(!extendedPrivateKey) {
	
		// Return
		return;
	}
	
	// Check if a timestamp is provided
	if(message->has_timestamp) {
	
		// Get timestamp as a string
		char timestampBuffer[MIMBLEWIMBLE_COIN_UINT64_BUFFER_SIZE + sizeof((char)'\0')];
		bn_format_uint64(message->timestamp, NULL, NULL, 0, 0, false, 0, timestampBuffer, sizeof(timestampBuffer));
		
		// Get MQS challenge signature of the timestamp
		resp->mqs_challenge_signature.size = mimbleWimbleCoinGetMqsChallengeSignature(resp->mqs_challenge_signature.bytes, extendedPrivateKey, coinInfo, message->index, timestampBuffer);
	}
	
	// Otherwise
	else {
	
		// Get MQS challenge signature of the default MQS challenge
		resp->mqs_challenge_signature.size = mimbleWimbleCoinGetMqsChallengeSignature(resp->mqs_challenge_signature.bytes, extendedPrivateKey, coinInfo, message->index, MIMBLEWIMBLE_COIN_DEFAULT_MQS_CHALLENGE);
	}
	
	// Check if getting MQS challenge signature failed
	if(!resp->mqs_challenge_signature.size) {
	
		// Send process error response
		fsm_sendFailure(FailureType_Failure_ProcessError, NULL);
		
		// Show home
		layoutHome();
		
		// Return
		return;
	}
	
	// Send MQS challenge signature response
	msg_write(MessageType_MessageType_MimbleWimbleCoinMqsChallengeSignature, resp);
	
	// Show home
	layoutHome();
}

// Get extended private key
HDNode *mimbleWimbleCoinGetExtendedPrivateKey(const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t account) {

	// Create BIP44 path
	const uint32_t bip44Path[] = {
	
		// Purpose
		MIMBLEWIMBLE_COIN_BIP44_PURPOSE | PATH_HARDENED,
		
		// Coin type
		coinInfo->slip44 | PATH_HARDENED,
		
		// Account
		account | PATH_HARDENED,
		
		// Change
		0,
		
		// Address index
		0
	};
	
	// Return node derived at path
	return fsm_getDerivedNode(SECP256K1_MIMBLEWIMBLE_COIN_NAME, bip44Path, sizeof(bip44Path) / sizeof(bip44Path[0]), NULL);
}

// Initialize storage
bool mimbleWimbleCoinInitializeStorage(void) {

	// Check if getting current transaction secret nonce index from storage failed
	uint32_t currentTransactionSecretNonceIndex;
	if(!config_getMimbleWimbleCoinCurrentTransactionSecretNonceIndex(&currentTransactionSecretNonceIndex)) {
	
		// Return false
		return false;
	}
	
	// Check if current transaction secret nonce index is invalid
	if(currentTransactionSecretNonceIndex >= MIMBLEWIMBLE_COIN_NUMBER_OF_TRANSACTION_SECRET_NONCES) {
	
		// Check if resetting current transaction secret nonce index in storage failed
		if(!config_setMimbleWimbleCoinCurrentTransactionSecretNonceIndex(0)) {
		
			// Return false
			return false;
		}
	}
	
	// Return true
	return true;
}
