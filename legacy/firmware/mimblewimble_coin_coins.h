// Header guard
#ifndef __MIMBLEWIMBLE_COIN_COINS_H__
#define __MIMBLEWIMBLE_COIN_COINS_H__


// Header files
#include "messages-mimblewimble-coin.pb.h"


// Definitions

// Address derivation type
typedef enum _MimbleWimbleCoinAddressDerivationType {

	// MWC address derivation
	MimbleWimbleCoinAddressDerivationType_MWC_ADDRESS_DERIVATION,
	
	// GRIN address derivation
	MimbleWimbleCoinAddressDerivationType_GRIN_ADDRESS_DERIVATION
	
} MimbleWimbleCoinAddressDerivationType;

// Payment proof message type
typedef enum _MimbleWimbleCoinPaymentProofMessageType {

	// ASCII payment proof message
	MimbleWimbleCoinPaymentProofMessageType_ASCII_PAYMENT_PROOF_MESSAGE,
	
	// Binary payment proof message
	MimbleWimbleCoinPaymentProofMessageType_BINARY_PAYMENT_PROOF_MESSAGE
	
} MimbleWimbleCoinPaymentProofMessageType;

// Payment proof address type
typedef enum _MimbleWimbleCoinPaymentProofAddressType {

	// MQS payment proof address
	MimbleWimbleCoinPaymentProofAddressType_MQS_PAYMENT_PROOF_ADDRESS = 1 << 0,
	
	// Tor payment proof address
	MimbleWimbleCoinPaymentProofAddressType_TOR_PAYMENT_PROOF_ADDRESS = 1 << 1,
	
	// Slatepack payment proof address
	MimbleWimbleCoinPaymentProofAddressType_SLATEPACK_PAYMENT_PROOF_ADDRESS = 1 << 2
	
} MimbleWimbleCoinPaymentProofAddressType;

// Slate encryption type
typedef enum _MimbleWimbleCoinSlateEncryptionType {

	// MQS slate encryption
	MimbleWimbleCoinSlateEncryptionType_MQS_SLATE_ENCRYPTION = 1 << 0,
	
	// Tor slate encryption
	MimbleWimbleCoinSlateEncryptionType_TOR_SLATE_ENCRYPTION = 1 << 1,
	
	// Slatepack slate encryption
	MimbleWimbleCoinSlateEncryptionType_SLATEPACK_SLATE_ENCRYPTION = 1 << 2
	
} MimbleWimbleCoinSlateEncryptionType;

// Coin info
typedef struct _MimbleWimbleCoinCoinInfo {

	// Name
	const char *name;
	
	// Coin type
	MimbleWimbleCoinCoinType coinType;
	
	// Network type
	MimbleWimbleCoinNetworkType networkType;
	
	// SLIP44
	uint32_t slip44;
	
	// Fractional digits
	uint8_t fractionalDigits;
	
	// Enable MQS address
	bool enableMqsAddress;
	
	// Enable Tor address
	bool enableTorAddress;
	
	// Enable Slatepack address
	bool enableSlatepackAddress;
	
	// Enable no recent duplicate kernels
	bool enableNoRecentDuplicateKernels;
	
	// MQS version
	uint8_t mqsVersion[2];
	
	// Slatepack address human readable part
	const char *slatepackAddressHumanReadablePart;
	
	// Maximum fee
	uint64_t maximumFee;
	
	// Address derivation type
	MimbleWimbleCoinAddressDerivationType addressDerivationType;
	
	// Payment proof message type
	MimbleWimbleCoinPaymentProofMessageType paymentProofMessageType;
	
	// Supported payment proof address types
	MimbleWimbleCoinPaymentProofAddressType supportedPaymentProofAddressTypes;
	
	// Supported slate encryption types
	MimbleWimbleCoinSlateEncryptionType supportedSlateEncryptionTypes;
	
	// MQS name
	const char *mqsName;
	
} MimbleWimbleCoinCoinInfo;


// Header files
#include "mimblewimble_coin_coin_info.h"


// Function prototypes

// Get MimbleWimble Coin coin info
const MimbleWimbleCoinCoinInfo *getMimbleWimbleCoinCoinInfo(const MimbleWimbleCoinCoinType coinType, const MimbleWimbleCoinNetworkType networkType);


#endif
