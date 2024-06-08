// Header guard
#ifndef __MIMBLEWIMBLE_COIN_SESSION_H__
#define __MIMBLEWIMBLE_COIN_SESSION_H__


// Header files
#include "sha2.h"
#include "chacha20poly1305/chacha20poly1305.h"
#include "messages-mimblewimble-coin.pb.h"
#include "aes/aes.h"


// Definitions

// AES key size
#define MIMBLEWIMBLE_COIN_AES_KEY_SIZE 32

// Blinding factor size
#define MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE 32

// Slatepack address size without human-readable part
#define MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART 59

// Number of transaction secret nonces
#define MIMBLEWIMBLE_COIN_NUMBER_OF_TRANSACTION_SECRET_NONCES 30

// Transaction secret nonce size
#define MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE 32

// Encrypted transaction secret nonce size
#define MIMBLEWIMBLE_COIN_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE (MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE + ((MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE % AES_BLOCK_SIZE) ? AES_BLOCK_SIZE - MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE % AES_BLOCK_SIZE : AES_BLOCK_SIZE))

// Encrypting or decryption state
typedef enum _MimbleWimbleCoinEncryptingOrDecryptingState {

	// Inactive state
	MimbleWimbleCoinEncryptingOrDecryptingState_INACTIVE_STATE,
	
	// Ready state
	MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE,
	
	// Active state
	MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE,
	
	// Complete state
	MimbleWimbleCoinEncryptingOrDecryptingState_COMPLETE_STATE
	
} MimbleWimbleCoinEncryptingOrDecryptingState;

// Encryption and decryption context
typedef struct _MimbleWimbleCoinEncryptionAndDecryptionContext {

	// Coin type
	MimbleWimbleCoinCoinType coinType;
	
	// Network type
	MimbleWimbleCoinNetworkType networkType;
	
	// Account
	uint32_t account;
	
	// Index
	uint32_t index;
	
	// Encrypting state
	MimbleWimbleCoinEncryptingOrDecryptingState encryptingState;
	
	// Decrypting state
	MimbleWimbleCoinEncryptingOrDecryptingState decryptingState;
	
	// AES key
	uint8_t aesKey[MIMBLEWIMBLE_COIN_AES_KEY_SIZE];
	
	// Message hash context
	SHA256_CTX messageHashContext;
	
	// Message hash context initialized
	bool messageHashContextInitialized;
	
	// ChaCha20 Poly1305 context
	chacha20poly1305_ctx chaCha20Poly1305Context;
	
	// Data length
	size_t dataLength;
	
} MimbleWimbleCoinEncryptionAndDecryptionContext;

// Transaction context
typedef struct _MimbleWimbleCoinTransactionContext {

	// Coin type
	MimbleWimbleCoinCoinType coinType;
	
	// Network type
	MimbleWimbleCoinNetworkType networkType;
	
	// Account
	uint32_t account;
	
	// Index
	uint32_t index;
	
	// Send
	uint64_t send;
	
	// receive
	uint64_t receive;
	
	// Fee
	uint64_t fee;
	
	// Remaining output
	uint64_t remainingOutput;
	
	// Remaining input
	uint64_t remainingInput;
	
	// Blinding factor
	uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
	
	// Secret nonce
	uint8_t secretNonce[MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE];
	
	// Started
	bool started;
	
	// Offset applied
	bool offsetApplied;
	
	// Message signed
	bool messageSigned;
	
	// Secret nonce index
	uint8_t secretNonceIndex;
	
	// Address
	char address[MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + sizeof("tgrin")];
	
} MimbleWimbleCoinTransactionContext;

// Session
typedef struct _MimbleWimbleCoinSession {

	// Encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext encryptionAndDecryptionContext;
	
	// Transaction context
	MimbleWimbleCoinTransactionContext transactionContext;
	
} MimbleWimbleCoinSession;


#endif
