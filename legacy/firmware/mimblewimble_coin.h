// Header guard
#ifndef __MIMBLEWIMBLE_COIN_H__
#define __MIMBLEWIMBLE_COIN_H__


// Header files
#include "mimblewimble_coin_coins.h"
#include "mimblewimble_coin_session.h"
#include "bip32.h"


// Definitions

// MQS address size
#define MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE 52

// Tor address size
#define MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE 56

// Identifier depth index
#define MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX 0

// Maximum identifier depth
#define MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH 4

// Hex character size
#define MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE (sizeof("FF") - sizeof((char)'\0'))

// X25519 public key size
#define MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE 32

// MQS encryption salt size
#define MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE 8

// Uint64 buffer size
#define MIMBLEWIMBLE_COIN_UINT64_BUFFER_SIZE (sizeof("18446744073709551615") - sizeof((char)'\0'))

// Kernel features
typedef enum _MimbleWimbleCoinKernelFeatures {

	// Plain features
	MimbleWimbleCoinKernelFeatures_PLAIN_FEATURES,
	
	// Coinbase features
	MimbleWimbleCoinKernelFeatures_COINBASE_FEATURES,
	
	// Height locked features
	MimbleWimbleCoinKernelFeatures_HEIGHT_LOCKED_FEATURES,
	
	// No recent duplicate features
	MimbleWimbleCoinKernelFeatures_NO_RECENT_DUPLICATE_FEATURES
	
} MimbleWimbleCoinKernelFeatures;


// Constants

// Default MQS challenge
static const char MIMBLEWIMBLE_COIN_DEFAULT_MQS_CHALLENGE[] = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";


// Function prototypes

// To hex string
void mimbleWimbleCoinToHexString(const uint8_t *data, const size_t length, char *string);

// Is zero
bool mimbleWimbleCoinIsZero(const uint8_t *data, const size_t length);

// Is valid UTF-8 string
bool mimbleWimbleCoinisValidUtf8String(const char *string, const size_t length);

// Get MQS address
bool mimbleWimbleCoinGetMqsAddress(char *mqsAddress, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index);

// Get Tor address
bool mimbleWimbleCoinGetTorAddress(char *torAddress, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index);

// Get Slatepack address
bool mimbleWimbleCoinGetSlatepackAddress(char *slatepackAddress, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index);

// Get seed cookie
void mimbleWimbleCoinGetSeedCookie(uint8_t *seedCookie, const HDNode *extendedPrivateKey);

// Get commitment
bool mimbleWimbleCoinGetCommitment(uint8_t *commitment, const HDNode *extendedPrivateKey, const uint64_t value, const uint8_t *identifier, const MimbleWimbleCoinSwitchType switchType);

// Get Bulletproof components
bool mimbleWimbleCoinGetBulletproofComponents(uint8_t *tauX, uint8_t *tOne, uint8_t *tTwo, const HDNode *extendedPrivateKey, const uint64_t value, const uint8_t *identifier, const MimbleWimbleCoinSwitchType switchType, const char *displayMessage);

// Is valid MQS address
bool mimbleWimbleCoinIsValidMqsAddress(const char *mqsAddress, const MimbleWimbleCoinCoinInfo *coinInfo, const size_t mqsAddressLength);

// Is valid Tor address
bool mimbleWimbleCoinIsValidTorAddress(const char *torAddress, const size_t torAddressLength);

// Is valid Slatepack address
bool mimbleWimbleCoinIsValidSlatepackAddress(const char *slatepackAddress, const MimbleWimbleCoinCoinInfo *coinInfo, const size_t slatepackAddressLength);

// Is valid MQS address domain
bool mimbleWimbleCoinIsValidMqsAddressDomain(const char *mqsAddressDomain, const size_t mqsAddressDomainLength);

// Is valid secp256k1 public key
bool mimbleWimbleCoinIsValidSecp256k1PublicKey(const uint8_t *publicKey, const size_t publicKeyLength);

// Is valid X25519 public key
bool mimbleWimbleCoinIsValidX25519PublicKey(const uint8_t *publicKey, const size_t publicKeyLength);

// Is valid commitment
bool mimbleWimbleCoinIsValidCommitment(const uint8_t *commitment, const size_t commitmentLength);

// Start MQS encryption
bool mimbleWimbleCoinStartMqsEncryption(uint8_t *nonce, uint8_t *salt, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *recipientAddress, const char *recipientAddressDomain, const size_t recipientAddressDomainLength);

// Start Tor encryption
bool mimbleWimbleCoinStartTorEncryption(uint8_t *nonce, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *recipientAddress);

// Encrypt data
bool mimbleWimbleCoinEncryptData(uint8_t *encryptedData, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const uint8_t *data, const size_t dataLength);

// Finish encryption
size_t mimbleWimbleCoinFinishEncryption(uint8_t *tag, uint8_t *mqsMessageSignature, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo);

// Start MQS decryption
bool mimbleWimbleCoinStartMqsDecryption(MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *senderAddress, const uint8_t *nonce, const uint8_t *salt);

// Start Tor decryption
bool mimbleWimbleCoinStartTorDecryption(MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *senderAddress, const uint8_t *nonce);

// Start Slatepack decryption
bool mimbleWimbleCoinStartSlatepackDecryption(MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const uint8_t *ephemeralX25519PublicKey, const uint8_t *nonce, const uint8_t *encryptedFileKey, const uint8_t *payloadNonce);

// Decrypt data
size_t mimbleWimbleCoinDecryptData(uint8_t *data, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const uint8_t *encryptedData, const size_t encryptedDataLength);

// Finish decryption
bool mimbleWimbleCoinFinishDecryption(uint8_t *aesKey, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const uint8_t *tag);

// Start transaction
bool mimbleWimbleCoinStartTransaction(MimbleWimbleCoinTransactionContext *transactionContext, const uint32_t index, const uint64_t output, const uint64_t input, const uint64_t fee, const uint8_t secretNonceIndex, const char *address, const size_t addressLength);

// Include output in transaction
bool mimbleWimbleCoinIncludeOutputInTransaction(MimbleWimbleCoinTransactionContext *transactionContext, const HDNode *extendedPrivateKey, const uint64_t value, const uint8_t *identifier, const MimbleWimbleCoinSwitchType switchType);

// Include input in transaction
bool mimbleWimbleCoinIncludeInputInTransaction(MimbleWimbleCoinTransactionContext *transactionContext, const HDNode *extendedPrivateKey, const uint64_t value, const uint8_t *identifier, const MimbleWimbleCoinSwitchType switchType);

// Is valid secp256k1 private key
bool mimbleWimbleCoinIsValidSecp256k1PrivateKey(const uint8_t *privateKey, const size_t privateKeyLength);

// Apply offset to transaction
uint8_t mimbleWimbleCoinApplyOffsetToTransaction(MimbleWimbleCoinTransactionContext *transactionContext, const uint8_t *offset);

// Get transaction public key
bool mimbleWimbleCoinGetTransactionPublicKey(uint8_t *publicKey, const MimbleWimbleCoinTransactionContext *transactionContext);

// Get transaction public nonce
bool mimbleWimbleCoinGetTransactionPublicNonce(uint8_t *publicNonce, const MimbleWimbleCoinTransactionContext *transactionContext);

// Get transaction message signature
bool mimbleWimbleCoinGetTransactionMessageSignature(uint8_t *messageSignature, MimbleWimbleCoinTransactionContext *transactionContext, const char *message, const size_t messageLength);

// Verify transaction payment proof
bool mimbleWimbleCoinVerifyTransactionPaymentProof(const MimbleWimbleCoinTransactionContext *transactionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const MimbleWimbleCoinAddressType addressType, const uint8_t *kernelCommitment, const uint8_t *paymentProof, const size_t paymentProofLength);

// Finish transaction
size_t mimbleWimbleCoinFinishTransaction(uint8_t *signature, uint8_t *paymentProof, const MimbleWimbleCoinTransactionContext *transactionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const MimbleWimbleCoinAddressType addressType, const uint8_t *publicNonce, const uint8_t *publicKey, const uint8_t *kernelInformation, const uint8_t *kernelCommitment);

// Get MQS challenge signature
size_t mimbleWimbleCoinGetMqsChallengeSignature(uint8_t *mqsChallengeSignature, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *challenge);


#endif
