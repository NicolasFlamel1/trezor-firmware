// Header files
#include <ctype.h>
#include "base58.h"
#include "base32.h"
#include "mimblewimble_coin_generators.h"
#include "mimblewimble_coin_generators.c"

/// package: trezorcrypto.mimblewimble_coin
/// from enum import IntEnum, IntFlag
/// from trezorcrypto.bip32 import HDNode
/// from apps.mimblewimble_coin.coins import CoinInfo
/// from trezor.enums import MimbleWimbleCoinSwitchType, MimbleWimbleCoinAddressType


// Definitions

// AES key size
#define MIMBLEWIMBLE_COIN_AES_KEY_SIZE 32

// Blinding factor size
#define MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE 32

// Transaction secret nonce size
#define MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE 32

// Encrypted transaction secret nonce size
#define MIMBLEWIMBLE_COIN_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE (MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE + ((MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE % AES_BLOCK_SIZE) ? AES_BLOCK_SIZE - MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE % AES_BLOCK_SIZE : AES_BLOCK_SIZE))

// MQS address size
#define MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE 52

// Tor address size
#define MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE 56

// Slatepack address size without human-readable part
#define MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART 59

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

// Secp256k1 private key size
#define MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE 32

// Secp256k1 compressed public key size
#define MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE 33

// Secp256k1 uncompressed public key size
#define MIMBLEWIMBLE_COIN_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_SIZE 65

// Secp256k1 even compressed public key prefix
#define MIMBLEWIMBLE_COIN_SECP256k1_EVEN_COMPRESSED_PUBLIC_KEY_PREFIX 2

// Secp256k1 odd compressed public key prefix
#define MIMBLEWIMBLE_COIN_SECP256k1_ODD_COMPRESSED_PUBLIC_KEY_PREFIX 3

// Ed25519 private key size
#define MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE 32

// Ed25519 public key size
#define MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE 32

// X25519 private key size
#define MIMBLEWIMBLE_COIN_X25519_PRIVATE_KEY_SIZE 32

// Commitment even prefix
#define MIMBLEWIMBLE_COIN_COMMITMENT_EVEN_PREFIX 8

// Commitment odd prefix
#define MIMBLEWIMBLE_COIN_COMMITMENT_ODD_PREFIX 9

// Public key prefix size
#define MIMBLEWIMBLE_COIN_PUBLIC_KEY_PREFIX_SIZE 1

// Public key component size
#define MIMBLEWIMBLE_COIN_PUBLIC_KEY_COMPONENT_SIZE 32

// Address private key blinding factor value
#define MIMBLEWIMBLE_COIN_ADDRESS_PRIVATE_KEY_BLINDING_FACTOR_VALUE 713

// Node size
#define MIMBLEWIMBLE_COIN_NODE_SIZE 64

// Chain code size
#define MIMBLEWIMBLE_COIN_CHAIN_CODE_SIZE 32

// Tor address checksum size
#define MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SIZE 2

// Bits in a byte
#define MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE 8

// Bech32 bits per character
#define MIMBLEWIMBLE_COIN_BECH32_BITS_PER_CHARACTER 5

// Compressed commitment size
#define MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE 33

// Uncompressed commitment size
#define MIMBLEWIMBLE_COIN_UNCOMPRESSED_COMMITMENT_SIZE 65

// Identifier size
#define MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE (sizeof(uint8_t) + MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH * sizeof(uint32_t))

// Bulletproof message size
#define MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_SIZE 20

// Bulletproof message switch type index
#define MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_SWITCH_TYPE_INDEX 2

// Bulletproof message identidier index
#define MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_IDENTIFIER_INDEX 3

// Bits to prove
#define MIMBLEWIMBLE_COIN_BITS_TO_PROVE (sizeof(uint64_t) * MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE)

// Multiexponentiation steps
#define MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS 8

// Secp256k1 compact signature size
#define MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE 64

// Ed25519 signature size
#define MIMBLEWIMBLE_COIN_ED25519_SIGNATURE_SIZE 64

// MQS shared private key number of iterations
#define MIMBLEWIMBLE_COIN_MQS_SHARED_PRIVATE_KEY_NUMBER_OF_ITERATIONS 100

// ChaCha20 key size
#define MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE 32

// ChaCha20 block counter index
#define MIMBLEWIMBLE_COIN_CHACHA20_BLOCK_COUNTER_INDEX 12

// ChaCha20 nonce size
#define MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE 12

// ChaCha20 block size
#define MIMBLEWIMBLE_COIN_CHACHA20_BLOCK_SIZE 64

// Poly1305 tag size
#define MIMBLEWIMBLE_COIN_POLY1305_TAG_SIZE 16

// AES IV size
#define MIMBLEWIMBLE_COIN_AES_IV_SIZE 16

// Age file key size
#define MIMBLEWIMBLE_COIN_AGE_FILE_KEY_SIZE 16

// Age payload nonce size
#define MIMBLEWIMBLE_COIN_AGE_PAYLOAD_NONCE_SIZE 16

// Scalar size
#define MIMBLEWIMBLE_COIN_SCALAR_SIZE 32

// Single-signer message size
#define MIMBLEWIMBLE_COIN_SINGLE_SIGNER_MESSAGE_SIZE 32

// Path hardened
#define MIMBLEWIMBLE_COIN_PATH_HARDENED 0x80000000

// Maximum DER signature size
#define MIMBLEWIMBLE_COIN_MAXIMUM_DER_SIGNATURE_SIZE 72

// Slatepack encryption file key size
#define MIMBLEWIMBLE_COIN_SLATEPACK_ENCRYPTION_ENCRYPTED_FILE_KEY_SIZE (MIMBLEWIMBLE_COIN_AGE_FILE_KEY_SIZE + MIMBLEWIMBLE_COIN_AGE_PAYLOAD_NONCE_SIZE)

// Seconds in a minute
#define MIMBLEWIMBLE_COIN_SECONDS_IN_A_MINUTE 60

// Months in a year
#define MIMBLEWIMBLE_COIN_MONTHS_IN_A_YEAR 12

// Rebase year
#define MIMBLEWIMBLE_COIN_REBASE_YEAR 1601

// Seconds from 1601 to 1970
#define MIMBLEWIMBLE_COIN_SECONDS_FROM_1601_TO_1970 11644473600

// Seconds in a quadricentennial
#define MIMBLEWIMBLE_COIN_SECONDS_IN_A_QUADRICENTENNIAL 12622780800

// Seconds in a centennial
#define MIMBLEWIMBLE_COIN_SECONDS_IN_A_CENTENNIAL 3155673600

// Seconds in a quadrennial
#define MIMBLEWIMBLE_COIN_SECONDS_IN_A_QUADRENNIAL 126230400

// Seconds in an annual
#define MIMBLEWIMBLE_COIN_SECONDS_IN_AN_ANNUAL 31536000

// Seconds in a day
#define MIMBLEWIMBLE_COIN_SECONDS_IN_A_DAY 86400

// Seconds in an hour
#define MIMBLEWIMBLE_COIN_SECONDS_IN_AN_HOUR 3600

// Maximum centennials
#define MIMBLEWIMBLE_COIN_MAXIMUM_CENTENNIALS 3

// Maximum quadrennials
#define MIMBLEWIMBLE_COIN_MAXIMUM_QUADRENNIALS 24

// Maximum annuals
#define MIMBLEWIMBLE_COIN_MAXIMUM_ANNUALS 3

// Years in a quadricentennial
#define MIMBLEWIMBLE_COIN_YEARS_IN_A_QUADRICENTENNIAL 400

// Years in a centennial
#define MIMBLEWIMBLE_COIN_YEARS_IN_A_CENTENNIAL 100

// Years in a quadrennial
#define MIMBLEWIMBLE_COIN_YEARS_IN_A_QUADRENNIAL 4

// Address derivation type
/// class AddressDerivationType(IntEnum):
///     """
///     Address derivation type
///     """
///     MWC_ADDRESS_DERIVATION = 0
///     GRIN_ADDRESS_DERIVATION = 1
typedef enum __attribute__((__packed__)) _MimbleWimbleCoinAddressDerivationType {

	// MWC address derivation
	MimbleWimbleCoinAddressDerivationType_MWC_ADDRESS_DERIVATION,
	
	// GRIN address derivation
	MimbleWimbleCoinAddressDerivationType_GRIN_ADDRESS_DERIVATION

} MimbleWimbleCoinAddressDerivationType;

// Payment proof message type
/// class PaymentProofMessageType(IntEnum):
///     """
///     Payment proof message type
///     """
///     ASCII_PAYMENT_PROOF_MESSAGE = 0
///     BINARY_PAYMENT_PROOF_MESSAGE = 1
typedef enum __attribute__((__packed__)) _MimbleWimbleCoinPaymentProofMessageType {

	// ASCII payment proof message
	MimbleWimbleCoinPaymentProofMessageType_ASCII_PAYMENT_PROOF_MESSAGE,
	
	// Binary payment proof message
	MimbleWimbleCoinPaymentProofMessageType_BINARY_PAYMENT_PROOF_MESSAGE

} MimbleWimbleCoinPaymentProofMessageType;

// Payment proof address type
/// class PaymentProofAddressType(IntFlag):
///     """
///     Payment proof address type
///     """
///     MQS_PAYMENT_PROOF_ADDRESS = 1 << 0
///     TOR_PAYMENT_PROOF_ADDRESS = 1 << 1
///     SLATEPACK_PAYMENT_PROOF_ADDRESS = 1 << 2
typedef enum __attribute__((__packed__)) _MimbleWimbleCoinPaymentProofAddressType {

	// MQS payment proof address
	MimbleWimbleCoinPaymentProofAddressType_MQS_PAYMENT_PROOF_ADDRESS = 1 << 0,
	
	// Tor payment proof address
	MimbleWimbleCoinPaymentProofAddressType_TOR_PAYMENT_PROOF_ADDRESS = 1 << 1,
	
	// Slatepack payment proof address
	MimbleWimbleCoinPaymentProofAddressType_SLATEPACK_PAYMENT_PROOF_ADDRESS = 1 << 2

} MimbleWimbleCoinPaymentProofAddressType;

// Slate encryption type
/// class SlateEncryptionType(IntFlag):
///     """
///     Slate encryption type
///     """
///     MQS_SLATE_ENCRYPTION = 1 << 0
///     TOR_SLATE_ENCRYPTION = 1 << 1
///     SLATEPACK_SLATE_ENCRYPTION = 1 << 2
typedef enum __attribute__((__packed__)) _MimbleWimbleCoinSlateEncryptionType {

	// MQS slate encryption
	MimbleWimbleCoinSlateEncryptionType_MQS_SLATE_ENCRYPTION = 1 << 0,
	
	// Tor slate encryption
	MimbleWimbleCoinSlateEncryptionType_TOR_SLATE_ENCRYPTION = 1 << 1,
	
	// Slatepack slate encryption
	MimbleWimbleCoinSlateEncryptionType_SLATEPACK_SLATE_ENCRYPTION = 1 << 2

} MimbleWimbleCoinSlateEncryptionType;

// Encrypting or decryption state
/// class EncryptingOrDecryptingState(IntEnum):
///     """
///     Encrypting or decryption state
///     """
///     INACTIVE_STATE = 0
///     READY_STATE = 1
///     ACTIVE_STATE = 2
///     COMPLETE_STATE = 3
typedef enum __attribute__((__packed__)) _MimbleWimbleCoinEncryptingOrDecryptingState {

	// Inactive state
	MimbleWimbleCoinEncryptingOrDecryptingState_INACTIVE_STATE,
	
	// Ready state
	MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE,
	
	// Active state
	MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE,
	
	// Complete state
	MimbleWimbleCoinEncryptingOrDecryptingState_COMPLETE_STATE
	
} MimbleWimbleCoinEncryptingOrDecryptingState;

// Kernel features
/// class KernelFeatures(IntEnum):
///     """
///     Kernel features
///     """
///     PLAIN_FEATURES = 0
///     COINBASE_FEATURES = 1
///     HEIGHT_LOCKED_FEATURES = 2
///     NO_RECENT_DUPLICATE_FEATURES = 3
typedef enum __attribute__((__packed__)) _MimbleWimbleCoinKernelFeatures {

	// Plain features
	MimbleWimbleCoinKernelFeatures_PLAIN_FEATURES,
	
	// Coinbase features
	MimbleWimbleCoinKernelFeatures_COINBASE_FEATURES,
	
	// Height locked features
	MimbleWimbleCoinKernelFeatures_HEIGHT_LOCKED_FEATURES,
	
	// No recent duplicate features
	MimbleWimbleCoinKernelFeatures_NO_RECENT_DUPLICATE_FEATURES
	
} MimbleWimbleCoinKernelFeatures;

// Encryption and decryption context
typedef struct _MimbleWimbleCoinEncryptionAndDecryptionContext {

	// Coin type
	uint8_t coinType;
	
	// Network type
	uint8_t networkType;
	
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
	uint8_t coinType;
	
	// Network type
	uint8_t networkType;
	
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

// Time
typedef struct _MimbleWimbleCoinTime {

	// Second
	uint8_t second;

	// Minute
	uint8_t minute;

	// Hour
	uint8_t hour;

	// Day
	uint16_t day;

	// Month
	uint8_t month;

	// Year
	uint32_t year;

} MimbleWimbleCoinTime;


// Function prototypes

/// mock:global

// Get root public key
/// def getRootPublicKey(extendedPrivateKey: HDNode) -> bytearray:
///     """
///     Get root public key
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getRootPublicKey(mp_obj_t extendedPrivateKeyObject);

// Get MQS address
/// def getMqsAddress(extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int) -> str:
///     """
///     Get MQS address
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getMqsAddress(const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject, const mp_obj_t indexObject);

// Get Tor address
/// def getTorAddress(extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int) -> str:
///     """
///     Get Tor address
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTorAddress(const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject, const mp_obj_t indexObject);

// Get Slatepack address
/// def getSlatepackAddress(extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int) -> str:
///     """
///     Get Slatepack address
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getSlatepackAddress(const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject, const mp_obj_t indexObject);

// Get seed cookie
/// def getSeedCookie(extendedPrivateKey: HDNode) -> bytes:
///     """
///     Get seed cookie
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getSeedCookie(mp_obj_t extendedPrivateKeyObject);

// Get commitment
/// def getCommitment(extendedPrivateKey: HDNode, value: int, identifier: bytes, switchType: MimbleWimbleCoinSwitchType) -> bytes:
///     """
///     Get commitment
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getCommitment(const size_t argumentsLength, const mp_obj_t *const arguments);

// Get Bulletproof components
/// def getBulletproofComponents(extendedPrivateKey: HDNode, value: int, identifier: bytes, switchType: MimbleWimbleCoinSwitchType, updateProgress: Callable[[int], None] | None) -> tuple[bytes, bytes, bytes]:
///     """
///     Get Bulletproof components
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getBulletproofComponents(const size_t argumentsLength, const mp_obj_t *arguments);

// Is valid MQS address domain
/// def isValidMqsAddressDomain(mqsAddressDomain: str) -> bool:
///     """
///     Is valid MQS address domain
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidMqsAddressDomain(const mp_obj_t mqsAddressDomainObject);

// Is valid MQS address
/// def isValidMqsAddress(mqsAddress: str, coinInfo: CoinInfo) -> bool:
///     """
///     Is valid MQS address
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidMqsAddress(const mp_obj_t mqsAddressObject, const mp_obj_t coinInfoObject);

// Start MQS encryption
/// def startMqsEncryption(encryptionAndDecryptionContext: memoryview, extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int, recipientAddress: str, recipientAddressDomain: str | None) -> tuple[bytes, bytes]:
///     """
///     Start MQS encryption
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_startMqsEncryption(const size_t argumentsLength, const mp_obj_t *arguments);

// Is valid Tor address
/// def isValidTorAddress(torAddress: str) -> bool:
///     """
///     Is valid Tor address
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidTorAddress(const mp_obj_t torAddressObject);

// Start Tor encryption
/// def startTorEncryption(encryptionAndDecryptionContext: memoryview, extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int, recipientAddress: str) -> bytes:
///     """
///     Start Tor encryption
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_startTorEncryption(const size_t argumentsLength, const mp_obj_t *arguments);

// Encrypt data
/// def encryptData(encryptionAndDecryptionContext: memoryview, data: bytes) -> bytes:
///     """
///     Encrypt data
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_encryptData(mp_obj_t encryptionAndDecryptionContextObject, const mp_obj_t dataObject);

// Finish encryption
/// def finishEncryption(encryptionAndDecryptionContext: memoryview, extendedPrivateKey: HDNode, coinInfo: CoinInfo) -> tuple[bytes, bytes | None]:
///     """
///     Finish encryption
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_finishEncryption(mp_obj_t encryptionAndDecryptionContextObject, const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject);

// Start MQS decryption
/// def startMqsDecryption(encryptionAndDecryptionContext: memoryview, extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int, senderAddress: str, nonce: bytes, salt: bytes) -> None:
///     """
///     Start MQS decryption
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_startMqsDecryption(const size_t argumentsLength, const mp_obj_t *arguments);

// Start Tor decryption
/// def startTorDecryption(encryptionAndDecryptionContext: memoryview, extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int, senderAddress: str, nonce: bytes) -> None:
///     """
///     Start Tor decryption
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_startTorDecryption(const size_t argumentsLength, const mp_obj_t *arguments);

// Is valid X25519 public key
/// def isValidX25519PublicKey(x25519PublicKey: bytes) -> bool:
///     """
///     Is valid X25519 public key
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidX25519PublicKey(const mp_obj_t x25519PublicKeyObject);

// Start Slatepack decryption
/// def startSlatepackDecryption(encryptionAndDecryptionContext: memoryview, extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int, ephemeralX25519PublicKey: bytes, nonce: bytes, encryptedFileKey: bytes, payloadNonce: bytes) -> None:
///     """
///     Start Slatepack decryption
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_startSlatepackDecryption(const size_t argumentsLength, const mp_obj_t *arguments);

// Decrypt data
/// def decryptData(encryptionAndDecryptionContext: memoryview, encryptedData: bytes) -> bytes:
///     """
///     Decrypt data
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_decryptData(mp_obj_t encryptionAndDecryptionContextObject, const mp_obj_t encryptedDataObject);

// Finish decryption
/// def finishDecryption(encryptionAndDecryptionContext: memoryview, tag: bytes) -> bytes:
///     """
///     Finish decryption
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_finishDecryption(mp_obj_t encryptionAndDecryptionContextObject, const mp_obj_t tagObject);

// Is valid Slatepack address
/// def isValidSlatepackAddress(slatepackAddress: str, coinInfo: CoinInfo) -> bool:
///     """
///     Is valid Slatepack address
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidSlatepackAddress(const mp_obj_t slatepackAddressObject, const mp_obj_t coinInfoObject);

// Is zero
/// def isZero(data: bytes) -> bool:
///     """
///     Is zero
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_isZero(const mp_obj_t dataObject);

// Start transaction
/// def startTransaction(transactionContext: memoryview, index: int, output: int, input: int, fee: int, secretNonceIndex: int, address: str) -> None:
///     """
///     Start transaction
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_startTransaction(const size_t argumentsLength, const mp_obj_t *arguments);

// Include output in transaction
/// def includeOutputInTransaction(transactionContext: memoryview, extendedPrivateKey: HDNode, value: int, identifier: bytes, switchType: MimbleWimbleCoinSwitchType) -> None:
///     """
///     Include output in transaction
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_includeOutputInTransaction(const size_t argumentsLength, const mp_obj_t *arguments);

// Include input in transaction
/// def includeInputInTransaction(transactionContext: memoryview, extendedPrivateKey: HDNode, value: int, identifier: bytes, switchType: MimbleWimbleCoinSwitchType) -> None:
///     """
///     Include input in transaction
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_includeInputInTransaction(const size_t argumentsLength, const mp_obj_t *arguments);

// Is valid secp256k1 private key
/// def isValidSecp256k1PrivateKey(privateKey: bytes) -> bool:
///     """
///     Is valid secp256k1 private key
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PrivateKey(const mp_obj_t privateKeyObject);

// Apply offset to transaction
/// def applyOffsetToTransaction(transactionContext: memoryview, offset: bytes) -> int | None:
///     """
///     Apply offset to transaction
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_applyOffsetToTransaction(mp_obj_t transactionContextObject, const mp_obj_t offsetObject);

// Get transaction public key
/// def getTransactionPublicKey(transactionContext: memoryview) -> bytes:
///     """
///     Get transaction public key
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTransactionPublicKey(const mp_obj_t transactionContextObject);

// Get transaction public nonce
/// def getTransactionPublicNonce(transactionContext: memoryview) -> bytes:
///     """
///     Get transaction public nonce
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTransactionPublicNonce(const mp_obj_t transactionContextObject);

// Get transaction message signature
/// def getTransactionMessageSignature(transactionContext: memoryview, message: str) -> bytes:
///     """
///     Get transaction message signature
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTransactionMessageSignature(mp_obj_t transactionContextObject, const mp_obj_t messageObject);

// Is valid secp256k1 public key
/// def isValidSecp256k1PublicKey(publicKey: bytes) -> bool:
///     """
///     Is valid secp256k1 public key
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PublicKey(const mp_obj_t publicKeyObject);

// Is valid commitment
/// def isValidCommitment(commitment: bytes) -> bool:
///     """
///     Is valid commitment
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidCommitment(const mp_obj_t commitmentObject);

// Verify transaction payment proof
/// def verifyTransactionPaymentProof(transactionContext: memoryview, extendedPrivateKey: HDNode, coinInfo: CoinInfo, addressType: MimbleWimbleCoinAddressType, kernelCommitment: bytes, paymentProof: bytes) -> bool:
///     """
///     Verify transaction payment proof
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_verifyTransactionPaymentProof(const size_t argumentsLength, const mp_obj_t *const arguments);

// Finish transaction
/// def finishTransaction(transactionContext: memoryview, extendedPrivateKey: HDNode, coinInfo: CoinInfo, addressType: MimbleWimbleCoinAddressType, publicNonce: bytes, publicKey: bytes, kernelInformation: bytes, kernelCommitment: bytes | None) -> tuple[bytes, bytes | None]:
///     """
///     Finish transaction
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_finishTransaction(const size_t argumentsLength, const mp_obj_t *const arguments);

// Get timestamp components
/// def getTimestampComponents(timestamp: int) -> tuple[int, int, int, int, int, int]:
///     """
///     Get timestamp components
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTimestampComponents(const mp_obj_t timestampObject);

// Get MQS challenge signature
/// def getMqsChallengeSignature(extendedPrivateKey: HDNode, coinInfo: CoinInfo, index: int, challenge: str) -> bytes:
///     """
///     Get MQS challenge signature
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getMqsChallengeSignature(const size_t argumentsLength, const mp_obj_t *const arguments);

// Get login challenge signature
/// def getLoginChallengeSignature(extendedPrivateKey: HDNode, identifier: str, challenge: str) -> tuple[bytes, bytes]:
///     """
///     Get login challenge signature
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getLoginChallengeSignature(const size_t argumentsLength, const mp_obj_t *const arguments);

// Is equal
STATIC bool mimbleWimbleCoinIsEqual(const uint8_t *dataOne, const uint8_t *dataTwo, const size_t length);

// Big number subtract modulo
STATIC void mimbleWimbleCoin_bn_submod(const bignum256 *minuend, const bignum256 *subtrahend, bignum256 *result, const bignum256 *prime);

// Get public key from secp256k1 private key
STATIC bool mimbleWimbleCoinGetPublicKeyFromSecp256k1PrivateKey(uint8_t *publicKey, const uint8_t *privateKey);

// Is valid Ed25519 private key
STATIC bool mimbleWimbleCoinIsValidEd25519PrivateKey(const uint8_t *privateKey, const size_t privateKeyLength);

// Is valid X25519 private key
STATIC bool mimbleWimbleCoinIsValidX25519PrivateKey(const uint8_t *privateKey, const size_t privateKeyLength);

// Is quadratic residue
STATIC bool mimbleWimbleCoinIsQuadraticResidue(const bignum256 *component);

// Derive child private key
STATIC bool mimbleWimbleCoinDeriveChildPrivateKey(uint8_t *childPrivateKey, const HDNode *extendedPrivateKey, const uint32_t *path, const size_t pathLength);

// Commit value
STATIC bool mimbleWimbleCoinCommitValue(uint8_t *commitment, const uint64_t value, const uint8_t *blindingFactor, const bool compress);

// Derive blinding factor
STATIC bool mimbleWimbleCoinDeriveBlindingFactor(uint8_t *blindingFactor, const HDNode *extendedPrivateKey, const uint64_t value, const uint32_t *path, const size_t pathLength, const mp_obj_t switchTypeObject);

// Get address private key
STATIC bool mimbleWimbleCoinGetAddressPrivateKey(uint8_t *addressPrivateKey, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index, const char *curveName);

// Get MQS address from public key
STATIC bool mimbleWimbleCoinGetMqsAddressFromPublicKey(char *mqsAddress, const mp_obj_t coinInfoObject, const uint8_t *publicKey);

// Get public key from MQS address
STATIC bool mimbleWimbleCoinGetPublicKeyFromMqsAddress(uint8_t *publicKey, const mp_obj_t coinInfoObject, const char *mqsAddress, const size_t mqsAddressLength);

// Get Tor address checksum
STATIC void mimbleWimbleCoinGetTorAddressChecksum(uint8_t *checksum, const uint8_t *publicKey);

// Get Tor address from public key
STATIC bool mimbleWimbleCoinGetTorAddressFromPublicKey(char *torAddress, const uint8_t *publicKey);

// Get public key from Tor address
STATIC bool mimbleWimbleCoinGetPublicKeyFromTorAddress(uint8_t *publicKey, const char *torAddress, const size_t torAddressLength);

// Get Slatepack address from public key
STATIC bool mimbleWimbleCoinGetSlatepackAddressFromPublicKey(char *slatepackAddress, const mp_obj_t coinInfoObject, const uint8_t *publicKey);

// Get public key from Slatepack address
STATIC bool mimbleWimbleCoinGetPublicKeyFromSlatepackAddress(uint8_t *publicKey, const mp_obj_t coinInfoObject, const char *slatepackAddress, const size_t slatepackAddressLength);

// Update Bulletproof challenge
STATIC void mimbleWimbleCoinUpdateBulletproofChallenge(uint8_t *challenge, const curve_point *leftPart, const curve_point *rightPart);

// Create scalars from ChaCha20
STATIC void mimbleWimbleCoinCreateScalarsFromChaCha20(bignum256 *firstScalar, bignum256 *secondScalar, const uint8_t *seed, const uint64_t index, const bool isPrivate);

// Use LR generator
STATIC void mimbleWimbleCoinUseLrGenerator(bignum256 *t0, bignum256 *t1, bignum256 *t2, const bignum256 *y, const bignum256 *z, const uint8_t *rewindNonce, const uint64_t value, const mp_obj_t updateProgressObject);

// Calculate Bulletproof components
STATIC bool mimbleWimbleCoinCalculateBulletproofComponents(uint8_t *tauX, uint8_t *tOne, uint8_t *tTwo, const uint64_t value, const uint8_t *blindingFactor, const uint8_t *commitment, const uint8_t *rewindNonce, const uint8_t *privateNonce, const uint8_t *message, const mp_obj_t updateProgressObject);

// Get MQS shared private key
STATIC bool mimbleWimbleCoinGetMqsSharedPrivateKey(uint8_t *mqsSharedPrivateKey, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index, const char *recipientAddress, const uint8_t *salt);

// Get X25519 private key from Ed25519 private key
STATIC bool mimbleWimbleCoinGetX25519PrivateKeyFromEd25519PrivateKey(uint8_t *x25519PrivateKey, const uint8_t *ed25519PrivateKey);

// Get X25519 public key from Ed25519 public key
STATIC bool mimbleWimbleCoinGetX25519PublicKeyFromEd25519PublicKey(uint8_t *x25519PublicKey, const uint8_t *ed25519PublicKey);

// Get Tor shared private key
STATIC bool mimbleWimbleCoinGetTorSharedPrivateKey(uint8_t *torSharedPrivateKey, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index, const char *recipientAddress);

// Get Slatepack shared private key
STATIC bool mimbleWimbleCoinGetSlatepackSharedPrivateKey(uint8_t *slatepackSharedPrivateKey, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index, const uint8_t *ephemeralX25519PublicKey, const uint8_t *encryptedFileKey, const uint8_t *payloadNonce);

// Create single-signer nonces
STATIC bool mimbleWimbleCoinCreateSingleSignerNonces(uint8_t *secretNonce, uint8_t *publicNonce);

// Update blinding factor sum
STATIC bool mimbleWimbleCoinUpdateBlindingFactorSum(uint8_t *blindingFactorSum, const uint8_t *blindingFactor, const bool blindingFactorIsPositive);

// Create single-signer signature
STATIC bool mimbleWimbleCoinCreateSingleSignerSignature(uint8_t *signature, const uint8_t *message, const uint8_t *privateKey, const uint8_t *secretNonce, const uint8_t *publicNonce, const uint8_t *publicKey);

// Get AES encrypted data length
STATIC size_t mimbleWimbleCoinGetAesEncryptedDataLength(const size_t dataLength);

// AES encrypt
STATIC bool mimbleWimbleCoinAesEncrypt(uint8_t *encryptedData, const uint8_t *key, const uint8_t *data, const size_t dataLength);

// AES decrypt
STATIC size_t mimbleWimbleCoinAesDecrypt(uint8_t *data, const uint8_t *key, const uint8_t *encryptedData, const size_t encryptedDataLength);

// Get payment proof message length
STATIC size_t mimbleWimbleCoinGetPaymentProofMessageLength(const mp_obj_t coinInfoObject, const uint64_t value, const char *senderAddress);

// Get payment proof message
STATIC bool mimbleWimbleCoinGetPaymentProofMessage(uint8_t *paymentProofMessage, const mp_obj_t coinInfoObject, uint64_t value, const uint8_t *kernelCommitment, const char *senderAddress);

// Verify payment proof message
STATIC bool mimbleWimbleCoinVerifyPaymentProofMessage(const uint8_t *paymentProofMessage, const size_t paymentProofMessageLength, const mp_obj_t coinInfoObject, const char *receiverAddress, const uint8_t *paymentProof, const size_t paymentProofLength);

// To hex string
STATIC void mimbleWimbleCoinToHexString(const uint8_t *data, const size_t length, char *string);

// Is zero
STATIC bool mimbleWimbleCoinIsZero(const uint8_t *data, const size_t length);

// Is valid secp256k1 public key
STATIC bool mimbleWimbleCoinIsValidSecp256k1PublicKey(const uint8_t *publicKey, const size_t publicKeyLength);

// Is valid X25519 public key
STATIC bool mimbleWimbleCoinIsValidX25519PublicKey(const uint8_t *publicKey, const size_t publicKeyLength);

// Is valid secp256k1 private key
STATIC bool mimbleWimbleCoinIsValidSecp256k1PrivateKey(const uint8_t *privateKey, const size_t privateKeyLength);

// Get MQS address
STATIC bool mimbleWimbleCoinGetMqsAddress(char *mqsAddress, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index);

// Get Tor address
STATIC bool mimbleWimbleCoinGetTorAddress(char *torAddress, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index);

// Get Slatepack address
STATIC bool mimbleWimbleCoinGetSlatepackAddress(char *slatepackAddress, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index);

// Is leap year
STATIC bool mimbleWimbleCoinIsLeapYear(const uint32_t year);

// Epoch to time
STATIC void mimbleWimbleCoinEpochToTime(MimbleWimbleCoinTime *time, const uint64_t epoch);

// Get login private key
STATIC bool mimbleWimbleCoinGetLoginPrivateKey(uint8_t *loginPrivateKey, const HDNode *extendedPrivateKey);


// Constants

// Default MQS challenge
STATIC const char MIMBLEWIMBLE_COIN_DEFAULT_MQS_CHALLENGE[] = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";

// Hex characters
STATIC const char MIMBLEWIMBLE_COIN_HEX_CHARACTERS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

// Generator H
STATIC const curve_point MIMBLEWIMBLE_COIN_GENERATOR_H = {
	.x = {0x0E803AC0, 0x1DFF74D6, 0x1B25B551, 0x14B41E51, 0x17A5E078, 0x05B01AF4, 0x0552DE2D, 0x0E983409, 0x0050929B},
	.y = {0x13A38904, 0x1861189F, 0x1D9A5A30, 0x158515E2, 0x1F40A36D, 0x11BE58DA, 0x09B81279, 0x10C72E72, 0x0031D3C6}
};

// Generator J
STATIC const curve_point MIMBLEWIMBLE_COIN_GENERATOR_J = {
	.x = {0x1621155F, 0x100C9C99, 0x0E62E34A, 0x09E936FC, 0x15A2F295, 0x029C1E8D, 0x0FCF085A, 0x0CF2BF80, 0x00B860F5},
	.y = {0x06C5C43A, 0x080D16E5, 0x13D5BF16, 0x0B4D34E9, 0x16A3165A, 0x013A01D2, 0x1D4D08FD, 0x1A659551, 0x00A43F09}
};

// Secp256k1 square root exponent
STATIC const bignum256 MIMBLEWIMBLE_COIN_SECP256k1_SQUARE_ROOT_EXPONENT = {
	.val = {0x1FFFFF0C, 0x1FFFFFFD, 0x1FFFFFFF, 0x1FFFFFFF, 0x1FFFFFFF, 0x1FFFFFFF, 0x1FFFFFFF, 0x1FFFFFFF, 0x003FFFFF}
};

// Address private key hash key
STATIC const char MIMBLEWIMBLE_COIN_ADDRESS_PRIVATE_KEY_HASH_KEY[] = {'G', 'r', 'i', 'n', 'b', 'o', 'x', '_', 's', 'e', 'e', 'd'};

// Tor base32 alphabet
STATIC const char *MIMBLEWIMBLE_COIN_TOR_BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

// Tor address checksum seed
STATIC const char MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SEED[] = {'.', 'o', 'n', 'i', 'o', 'n', ' ', 'c', 'h', 'e', 'c', 'k', 's', 'u', 'm'};

// Tor address version
STATIC const uint8_t MIMBLEWIMBLE_COIN_TOR_ADDRESS_VERSION = 3;

// MQS message part one
STATIC const char MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_ONE[] = {'{', '"', 'd', 'e', 's', 't', 'i', 'n', 'a', 't', 'i', 'o', 'n', '"', ':', '{', '"', 'p', 'u', 'b', 'l', 'i', 'c', '_', 'k', 'e', 'y', '"', ':', '"'};

// MQS message part two
STATIC const char MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_TWO[] = {'"', ',', '"', 'd', 'o', 'm', 'a', 'i', 'n', '"', ':', '"'};

// MQS message part three
STATIC const char MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_THREE[] = {'"', ',', '"', 'p', 'o', 'r', 't', '"', ':'};

// MQS message part four
STATIC const char MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_FOUR[] = {'}', ',', '"', 'n', 'o', 'n', 'c', 'e', '"', ':', '"'};

// MQS message part five
STATIC const char MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_FIVE[] = {'"', ',', '"', 's', 'a', 'l', 't', '"', ':', '"'};

// MQS message part six
STATIC const char MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_SIX[] = {'"', ',', '"', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'e', 'd', '_', 'm', 'e', 's', 's', 'a', 'g', 'e', '"', ':', '"'};

// MQS message part seven
STATIC const char MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_SEVEN[] = {'"', '}'};

// MQS message no port
STATIC const char MIMBLEWIMBLE_COIN_MQS_MESSAGE_NO_PORT[] = {'n', 'u', 'l', 'l'};

// Age wrap key info and counter
STATIC const char MIMBLEWIMBLE_COIN_AGE_WRAP_KEY_INFO_AND_COUNTER[] = {'a', 'g', 'e', '-', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n', '.', 'o', 'r', 'g', '/', 'v', '1', '/', 'X', '2', '5', '5', '1', '9', '\x01'};

// Age payload key info
STATIC const char MIMBLEWIMBLE_COIN_AGE_PAYLOAD_KEY_INFO_AND_COUNTER[] = {'p', 'a', 'y', 'l', 'o', 'a', 'd', '\x01'};

// Days since January first
STATIC const uint16_t MIMBLEWIMBLE_COIN_DAYS_SINCE_JANUARY_FIRST[2][MIMBLEWIMBLE_COIN_MONTHS_IN_A_YEAR + 1] = {

	// 365 days non-leap
	{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},

	// 366 days leap
	{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366},
};

// Address derivation type table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_table[] = {

	// MWC address derivation
	{MP_ROM_QSTR(MP_QSTR_MWC_ADDRESS_DERIVATION), MP_ROM_INT(MimbleWimbleCoinAddressDerivationType_MWC_ADDRESS_DERIVATION)},
	
	// GRIN address derivation
	{MP_ROM_QSTR(MP_QSTR_GRIN_ADDRESS_DERIVATION), MP_ROM_INT(MimbleWimbleCoinAddressDerivationType_GRIN_ADDRESS_DERIVATION)}
};

// Address derivation type dictionary
STATIC const MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_dictionary, mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_table);

// Address derivation type type
STATIC const mp_obj_type_t mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_type = {
	.base = {&mp_type_type},
	.name = MP_QSTR_AddressDerivationType,
	.locals_dict = (mp_obj_dict_t *)&mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_dictionary
};

// Payment proof message type table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_PaymentProofMessageType_table[] = {

	// ASCII payment proof message
	{MP_ROM_QSTR(MP_QSTR_ASCII_PAYMENT_PROOF_MESSAGE), MP_ROM_INT(MimbleWimbleCoinPaymentProofMessageType_ASCII_PAYMENT_PROOF_MESSAGE)},
	
	// Binary payment proof message
	{MP_ROM_QSTR(MP_QSTR_BINARY_PAYMENT_PROOF_MESSAGE), MP_ROM_INT(MimbleWimbleCoinPaymentProofMessageType_BINARY_PAYMENT_PROOF_MESSAGE)}
};

// Payment proof message type dictionary
STATIC const MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_PaymentProofMessageType_dictionary, mod_trezorcrypto_mimblewimble_coin_PaymentProofMessageType_table);

// Payment proof message type type
STATIC const mp_obj_type_t mod_trezorcrypto_mimblewimble_coin_PaymentProofMessageType_type = {
	.base = {&mp_type_type},
	.name = MP_QSTR_PaymentProofMessageType,
	.locals_dict = (mp_obj_dict_t *)&mod_trezorcrypto_mimblewimble_coin_PaymentProofMessageType_dictionary
};

// Payment proof address type table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_PaymentProofAddressType_table[] = {

	// MQS payment proof address
	{MP_ROM_QSTR(MP_QSTR_MQS_PAYMENT_PROOF_ADDRESS), MP_ROM_INT(MimbleWimbleCoinPaymentProofAddressType_MQS_PAYMENT_PROOF_ADDRESS)},
	
	// Tor payment proof address
	{MP_ROM_QSTR(MP_QSTR_TOR_PAYMENT_PROOF_ADDRESS), MP_ROM_INT(MimbleWimbleCoinPaymentProofAddressType_TOR_PAYMENT_PROOF_ADDRESS)},
	
	// Slatepack payment proof address
	{MP_ROM_QSTR(MP_QSTR_SLATEPACK_PAYMENT_PROOF_ADDRESS), MP_ROM_INT(MimbleWimbleCoinPaymentProofAddressType_SLATEPACK_PAYMENT_PROOF_ADDRESS)}
};

// Payment proof address type dictionary
STATIC const MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_PaymentProofAddressType_dictionary, mod_trezorcrypto_mimblewimble_coin_PaymentProofAddressType_table);

// Payment proof address type type
STATIC const mp_obj_type_t mod_trezorcrypto_mimblewimble_coin_PaymentProofAddressType_type = {
	.base = {&mp_type_type},
	.name = MP_QSTR_PaymentProofAddressType,
	.locals_dict = (mp_obj_dict_t *)&mod_trezorcrypto_mimblewimble_coin_PaymentProofAddressType_dictionary
};

// Slate encryption type table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_table[] = {

	// MQS slate encryption
	{MP_ROM_QSTR(MP_QSTR_MQS_SLATE_ENCRYPTION), MP_ROM_INT(MimbleWimbleCoinSlateEncryptionType_MQS_SLATE_ENCRYPTION)},
	
	// Tor slate encryption
	{MP_ROM_QSTR(MP_QSTR_TOR_SLATE_ENCRYPTION), MP_ROM_INT(MimbleWimbleCoinSlateEncryptionType_TOR_SLATE_ENCRYPTION)},
	
	// Slatepack slate encryption
	{MP_ROM_QSTR(MP_QSTR_SLATEPACK_SLATE_ENCRYPTION), MP_ROM_INT(MimbleWimbleCoinSlateEncryptionType_SLATEPACK_SLATE_ENCRYPTION)}
};

// Slate encryption type dictionary
STATIC const MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_dictionary, mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_table);

// Slate encryption type type
STATIC const mp_obj_type_t mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_type = {
	.base = {&mp_type_type},
	.name = MP_QSTR_SlateEncryptionType,
	.locals_dict = (mp_obj_dict_t *)&mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_dictionary
};

// Encrypting or decrypting state table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_EncryptingOrDecryptingState_table[] = {

	// Inactive state
	{MP_ROM_QSTR(MP_QSTR_INACTIVE_STATE), MP_ROM_INT(MimbleWimbleCoinEncryptingOrDecryptingState_INACTIVE_STATE)},
	
	// Ready state
	{MP_ROM_QSTR(MP_QSTR_READY_STATE), MP_ROM_INT(MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE)},
	
	// Active state
	{MP_ROM_QSTR(MP_QSTR_ACTIVE_STATE), MP_ROM_INT(MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE)},
	
	// Complete state
	{MP_ROM_QSTR(MP_QSTR_COMPLETE_STATE), MP_ROM_INT(MimbleWimbleCoinEncryptingOrDecryptingState_COMPLETE_STATE)}
};

// Encrypting or decrypting state dictionary
STATIC const MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_EncryptingOrDecryptingState_dictionary, mod_trezorcrypto_mimblewimble_coin_EncryptingOrDecryptingState_table);

// Encrypting or decrypting state type
STATIC const mp_obj_type_t mod_trezorcrypto_mimblewimble_coin_EncryptingOrDecryptingState_type = {
	.base = {&mp_type_type},
	.name = MP_QSTR_EncryptingOrDecryptingState,
	.locals_dict = (mp_obj_dict_t *)&mod_trezorcrypto_mimblewimble_coin_EncryptingOrDecryptingState_dictionary
};

// Kernel features table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_KernelFeatures_table[] = {

	// Plain features
	{MP_ROM_QSTR(MP_QSTR_PLAIN_FEATURES), MP_ROM_INT(MimbleWimbleCoinKernelFeatures_PLAIN_FEATURES)},
	
	// Coinbase features
	{MP_ROM_QSTR(MP_QSTR_COINBASE_FEATURES), MP_ROM_INT(MimbleWimbleCoinKernelFeatures_COINBASE_FEATURES)},
	
	// Height locked features
	{MP_ROM_QSTR(MP_QSTR_HEIGHT_LOCKED_FEATURES), MP_ROM_INT(MimbleWimbleCoinKernelFeatures_HEIGHT_LOCKED_FEATURES)},
	
	// No recent duplicate features
	{MP_ROM_QSTR(MP_QSTR_NO_RECENT_DUPLICATE_FEATURES), MP_ROM_INT(MimbleWimbleCoinKernelFeatures_NO_RECENT_DUPLICATE_FEATURES)}
};

// Kernel features dictionary
STATIC const MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_KernelFeatures_dictionary, mod_trezorcrypto_mimblewimble_coin_KernelFeatures_table);

// Kernel features type
STATIC const mp_obj_type_t mod_trezorcrypto_mimblewimble_coin_KernelFeatures_type = {
	.base = {&mp_type_type},
	.name = MP_QSTR_KernelFeatures,
	.locals_dict = (mp_obj_dict_t *)&mod_trezorcrypto_mimblewimble_coin_KernelFeatures_dictionary
};

// Get root public key function
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_getRootPublicKey_function, mod_trezorcrypto_mimblewimble_coin_getRootPublicKey);

// Get MQS address function
STATIC const MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_mimblewimble_coin_getMqsAddress_function, mod_trezorcrypto_mimblewimble_coin_getMqsAddress);

// Get Tor address function
STATIC const MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_mimblewimble_coin_getTorAddress_function, mod_trezorcrypto_mimblewimble_coin_getTorAddress);

// Get Slatepack address function
STATIC const MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_mimblewimble_coin_getSlatepackAddress_function, mod_trezorcrypto_mimblewimble_coin_getSlatepackAddress);

// Get seed cookie function
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_getSeedCookie_function, mod_trezorcrypto_mimblewimble_coin_getSeedCookie);

// Get commitment function
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_getCommitment_function, 4, 4, mod_trezorcrypto_mimblewimble_coin_getCommitment);

// Get Bulletproof components function
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_getBulletproofComponents_function, 5, 5, mod_trezorcrypto_mimblewimble_coin_getBulletproofComponents);

// Is valid MQS address domain
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_isValidMqsAddressDomain_function, mod_trezorcrypto_mimblewimble_coin_isValidMqsAddressDomain);

// Is valid MQS address
STATIC const MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_mimblewimble_coin_isValidMqsAddress_function, mod_trezorcrypto_mimblewimble_coin_isValidMqsAddress);

// Start MQS encryption
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_startMqsEncryption_function, 6, 6, mod_trezorcrypto_mimblewimble_coin_startMqsEncryption);

// Is valid Tor address
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_isValidTorAddress_function, mod_trezorcrypto_mimblewimble_coin_isValidTorAddress);

// Start Tor encryption
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_startTorEncryption_function, 5, 5, mod_trezorcrypto_mimblewimble_coin_startTorEncryption);

// Encrypt data
STATIC const MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_mimblewimble_coin_encryptData_function, mod_trezorcrypto_mimblewimble_coin_encryptData);

// Finish encryption
STATIC const MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_mimblewimble_coin_finishEncryption_function, mod_trezorcrypto_mimblewimble_coin_finishEncryption);

// Start MQS decryption
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_startMqsDecryption_function, 7, 7, mod_trezorcrypto_mimblewimble_coin_startMqsDecryption);

// Start Tor decryption
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_startTorDecryption_function, 6, 6, mod_trezorcrypto_mimblewimble_coin_startTorDecryption);

// Is valid X25519 public key
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_isValidX25519PublicKey_function, mod_trezorcrypto_mimblewimble_coin_isValidX25519PublicKey);

// Start Slatepack decryption
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_startSlatepackDecryption_function, 8, 8, mod_trezorcrypto_mimblewimble_coin_startSlatepackDecryption);

// Decrypt data
STATIC const MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_mimblewimble_coin_decryptData_function, mod_trezorcrypto_mimblewimble_coin_decryptData);

// Finish decryption
STATIC const MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_mimblewimble_coin_finishDecryption_function, mod_trezorcrypto_mimblewimble_coin_finishDecryption);

// Is valid Slatepack address
STATIC const MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_mimblewimble_coin_isValidSlatepackAddress_function, mod_trezorcrypto_mimblewimble_coin_isValidSlatepackAddress);

// Is zero
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_isZero_function, mod_trezorcrypto_mimblewimble_coin_isZero);

// Start transaction
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_startTransaction_function, 7, 7, mod_trezorcrypto_mimblewimble_coin_startTransaction);

// Include output in transaction
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_includeOutputInTransaction_function, 5, 5, mod_trezorcrypto_mimblewimble_coin_includeOutputInTransaction);

// Include input in transaction
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_includeInputInTransaction_function, 5, 5, mod_trezorcrypto_mimblewimble_coin_includeInputInTransaction);

// Is valid secp256k1 private key
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PrivateKey_function, mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PrivateKey);

// Apply offset to transaction
STATIC const MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_mimblewimble_coin_applyOffsetToTransaction_function, mod_trezorcrypto_mimblewimble_coin_applyOffsetToTransaction);

// Get transaction public key
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_getTransactionPublicKey_function, mod_trezorcrypto_mimblewimble_coin_getTransactionPublicKey);

// Get transaction public nonce
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_getTransactionPublicNonce_function, mod_trezorcrypto_mimblewimble_coin_getTransactionPublicNonce);

// Get transaction message signature
STATIC const MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_mimblewimble_coin_getTransactionMessageSignature_function, mod_trezorcrypto_mimblewimble_coin_getTransactionMessageSignature);

// Is valid secp256k1 public key
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PublicKey_function, mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PublicKey);

// Is valid commitment
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_isValidCommitment_function, mod_trezorcrypto_mimblewimble_coin_isValidCommitment);

// Verify transaction payment proof
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_verifyTransactionPaymentProof_function, 6, 6, mod_trezorcrypto_mimblewimble_coin_verifyTransactionPaymentProof);

// Finish transaction
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_finishTransaction_function, 8, 8, mod_trezorcrypto_mimblewimble_coin_finishTransaction);

// Get timestamp components
STATIC const MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_getTimestampComponents_function, mod_trezorcrypto_mimblewimble_coin_getTimestampComponents);

// Get MQS challenge signature
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_getMqsChallengeSignature_function, 4, 4, mod_trezorcrypto_mimblewimble_coin_getMqsChallengeSignature);

// Default MQS challenge string
STATIC const MP_DEFINE_STR_OBJ(mod_trezorcrypto_mimblewimble_coin_DEFAULT_MQS_CHALLENGE_string, MIMBLEWIMBLE_COIN_DEFAULT_MQS_CHALLENGE);

// Get login challenge signature
STATIC const MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_getLoginChallengeSignature_function, 3, 3, mod_trezorcrypto_mimblewimble_coin_getLoginChallengeSignature);

// Globals table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_globals_table[] = {

	// Name
	{MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_mimblewimble_coin)},
	
	// Encrypted transaction secret nonce size
	{MP_ROM_QSTR(MP_QSTR_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE)},
	
	// MQS address size
	{MP_ROM_QSTR(MP_QSTR_MQS_ADDRESS_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE)},
	
	// Tor address size
	{MP_ROM_QSTR(MP_QSTR_TOR_ADDRESS_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE)},
	
	// Slatepack address size without human-readable part
	{MP_ROM_QSTR(MP_QSTR_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART), MP_ROM_INT(MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART)},
	
	// Identifier depth index
	{MP_ROM_QSTR(MP_QSTR_IDENTIFIER_DEPTH_INDEX), MP_ROM_INT(MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX)},
	
	// Maximum identifier depth
	{MP_ROM_QSTR(MP_QSTR_MAXIMUM_IDENTIFIER_DEPTH), MP_ROM_INT(MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH)},
	
	// Identifier size
	{MP_ROM_QSTR(MP_QSTR_IDENTIFIER_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE)},
	
	// X25519 public key size
	{MP_ROM_QSTR(MP_QSTR_X25519_PUBLIC_KEY_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE)},
	
	// MQS encryption salt size
	{MP_ROM_QSTR(MP_QSTR_MQS_ENCRYPTION_SALT_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE)},
	
	// ChaCha20 nonce size
	{MP_ROM_QSTR(MP_QSTR_CHACHA20_NONCE_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE)},
	
	// ChaCha20 block size
	{MP_ROM_QSTR(MP_QSTR_CHACHA20_BLOCK_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_CHACHA20_BLOCK_SIZE)},
	
	// Poly1305 tag size
	{MP_ROM_QSTR(MP_QSTR_POLY1305_TAG_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_POLY1305_TAG_SIZE)},
	
	// Age payload nonce size
	{MP_ROM_QSTR(MP_QSTR_AGE_PAYLOAD_NONCE_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_AGE_PAYLOAD_NONCE_SIZE)},
	
	// Slatepack encryption encrypted file key size
	{MP_ROM_QSTR(MP_QSTR_SLATEPACK_ENCRYPTION_ENCRYPTED_FILE_KEY_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_SLATEPACK_ENCRYPTION_ENCRYPTED_FILE_KEY_SIZE)},
	
	// Address derivation type
	{MP_ROM_QSTR(MP_QSTR_AddressDerivationType), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_type)},
	
	// Payment proof message type
	{MP_ROM_QSTR(MP_QSTR_PaymentProofMessageType), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_PaymentProofMessageType_type)},
	
	// Payment proof address type
	{MP_ROM_QSTR(MP_QSTR_PaymentProofAddressType), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_PaymentProofAddressType_type)},
	
	// Slate encryption type
	{MP_ROM_QSTR(MP_QSTR_SlateEncryptionType), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_type)},
	
	// Encrypting or decrypting state
	{MP_ROM_QSTR(MP_QSTR_EncryptingOrDecryptingState), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_EncryptingOrDecryptingState_type)},
	
	// Kernel features
	{MP_ROM_QSTR(MP_QSTR_KernelFeatures), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_KernelFeatures_type)},
	
	// Encryption and decryption context size
	{MP_ROM_QSTR(MP_QSTR_ENCRYPTION_AND_DECRYPTION_CONTEXT_SIZE), MP_ROM_INT(sizeof(MimbleWimbleCoinEncryptionAndDecryptionContext))},
	
	// Encryption and decryption context coin type offset
	{MP_ROM_QSTR(MP_QSTR_ENCRYPTION_AND_DECRYPTION_CONTEXT_COIN_TYPE_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinEncryptionAndDecryptionContext, coinType))},
	
	// Encryption and decryption context network type offset
	{MP_ROM_QSTR(MP_QSTR_ENCRYPTION_AND_DECRYPTION_CONTEXT_NETWORK_TYPE_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinEncryptionAndDecryptionContext, networkType))},
	
	// Encryption and decryption context account offset
	{MP_ROM_QSTR(MP_QSTR_ENCRYPTION_AND_DECRYPTION_CONTEXT_ACCOUNT_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinEncryptionAndDecryptionContext, account))},
	
	// Encryption and decryption context encrypting state offset
	{MP_ROM_QSTR(MP_QSTR_ENCRYPTION_AND_DECRYPTION_CONTEXT_ENCRYPTING_STATE_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinEncryptionAndDecryptionContext, encryptingState))},
	
	// Encryption and decryption context decrypting state offset
	{MP_ROM_QSTR(MP_QSTR_ENCRYPTION_AND_DECRYPTION_CONTEXT_DECRYPTING_STATE_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinEncryptionAndDecryptionContext, decryptingState))},
	
	// Transaction context size
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_SIZE), MP_ROM_INT(sizeof(MimbleWimbleCoinTransactionContext))},
	
	// Transaction context coin type offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_COIN_TYPE_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, coinType))},
	
	// Transaction context network type offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_NETWORK_TYPE_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, networkType))},
	
	// Transaction context account offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_ACCOUNT_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, account))},
	
	// Transaction context send offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_SEND_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, send))},
	
	// Transaction context receive offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_RECEIVE_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, receive))},
	
	// Transaction context fee offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_FEE_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, fee))},
	
	// Transaction context remaining output offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_REMAINING_OUTPUT_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, remainingOutput))},
	
	// Transaction context remaining input offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_REMAINING_INPUT_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, remainingInput))},
	
	// Transaction context started offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_STARTED_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, started))},
	
	// Transaction context offset applied offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_OFFSET_APPLIED_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, offsetApplied))},
	
	// Transaction context message signed offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_MESSAGE_SIGNED_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, messageSigned))},
	
	// Transaction context address offset
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_ADDRESS_OFFSET), MP_ROM_INT(offsetof(MimbleWimbleCoinTransactionContext, address))},
	
	// Transaction context address size
	{MP_ROM_QSTR(MP_QSTR_TRANSACTION_CONTEXT_ADDRESS_SIZE), MP_ROM_INT(sizeof(((const MimbleWimbleCoinTransactionContext *)NULL)->address))},
	
	// Default MQS challenge
	{MP_ROM_QSTR(MP_QSTR_DEFAULT_MQS_CHALLENGE), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_DEFAULT_MQS_CHALLENGE_string)},
	
	// Get root public key
	{MP_ROM_QSTR(MP_QSTR_getRootPublicKey), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getRootPublicKey_function)},
	
	// Get MQS address
	{MP_ROM_QSTR(MP_QSTR_getMqsAddress), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getMqsAddress_function)},
	
	// Get Tor address
	{MP_ROM_QSTR(MP_QSTR_getTorAddress), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getTorAddress_function)},
	
	// Get Slatepack address
	{MP_ROM_QSTR(MP_QSTR_getSlatepackAddress), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getSlatepackAddress_function)},
	
	// Get seed cookie
	{MP_ROM_QSTR(MP_QSTR_getSeedCookie), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getSeedCookie_function)},
	
	// Get commitment
	{MP_ROM_QSTR(MP_QSTR_getCommitment), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getCommitment_function)},
	
	// Get Bulletproof components
	{MP_ROM_QSTR(MP_QSTR_getBulletproofComponents), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getBulletproofComponents_function)},
	
	// Is valid MQS address domain
	{MP_ROM_QSTR(MP_QSTR_isValidMqsAddressDomain), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_isValidMqsAddressDomain_function)},
	
	// Is valid MQS address
	{MP_ROM_QSTR(MP_QSTR_isValidMqsAddress), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_isValidMqsAddress_function)},
	
	// Start MQS encryption
	{MP_ROM_QSTR(MP_QSTR_startMqsEncryption), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_startMqsEncryption_function)},
	
	// Is valid Tor address
	{MP_ROM_QSTR(MP_QSTR_isValidTorAddress), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_isValidTorAddress_function)},
	
	// Start Tor encryption
	{MP_ROM_QSTR(MP_QSTR_startTorEncryption), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_startTorEncryption_function)},
	
	// Encrypt data
	{MP_ROM_QSTR(MP_QSTR_encryptData), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_encryptData_function)},
	
	// Finish encryption
	{MP_ROM_QSTR(MP_QSTR_finishEncryption), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_finishEncryption_function)},
	
	// Start MQS decryption
	{MP_ROM_QSTR(MP_QSTR_startMqsDecryption), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_startMqsDecryption_function)},

	// Start Tor decryption
	{MP_ROM_QSTR(MP_QSTR_startTorDecryption), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_startTorDecryption_function)},

	// Is valid X25519 public key
	{MP_ROM_QSTR(MP_QSTR_isValidX25519PublicKey), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_isValidX25519PublicKey_function)},

	// Start Slatepack decryption
	{MP_ROM_QSTR(MP_QSTR_startSlatepackDecryption), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_startSlatepackDecryption_function)},
	
	// Decrypt data
	{MP_ROM_QSTR(MP_QSTR_decryptData), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_decryptData_function)},
	
	// Finish decryption
	{MP_ROM_QSTR(MP_QSTR_finishDecryption), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_finishDecryption_function)},
	
	// Is valid Slatepack address
	{MP_ROM_QSTR(MP_QSTR_isValidSlatepackAddress), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_isValidSlatepackAddress_function)},
	
	// Is zero
	{MP_ROM_QSTR(MP_QSTR_isZero), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_isZero_function)},
	
	// Start transaction
	{MP_ROM_QSTR(MP_QSTR_startTransaction), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_startTransaction_function)},
	
	// Include output in transaction
	{MP_ROM_QSTR(MP_QSTR_includeOutputInTransaction), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_includeOutputInTransaction_function)},
	
	// Include input in transaction
	{MP_ROM_QSTR(MP_QSTR_includeInputInTransaction), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_includeInputInTransaction_function)},
	
	// Is valid secp256k1 private key
	{MP_ROM_QSTR(MP_QSTR_isValidSecp256k1PrivateKey), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PrivateKey_function)},
	
	// Apply offset to transaction
	{MP_ROM_QSTR(MP_QSTR_applyOffsetToTransaction), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_applyOffsetToTransaction_function)},
	
	// Get transaction public key
	{MP_ROM_QSTR(MP_QSTR_getTransactionPublicKey), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getTransactionPublicKey_function)},
	
	// Get transaction public nonce
	{MP_ROM_QSTR(MP_QSTR_getTransactionPublicNonce), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getTransactionPublicNonce_function)},
	
	// Get transaction message signature
	{MP_ROM_QSTR(MP_QSTR_getTransactionMessageSignature), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getTransactionMessageSignature_function)},
	
	// Is valid secp256k1 public key
	{MP_ROM_QSTR(MP_QSTR_isValidSecp256k1PublicKey), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PublicKey_function)},
	
	// Is valid commitment
	{MP_ROM_QSTR(MP_QSTR_isValidCommitment), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_isValidCommitment_function)},
	
	// Verify transaction payment proof
	{MP_ROM_QSTR(MP_QSTR_verifyTransactionPaymentProof), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_verifyTransactionPaymentProof_function)},
	
	// Finish transaction
	{MP_ROM_QSTR(MP_QSTR_finishTransaction), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_finishTransaction_function)},
	
	// Get timestamp components
	{MP_ROM_QSTR(MP_QSTR_getTimestampComponents), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getTimestampComponents_function)},
	
	// Get MQS challenge signature
	{MP_ROM_QSTR(MP_QSTR_getMqsChallengeSignature), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getMqsChallengeSignature_function)},
	
	// Get login challenge signature
	{MP_ROM_QSTR(MP_QSTR_getLoginChallengeSignature), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getLoginChallengeSignature_function)}
};

// Globals dictionary
STATIC const MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_globals_dictionary, mod_trezorcrypto_mimblewimble_coin_globals_table);

// Module
STATIC const mp_obj_module_t mod_trezorcrypto_mimblewimble_coin_module = {
	.base = {&mp_type_module},
	.globals = (mp_obj_dict_t *)&mod_trezorcrypto_mimblewimble_coin_globals_dictionary
};


// Supporting function implementation

// Get root public key
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getRootPublicKey(mp_obj_t extendedPrivateKeyObject) {

	// Get extended private key
	HDNode *extendedPrivateKey = &((mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Set root public key to the extended private key's public key
	const mp_obj_t rootPublicKey = mp_obj_new_bytearray(sizeof(extendedPrivateKey->public_key), extendedPrivateKey->public_key);
	
	// Clear extended private key's public key
	memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Return root public key
	return rootPublicKey;
}

// Get MQS address
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getMqsAddress(const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject, const mp_obj_t indexObject) {

	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Initialize MQS address
	vstr_t mqsAddress;
	vstr_init_len(&mqsAddress, MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE);
	
	// Check if getting MQS address failed
	if(!mimbleWimbleCoinGetMqsAddress(mqsAddress.buf, extendedPrivateKey, coinInfoObject, index)) {
	
		// Free MQS address
		vstr_clear(&mqsAddress);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Return MQS address
	return mp_obj_new_str_from_vstr(&mp_type_str, &mqsAddress);
}

// Get Tor address
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTorAddress(const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject, const mp_obj_t indexObject) {

	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Initialize Tor address
	vstr_t torAddress;
	vstr_init_len(&torAddress, MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE);
	
	// Check if getting Tor address failed
	if(!mimbleWimbleCoinGetTorAddress(torAddress.buf, extendedPrivateKey, coinInfoObject, index)) {
	
		// Free Tor address
		vstr_clear(&torAddress);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Return Tor address
	return mp_obj_new_str_from_vstr(&mp_type_str, &torAddress);
}

// Get Slatepack address
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getSlatepackAddress(const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject, const mp_obj_t indexObject) {

	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get currency's Slatepack address human-readable part
	mp_buffer_info_t slatepackAddressHumanReadablePart;
	mp_get_buffer(mp_load_attr(coinInfoObject, MP_QSTR_slatepackAddressHumanReadablePart), &slatepackAddressHumanReadablePart, MP_BUFFER_READ);
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Initialize Slatepack address
	vstr_t slatepackAddress;
	vstr_init_len(&slatepackAddress, MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + slatepackAddressHumanReadablePart.len);
	
	// Check if getting Slatepack address failed
	if(!mimbleWimbleCoinGetSlatepackAddress(slatepackAddress.buf, extendedPrivateKey, coinInfoObject, index)) {
	
		// Free Slatepack address
		vstr_clear(&slatepackAddress);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Return Slatepack address
	return mp_obj_new_str_from_vstr(&mp_type_str, &slatepackAddress);
}

// Get seed cookie
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getSeedCookie(mp_obj_t extendedPrivateKeyObject) {

	// Get extended private key
	HDNode *extendedPrivateKey = &((mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Initialize seed cookie
	vstr_t seedCookie;
	vstr_init(&seedCookie, SHA512_DIGEST_LENGTH);
	seedCookie.len = SHA512_DIGEST_LENGTH;
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Free seed cookie
		vstr_clear(&seedCookie);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Set seed cookie to the hash of the extended private key's public key
	sha512_Raw(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key), (uint8_t *)seedCookie.buf);
	
	// Clear extended private key's public key
	memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Return seed cookie
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &seedCookie);
}

// Get commitment
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getCommitment(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *const arguments) {

	// Get arguments
	const mp_obj_t extendedPrivateKeyObject = arguments[0];
	const mp_obj_t valueObject = arguments[1];
	const mp_obj_t identifierObject = arguments[2];
	const mp_obj_t switchTypeObject = arguments[3];
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get value
	const uint64_t value = trezor_obj_get_uint64(valueObject);
	
	// Get identifier
	mp_buffer_info_t identifier;
	mp_get_buffer(identifierObject, &identifier, MP_BUFFER_READ);
	
	// Initialize commitment
	vstr_t commitment;
	vstr_init(&commitment, MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE);
	commitment.len = MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE;
	
	// Get identifier depth
	const uint8_t identifierDepth = ((const uint8_t *)identifier.buf)[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &((const uint8_t *)identifier.buf)[sizeof(identifierDepth)], MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE - sizeof(identifierDepth));
	
	// Check if little endian
	#if BYTE_ORDER == LITTLE_ENDIAN
	
		// Go through all parts of the identifier path
		for(size_t i = 0; i < sizeof(identifierPath) / sizeof(identifierPath[0]); ++i) {
		
			// Make part little endian
			REVERSE32(identifierPath[i], identifierPath[i]);
		}
	#endif
	
	// Check if deriving blinding factor failed
	uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
	if(!mimbleWimbleCoinDeriveBlindingFactor(blindingFactor, extendedPrivateKey, value, identifierPath, identifierDepth, switchTypeObject)) {
	
		// Free commitment
		vstr_clear(&commitment);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if commiting value failed
	if(!mimbleWimbleCoinCommitValue((uint8_t *)commitment.buf, value, blindingFactor, true)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free commitment
		vstr_clear(&commitment);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Return commitment
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &commitment);
}

// Get Bulletproof components
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getBulletproofComponents(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *arguments) {

	// Get arguments
	mp_obj_t extendedPrivateKeyObject = arguments[0];
	const mp_obj_t valueObject = arguments[1];
	const mp_obj_t identifierObject = arguments[2];
	const mp_obj_t switchTypeObject = arguments[3];
	const mp_obj_t updateProgressObject = arguments[4];
	
	// Get extended private key
	HDNode *extendedPrivateKey = &((mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get value
	const uint64_t value = trezor_obj_get_uint64(valueObject);
	
	// Get identifier
	mp_buffer_info_t identifier;
	mp_get_buffer(identifierObject, &identifier, MP_BUFFER_READ);
	
	// Initialize tau x
	vstr_t tauX;
	vstr_init(&tauX, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE);
	tauX.len = MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE;
	
	// Initialize t one
	vstr_t tOne;
	vstr_init(&tOne, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	tOne.len = MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE;
	
	// Initialize t two
	vstr_t tTwo;
	vstr_init(&tTwo, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	tTwo.len = MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE;
	
	// Initialize result
	mp_obj_tuple_t *result = MP_OBJ_TO_PTR(mp_obj_new_tuple(3, NULL));
	
	// Get identifier depth
	const uint8_t identifierDepth = ((const uint8_t *)identifier.buf)[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &((const uint8_t *)identifier.buf)[sizeof(identifierDepth)], MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE - sizeof(identifierDepth));
	
	// Check if little endian
	#if BYTE_ORDER == LITTLE_ENDIAN
	
		// Go through all parts of the identifier path
		for(size_t i = 0; i < sizeof(identifierPath) / sizeof(identifierPath[0]); ++i) {
		
			// Make part little endian
			REVERSE32(identifierPath[i], identifierPath[i]);
		}
	#endif
	
	// Check if deriving blinding factor failed
	uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
	if(!mimbleWimbleCoinDeriveBlindingFactor(blindingFactor, extendedPrivateKey, value, identifierPath, identifierDepth, switchTypeObject)) {
	
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if commiting value failed
	uint8_t commitment[MIMBLEWIMBLE_COIN_UNCOMPRESSED_COMMITMENT_SIZE];
	if(!mimbleWimbleCoinCommitValue(commitment, value, blindingFactor, false)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if getting private hash as the hash of the extended private key's private key failed
	uint8_t privateHash[MIMBLEWIMBLE_COIN_SCALAR_SIZE];
	if(blake2b(extendedPrivateKey->private_key, sizeof(extendedPrivateKey->private_key), privateHash, sizeof(privateHash))) {
	
		// Clear private hash
		memzero(privateHash, sizeof(privateHash));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if getting private nonce as the hash of the private hash and commitment failed
	uint8_t privateNonce[MIMBLEWIMBLE_COIN_SCALAR_SIZE];
	if(blake2b_Key(privateHash, sizeof(privateHash), commitment, MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE, privateNonce, sizeof(privateNonce))) {
	
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear private hash
		memzero(privateHash, sizeof(privateHash));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear private hash
	memzero(privateHash, sizeof(privateHash));
	
	// Check if private nonce isn't a valid secp256k1 private key
	if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(privateNonce, sizeof(privateNonce))) {
	
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if getting rewind hash as the hash of the extended private key's public key failed
	uint8_t rewindHash[MIMBLEWIMBLE_COIN_SCALAR_SIZE];
	if(blake2b(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key), rewindHash, sizeof(rewindHash))) {
	
		// Clear rewind hash
		memzero(rewindHash, sizeof(rewindHash));
		
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear extended private key's public key
	memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Check if getting rewind nonce as the hash of the rewind hash and commitment failed
	uint8_t rewindNonce[MIMBLEWIMBLE_COIN_SCALAR_SIZE];
	if(blake2b_Key(rewindHash, sizeof(rewindHash), commitment, MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE, rewindNonce, sizeof(rewindNonce))) {
	
		// Clear rewind hash
		memzero(rewindHash, sizeof(rewindHash));
		
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear rewind hash
	memzero(rewindHash, sizeof(rewindHash));
	
	// Check if rewind nonce isn't a valid secp256k1 private key
	if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(rewindNonce, sizeof(rewindNonce))) {
	
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Create message
	uint8_t message[MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_SIZE] = {
	
		// Switch type
		[MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_SWITCH_TYPE_INDEX] = mp_obj_get_int(switchTypeObject)
	};
	memcpy(&message[MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_IDENTIFIER_INDEX], identifier.buf, MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE);
	
	// Check if calculating Bulletproof components failed
	if(!mimbleWimbleCoinCalculateBulletproofComponents((uint8_t *)tauX.buf, (uint8_t *)tOne.buf, (uint8_t *)tTwo.buf, value, blindingFactor, commitment, rewindNonce, privateNonce, message, updateProgressObject)) {
	
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Free tau x
		vstr_clear(&tauX);
		
		// Free tau one
		vstr_clear(&tOne);
		
		// Free t two
		vstr_clear(&tTwo);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear private nonce
	memzero(privateNonce, sizeof(privateNonce));
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Return tau x, t one, and t two
	result->items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &tauX);
	result->items[1] = mp_obj_new_str_from_vstr(&mp_type_bytes, &tOne);
	result->items[2] = mp_obj_new_str_from_vstr(&mp_type_bytes, &tTwo);
	return MP_OBJ_FROM_PTR(result);
}

// Is valid MQS address domain
mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidMqsAddressDomain(const mp_obj_t mqsAddressDomainObject) {

	// Get MQS address domain
	mp_buffer_info_t mqsAddressDomain;
	mp_get_buffer(mqsAddressDomainObject, &mqsAddressDomain, MP_BUFFER_READ);
	
	// Check if MQS address domain is empty
	if(!mqsAddressDomain.len) {
	
		// Return false
		return mp_const_false;
	}
	
	// Go through all characters in the MQS address domain
	for(size_t i = 0; i < mqsAddressDomain.len; ++i) {
	
		// Check if character isn't alphanumeric or a period not as the first or last character
		if(!isalnum((int)((const char *)mqsAddressDomain.buf)[i]) && (((const char *)mqsAddressDomain.buf)[i] != '.' || i == 0 || i == mqsAddressDomain.len - 1)) {
		
			// Check if at the MQS address domain's port, not at the first or last character, and not following a period
			if(((const char *)mqsAddressDomain.buf)[i] == ':' && i != 0 && i != mqsAddressDomain.len - 1 && ((const char *)mqsAddressDomain.buf)[i - 1] != '.') {
			
				// Set port to zero
				unsigned int port = 0;
				
				// Go through the remaining characters in the MQS address domain
				for(size_t j = i + 1; j < mqsAddressDomain.len; ++j) {
				
					// Check if character isn't a digit or a zero at the first character
					if(!isdigit((int)((const char *)mqsAddressDomain.buf)[j]) || (((const char *)mqsAddressDomain.buf)[j] == '0' && j == i + 1)) {
					
						// Return false;
						return mp_const_false;
					}
					
					// Update port with character
					port *= 10;
					port += ((const char *)mqsAddressDomain.buf)[j] - '0';
					
					// Check if port is invalid
					if(port > UINT16_MAX) {
					
						// Return false
						return mp_const_false;
					}
				}
				
				// Break
				break;
			}
			
			// Otherwise
			else {
			
				// Return false;
				return mp_const_false;
			}
		}
	}
	
	// Return true
	return mp_const_true;
}

// Is valid MQS address
mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidMqsAddress(const mp_obj_t mqsAddressObject, const mp_obj_t coinInfoObject) {

	// Get MQS address
	mp_buffer_info_t mqsAddress;
	mp_get_buffer(mqsAddressObject, &mqsAddress, MP_BUFFER_READ);
	
	// Return if getting the public key from the MQS address was successful
	return mimbleWimbleCoinGetPublicKeyFromMqsAddress(NULL, coinInfoObject, mqsAddress.buf, mqsAddress.len) ? mp_const_true : mp_const_false;
}

// Start MQS encryption
mp_obj_t mod_trezorcrypto_mimblewimble_coin_startMqsEncryption(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *arguments) {

	// Get arguments
	mp_obj_t encryptionAndDecryptionContextObject = arguments[0];
	const mp_obj_t extendedPrivateKeyObject = arguments[1];
	const mp_obj_t coinInfoObject = arguments[2];
	const mp_obj_t indexObject = arguments[3];
	const mp_obj_t recipientAddressObject = arguments[4];
	const mp_obj_t recipientAddressDomainObject = arguments[5];
	
	// Get encryption and decryption context
	mp_buffer_info_t encryptionAndDecryptionContext;
	mp_get_buffer(encryptionAndDecryptionContextObject, &encryptionAndDecryptionContext, MP_BUFFER_RW);
	
	// Copy encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext workingEncryptionAndDecryptionContext;
	memcpy(&workingEncryptionAndDecryptionContext, encryptionAndDecryptionContext.buf, encryptionAndDecryptionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Get recipient address
	mp_buffer_info_t recipientAddress;
	mp_get_buffer(recipientAddressObject, &recipientAddress, MP_BUFFER_READ);
	
	// Get recipient address domain
	mp_buffer_info_t recipientAddressDomain;
	if(recipientAddressDomainObject != mp_const_none) {
		mp_get_buffer(recipientAddressDomainObject, &recipientAddressDomain, MP_BUFFER_READ);
	}
	
	// Initialize nonce
	vstr_t nonce;
	vstr_init(&nonce, MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE);
	nonce.len = MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE;
	
	// Initialize salt
	vstr_t salt;
	vstr_init(&salt, MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE);
	salt.len = MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE;
	
	// Initialize result
	mp_obj_tuple_t *result = MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
	
	// Create random salt
	random_buffer((uint8_t *)salt.buf, MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE);
	
	// Check if getting MQS shared private key failed
	uint8_t mqsSharedPrivateKey[MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE];
	if(!mimbleWimbleCoinGetMqsSharedPrivateKey(mqsSharedPrivateKey, extendedPrivateKey, coinInfoObject, index, recipientAddress.buf, (const uint8_t *)salt.buf)) {
	
		// Clear salt
		memzero(salt.buf, MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE);
		
		// Free nonce
		vstr_clear(&nonce);
		
		// Free salt
		vstr_clear(&salt);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Create random nonce
	random_buffer((uint8_t *)nonce.buf, MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE);
	
	// Initialize working encryption and decryption context's ChaCha20 Poly1305 context with the MQS shared private key and nonce
	rfc7539_init(&workingEncryptionAndDecryptionContext.chaCha20Poly1305Context, mqsSharedPrivateKey, (const uint8_t *)nonce.buf);
	
	// Clear MQS shared private key
	memzero(mqsSharedPrivateKey, sizeof(mqsSharedPrivateKey));
	
	// Initialize working encryption and decryption context's message hash context
	sha256_Init(&workingEncryptionAndDecryptionContext.messageHashContext);
	
	// Set working encryption and decryption context's message hash context initialized
	workingEncryptionAndDecryptionContext.messageHashContextInitialized = true;
	
	// Add MQS message part one to the working encryption and decryption context's message hash context
	sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_ONE, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_ONE));
	
	// Add recipient address to the working encryption and decryption context's message hash context
	sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)recipientAddress.buf, MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE);
	
	// Add MQS message part two to the working encryption and decryption context's message hash context
	sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_TWO, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_TWO));
	
	// Check if recipient address has a domain
	if(recipientAddressDomainObject != mp_const_none) {
	
		// Get recipient address domain port
		const char *recipientAddressDomainPort = memchr(recipientAddressDomain.buf, ':', recipientAddressDomain.len);
		
		// Check if recipient address domain has a port
		if(recipientAddressDomainPort) {
		
			// Add recipient address domain without port to the working encryption and decryption context's message hash context
			sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)recipientAddressDomain.buf, recipientAddressDomainPort - (const char *)recipientAddressDomain.buf);
			
			// Add MQS message part three to the working encryption and decryption context's message hash context
			sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_THREE, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_THREE));
			
			// Add recipient address domain port to the working encryption and decryption context's message hash context
			sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)&recipientAddressDomainPort[sizeof((char)':')], recipientAddressDomain.len - (recipientAddressDomainPort - (const char *)recipientAddressDomain.buf + sizeof((char)':')));
		}
		
		// Otherwise
		else {
		
			// Add recipient address domain to the working encryption and decryption context's message hash context
			sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)recipientAddressDomain.buf, recipientAddressDomain.len);
			
			// Add MQS message part three to the working encryption and decryption context's message hash context
			sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_THREE, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_THREE));
			
			// Add MQS message no port to the working encryption and decryption context's message hash context
			sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_NO_PORT, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_NO_PORT));
		}
	}
	
	// Otherwise
	else {
	
		// Add MQS message part three to the working encryption and decryption context's message hash context
		sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_THREE, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_THREE));
		
		// Add MQS message no port to the working encryption and decryption context's message hash context
		sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_NO_PORT, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_NO_PORT));
	}
	
	// Add MQS message part four to the working encryption and decryption context's message hash context
	sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_FOUR, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_FOUR));
	
	// Add nonce to the working encryption and decryption context's message hash context
	char nonceBuffer[MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE];
	mimbleWimbleCoinToHexString((const uint8_t *)nonce.buf, MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE, nonceBuffer);
	sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)nonceBuffer, sizeof(nonceBuffer));
	
	// Add MQS message part five to the working encryption and decryption context's message hash context
	sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_FIVE, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_FIVE));
	
	// Add salt to the working encryption and decryption context's message hash context
	char saltBuffer[MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE];
	mimbleWimbleCoinToHexString((const uint8_t *)salt.buf, MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE, saltBuffer);
	sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)saltBuffer, sizeof(saltBuffer));
	
	// Add MQS message part six to the working encryption and decryption context's message hash context
	sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_SIX, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_SIX));
	
	// Set working encryption and decryption context's index
	workingEncryptionAndDecryptionContext.index = index;
	
	// Set working encryption and decryption context's encrypting state to ready
	workingEncryptionAndDecryptionContext.encryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Update encryption and decryption context
	memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Clear working encryption and decryption context
	memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Return nonce and salt
	result->items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &nonce);
	result->items[1] = mp_obj_new_str_from_vstr(&mp_type_bytes, &salt);
	return MP_OBJ_FROM_PTR(result);
}

// Is valid Tor address
mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidTorAddress(const mp_obj_t torAddressObject) {

	// Get Tor address
	mp_buffer_info_t torAddress;
	mp_get_buffer(torAddressObject, &torAddress, MP_BUFFER_READ);
	
	// Return if getting the public key from the Tor address was successful
	return mimbleWimbleCoinGetPublicKeyFromTorAddress(NULL, torAddress.buf, torAddress.len) ? mp_const_true : mp_const_false;
}

// Start Tor encryption
mp_obj_t mod_trezorcrypto_mimblewimble_coin_startTorEncryption(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *arguments) {

	// Get arguments
	mp_obj_t encryptionAndDecryptionContextObject = arguments[0];
	const mp_obj_t extendedPrivateKeyObject = arguments[1];
	const mp_obj_t coinInfoObject = arguments[2];
	const mp_obj_t indexObject = arguments[3];
	const mp_obj_t recipientAddressObject = arguments[4];
	
	// Get encryption and decryption context
	mp_buffer_info_t encryptionAndDecryptionContext;
	mp_get_buffer(encryptionAndDecryptionContextObject, &encryptionAndDecryptionContext, MP_BUFFER_RW);
	
	// Copy encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext workingEncryptionAndDecryptionContext;
	memcpy(&workingEncryptionAndDecryptionContext, encryptionAndDecryptionContext.buf, encryptionAndDecryptionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Get recipient address
	mp_buffer_info_t recipientAddress;
	mp_get_buffer(recipientAddressObject, &recipientAddress, MP_BUFFER_READ);
	
	// Initialize nonce
	vstr_t nonce;
	vstr_init(&nonce, MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE);
	nonce.len = MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE;
	
	// Check if getting Tor shared private key failed
	uint8_t torSharedPrivateKey[MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE];
	if(!mimbleWimbleCoinGetTorSharedPrivateKey(torSharedPrivateKey, extendedPrivateKey, coinInfoObject, index, recipientAddress.buf)) {
	
		// Free nonce
		vstr_clear(&nonce);
		
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Create random nonce
	random_buffer((uint8_t *)nonce.buf, MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE);
	
	// Initialize working encryption and decryption context's ChaCha20 Poly1305 context with the Tor shared private key and nonce
	rfc7539_init(&workingEncryptionAndDecryptionContext.chaCha20Poly1305Context, torSharedPrivateKey, (const uint8_t *)nonce.buf);
	
	// Clear Tor shared private key
	memzero(torSharedPrivateKey, sizeof(torSharedPrivateKey));
	
	// Set working encryption and decryption context's index
	workingEncryptionAndDecryptionContext.index = index;
	
	// Set working encryption and decryption context's encrypting state to ready
	workingEncryptionAndDecryptionContext.encryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Update encryption and decryption context
	memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Clear working encryption and decryption context
	memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Return nonce
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &nonce);
}

// Encrypt data
mp_obj_t mod_trezorcrypto_mimblewimble_coin_encryptData(mp_obj_t encryptionAndDecryptionContextObject, const mp_obj_t dataObject) {

	// Get encryption and decryption context
	mp_buffer_info_t encryptionAndDecryptionContext;
	mp_get_buffer(encryptionAndDecryptionContextObject, &encryptionAndDecryptionContext, MP_BUFFER_RW);
	
	// Copy encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext workingEncryptionAndDecryptionContext;
	memcpy(&workingEncryptionAndDecryptionContext, encryptionAndDecryptionContext.buf, encryptionAndDecryptionContext.len);
	
	// Get data
	mp_buffer_info_t data;
	mp_get_buffer(dataObject, &data, MP_BUFFER_READ);
	
	// Initialize encrypted data
	vstr_t encryptedData;
	vstr_init(&encryptedData, data.len);
	encryptedData.len = data.len;
	
	// Check if data length or block counter will overflow
	if((size_t)UINT64_MAX - workingEncryptionAndDecryptionContext.dataLength < data.len || workingEncryptionAndDecryptionContext.chaCha20Poly1305Context.chacha20.input[MIMBLEWIMBLE_COIN_CHACHA20_BLOCK_COUNTER_INDEX] == UINT32_MAX) {
	
		// Free encrypted data
		vstr_clear(&encryptedData);
		
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Encrypt data
	chacha20poly1305_encrypt(&workingEncryptionAndDecryptionContext.chaCha20Poly1305Context, data.buf, (uint8_t *)encryptedData.buf, data.len);
	
	// Update working encryption and decryption context's data length
	workingEncryptionAndDecryptionContext.dataLength += data.len;
	
	// Check if the working encryption and decryption context's message hash context is initialized
	if(workingEncryptionAndDecryptionContext.messageHashContextInitialized) {
	
		// Add encrypted data to the working encryption and decryption context's message hash context
		char encryptedDataBuffer[data.len * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE];
		mimbleWimbleCoinToHexString((const uint8_t *)encryptedData.buf, data.len, encryptedDataBuffer);
		sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)encryptedDataBuffer, sizeof(encryptedDataBuffer));
	}
	
	// Check if at the last data
	if(data.len < MIMBLEWIMBLE_COIN_CHACHA20_BLOCK_SIZE) {
	
		// Set working encryption and decryption context's encrypting state to complete
		workingEncryptionAndDecryptionContext.encryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_COMPLETE_STATE;
	}
	
	// Otherwise
	else {
	
		// Set working encryption and decryption context's encrypting state to active
		workingEncryptionAndDecryptionContext.encryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE;
	}
	
	// Update encryption and decryption context
	memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Clear working encryption and decryption context
	memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Return encrypted data
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &encryptedData);
}

// Finish encryption
mp_obj_t mod_trezorcrypto_mimblewimble_coin_finishEncryption(mp_obj_t encryptionAndDecryptionContextObject, const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject) {

	// Get encryption and decryption context
	mp_buffer_info_t encryptionAndDecryptionContext;
	mp_get_buffer(encryptionAndDecryptionContextObject, &encryptionAndDecryptionContext, MP_BUFFER_RW);
	
	// Copy encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext workingEncryptionAndDecryptionContext;
	memcpy(&workingEncryptionAndDecryptionContext, encryptionAndDecryptionContext.buf, encryptionAndDecryptionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Initialize nonce
	vstr_t tag;
	vstr_init(&tag, MIMBLEWIMBLE_COIN_POLY1305_TAG_SIZE);
	tag.len = MIMBLEWIMBLE_COIN_POLY1305_TAG_SIZE;
	
	// Initialize MQS message signature
	vstr_t mqsMessageSignature;
	if(workingEncryptionAndDecryptionContext.messageHashContextInitialized) {
		vstr_init(&mqsMessageSignature, MIMBLEWIMBLE_COIN_MAXIMUM_DER_SIGNATURE_SIZE);
	}
	
	// Initialize result
	mp_obj_tuple_t *result = MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
	
	// Get encrypted data tag
	rfc7539_finish(&workingEncryptionAndDecryptionContext.chaCha20Poly1305Context, 0, workingEncryptionAndDecryptionContext.dataLength, (uint8_t *)tag.buf);
	
	// Check if the working encryption and decryption context's message hash context is initialized
	if(workingEncryptionAndDecryptionContext.messageHashContextInitialized) {
	
		// Add tag to the working encryption and decryption context's message hash context
		char tagBuffer[MIMBLEWIMBLE_COIN_POLY1305_TAG_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE];
		mimbleWimbleCoinToHexString((const uint8_t *)tag.buf, MIMBLEWIMBLE_COIN_POLY1305_TAG_SIZE, tagBuffer);
		sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)tagBuffer, sizeof(tagBuffer));
		
		// Add MQS message part seven to the working encryption and decryption context's message hash context
		sha256_Update(&workingEncryptionAndDecryptionContext.messageHashContext, (const uint8_t *)MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_SEVEN, sizeof(MIMBLEWIMBLE_COIN_MQS_MESSAGE_PART_SEVEN));
		
		// Get MQS message's hash
		uint8_t mqsMessageHash[SHA256_DIGEST_LENGTH];
		sha256_Final(&workingEncryptionAndDecryptionContext.messageHashContext, mqsMessageHash);
		
		// Check if getting address private key failed
		uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE];
		if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, workingEncryptionAndDecryptionContext.index, SECP256K1_NAME)) {
		
			// Free tag
			vstr_clear(&tag);
			
			// Free MQS message signature
			vstr_clear(&mqsMessageSignature);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working encryption and decryption context
			memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
		// Check if getting signature of the MQS message failed
		uint8_t signature[MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE];
		if(ecdsa_sign_digest(&secp256k1, addressPrivateKey, mqsMessageHash, signature, NULL, NULL)) {
		
			// Clear address private key
			memzero(addressPrivateKey, sizeof(addressPrivateKey));
			
			// Free tag
			vstr_clear(&tag);
			
			// Free MQS message signature
			vstr_clear(&mqsMessageSignature);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working encryption and decryption context
			memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Get signature in DER format
		mqsMessageSignature.len = ecdsa_sig_to_der(signature, (uint8_t *)mqsMessageSignature.buf);
		
		// Update encryption and decryption context
		memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Return tag and MQS message signature
		result->items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &tag);
		result->items[1] = mp_obj_new_str_from_vstr(&mp_type_bytes, &mqsMessageSignature);
		return MP_OBJ_FROM_PTR(result);
	}
	
	// Otherwise
	else {
	
		// Update encryption and decryption context
		memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Return tag
		result->items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &tag);
		result->items[1] = mp_const_none;
		return MP_OBJ_FROM_PTR(result);
	}
}

// Start MQS decryption
mp_obj_t mod_trezorcrypto_mimblewimble_coin_startMqsDecryption(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *arguments) {

	// Get arguments
	mp_obj_t encryptionAndDecryptionContextObject = arguments[0];
	const mp_obj_t extendedPrivateKeyObject = arguments[1];
	const mp_obj_t coinInfoObject = arguments[2];
	const mp_obj_t indexObject = arguments[3];
	const mp_obj_t senderAddressObject = arguments[4];
	const mp_obj_t nonceObject = arguments[5];
	const mp_obj_t saltObject = arguments[6];
	
	// Get encryption and decryption context
	mp_buffer_info_t encryptionAndDecryptionContext;
	mp_get_buffer(encryptionAndDecryptionContextObject, &encryptionAndDecryptionContext, MP_BUFFER_RW);
	
	// Copy encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext workingEncryptionAndDecryptionContext;
	memcpy(&workingEncryptionAndDecryptionContext, encryptionAndDecryptionContext.buf, encryptionAndDecryptionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Get sender address
	mp_buffer_info_t senderAddress;
	mp_get_buffer(senderAddressObject, &senderAddress, MP_BUFFER_READ);
	
	// Get nonce
	mp_buffer_info_t nonce;
	mp_get_buffer(nonceObject, &nonce, MP_BUFFER_READ);
	
	// Get salt
	mp_buffer_info_t salt;
	mp_get_buffer(saltObject, &salt, MP_BUFFER_READ);
	
	// Check if getting MQS shared private key failed
	uint8_t mqsSharedPrivateKey[MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE];
	if(!mimbleWimbleCoinGetMqsSharedPrivateKey(mqsSharedPrivateKey, extendedPrivateKey, coinInfoObject, index, senderAddress.buf, salt.buf)) {
	
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Initialize working encryption and decryption context's ChaCha20 Poly1305 context with the MQS shared private key and nonce
	rfc7539_init(&workingEncryptionAndDecryptionContext.chaCha20Poly1305Context, mqsSharedPrivateKey, nonce.buf);
	
	// Clear MQS shared private key
	memzero(mqsSharedPrivateKey, sizeof(mqsSharedPrivateKey));
	
	// Create random working encryption and decryption context's AES key
	random_buffer(workingEncryptionAndDecryptionContext.aesKey, sizeof(workingEncryptionAndDecryptionContext.aesKey));
	
	// Set working encryption and decryption context's decrypting state to ready
	workingEncryptionAndDecryptionContext.decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Update encryption and decryption context
	memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Clear working encryption and decryption context
	memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));

	// Return none
	return mp_const_none;
}

// Start Tor decryption
mp_obj_t mod_trezorcrypto_mimblewimble_coin_startTorDecryption(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *arguments) {

	// Get arguments
	mp_obj_t encryptionAndDecryptionContextObject = arguments[0];
	const mp_obj_t extendedPrivateKeyObject = arguments[1];
	const mp_obj_t coinInfoObject = arguments[2];
	const mp_obj_t indexObject = arguments[3];
	const mp_obj_t senderAddressObject = arguments[4];
	const mp_obj_t nonceObject = arguments[5];
	
	// Get encryption and decryption context
	mp_buffer_info_t encryptionAndDecryptionContext;
	mp_get_buffer(encryptionAndDecryptionContextObject, &encryptionAndDecryptionContext, MP_BUFFER_RW);
	
	// Copy encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext workingEncryptionAndDecryptionContext;
	memcpy(&workingEncryptionAndDecryptionContext, encryptionAndDecryptionContext.buf, encryptionAndDecryptionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Get sender address
	mp_buffer_info_t senderAddress;
	mp_get_buffer(senderAddressObject, &senderAddress, MP_BUFFER_READ);
	
	// Get nonce
	mp_buffer_info_t nonce;
	mp_get_buffer(nonceObject, &nonce, MP_BUFFER_READ);
	
	// Check if getting Tor shared private key failed
	uint8_t torSharedPrivateKey[MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE];
	if(!mimbleWimbleCoinGetTorSharedPrivateKey(torSharedPrivateKey, extendedPrivateKey, coinInfoObject, index, senderAddress.buf)) {
	
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Initialize working encryption and decryption context's ChaCha20 Poly1305 context with the Tor shared private key and nonce
	rfc7539_init(&workingEncryptionAndDecryptionContext.chaCha20Poly1305Context, torSharedPrivateKey, nonce.buf);
	
	// Clear Tor shared private key
	memzero(torSharedPrivateKey, sizeof(torSharedPrivateKey));
	
	// Create random working encryption and decryption context's AES key
	random_buffer(workingEncryptionAndDecryptionContext.aesKey, sizeof(workingEncryptionAndDecryptionContext.aesKey));
	
	// Set working encryption and decryption context's decrypting state to ready
	workingEncryptionAndDecryptionContext.decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Update encryption and decryption context
	memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Clear working encryption and decryption context
	memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Return none
	return mp_const_none;
}

// Is valid X25519 public key
mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidX25519PublicKey(const mp_obj_t x25519PublicKeyObject) {

	// Get X25519 public key
	mp_buffer_info_t x25519PublicKey;
	mp_get_buffer(x25519PublicKeyObject, &x25519PublicKey, MP_BUFFER_READ);
	
	// Return if X25519 public key is a valid X25519 public key
	return mimbleWimbleCoinIsValidX25519PublicKey(x25519PublicKey.buf, x25519PublicKey.len) ? mp_const_true : mp_const_false;
}

// Start Slatepack decryption
mp_obj_t mod_trezorcrypto_mimblewimble_coin_startSlatepackDecryption(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *arguments) {

	// Get arguments
	mp_obj_t encryptionAndDecryptionContextObject = arguments[0];
	const mp_obj_t extendedPrivateKeyObject = arguments[1];
	const mp_obj_t coinInfoObject = arguments[2];
	const mp_obj_t indexObject = arguments[3];
	const mp_obj_t ephemeralX25519PublicKeyObject = arguments[4];
	const mp_obj_t nonceObject = arguments[5];
	const mp_obj_t encryptedFileKeyObject = arguments[6];
	const mp_obj_t payloadNonceObject = arguments[7];
	
	// Get encryption and decryption context
	mp_buffer_info_t encryptionAndDecryptionContext;
	mp_get_buffer(encryptionAndDecryptionContextObject, &encryptionAndDecryptionContext, MP_BUFFER_RW);
	
	// Copy encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext workingEncryptionAndDecryptionContext;
	memcpy(&workingEncryptionAndDecryptionContext, encryptionAndDecryptionContext.buf, encryptionAndDecryptionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Get ephemeral X25519 public key
	mp_buffer_info_t ephemeralX25519PublicKey;
	mp_get_buffer(ephemeralX25519PublicKeyObject, &ephemeralX25519PublicKey, MP_BUFFER_READ);
	
	// Get nonce
	mp_buffer_info_t nonce;
	mp_get_buffer(nonceObject, &nonce, MP_BUFFER_READ);
	
	// Get encrypted file key
	mp_buffer_info_t encryptedFileKey;
	mp_get_buffer(encryptedFileKeyObject, &encryptedFileKey, MP_BUFFER_READ);
	
	// Get payload nonce
	mp_buffer_info_t payloadNonce;
	mp_get_buffer(payloadNonceObject, &payloadNonce, MP_BUFFER_READ);
	
	// Check if getting Slatepack shared private key failed
	uint8_t slatepackSharedPrivateKey[MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE];
	if(!mimbleWimbleCoinGetSlatepackSharedPrivateKey(slatepackSharedPrivateKey, extendedPrivateKey, coinInfoObject, index, ephemeralX25519PublicKey.buf, encryptedFileKey.buf, payloadNonce.buf)) {
	
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Initialize working encryption and decryption context's ChaCha20 Poly1305 context with the Slatepack shared private key and nonce
	rfc7539_init(&workingEncryptionAndDecryptionContext.chaCha20Poly1305Context, slatepackSharedPrivateKey, nonce.buf);
	
	// Clear Slatepack shared private key
	memzero(slatepackSharedPrivateKey, sizeof(slatepackSharedPrivateKey));
	
	// Create random working encryption and decryption context's AES key
	random_buffer(workingEncryptionAndDecryptionContext.aesKey, sizeof(workingEncryptionAndDecryptionContext.aesKey));
	
	// Set working encryption and decryption context's decrypting state to ready
	workingEncryptionAndDecryptionContext.decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Update encryption and decryption context
	memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Clear working encryption and decryption context
	memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Return none
	return mp_const_none;
}

// Decrypt data
mp_obj_t mod_trezorcrypto_mimblewimble_coin_decryptData(mp_obj_t encryptionAndDecryptionContextObject, const mp_obj_t encryptedDataObject) {

	// Get encryption and decryption context
	mp_buffer_info_t encryptionAndDecryptionContext;
	mp_get_buffer(encryptionAndDecryptionContextObject, &encryptionAndDecryptionContext, MP_BUFFER_RW);
	
	// Copy encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext workingEncryptionAndDecryptionContext;
	memcpy(&workingEncryptionAndDecryptionContext, encryptionAndDecryptionContext.buf, encryptionAndDecryptionContext.len);
	
	// Get encrypted data
	mp_buffer_info_t encryptedData;
	mp_get_buffer(encryptedDataObject, &encryptedData, MP_BUFFER_READ);
	
	// Initialize data
	vstr_t data;
	vstr_init(&data, mimbleWimbleCoinGetAesEncryptedDataLength(encryptedData.len));
	data.len = mimbleWimbleCoinGetAesEncryptedDataLength(encryptedData.len);
	
	// Check if data length or block counter will overflow
	if((size_t)UINT64_MAX - workingEncryptionAndDecryptionContext.dataLength < encryptedData.len || workingEncryptionAndDecryptionContext.chaCha20Poly1305Context.chacha20.input[MIMBLEWIMBLE_COIN_CHACHA20_BLOCK_COUNTER_INDEX] == UINT32_MAX) {
	
		// Free data
		vstr_clear(&data);
		
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Decrypt data
	uint8_t decryptedData[encryptedData.len];
	chacha20poly1305_decrypt(&workingEncryptionAndDecryptionContext.chaCha20Poly1305Context, encryptedData.buf, decryptedData, sizeof(decryptedData));
	
	// Update working encryption and decryption context's data length
	workingEncryptionAndDecryptionContext.dataLength += encryptedData.len;
	
	// Check if at the last data
	if(encryptedData.len < MIMBLEWIMBLE_COIN_CHACHA20_BLOCK_SIZE) {
	
		// Set working encryption and decryption context's decrypting state to complete
		workingEncryptionAndDecryptionContext.decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_COMPLETE_STATE;
	}
	
	// Otherwise
	else {
	
		// Set working encryption and decryption context's decrypting state to active
		workingEncryptionAndDecryptionContext.decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE;
	}
	
	// Check if AES encrypting the decrypted data with the working encryption and decryption context's AES key failed
	if(!mimbleWimbleCoinAesEncrypt((uint8_t *)data.buf, workingEncryptionAndDecryptionContext.aesKey, decryptedData, sizeof(decryptedData))) {
	
		// Clear decrypted data
		memzero(decryptedData, sizeof(decryptedData));
		
		// Free data
		vstr_clear(&data);
		
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear decrypted data
	memzero(decryptedData, sizeof(decryptedData));
	
	// Update encryption and decryption context
	memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Clear working encryption and decryption context
	memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Return data
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &data);
}

// Finish decryption
mp_obj_t mod_trezorcrypto_mimblewimble_coin_finishDecryption(mp_obj_t encryptionAndDecryptionContextObject, const mp_obj_t tagObject) {

	// Get encryption and decryption context
	mp_buffer_info_t encryptionAndDecryptionContext;
	mp_get_buffer(encryptionAndDecryptionContextObject, &encryptionAndDecryptionContext, MP_BUFFER_RW);
	
	// Copy encryption and decryption context
	MimbleWimbleCoinEncryptionAndDecryptionContext workingEncryptionAndDecryptionContext;
	memcpy(&workingEncryptionAndDecryptionContext, encryptionAndDecryptionContext.buf, encryptionAndDecryptionContext.len);
	
	// Get tag
	mp_buffer_info_t tag;
	mp_get_buffer(tagObject, &tag, MP_BUFFER_READ);
	
	// Initialize AES key
	vstr_t aesKey;
	vstr_init(&aesKey, MIMBLEWIMBLE_COIN_AES_KEY_SIZE);
	aesKey.len = MIMBLEWIMBLE_COIN_AES_KEY_SIZE;
	
	// Get decrypted data tags
	uint8_t decryptedDataTag[MIMBLEWIMBLE_COIN_POLY1305_TAG_SIZE];
	rfc7539_finish(&workingEncryptionAndDecryptionContext.chaCha20Poly1305Context, 0, workingEncryptionAndDecryptionContext.dataLength, decryptedDataTag);
	
	// Check if tag is invalid
	if(!mimbleWimbleCoinIsEqual(tag.buf, decryptedDataTag, sizeof(decryptedDataTag))) {
	
		// Clear decrypted data tag
		memzero(decryptedDataTag, sizeof(decryptedDataTag));
		
		// Free AES key
		vstr_clear(&aesKey);
		
		// Clear working encryption and decryption context
		memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear decrypted data tag
	memzero(decryptedDataTag, sizeof(decryptedDataTag));
	
	// Set AES key to the working encryption and decryption context's AES key
	memcpy(aesKey.buf, workingEncryptionAndDecryptionContext.aesKey, sizeof(workingEncryptionAndDecryptionContext.aesKey));
	
	// Update encryption and decryption context
	memcpy(encryptionAndDecryptionContext.buf, &workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Clear working encryption and decryption context
	memzero(&workingEncryptionAndDecryptionContext, sizeof(workingEncryptionAndDecryptionContext));
	
	// Return AES key
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &aesKey);
}

// Is valid Slatepack address
mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidSlatepackAddress(const mp_obj_t slatepackAddressObject, const mp_obj_t coinInfoObject) {

	// Get Slatepack address
	mp_buffer_info_t slatepackAddress;
	mp_get_buffer(slatepackAddressObject, &slatepackAddress, MP_BUFFER_READ);
	
	// Return if getting the public key from the Slatepack address was successful
	return mimbleWimbleCoinGetPublicKeyFromSlatepackAddress(NULL, coinInfoObject, slatepackAddress.buf, slatepackAddress.len) ? mp_const_true : mp_const_false;
}

// Is zero
mp_obj_t mod_trezorcrypto_mimblewimble_coin_isZero(const mp_obj_t dataObject) {

	// Get data
	mp_buffer_info_t data;
	mp_get_buffer(dataObject, &data, MP_BUFFER_READ);
	
	// Return if data is zero
	return mimbleWimbleCoinIsZero(data.buf, data.len) ? mp_const_true : mp_const_false;
}

// Start transaction
mp_obj_t mod_trezorcrypto_mimblewimble_coin_startTransaction(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *arguments) {

	// Get arguments
	mp_obj_t transactionContextObject = arguments[0];
	const mp_obj_t indexObject = arguments[1];
	const mp_obj_t outputObject = arguments[2];
	const mp_obj_t inputObject = arguments[3];
	const mp_obj_t feeObject = arguments[4];
	const mp_obj_t secretNonceIndexObject = arguments[5];
	const mp_obj_t addressObject = arguments[6];
	
	// Get transaction context
	mp_buffer_info_t transactionContext;
	mp_get_buffer(transactionContextObject, &transactionContext, MP_BUFFER_RW);
	
	// Copy transaction context
	MimbleWimbleCoinTransactionContext workingTransactionContext;
	memcpy(&workingTransactionContext, transactionContext.buf, transactionContext.len);
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Get output
	const uint64_t output = trezor_obj_get_uint64(outputObject);
	
	// Get input
	const uint64_t input = trezor_obj_get_uint64(inputObject);
	
	// Get fee
	const uint64_t fee = trezor_obj_get_uint64(feeObject);
	
	// Get secret nonce index
	const uint32_t secretNonceIndex = mp_obj_get_int(secretNonceIndexObject);
	
	// Get address
	mp_buffer_info_t address;
	if(addressObject != mp_const_none) {
		mp_get_buffer(addressObject, &address, MP_BUFFER_READ);
	}
	
	// Check if an input exists
	if(input) {
	
		// Set working transaction context's remaining input
		workingTransactionContext.remainingInput = input + fee;
		
		// Set working transaction context's send
		workingTransactionContext.send = input - output;
		
		// Set working transaction context's secret nonce index
		workingTransactionContext.secretNonceIndex = secretNonceIndex;
	}
	
	// Otherwise
	else {
	
		// Check if creating working transaction context's secret nonce failed
		if(!mimbleWimbleCoinCreateSingleSignerNonces(workingTransactionContext.secretNonce, NULL)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
		// Set working transaction context's receive
		workingTransactionContext.receive = output;
	}
	
	// Set working transaction context's index
	workingTransactionContext.index = index;
	
	// Set working transaction context's remaining output
	workingTransactionContext.remainingOutput = output;
	
	// Set working transaction context's fee
	workingTransactionContext.fee = fee;
	
	// Check if address exists
	if(addressObject != mp_const_none) {
	
		// Set working transaction context's address
		memcpy(workingTransactionContext.address, address.buf, address.len);
	}
	
	// Set that working transaction context has been started
	workingTransactionContext.started = true;
	
	// Update transaction context
	memcpy(transactionContext.buf, &workingTransactionContext, sizeof(workingTransactionContext));
	
	// Clear working transaction context
	memzero(&workingTransactionContext, sizeof(workingTransactionContext));
	
	// Return none
	return mp_const_none;
}

// Include output in transaction
mp_obj_t mod_trezorcrypto_mimblewimble_coin_includeOutputInTransaction(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *arguments) {

	// Get arguments
	mp_obj_t transactionContextObject = arguments[0];
	const mp_obj_t extendedPrivateKeyObject = arguments[1];
	const mp_obj_t valueObject = arguments[2];
	const mp_obj_t identifierObject = arguments[3];
	const mp_obj_t switchTypeObject = arguments[4];
	
	// Get transaction context
	mp_buffer_info_t transactionContext;
	mp_get_buffer(transactionContextObject, &transactionContext, MP_BUFFER_RW);
	
	// Copy transaction context
	MimbleWimbleCoinTransactionContext workingTransactionContext;
	memcpy(&workingTransactionContext, transactionContext.buf, transactionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get value
	const uint64_t value = trezor_obj_get_uint64(valueObject);
	
	// Get identifier
	mp_buffer_info_t identifier;
	mp_get_buffer(identifierObject, &identifier, MP_BUFFER_READ);
	
	// Get identifier depth
	const uint8_t identifierDepth = ((const uint8_t *)identifier.buf)[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &((const uint8_t *)identifier.buf)[sizeof(identifierDepth)], MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE - sizeof(identifierDepth));
	
	// Check if little endian
	#if BYTE_ORDER == LITTLE_ENDIAN
	
		// Go through all parts of the identifier path
		for(size_t i = 0; i < sizeof(identifierPath) / sizeof(identifierPath[0]); ++i) {
		
			// Make part little endian
			REVERSE32(identifierPath[i], identifierPath[i]);
		}
	#endif
	
	// Check if deriving blinding factor failed
	uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
	if(!mimbleWimbleCoinDeriveBlindingFactor(blindingFactor, extendedPrivateKey, value, identifierPath, identifierDepth, switchTypeObject)) {
	
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if updating the transaction's blinding factor failed
	if(!mimbleWimbleCoinUpdateBlindingFactorSum(workingTransactionContext.blindingFactor, blindingFactor, true)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Remove value from the working transaction context's remaining output
	workingTransactionContext.remainingOutput -= value;
	
	// Update transaction context
	memcpy(transactionContext.buf, &workingTransactionContext, sizeof(workingTransactionContext));
	
	// Clear working transaction context
	memzero(&workingTransactionContext, sizeof(workingTransactionContext));
	
	// Return none
	return mp_const_none;
}

// Include input in transaction
mp_obj_t mod_trezorcrypto_mimblewimble_coin_includeInputInTransaction(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *arguments) {

	// Get arguments
	mp_obj_t transactionContextObject = arguments[0];
	const mp_obj_t extendedPrivateKeyObject = arguments[1];
	const mp_obj_t valueObject = arguments[2];
	const mp_obj_t identifierObject = arguments[3];
	const mp_obj_t switchTypeObject = arguments[4];
	
	// Get transaction context
	mp_buffer_info_t transactionContext;
	mp_get_buffer(transactionContextObject, &transactionContext, MP_BUFFER_RW);
	
	// Copy transaction context
	MimbleWimbleCoinTransactionContext workingTransactionContext;
	memcpy(&workingTransactionContext, transactionContext.buf, transactionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get value
	const uint64_t value = trezor_obj_get_uint64(valueObject);
	
	// Get identifier
	mp_buffer_info_t identifier;
	mp_get_buffer(identifierObject, &identifier, MP_BUFFER_READ);
	
	// Get identifier depth
	const uint8_t identifierDepth = ((const uint8_t *)identifier.buf)[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &((const uint8_t *)identifier.buf)[sizeof(identifierDepth)], MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE - sizeof(identifierDepth));
	
	// Check if little endian
	#if BYTE_ORDER == LITTLE_ENDIAN
	
		// Go through all parts of the identifier path
		for(size_t i = 0; i < sizeof(identifierPath) / sizeof(identifierPath[0]); ++i) {
		
			// Make part little endian
			REVERSE32(identifierPath[i], identifierPath[i]);
		}
	#endif
	
	// Check if deriving blinding factor failed
	uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
	if(!mimbleWimbleCoinDeriveBlindingFactor(blindingFactor, extendedPrivateKey, value, identifierPath, identifierDepth, switchTypeObject)) {
	
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if updating the transaction's blinding factor failed
	if(!mimbleWimbleCoinUpdateBlindingFactorSum(workingTransactionContext.blindingFactor, blindingFactor, false)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Remove value from the working transaction context's remaining input
	workingTransactionContext.remainingInput -= value;
	
	// Update transaction context
	memcpy(transactionContext.buf, &workingTransactionContext, sizeof(workingTransactionContext));
	
	// Clear working transaction context
	memzero(&workingTransactionContext, sizeof(workingTransactionContext));
	
	// Return none
	return mp_const_none;
}

// Is valid secp256k1 private key
mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PrivateKey(const mp_obj_t privateKeyObject) {

	// Get private key
	mp_buffer_info_t privateKey;
	mp_get_buffer(privateKeyObject, &privateKey, MP_BUFFER_READ);
	
	// Return if private key is a valid secp256k1 private key
	return mimbleWimbleCoinIsValidSecp256k1PrivateKey(privateKey.buf, privateKey.len) ? mp_const_true : mp_const_false;
}

// Apply offset to transaction
mp_obj_t mod_trezorcrypto_mimblewimble_coin_applyOffsetToTransaction(mp_obj_t transactionContextObject, const mp_obj_t offsetObject) {

	// Import storage module
	const mp_obj_t storageModule = mp_import_name(qstr_from_str("apps.mimblewimble_coin.storage"), mp_const_empty_tuple, MP_OBJ_NEW_SMALL_INT(0));
	
	// Get transaction context
	mp_buffer_info_t transactionContext;
	mp_get_buffer(transactionContextObject, &transactionContext, MP_BUFFER_RW);
	
	// Copy transaction context
	MimbleWimbleCoinTransactionContext workingTransactionContext;
	memcpy(&workingTransactionContext, transactionContext.buf, transactionContext.len);
	
	// Get offset
	mp_buffer_info_t offset;
	mp_get_buffer(offsetObject, &offset, MP_BUFFER_READ);
	
	// Initialize secret nonce index
	mp_obj_t secretNonceIndex = mp_const_none;
	
	// Check if updating the working transaction's blinding factor failed
	if(!mimbleWimbleCoinUpdateBlindingFactorSum(workingTransactionContext.blindingFactor, offset.buf, false)) {
	
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Set that working transaction context's offset was applied
	workingTransactionContext.offsetApplied = true;
	
	// Check if working transaction context is sending
	if(workingTransactionContext.send) {
	
		// Check if working transaction context doesn't have a secret nonce index
		if(!workingTransactionContext.secretNonceIndex) {
		
			// Check if creating working transaction context's secret nonce failed
			if(!mimbleWimbleCoinCreateSingleSignerNonces(workingTransactionContext.secretNonce, NULL)) {
			
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Check if AES encrypting the working transaction context's secret nonce with the working transaction context's blinding factor failed
			uint8_t encryptedTransactionSecretNonce[MIMBLEWIMBLE_COIN_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE];
			if(!mimbleWimbleCoinAesEncrypt(encryptedTransactionSecretNonce, workingTransactionContext.blindingFactor, workingTransactionContext.secretNonce, sizeof(workingTransactionContext.secretNonce))) {
			
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Check if the encrypted transaction secret nonce is invalid
			if(mimbleWimbleCoinIsZero(encryptedTransactionSecretNonce, sizeof(encryptedTransactionSecretNonce))) {
			
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			
			// Check if getting current transaction secret nonce index from storage failed
			const mp_obj_t currentTransactionSecretNonceIndexObject = mp_call_function_0(mp_load_attr(storageModule, MP_QSTR_getCurrentTransactionSecretNonceIndex));
			if(currentTransactionSecretNonceIndexObject == mp_const_false) {
			
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Check if saving the encrypted transaction secret nonce at the current transaction secret nonce index in storage failed
			const mp_obj_str_t encryptedTransactionSecretNonceObject = {{&mp_type_bytes}, 0, sizeof(encryptedTransactionSecretNonce), encryptedTransactionSecretNonce};
			if(mp_call_function_2(mp_load_attr(storageModule, MP_QSTR_setTransactionSecretNonce), MP_OBJ_FROM_PTR(&encryptedTransactionSecretNonceObject), currentTransactionSecretNonceIndexObject) == mp_const_false) {
			
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Set working transaction context's secret nonce index
			workingTransactionContext.secretNonceIndex = mp_obj_get_int(currentTransactionSecretNonceIndexObject) + 1;
			
			// Check if incrementing current transaction secret nonce index in storage failed
			if(mp_call_function_0(mp_load_attr(storageModule, MP_QSTR_incrementCurrentTransactionSecretNonceIndex)) == mp_const_false) {
			
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Set secret nonce index to the working transaction context's secret nonce index
			secretNonceIndex = MP_OBJ_NEW_SMALL_INT(workingTransactionContext.secretNonceIndex);
		}
		
		// Otherwise
		else {
		
			// Check if getting the encrypted transaction secret nonce at the working transaction context's secret nonce index from storage failed
			const mp_obj_t encryptedTransactionSecretNonceObject = mp_call_function_1(mp_load_attr(storageModule, MP_QSTR_getTransactionSecretNonce), MP_OBJ_NEW_SMALL_INT(workingTransactionContext.secretNonceIndex - 1));
			if(encryptedTransactionSecretNonceObject == mp_const_false) {
			
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Get encrypted transaction secret nonce
			mp_buffer_info_t encryptedTransactionSecretNonce;
			mp_get_buffer(encryptedTransactionSecretNonceObject, &encryptedTransactionSecretNonce, MP_BUFFER_READ);
			
			// Check if encrypted transaction secret nonce is invalid
			if(mimbleWimbleCoinIsZero(encryptedTransactionSecretNonce.buf, encryptedTransactionSecretNonce.len)) {
			
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Check if AES decrypting the encrypted transaction secret nonce with the working transaction context's blinding factor failed
			uint8_t transactionSecretNonce[encryptedTransactionSecretNonce.len];
			const size_t transactionSecretNonceLength = mimbleWimbleCoinAesDecrypt(transactionSecretNonce, workingTransactionContext.blindingFactor, encryptedTransactionSecretNonce.buf, encryptedTransactionSecretNonce.len);
			if(!transactionSecretNonceLength) {
			
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Check if transaction secret nonce length is invalid
			if(transactionSecretNonceLength != sizeof(workingTransactionContext.secretNonce)) {
			
				// Clear transaction secret nonce
				memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Set working transaction context's secret nonce to the transaction secret nonce
			memcpy(workingTransactionContext.secretNonce, transactionSecretNonce, transactionSecretNonceLength);
			
			// Clear transaction secret nonce
			memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
		}
	}
	
	// Update transaction context
	memcpy(transactionContext.buf, &workingTransactionContext, sizeof(workingTransactionContext));
	
	// Clear working transaction context
	memzero(&workingTransactionContext, sizeof(workingTransactionContext));
	
	// Return secret nonce index
	return secretNonceIndex;
}

// Get transaction public key
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTransactionPublicKey(const mp_obj_t transactionContextObject) {

	// Get transaction context
	mp_buffer_info_t transactionContext;
	mp_get_buffer(transactionContextObject, &transactionContext, MP_BUFFER_READ);
	
	// Initialize public key
	vstr_t publicKey;
	vstr_init(&publicKey, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	publicKey.len = MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE;
	
	// Check if getting the pubic key of the transaction context's blinding factor failed
	if(!mimbleWimbleCoinGetPublicKeyFromSecp256k1PrivateKey((uint8_t *)publicKey.buf, ((const MimbleWimbleCoinTransactionContext *)transactionContext.buf)->blindingFactor)) {
	
		// Free public key
		vstr_clear(&publicKey);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Return public key
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &publicKey);
}

// Get transaction public nonce
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTransactionPublicNonce(const mp_obj_t transactionContextObject) {

	// Get transaction context
	mp_buffer_info_t transactionContext;
	mp_get_buffer(transactionContextObject, &transactionContext, MP_BUFFER_READ);
	
	// Initialize public nonce
	vstr_t publicNonce;
	vstr_init(&publicNonce, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	publicNonce.len = MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE;
	
	// Check if getting the pubic key of the transaction context's secret nonce failed
	if(!mimbleWimbleCoinGetPublicKeyFromSecp256k1PrivateKey((uint8_t *)publicNonce.buf, ((const MimbleWimbleCoinTransactionContext *)transactionContext.buf)->secretNonce)) {
	
		// Free public nonce
		vstr_clear(&publicNonce);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Return public nonce
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &publicNonce);
}

// Get transaction message signature
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTransactionMessageSignature(mp_obj_t transactionContextObject, const mp_obj_t messageObject) {

	// Get transaction context
	mp_buffer_info_t transactionContext;
	mp_get_buffer(transactionContextObject, &transactionContext, MP_BUFFER_RW);
	
	// Copy transaction context
	MimbleWimbleCoinTransactionContext workingTransactionContext;
	memcpy(&workingTransactionContext, transactionContext.buf, transactionContext.len);
	
	// Get message
	mp_buffer_info_t message;
	mp_get_buffer(messageObject, &message, MP_BUFFER_READ);
	
	// Initialize message signature
	vstr_t messageSignature;
	vstr_init(&messageSignature, MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE);
	messageSignature.len = MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE;
	
	// Check if getting message hash failed
	uint8_t messageHash[MIMBLEWIMBLE_COIN_SINGLE_SIGNER_MESSAGE_SIZE];
	if(blake2b((const uint8_t *)message.buf, message.len, messageHash, sizeof(messageHash))) {
			
		// Free message signature
		vstr_clear(&messageSignature);
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if getting the public key of the working transaction context's blinding factor failed
	uint8_t publicKey[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	if(!mimbleWimbleCoinGetPublicKeyFromSecp256k1PrivateKey(publicKey, workingTransactionContext.blindingFactor)) {
	
		// Free message signature
		vstr_clear(&messageSignature);
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Loop while secret nonce is the same as the working transaction context's secret nonce
	uint8_t secretNonce[MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE];
	uint8_t publicNonce[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	do {
	
		// Check if creating secret nonce and public nonce failed
		if(!mimbleWimbleCoinCreateSingleSignerNonces(secretNonce, publicNonce)) {
		
			// Free message signature
			vstr_clear(&messageSignature);
			
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
	} while(mimbleWimbleCoinIsEqual(secretNonce, workingTransactionContext.secretNonce, sizeof(workingTransactionContext.secretNonce)));
	
	// Check if creating single-signer signature failed
	if(!mimbleWimbleCoinCreateSingleSignerSignature((uint8_t *)messageSignature.buf, messageHash, workingTransactionContext.blindingFactor, secretNonce, publicNonce, publicKey)) {
	
		// Clear secret nonce
		memzero(secretNonce, sizeof(secretNonce));
		
		// Free message signature
		vstr_clear(&messageSignature);
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear secret nonce
	memzero(secretNonce, sizeof(secretNonce));
	
	// Set that working transaction context has signed a message
	workingTransactionContext.messageSigned = true;
	
	// Update transaction context
	memcpy(transactionContext.buf, &workingTransactionContext, sizeof(workingTransactionContext));
	
	// Clear working transaction context
	memzero(&workingTransactionContext, sizeof(workingTransactionContext));
	
	// Return message signature
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &messageSignature);
}

// Is valid secp256k1 public key
mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidSecp256k1PublicKey(const mp_obj_t publicKeyObject) {

	// Get public key
	mp_buffer_info_t publicKey;
	mp_get_buffer(publicKeyObject, &publicKey, MP_BUFFER_READ);
	
	// Return if public key is a valid secp256k1 public key
	return mimbleWimbleCoinIsValidSecp256k1PublicKey(publicKey.buf, publicKey.len) ? mp_const_true : mp_const_false;
}

// Is valid commitment
mp_obj_t mod_trezorcrypto_mimblewimble_coin_isValidCommitment(const mp_obj_t commitmentObject) {

	// Get commitment
	mp_buffer_info_t commitment;
	mp_get_buffer(commitmentObject, &commitment, MP_BUFFER_READ);
	
	// Check if commitment length isn't correct
	if(commitment.len!= MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE) {
	
		// Return false
		return mp_const_false;
	}
	
	// Copy commitment
	uint8_t copy[commitment.len];
	memcpy(copy, commitment.buf, commitment.len);
	
	// Change copy's prefix to its corresponding secp256k1 public key prefix
	copy[0] -= MIMBLEWIMBLE_COIN_COMMITMENT_EVEN_PREFIX - MIMBLEWIMBLE_COIN_SECP256k1_EVEN_COMPRESSED_PUBLIC_KEY_PREFIX;
	
	// Return if copy is a valid secp256k1 public key
	return mimbleWimbleCoinIsValidSecp256k1PublicKey(copy, sizeof(copy)) ? mp_const_true : mp_const_false;
}

// Verify transaction payment proof
mp_obj_t mod_trezorcrypto_mimblewimble_coin_verifyTransactionPaymentProof(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *const arguments) {

	// Import address type module
	const mp_obj_t addressTypeModule = mp_import_name(qstr_from_str("trezor.enums.MimbleWimbleCoinAddressType"), mp_const_empty_tuple, MP_OBJ_NEW_SMALL_INT(0));
	
	// Get arguments
	const mp_obj_t transactionContextObject = arguments[0];
	const mp_obj_t extendedPrivateKeyObject = arguments[1];
	const mp_obj_t coinInfoObject = arguments[2];
	const mp_obj_t addressTypeObject = arguments[3];
	const mp_obj_t kernelCommitmentObject = arguments[4];
	const mp_obj_t paymentProofObject = arguments[5];
	
	// Get transaction context
	mp_buffer_info_t transactionContext;
	mp_get_buffer(transactionContextObject, &transactionContext, MP_BUFFER_READ);
	
	// Copy transaction context
	MimbleWimbleCoinTransactionContext workingTransactionContext;
	memcpy(&workingTransactionContext, transactionContext.buf, transactionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get currency's Slatepack address human-readable part
	mp_buffer_info_t slatepackAddressHumanReadablePart;
	mp_get_buffer(mp_load_attr(coinInfoObject, MP_QSTR_slatepackAddressHumanReadablePart), &slatepackAddressHumanReadablePart, MP_BUFFER_READ);
	
	// Get kernel commitment
	mp_buffer_info_t kernelCommitment;
	mp_get_buffer(kernelCommitmentObject, &kernelCommitment, MP_BUFFER_READ);
	
	// Get payment proof
	mp_buffer_info_t paymentProof;
	mp_get_buffer(paymentProofObject, &paymentProof, MP_BUFFER_READ);
	
	// Check if address type is MQS
	if(mp_obj_equal(addressTypeObject, mp_load_attr(addressTypeModule, MP_QSTR_MQS))) {
	
		// Check if getting MQS address failed
		char mqsAddress[MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE + sizeof((char)'\0')];
		if(!mimbleWimbleCoinGetMqsAddress(mqsAddress, extendedPrivateKey, coinInfoObject, workingTransactionContext.index)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}
		
		// Check if getting payment proof message length failed
		const size_t paymentProofMessageLength = mimbleWimbleCoinGetPaymentProofMessageLength(coinInfoObject, workingTransactionContext.send, mqsAddress);
		if(!paymentProofMessageLength) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}

		// Check if getting payment proof message failed
		uint8_t paymentProofMessage[paymentProofMessageLength];
		if(!mimbleWimbleCoinGetPaymentProofMessage(paymentProofMessage, coinInfoObject, workingTransactionContext.send, kernelCommitment.buf, mqsAddress)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}
		
		// Check if verifying payment proof message failed
		if(!mimbleWimbleCoinVerifyPaymentProofMessage(paymentProofMessage, sizeof(paymentProofMessage), coinInfoObject, workingTransactionContext.address, paymentProof.buf, paymentProof.len)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Return true
		return mp_const_true;
	}
	
	// Otherwise check if address type is Tor
	else if(mp_obj_equal(addressTypeObject, mp_load_attr(addressTypeModule, MP_QSTR_TOR))) {
		
		// Check if getting Tor address failed
		char torAddress[MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE + sizeof((char)'\0')];
		if(!mimbleWimbleCoinGetTorAddress(torAddress, extendedPrivateKey, coinInfoObject, workingTransactionContext.index)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}
		
		// Check if getting payment proof message length failed
		const size_t paymentProofMessageLength = mimbleWimbleCoinGetPaymentProofMessageLength(coinInfoObject, workingTransactionContext.send, torAddress);
		if(!paymentProofMessageLength) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}

		// Check if getting payment proof message failed
		uint8_t paymentProofMessage[paymentProofMessageLength];
		if(!mimbleWimbleCoinGetPaymentProofMessage(paymentProofMessage, coinInfoObject, workingTransactionContext.send, kernelCommitment.buf, torAddress)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}
		
		// Check if verifying payment proof message failed
		if(!mimbleWimbleCoinVerifyPaymentProofMessage(paymentProofMessage, sizeof(paymentProofMessage), coinInfoObject, workingTransactionContext.address, paymentProof.buf, paymentProof.len)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Return true
		return mp_const_true;
	}
	
	// Otherwise check if address type is Slatepack
	else if(mp_obj_equal(addressTypeObject, mp_load_attr(addressTypeModule, MP_QSTR_SLATEPACK))) {
		
		// Check if getting Slatepack address failed
		char slatepackAddress[MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + slatepackAddressHumanReadablePart.len + sizeof((char)'\0')];
		if(!mimbleWimbleCoinGetSlatepackAddress(slatepackAddress, extendedPrivateKey, coinInfoObject, workingTransactionContext.index)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}
		
		// Check if getting payment proof message length failed
		const size_t paymentProofMessageLength = mimbleWimbleCoinGetPaymentProofMessageLength(coinInfoObject, workingTransactionContext.send, slatepackAddress);
		if(!paymentProofMessageLength) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}

		// Check if getting payment proof message failed
		uint8_t paymentProofMessage[paymentProofMessageLength];
		if(!mimbleWimbleCoinGetPaymentProofMessage(paymentProofMessage, coinInfoObject, workingTransactionContext.send, kernelCommitment.buf, slatepackAddress)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}
		
		// Check if verifying payment proof message failed
		if(!mimbleWimbleCoinVerifyPaymentProofMessage(paymentProofMessage, sizeof(paymentProofMessage), coinInfoObject, workingTransactionContext.address, paymentProof.buf, paymentProof.len)) {
		
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Return false
			return mp_const_false;
		}
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Return true
		return mp_const_true;
	}
	
	// Clear working transaction context
	memzero(&workingTransactionContext, sizeof(workingTransactionContext));
	
	// Return false
	return mp_const_false;
}

// Finish transaction
mp_obj_t mod_trezorcrypto_mimblewimble_coin_finishTransaction(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *const arguments) {

	// Import address type module
	const mp_obj_t addressTypeModule = mp_import_name(qstr_from_str("trezor.enums.MimbleWimbleCoinAddressType"), mp_const_empty_tuple, MP_OBJ_NEW_SMALL_INT(0));
	
	// Import storage module
	const mp_obj_t storageModule = mp_import_name(qstr_from_str("apps.mimblewimble_coin.storage"), mp_const_empty_tuple, MP_OBJ_NEW_SMALL_INT(0));
	
	// Get arguments
	const mp_obj_t transactionContextObject = arguments[0];
	const mp_obj_t extendedPrivateKeyObject = arguments[1];
	const mp_obj_t coinInfoObject = arguments[2];
	const mp_obj_t addressTypeObject = arguments[3];
	const mp_obj_t publicNonceObject = arguments[4];
	const mp_obj_t publicKeyObject = arguments[5];
	const mp_obj_t kernelInformationObject = arguments[6];
	const mp_obj_t kernelCommitmentObject = arguments[7];
	
	// Get transaction context
	mp_buffer_info_t transactionContext;
	mp_get_buffer(transactionContextObject, &transactionContext, MP_BUFFER_READ);
	
	// Copy transaction context
	MimbleWimbleCoinTransactionContext workingTransactionContext;
	memcpy(&workingTransactionContext, transactionContext.buf, transactionContext.len);
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get public nonce
	mp_buffer_info_t publicNonce;
	mp_get_buffer(publicNonceObject, &publicNonce, MP_BUFFER_READ);
	
	// Get public key
	mp_buffer_info_t publicKey;
	mp_get_buffer(publicKeyObject, &publicKey, MP_BUFFER_READ);
	
	// Get kernel information
	mp_buffer_info_t kernelInformation;
	mp_get_buffer(kernelInformationObject, &kernelInformation, MP_BUFFER_READ);
	
	// Get kernel commitment
	mp_buffer_info_t kernelCommitment;
	if(kernelCommitmentObject != mp_const_none) {
		mp_get_buffer(kernelCommitmentObject, &kernelCommitment, MP_BUFFER_READ);
	}
	
	// Initialize signature
	vstr_t signature;
	vstr_init(&signature, MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE);
	signature.len = MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE;
	
	// Initialize payment proof
	vstr_t paymentProof;
	if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
		vstr_init(&paymentProof, MIMBLEWIMBLE_COIN_MAXIMUM_DER_SIGNATURE_SIZE);
	}
	
	// Initialize result
	mp_obj_tuple_t *result = MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
	
	// Check if working transaction context is sending
	if(workingTransactionContext.send) {
	
		// Check if getting the encrypted transaction secret nonce at the working transaction context's secret nonce index from storage failed
		const mp_obj_t encryptedTransactionSecretNonceObject = mp_call_function_1(mp_load_attr(storageModule, MP_QSTR_getTransactionSecretNonce), MP_OBJ_NEW_SMALL_INT(workingTransactionContext.secretNonceIndex - 1));
		if(encryptedTransactionSecretNonceObject == mp_const_false) {
		
			// Free signature
			vstr_clear(&signature);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
		// Get encrypted transaction secret nonce
		mp_buffer_info_t encryptedTransactionSecretNonce;
		mp_get_buffer(encryptedTransactionSecretNonceObject, &encryptedTransactionSecretNonce, MP_BUFFER_READ);
		
		// Check if encrypted transaction secret nonce is invalid
		if(mimbleWimbleCoinIsZero(encryptedTransactionSecretNonce.buf, encryptedTransactionSecretNonce.len)) {
		
			// Free signature
			vstr_clear(&signature);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
		// Check if AES decrypting the encrypted transaction secret nonce with the working transaction context's blinding factor failed
		uint8_t transactionSecretNonce[encryptedTransactionSecretNonce.len];
		const size_t transactionSecretNonceLength = mimbleWimbleCoinAesDecrypt(transactionSecretNonce, workingTransactionContext.blindingFactor, encryptedTransactionSecretNonce.buf, encryptedTransactionSecretNonce.len);
		if(!transactionSecretNonceLength) {
		
			// Free signature
			vstr_clear(&signature);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
		// Check if transaction secret nonce length is invalid
		if(transactionSecretNonceLength != sizeof(workingTransactionContext.secretNonce)) {
		
			// Clear transaction secret nonce
			memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
			
			// Free signature
			vstr_clear(&signature);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
		// Check if the working transaction context's secret nonce isn't the transaction secret nonce
		if(!mimbleWimbleCoinIsEqual(workingTransactionContext.secretNonce, transactionSecretNonce, transactionSecretNonceLength)) {
		
			// Clear transaction secret nonce
			memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
			
			// Free signature
			vstr_clear(&signature);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
		// Clear transaction secret nonce
		memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
		
		// Check if erasing the encrypted transaction secret nonce at the working transaction context's secret nonce index in storage failed
		if(mp_call_function_1(mp_load_attr(storageModule, MP_QSTR_clearTransactionSecretNonce), MP_OBJ_NEW_SMALL_INT(workingTransactionContext.secretNonceIndex - 1)) == mp_const_false) {
	
			// Free signature
			vstr_clear(&signature);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
	}
	
	// Check if initializing hash context failed
	BLAKE2B_CTX hashContext;
	if(blake2b_Init(&hashContext, MIMBLEWIMBLE_COIN_SINGLE_SIGNER_MESSAGE_SIZE)) {
	
		// Free signature
		vstr_clear(&signature);
		
		// Free payment proof
		if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
			vstr_clear(&paymentProof);
		}
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	// Check if adding kernel information's features to the hash context failed
	if(blake2b_Update(&hashContext, &((const uint8_t *)kernelInformation.buf)[0], sizeof(((const uint8_t *)kernelInformation.buf)[0]))) {
	
		// Free signature
		vstr_clear(&signature);
		
		// Free payment proof
		if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
			vstr_clear(&paymentProof);
		}
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check kernel information's features
	switch(((const uint8_t *)kernelInformation.buf)[0]) {
	
		// Plain features
		case MimbleWimbleCoinKernelFeatures_PLAIN_FEATURES: {
		
			// Get working transaction context's fee
			uint64_t fee = workingTransactionContext.fee;
			
			// Check if little endian
			#if BYTE_ORDER == LITTLE_ENDIAN
			
				// Make fee big endian
				REVERSE64(fee, fee);
			#endif
			
			// Check if adding fee to the hash context failed
			if(blake2b_Update(&hashContext, &fee, sizeof(fee))) {
			
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
					vstr_clear(&paymentProof);
				}
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
		
			// Break
			break;
		}
		
		// Height locked features
		case MimbleWimbleCoinKernelFeatures_HEIGHT_LOCKED_FEATURES: {
		
			// Get working transaction context's fee
			uint64_t fee = workingTransactionContext.fee;
			
			// Check if little endian
			#if BYTE_ORDER == LITTLE_ENDIAN
			
				// Make fee big endian
				REVERSE64(fee, fee);
			#endif
			
			// Check if adding fee to the hash context failed
			if(blake2b_Update(&hashContext, &fee, sizeof(fee))) {
			
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
					vstr_clear(&paymentProof);
				}
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Get lock height from kernel information
			uint64_t lockHeight;
			memcpy(&lockHeight, &((const uint8_t *)kernelInformation.buf)[sizeof(((const uint8_t *)kernelInformation.buf)[0])], sizeof(lockHeight));
			
			// Make lock height big endian
			REVERSE64(lockHeight, lockHeight);
			
			// Check if adding lock height to the hash context failed
			if(blake2b_Update(&hashContext, &lockHeight, sizeof(lockHeight))) {
			
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
					vstr_clear(&paymentProof);
				}
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Break
			break;
		}
		
		// No recent duplicate features
		case MimbleWimbleCoinKernelFeatures_NO_RECENT_DUPLICATE_FEATURES: {
		
			// Get working transaction context's fee
			uint64_t fee = workingTransactionContext.fee;
			
			// Check if little endian
			#if BYTE_ORDER == LITTLE_ENDIAN
			
				// Make fee big endian
				REVERSE64(fee, fee);
			#endif
			
			// Check if adding fee to the hash context failed
			if(blake2b_Update(&hashContext, &fee, sizeof(fee))) {
			
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
					vstr_clear(&paymentProof);
				}
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Get relative height from kernel information
			uint16_t relativeHeight;
			memcpy(&relativeHeight, &((const uint8_t *)kernelInformation.buf)[sizeof(((const uint8_t *)kernelInformation.buf)[0])], sizeof(relativeHeight));
			
			// Make relative height big endian
			REVERSE16(relativeHeight, relativeHeight);
			
			// Check if adding relative height to the hash context failed
			if(blake2b_Update(&hashContext, &relativeHeight, sizeof(relativeHeight))) {
			
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
					vstr_clear(&paymentProof);
				}
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Break
			break;
		}
	}
	
	// Check if getting message hash from the hash context failed
	uint8_t messageHash[MIMBLEWIMBLE_COIN_SINGLE_SIGNER_MESSAGE_SIZE];
	if(blake2b_Final(&hashContext, messageHash, sizeof(messageHash))) {
	
		// Free signature
		vstr_clear(&signature);
		
		// Free payment proof
		if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
			vstr_clear(&paymentProof);
		}
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if creating single-signer signature failed
	if(!mimbleWimbleCoinCreateSingleSignerSignature((uint8_t *)signature.buf, messageHash, workingTransactionContext.blindingFactor, workingTransactionContext.secretNonce, publicNonce.buf, publicKey.buf)) {
	
		// Free signature
		vstr_clear(&signature);
		
		// Free payment proof
		if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
			vstr_clear(&paymentProof);
		}
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if working transaction context is receiving and kernel commitment exists
	if(workingTransactionContext.receive && kernelCommitmentObject != mp_const_none) {
	
		// Check if getting payment proof message length failed
		const size_t paymentProofMessageLength = mimbleWimbleCoinGetPaymentProofMessageLength(coinInfoObject, workingTransactionContext.receive, workingTransactionContext.address);
		if(!paymentProofMessageLength) {
		
			// Free signature
			vstr_clear(&signature);
			
			// Free payment proof
			vstr_clear(&paymentProof);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
	
		// Check if getting payment proof message failed
		uint8_t paymentProofMessage[paymentProofMessageLength];
		if(!mimbleWimbleCoinGetPaymentProofMessage(paymentProofMessage, coinInfoObject, workingTransactionContext.receive, kernelCommitment.buf, workingTransactionContext.address)) {
		
			// Free signature
			vstr_clear(&signature);
			
			// Free payment proof
			vstr_clear(&paymentProof);
			
			// Free result
			mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
			
			// Clear working transaction context
			memzero(&workingTransactionContext, sizeof(workingTransactionContext));
			
			// Raise error
			mp_raise_ValueError(NULL);
		}
		
		// Check if address type is MQS
		if(mp_obj_equal(addressTypeObject, mp_load_attr(addressTypeModule, MP_QSTR_MQS))) {
			
			// Check if getting address private key failed
			uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE];
			if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, workingTransactionContext.index, SECP256K1_NAME)) {
			
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				vstr_clear(&paymentProof);
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Check if getting address private key's public key failed
			uint8_t addressPublicKey[MIMBLEWIMBLE_COIN_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_SIZE];
			if(ecdsa_get_public_key65(&secp256k1, addressPrivateKey, addressPublicKey)) {
			
				// Clear address private key
				memzero(addressPrivateKey, sizeof(addressPrivateKey));
				
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				vstr_clear(&paymentProof);
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Check if address public key isn't a valid secp256k1 public key
			curve_point temp;
			if(!ecdsa_read_pubkey(&secp256k1, addressPublicKey, &temp)) {
			
				// Clear address private key
				memzero(addressPrivateKey, sizeof(addressPrivateKey));
				
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				vstr_clear(&paymentProof);
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Check if the address public key is in the payment proof message
			if(memmem(paymentProofMessage, sizeof(paymentProofMessage), addressPublicKey, sizeof(addressPublicKey))) {
			
				// Clear address private key
				memzero(addressPrivateKey, sizeof(addressPrivateKey));
				
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				vstr_clear(&paymentProof);
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Compress the address public key
			addressPublicKey[0] = (addressPublicKey[sizeof(addressPublicKey) - 1] & 1) ? MIMBLEWIMBLE_COIN_SECP256k1_ODD_COMPRESSED_PUBLIC_KEY_PREFIX : MIMBLEWIMBLE_COIN_SECP256k1_EVEN_COMPRESSED_PUBLIC_KEY_PREFIX;
			
			// Check if the compressed address public key is in the payment proof message
			if(memmem(paymentProofMessage, sizeof(paymentProofMessage), addressPublicKey, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE)) {
			
				// Clear address private key
				memzero(addressPrivateKey, sizeof(addressPrivateKey));
				
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				vstr_clear(&paymentProof);
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}			
			
			// Check if getting signature of the payment proof message failed
			uint8_t paymentProofSignature[MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE];
			if(ecdsa_sign(&secp256k1, HASHER_SHA2, addressPrivateKey, paymentProofMessage, sizeof(paymentProofMessage), paymentProofSignature, NULL, NULL)) {
			
				// Clear address private key
				memzero(addressPrivateKey, sizeof(addressPrivateKey));
				
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				vstr_clear(&paymentProof);
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Clear address private key
			memzero(addressPrivateKey, sizeof(addressPrivateKey));
			
			// Get payment proof signature in DER format
			paymentProof.len = ecdsa_sig_to_der(paymentProofSignature, (uint8_t *)paymentProof.buf);
		}
		
		// Otherwise check if address type is Tor or Slatepack
		else if(mp_obj_equal(addressTypeObject, mp_load_attr(addressTypeModule, MP_QSTR_TOR)) || mp_obj_equal(addressTypeObject, mp_load_attr(addressTypeModule, MP_QSTR_SLATEPACK))) {
			
			// Check if getting address private key failed
			uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE];
			if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, workingTransactionContext.index, ED25519_NAME)) {
			
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				vstr_clear(&paymentProof);
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Get address private key's public key
			uint8_t addressPublicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
			ed25519_publickey(addressPrivateKey, addressPublicKey);
			
			// Check if the address public key is in the payment proof message
			if(memmem(paymentProofMessage, sizeof(paymentProofMessage), addressPublicKey, sizeof(addressPublicKey))) {
			
				// Clear address private key
				memzero(addressPrivateKey, sizeof(addressPrivateKey));
				
				// Free signature
				vstr_clear(&signature);
				
				// Free payment proof
				vstr_clear(&paymentProof);
				
				// Free result
				mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
				
				// Clear working transaction context
				memzero(&workingTransactionContext, sizeof(workingTransactionContext));
				
				// Raise error
				mp_raise_ValueError(NULL);
			}
			
			// Get signature of the payment proof message
			ed25519_sign(paymentProofMessage, sizeof(paymentProofMessage), addressPrivateKey, (uint8_t *)paymentProof.buf);
			
			// Clear address private key
			memzero(addressPrivateKey, sizeof(addressPrivateKey));
			
			// Set payment proof signature size
			paymentProof.len = MIMBLEWIMBLE_COIN_ED25519_SIGNATURE_SIZE;
		}
		
		// Clear working transaction context
		memzero(&workingTransactionContext, sizeof(workingTransactionContext));
		
		// Return signature and payment proof
		result->items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &signature);
		result->items[1] = mp_obj_new_str_from_vstr(&mp_type_bytes, &paymentProof);
		return MP_OBJ_FROM_PTR(result);
	}
	
	// Clear working transaction context
	memzero(&workingTransactionContext, sizeof(workingTransactionContext));
	
	// Return signature
	result->items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &signature);
	result->items[1] = mp_const_none;
	return MP_OBJ_FROM_PTR(result);
}

// Get timestamp components
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTimestampComponents(const mp_obj_t timestampObject) {

	// Get timestamp
	const uint64_t timestamp = trezor_obj_get_uint64(timestampObject);
	
	// Initialize result
	mp_obj_tuple_t *result = MP_OBJ_TO_PTR(mp_obj_new_tuple(6, NULL));
	
	// Get time from timestamp
	MimbleWimbleCoinTime time;
	mimbleWimbleCoinEpochToTime(&time, timestamp);
	
	// Return timestamp components
	result->items[0] = MP_OBJ_NEW_SMALL_INT(time.year);
	result->items[1] = MP_OBJ_NEW_SMALL_INT(time.month);
	result->items[2] = MP_OBJ_NEW_SMALL_INT(time.day);
	result->items[3] = MP_OBJ_NEW_SMALL_INT(time.hour);
	result->items[4] = MP_OBJ_NEW_SMALL_INT(time.minute);
	result->items[5] = MP_OBJ_NEW_SMALL_INT(time.second);
	return MP_OBJ_FROM_PTR(result);
}

// Get MQS challenge signature
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getMqsChallengeSignature(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *const arguments) {

	// Get arguments
	const mp_obj_t extendedPrivateKeyObject = arguments[0];
	const mp_obj_t coinInfoObject = arguments[1];
	const mp_obj_t indexObject = arguments[2];
	const mp_obj_t challengeObject = arguments[3];
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Get challenge
	mp_buffer_info_t challenge;
	mp_get_buffer(challengeObject, &challenge, MP_BUFFER_READ);
	
	// Initialize MQS challenge signature
	vstr_t mqsChallengeSignature;
	vstr_init(&mqsChallengeSignature, MIMBLEWIMBLE_COIN_MAXIMUM_DER_SIGNATURE_SIZE);
	
	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, SECP256K1_NAME)) {
	
		// Free MQS challenge signature
		vstr_clear(&mqsChallengeSignature);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if getting signature of the challenge failed
	uint8_t signature[MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE];
	if(ecdsa_sign(&secp256k1, HASHER_SHA2, addressPrivateKey, challenge.buf, challenge.len, signature, NULL, NULL)) {
	
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Free MQS challenge signature
		vstr_clear(&mqsChallengeSignature);
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Get signature in DER format
	mqsChallengeSignature.len = ecdsa_sig_to_der(signature, (uint8_t *)mqsChallengeSignature.buf);
	
	// Return MQS challenge signature
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &mqsChallengeSignature);
}

// Get login challenge signature
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getLoginChallengeSignature(__attribute__((unused)) const size_t argumentsLength, const mp_obj_t *const arguments) {

	// Get arguments
	const mp_obj_t extendedPrivateKeyObject = arguments[0];
	const mp_obj_t identifierObject = arguments[1];
	const mp_obj_t challengeObject = arguments[2];
	
	// Get extended private key
	const HDNode *extendedPrivateKey = &((const mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get identifier
	mp_buffer_info_t identifier;
	mp_get_buffer(identifierObject, &identifier, MP_BUFFER_READ);
	
	// Get challenge
	mp_buffer_info_t challenge;
	mp_get_buffer(challengeObject, &challenge, MP_BUFFER_READ);
	
	// Initialize login public key
	vstr_t loginPublicKey;
	vstr_init(&loginPublicKey, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	loginPublicKey.len = MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE;
	
	// Initialize login challenge signature
	vstr_t loginChallengeSignature;
	vstr_init(&loginChallengeSignature, MIMBLEWIMBLE_COIN_MAXIMUM_DER_SIGNATURE_SIZE);
	
	// Initialize result
	mp_obj_tuple_t *result = MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
	
	// Get hash of challenge and identifier
	SHA256_CTX hashContext;
	sha256_Init(&hashContext);
	sha256_Update(&hashContext, challenge.buf, challenge.len);
	sha256_Update(&hashContext, (const uint8_t *)" ", sizeof(" ") - sizeof((char)'\0'));
	sha256_Update(&hashContext, identifier.buf, identifier.len);
	uint8_t hash[SHA256_DIGEST_LENGTH];
	sha256_Final(&hashContext, hash);
	
	// Check if getting login private key failed
	uint8_t loginPrivateKey[MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetLoginPrivateKey(loginPrivateKey, extendedPrivateKey)) {
	
		// Free login public key
		vstr_clear(&loginPublicKey);
		
		// Free login challenge signature
		vstr_clear(&loginChallengeSignature);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if getting signature of the hash failed
	uint8_t signature[MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE];
	if(ecdsa_sign_digest(&secp256k1, loginPrivateKey, hash, signature, NULL, NULL)) {
	
		// Clear login private key
		memzero(loginPrivateKey, sizeof(loginPrivateKey));
		
		// Free login public key
		vstr_clear(&loginPublicKey);
		
		// Free login challenge signature
		vstr_clear(&loginChallengeSignature);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check ig getting the login private key's public key failed
	if(!mimbleWimbleCoinGetPublicKeyFromSecp256k1PrivateKey((uint8_t *)loginPublicKey.buf, loginPrivateKey)) {
	
		// Clear login private key
		memzero(loginPrivateKey, sizeof(loginPrivateKey));
		
		// Free login public key
		vstr_clear(&loginPublicKey);
		
		// Free login challenge signature
		vstr_clear(&loginChallengeSignature);
		
		// Free result
		mp_obj_tuple_del(MP_OBJ_FROM_PTR(result));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear login private key
	memzero(loginPrivateKey, sizeof(loginPrivateKey));
	
	// Get signature in DER format
	loginChallengeSignature.len = ecdsa_sig_to_der(signature, (uint8_t *)loginChallengeSignature.buf);
	
	// Return login challenge signature and login public key
	result->items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &loginPublicKey);
	result->items[1] = mp_obj_new_str_from_vstr(&mp_type_bytes, &loginChallengeSignature);
	return MP_OBJ_FROM_PTR(result);
}

// Is equal
bool mimbleWimbleCoinIsEqual(const uint8_t *dataOne, const uint8_t *dataTwo, const size_t length) {

	// Initialize sum
	uint8_t sum = 0;
	
	// Go through all bytes in the data
	for(size_t i = 0; i < length; ++i) {
	
		// Or xored bytes with the sum
		sum |= dataOne[i] ^ dataTwo[i];
	}
	
	// Return if sum is zero
	return !sum;
}

// Big number subtract modulo
void mimbleWimbleCoin_bn_submod(const bignum256 *minuend, const bignum256 *subtrahend, bignum256 *result, const bignum256 *prime) {

	// Get negative subtrahend
	bignum256 negativeSubtrahend;
	bn_copy(subtrahend, &negativeSubtrahend);
	bn_cnegate(true, &negativeSubtrahend, prime);
	bn_fast_mod(&negativeSubtrahend, prime);
	
	// Set result to the sum of minuend and negative subtrahend
	bn_copy(minuend, result);
	bn_addmod(result, &negativeSubtrahend, prime);
	
	// Clear negative subtrahend
	memzero(&negativeSubtrahend, sizeof(negativeSubtrahend));
}

// Get public key from secp256k1 private key
bool mimbleWimbleCoinGetPublicKeyFromSecp256k1PrivateKey(uint8_t *publicKey, const uint8_t *privateKey) {

	// Check if getting private key's public key failed
	if(ecdsa_get_public_key33(&secp256k1, privateKey, publicKey)) {
	
		// Clear public key
		memzero(publicKey, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Check if public key isn't a valid secp256k1 public key
	if(!mimbleWimbleCoinIsValidSecp256k1PublicKey(publicKey, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE)) {
	
		// Clear public key
		memzero(publicKey, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid Ed25519 private key
bool mimbleWimbleCoinIsValidEd25519PrivateKey(__attribute__((unused)) const uint8_t *privateKey, const size_t privateKeyLength) {

	// Return if private key length is correct
	return privateKeyLength == MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE;
}

// Is valid X25519 private key
bool mimbleWimbleCoinIsValidX25519PrivateKey(__attribute__((unused)) const uint8_t *privateKey, const size_t privateKeyLength) {

	// Return if private key length is correct
	return privateKeyLength == MIMBLEWIMBLE_COIN_X25519_PRIVATE_KEY_SIZE;
}

// Is quadratic residue
bool mimbleWimbleCoinIsQuadraticResidue(const bignum256 *component) {

	// Get the square root squared of the component
	bignum256 squareRootSquared;
	bn_power_mod(component, &MIMBLEWIMBLE_COIN_SECP256k1_SQUARE_ROOT_EXPONENT, &secp256k1.prime, &squareRootSquared);
	bn_multiply(&squareRootSquared, &squareRootSquared, &secp256k1.prime);
	bn_mod(&squareRootSquared, &secp256k1.prime);
	
	// Return if the result is equal to the component
	return bn_is_equal(&squareRootSquared, component);
}

// Derive child private key
bool mimbleWimbleCoinDeriveChildPrivateKey(uint8_t *childPrivateKey, const HDNode *extendedPrivateKey, const uint32_t *path, const size_t pathLength) {

	// Set child private key to the extended private key's private key
	memcpy(childPrivateKey, extendedPrivateKey->private_key, sizeof(extendedPrivateKey->private_key));
	
	// Set chain code to the extended private key's chain code
	uint8_t chainCode[sizeof(extendedPrivateKey->chain_code)];
	memcpy(chainCode, extendedPrivateKey->chain_code, sizeof(extendedPrivateKey->chain_code));
	
	// Initialize data
	uint8_t data[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE + sizeof(uint32_t)];
	
	// Go through the path
	for(size_t i = 0; i < pathLength; ++i) {
	
		// Check if path is hardened
		if(path[i] & MIMBLEWIMBLE_COIN_PATH_HARDENED) {
		
			// Set the first part of data to zero
			data[0] = 0;
			
			// Append child private key to the data
			memcpy(&data[sizeof(data[0])], childPrivateKey, sizeof(extendedPrivateKey->private_key));
		}
		
		// Otherwise
		else {
		
			// Check if setting data to the child private key's compressed public key failed
			if(!mimbleWimbleCoinGetPublicKeyFromSecp256k1PrivateKey(data, childPrivateKey)) {
			
				// Clear child private key
				memzero(childPrivateKey, sizeof(extendedPrivateKey->private_key));
				
				// Clear chain code
				memzero(chainCode, sizeof(chainCode));
				
				// Return false
				return false;
			}
		}
		
		// Append path to data
		write_be(&data[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE], path[i]);
		
		// Get the path's node as the HMAC-SHA512 of the data with the chain code as the key
		uint8_t node[sizeof(extendedPrivateKey->private_key) + sizeof(chainCode)];
		hmac_sha512(chainCode, sizeof(chainCode), data, sizeof(data), node);
		
		// Clear data
		memzero(data, sizeof(data));
		
		// Check if node's private key isn't a valid secp256k1 private key
		if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(node, sizeof(extendedPrivateKey->private_key))) {
		
			// Clear node
			memzero(node, sizeof(node));
			
			// Clear child private key
			memzero(childPrivateKey, sizeof(extendedPrivateKey->private_key));
			
			// Clear chain code
			memzero(chainCode, sizeof(chainCode));
			
			// Return false
			return false;
		}
		
		// Get child private key and new node's private key as big numbers
		bignum256 childPrivateKeyBigNumber;
		bn_read_be(childPrivateKey, &childPrivateKeyBigNumber);
		bignum256 nodePrivateKeyBigNumber;
		bn_read_be(node, &nodePrivateKeyBigNumber);
		
		// Add child private key to the new node's private key
		bn_addmod(&nodePrivateKeyBigNumber, &childPrivateKeyBigNumber, &secp256k1.order);
		bn_mod(&nodePrivateKeyBigNumber, &secp256k1.order);
		
		// Set child private key to the result
		bn_write_be(&nodePrivateKeyBigNumber, childPrivateKey);
		
		// Clear child private key and node's private key big numbers
		memzero(&childPrivateKeyBigNumber, sizeof(childPrivateKeyBigNumber));
		memzero(&nodePrivateKeyBigNumber, sizeof(nodePrivateKeyBigNumber));
		
		// Check if child private key isn't a valid secp256k1 private key
		if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(childPrivateKey, sizeof(extendedPrivateKey->private_key))) {
		
			// Clear node
			memzero(node, sizeof(node));
			
			// Clear child private key
			memzero(childPrivateKey, sizeof(extendedPrivateKey->private_key));
			
			// Clear chain code
			memzero(chainCode, sizeof(chainCode));
			
			// Return false
			return false;
		}
		
		// Set chain code to the node's chain code
		memcpy(chainCode, &node[sizeof(extendedPrivateKey->private_key)], sizeof(chainCode));
		
		// Clear node
		memzero(node, sizeof(node));
	}
	
	// Clear chain code
	memzero(chainCode, sizeof(chainCode));
	
	// Return true
	return true;
}

// Commit value
bool mimbleWimbleCoinCommitValue(uint8_t *commitment, const uint64_t value, const uint8_t *blindingFactor, const bool compress) {

	// Get value as a big number
	bignum256 valueBigNumber;
	bn_read_uint64(value, &valueBigNumber);
	
	// Check if getting the product of the value big number and generator H failed
	curve_point hImage;
	if(point_multiply(&secp256k1, &valueBigNumber, &MIMBLEWIMBLE_COIN_GENERATOR_H, &hImage)) {
	
		// Return false
		return false;
	}
	
	// Check if the result is infinity
	if(point_is_infinity(&hImage)) {
	
		// Return false
		return false;
	}
	
	// Get blinding factor as a big number
	bignum256 blindingFactorBigNumber;
	bn_read_be(blindingFactor, &blindingFactorBigNumber);
	
	// Check if getting the product of the blinding factor big number and generator G failed
	curve_point gImage;
	if(scalar_multiply(&secp256k1, &blindingFactorBigNumber, &gImage)) {
	
		// Clear blinding factor big number
		memzero(&blindingFactorBigNumber, sizeof(blindingFactorBigNumber));
	
		// Return false
		return false;
	}
	
	// Clear blinding factor big number
	memzero(&blindingFactorBigNumber, sizeof(blindingFactorBigNumber));
	
	// Check if the result is infinity
	if(point_is_infinity(&gImage)) {
	
		// Return false
		return false;
	}
	
	// Add the products
	point_add(&secp256k1, &hImage, &gImage);
	
	// Check if the result is infinity
	if(point_is_infinity(&gImage)) {
	
		// Return false
		return false;
	}
	
	// Set commitment's prefix based on the result's y component
	commitment[0] = mimbleWimbleCoinIsQuadraticResidue(&gImage.y) ? MIMBLEWIMBLE_COIN_COMMITMENT_EVEN_PREFIX : MIMBLEWIMBLE_COIN_COMMITMENT_ODD_PREFIX;
	
	// Copy result's x component to the commitment
	bn_write_be(&gImage.x, &commitment[MIMBLEWIMBLE_COIN_PUBLIC_KEY_PREFIX_SIZE]);
	
	// Check if not compressing
	if(!compress) {
	
		// Copy result's y component to the commitment
		bn_write_be(&gImage.y, &commitment[MIMBLEWIMBLE_COIN_PUBLIC_KEY_PREFIX_SIZE + MIMBLEWIMBLE_COIN_PUBLIC_KEY_COMPONENT_SIZE]);
	}
	
	// Return true
	return true;
}

// Derive blinding factor
bool mimbleWimbleCoinDeriveBlindingFactor(uint8_t *blindingFactor, const HDNode *extendedPrivateKey, const uint64_t value, const uint32_t *path, const size_t pathLength, const mp_obj_t switchTypeObject) {

	// Import switch type module
	const mp_obj_t switchTypeModule = mp_import_name(qstr_from_str("trezor.enums.MimbleWimbleCoinSwitchType"), mp_const_empty_tuple, MP_OBJ_NEW_SMALL_INT(0));
	
	// Check if deriving the extended private key's child private key failed
	uint8_t childPrivateKey[MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinDeriveChildPrivateKey(childPrivateKey, extendedPrivateKey, path, pathLength)) {
	
		// Return false
		return false;
	}
	
	// Check if switch type is none
	if(mp_obj_equal(switchTypeObject, mp_load_attr(switchTypeModule, MP_QSTR_NONE))) {
	
		// Set blinding factor to the child private key
		memcpy(blindingFactor, childPrivateKey, sizeof(childPrivateKey));
		
		// Clear child private key
		memzero(childPrivateKey, sizeof(childPrivateKey));
	}
	
	// Otherwise check if switch type is regular
	else if(mp_obj_equal(switchTypeObject, mp_load_attr(switchTypeModule, MP_QSTR_REGULAR))) {
		
		// Check if getting commitment from value and child private key failed
		uint8_t commitment[MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE];
		if(!mimbleWimbleCoinCommitValue(commitment, value, childPrivateKey, true)) {
		
			// Clear child private key
			memzero(childPrivateKey, sizeof(childPrivateKey));
			
			// Return false
			return false;
		}
		
		// Add commitment to the hash
		SHA256_CTX hash;
		sha256_Init(&hash);
		sha256_Update(&hash, commitment, sizeof(commitment));
		
		// Clear commitment
		memzero(commitment, sizeof(commitment));
		
		// Get child private key as a big number
		bignum256 childPrivateKeyBigNumber;
		bn_read_be(childPrivateKey, &childPrivateKeyBigNumber);
		
		// Clear child private key
		memzero(childPrivateKey, sizeof(childPrivateKey));
		
		// Check if getting the product of the child private key big number and generator J failed
		curve_point jImage;
		if(point_multiply(&secp256k1, &childPrivateKeyBigNumber, &MIMBLEWIMBLE_COIN_GENERATOR_J, &jImage)) {
		
			// Clear result
			memzero(&jImage, sizeof(jImage));
			
			// Clear child private key big number
			memzero(&childPrivateKeyBigNumber, sizeof(childPrivateKeyBigNumber));
			
			// Clear hash
			memzero(&hash, sizeof(hash));
			
			// Return false
			return false;
		}
		
		// Check if the result is infinity
		if(point_is_infinity(&jImage)) {
		
			// Clear result
			memzero(&jImage, sizeof(jImage));
			
			// Clear child private key big number
			memzero(&childPrivateKeyBigNumber, sizeof(childPrivateKeyBigNumber));
			
			// Clear hash
			memzero(&hash, sizeof(hash));
			
			// Return false
			return false;
		}
		
		// Get public key from the result
		uint8_t jImagePublicKey[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
		compress_coords(&jImage, jImagePublicKey);
		
		// Clear result
		memzero(&jImage, sizeof(jImage));
		
		// Add public key to the hash
		sha256_Update(&hash, jImagePublicKey, sizeof(jImagePublicKey));
		
		// Clear result's public key
		memzero(jImagePublicKey, sizeof(jImagePublicKey));
		
		// Set blinding factor to the hash
		sha256_Final(&hash, blindingFactor);
		
		// Get the blinding factor as a big number
		bignum256 blindingFactorBigNumber;
		bn_read_be(blindingFactor, &blindingFactorBigNumber);
		
		// Check if the blinding factor big number overflows
		if(!bn_is_less(&blindingFactorBigNumber, &secp256k1.order)) {
		
			// Clear blinding factor big bumber
			memzero(&blindingFactorBigNumber, sizeof(blindingFactorBigNumber));
			
			// Clear blinding factor
			memzero(blindingFactor, MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE);
			
			// Clear child private key big number
			memzero(&childPrivateKeyBigNumber, sizeof(childPrivateKeyBigNumber));
			
			// Return false
			return false;
		}
		
		// Add child private key to the blinding factor
		bn_addmod(&blindingFactorBigNumber, &childPrivateKeyBigNumber, &secp256k1.order);
		bn_mod(&blindingFactorBigNumber, &secp256k1.order);
		
		// Clear child private key big number
		memzero(&childPrivateKeyBigNumber, sizeof(childPrivateKeyBigNumber));
		
		// Set blinding factor to the result
		bn_write_be(&blindingFactorBigNumber, blindingFactor);
		
		// Clear blinding factor big number
		memzero(&blindingFactorBigNumber, sizeof(blindingFactorBigNumber));
		
		// Check if blinding factor isn't a valid secp256k1 private key
		if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(blindingFactor, MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE)) {
		
			// Clear blinding factor
			memzero(blindingFactor, MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE);
			
			// Return false
			return false;
		}
	}
	
	// Return true
	return true;
}

// Get address private key
bool mimbleWimbleCoinGetAddressPrivateKey(uint8_t *addressPrivateKey, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index, const char *curveName) {

	// Import switch type module
	const mp_obj_t switchTypeModule = mp_import_name(qstr_from_str("trezor.enums.MimbleWimbleCoinSwitchType"), mp_const_empty_tuple, MP_OBJ_NEW_SMALL_INT(0));
	
	// Check currency's address derivation type
	switch(mp_obj_get_int(mp_load_attr(coinInfoObject, MP_QSTR_addressDerivationType))) {
	
		// MWC address derivation
		case MimbleWimbleCoinAddressDerivationType_MWC_ADDRESS_DERIVATION: {
		
			// Check if deriving blinding factor from the address private key blinding factor value and root path failed
			uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
			if(!mimbleWimbleCoinDeriveBlindingFactor(blindingFactor, extendedPrivateKey, MIMBLEWIMBLE_COIN_ADDRESS_PRIVATE_KEY_BLINDING_FACTOR_VALUE, NULL, 0, mp_load_attr(switchTypeModule, MP_QSTR_REGULAR))) {
			
				// Return false
				return false;
			}
			
			// Get the node as the HMAC-SHA512 of the blinding factor with the addres private key hash key as the key
			uint8_t node[MIMBLEWIMBLE_COIN_NODE_SIZE];
			hmac_sha512((const uint8_t *)MIMBLEWIMBLE_COIN_ADDRESS_PRIVATE_KEY_HASH_KEY, sizeof(MIMBLEWIMBLE_COIN_ADDRESS_PRIVATE_KEY_HASH_KEY), blindingFactor, sizeof(blindingFactor), node);
			
			// Clear blinding factor
			memzero(blindingFactor, sizeof(blindingFactor));
			
			// Check if node private key isn't a valid secp256k1 private key
			if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(node, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE)) {
			
				// Clear node
				memzero(node, sizeof(node));
				
				// Return false
				return false;
			}
			
			// Create current extended private key from the node
			HDNode currentExtendedPrivateKey;
			memcpy(currentExtendedPrivateKey.private_key, node, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE);
			memcpy(currentExtendedPrivateKey.chain_code, &node[MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE], MIMBLEWIMBLE_COIN_CHAIN_CODE_SIZE);
			
			// Clear node
			memzero(node, sizeof(node));
			
			// Check if derive the address private key from the current extended private key at the index failed
			if(!mimbleWimbleCoinDeriveChildPrivateKey(addressPrivateKey, &currentExtendedPrivateKey, &index, 1)) {
			
				// Clear current extended private key
				memzero(&currentExtendedPrivateKey, sizeof(currentExtendedPrivateKey));
				
				// Return false
				return false;
			}
			
			// Clear current extended private key
			memzero(&currentExtendedPrivateKey, sizeof(currentExtendedPrivateKey));
			
			// Break
			break;
		}
		
		// GRIN address derivation
		case MimbleWimbleCoinAddressDerivationType_GRIN_ADDRESS_DERIVATION: {
		
			// Initialize path
			const uint32_t path[] = {
				0,
				1,
				index
			};
			
			// Check if deriving blinding factor from the path failed
			uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
			if(!mimbleWimbleCoinDeriveBlindingFactor(blindingFactor, extendedPrivateKey, 0, path, sizeof(path) / sizeof(path[0]), mp_load_attr(switchTypeModule, MP_QSTR_NONE))) {
			
				// Return false
				return false;
			}
			
			// Check if getting address private key as the hash of the blinding factor failed
			if(blake2b(blindingFactor, sizeof(blindingFactor), addressPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE)) {
			
				// Clear address private key
				memzero(addressPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE);
				
				// Clear blinding factor
				memzero(blindingFactor, sizeof(blindingFactor));
				
				// Return false
				return false;
			}
			
			// Clear blinding factor
			memzero(blindingFactor, sizeof(blindingFactor));
			
			// Check if address private key isn't a valid secp256k1 private key
			if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(addressPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE)) {
			
				// Clear address private key
				memzero(addressPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE);
				
				// Return false
				return false;
			}
			
			// Break
			break;
		}
		
		// Default
		default:
		
			// Return false
			return false;
	}
	
	// Check if curve is secp256k1
	if(!strcmp(curveName, SECP256K1_NAME)) {
	
		// Check if address private key isn't a valid secp256k1 private key
		if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(addressPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE)) {
		
			// Clear address private key
			memzero(addressPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
	}
	
	// Otherwise check if curve is Ed25519
	else if(!strcmp(curveName, ED25519_NAME)) {
	
		// Check if address private key isn't a valid Ed25519 private key
		if(!mimbleWimbleCoinIsValidEd25519PrivateKey(addressPrivateKey, MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE)) {
		
			// Clear address private key
			memzero(addressPrivateKey, MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
	}
	
	// Otherwise
	else {
	
		// Clear address private key
		memzero(addressPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get MQS address from public key
bool mimbleWimbleCoinGetMqsAddressFromPublicKey(char *mqsAddress, const mp_obj_t coinInfoObject, const uint8_t *publicKey) {

	// Get currency's MQS version
	size_t mqsVersionLength;
	mp_obj_t *mqsVersion;
	mp_obj_list_get(mp_load_attr(coinInfoObject, MP_QSTR_mqsVersion), &mqsVersionLength, &mqsVersion);
	
	// Create address data from version and public key
	uint8_t addressData[mqsVersionLength + MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	for(size_t i = 0; i < mqsVersionLength; ++i) {
		addressData[i] = mp_obj_get_int(mqsVersion[i]);
	}
	memcpy(&addressData[mqsVersionLength], publicKey, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	
	// Return if getting the MQS address by base58 encoding the address data was successful
	return base58_encode_check(addressData, sizeof(addressData), HASHER_SHA2D, mqsAddress, MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE + sizeof((char)'\0'));
}

// Get public key from MQS address
bool mimbleWimbleCoinGetPublicKeyFromMqsAddress(uint8_t *publicKey, const mp_obj_t coinInfoObject, const char *mqsAddress, const size_t mqsAddressLength) {

	// Get currency's MQS version
	size_t mqsVersionLength;
	mp_obj_t *mqsVersion;
	mp_obj_list_get(mp_load_attr(coinInfoObject, MP_QSTR_mqsVersion), &mqsVersionLength, &mqsVersion);
	
	// Check if MQS address's length is invalid
	if(mqsAddressLength != MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if decoding MQS address failed
	char mqsAddressString[mqsAddressLength + sizeof((char)'\0')];
	memcpy(mqsAddressString, mqsAddress, mqsAddressLength);
	mqsAddressString[mqsAddressLength] = '\0';
	uint8_t addressData[mqsVersionLength + MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	if(!base58_decode_check(mqsAddressString, HASHER_SHA2D, addressData, sizeof(addressData))) {
	
		// Return false
		return false;
	}
	
	// Go through MQS version
	for(size_t i = 0; i < mqsVersionLength; ++i) {
	
		// Check if MQS address's version is invalid
		if(addressData[i] != mp_obj_get_int(mqsVersion[i])) {
		
			// Return false
			return false;
		}
	}
	
	// Check if MQS address's public key isn't a valid secp256k1 public key
	if(!mimbleWimbleCoinIsValidSecp256k1PublicKey(&addressData[mqsVersionLength], MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting public key
	if(publicKey) {
	
		// Set public key to the MQS address's public key
		memcpy(publicKey, &addressData[mqsVersionLength], MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	}
	
	// Return true
	return true;
}

// Get Tor address checksum
void mimbleWimbleCoinGetTorAddressChecksum(uint8_t *checksum, const uint8_t *publicKey) {

	// Create address data from checksum seed, public key, and version
	uint8_t addressData[sizeof(MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SEED) + MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE + sizeof(MIMBLEWIMBLE_COIN_TOR_ADDRESS_VERSION)];
	memcpy(addressData, MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SEED, sizeof(MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SEED));
	memcpy(&addressData[sizeof(MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SEED)], publicKey, MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE);
	addressData[sizeof(MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SEED) + MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE] = MIMBLEWIMBLE_COIN_TOR_ADDRESS_VERSION;
	
	// Get hash of address data
	uint8_t hash[sha3_256_hash_size];
	sha3_256(addressData, sizeof(addressData), hash);
	
	// Get checksum from the hash
	memcpy(checksum, hash, MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SIZE);
}

// Get Tor address from public key
bool mimbleWimbleCoinGetTorAddressFromPublicKey(char *torAddress, const uint8_t *publicKey) {

	// Get checksum
	uint8_t checksum[MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SIZE];
	mimbleWimbleCoinGetTorAddressChecksum(checksum, publicKey);
	
	// Get address data from public key and checksum
	uint8_t addressData[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE + sizeof(checksum) + sizeof(MIMBLEWIMBLE_COIN_TOR_ADDRESS_VERSION)];
	memcpy(addressData, publicKey, MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE);
	memcpy(&addressData[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE], checksum, sizeof(checksum));
	addressData[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE + sizeof(checksum)] = MIMBLEWIMBLE_COIN_TOR_ADDRESS_VERSION;
	
	// Return if getting the Tor address by base32 encoding the address data was successful
	return base32_encode(addressData, sizeof(addressData), torAddress, MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE + sizeof((char)'\0'), MIMBLEWIMBLE_COIN_TOR_BASE32_ALPHABET);
}

// Get public key from Tor address
bool mimbleWimbleCoinGetPublicKeyFromTorAddress(uint8_t *publicKey, const char *torAddress, const size_t torAddressLength) {

	// Check if Tor address's length is invalid
	if(torAddressLength != MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if decoding Tor address failed
	uint8_t addressData[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE + MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SIZE + sizeof(MIMBLEWIMBLE_COIN_TOR_ADDRESS_VERSION)];
	if(!base32_decode(torAddress, torAddressLength, addressData, sizeof(addressData), MIMBLEWIMBLE_COIN_TOR_BASE32_ALPHABET)) {
	
		// Return false
		return false;
	}
	
	// Check if Tor address's version is invalid
	if(addressData[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE + MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SIZE] != MIMBLEWIMBLE_COIN_TOR_ADDRESS_VERSION) {
	
		// Return false
		return false;
	}
	
	// Check if Tor address's checksum is invalid
	uint8_t checksum[MIMBLEWIMBLE_COIN_TOR_ADDRESS_CHECKSUM_SIZE];
	mimbleWimbleCoinGetTorAddressChecksum(checksum, addressData);
	if(memcmp(&addressData[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE], checksum, sizeof(checksum))) {
	
		// Return false
		return false;
	}
	
	// Check if Tor address's public key isn't a valid Ed25519 public key
	ge25519 temp;
	if(!ge25519_unpack_negative_vartime(&temp, addressData)) {
	
		// Return false
		return false;
	}
	
	// Check if getting public key
	if(publicKey) {
	
		// Set public key to the Tor address's public key
		memcpy(publicKey, addressData, MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE);
	}
	
	// Return true
	return true;
}

// Get Slatepack address from public key
bool mimbleWimbleCoinGetSlatepackAddressFromPublicKey(char *slatepackAddress, const mp_obj_t coinInfoObject, const uint8_t *publicKey) {

	// Get currency's Slatepack address human-readable part
	mp_buffer_info_t slatepackAddressHumanReadablePart;
	mp_get_buffer(mp_load_attr(coinInfoObject, MP_QSTR_slatepackAddressHumanReadablePart), &slatepackAddressHumanReadablePart, MP_BUFFER_READ);

	// Check if converting public key to bits failed
	uint8_t bits[(MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE * MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE + (MIMBLEWIMBLE_COIN_BECH32_BITS_PER_CHARACTER - 1)) / MIMBLEWIMBLE_COIN_BECH32_BITS_PER_CHARACTER];
	size_t bitsLength = 0;
	if(!convert_bits(bits, &bitsLength, MIMBLEWIMBLE_COIN_BECH32_BITS_PER_CHARACTER, publicKey, MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE, MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE, true)) {
	
		// Return false
		return false;
	}
	
	// Return if getting the Slatepack address by Bech32 encoding the address data was successful
	return bech32_encode(slatepackAddress, slatepackAddressHumanReadablePart.buf, bits, bitsLength, BECH32_ENCODING_BECH32);
}

// Get public key from Slatepack address
bool mimbleWimbleCoinGetPublicKeyFromSlatepackAddress(uint8_t *publicKey, const mp_obj_t coinInfoObject, const char *slatepackAddress, const size_t slatepackAddressLength) {

	// Get currency's Slatepack address human-readable part
	mp_buffer_info_t slatepackAddressHumanReadablePart;
	mp_get_buffer(mp_load_attr(coinInfoObject, MP_QSTR_slatepackAddressHumanReadablePart), &slatepackAddressHumanReadablePart, MP_BUFFER_READ);
	
	// Check if Slatepack address's length is invalid
	if(slatepackAddressLength != MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + slatepackAddressHumanReadablePart.len) {
	
		// Return false
		return false;
	}
	
	// Check if decoding Slatepack address failed
	char humanReadablePart[BECH32_MAX_HRP_LEN + sizeof((char)'\0')];
	uint8_t bits[slatepackAddressLength];
	size_t bitsLength = 0;
	char slatepackAddressString[slatepackAddressLength + sizeof((char)'\0')];
	memcpy(slatepackAddressString, slatepackAddress, slatepackAddressLength);
	slatepackAddressString[slatepackAddressLength] = '\0';
	if(bech32_decode(humanReadablePart, bits, &bitsLength, slatepackAddressString) != BECH32_ENCODING_BECH32) {
	
		// Return false
		return false;
	}
	
	// Check if bits length is invalid
	if(bitsLength != (MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE * MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE + (MIMBLEWIMBLE_COIN_BECH32_BITS_PER_CHARACTER - 1)) / MIMBLEWIMBLE_COIN_BECH32_BITS_PER_CHARACTER) {
	
		// Return false
		return false;
	}
	
	// Check if Slatepack address's human-readable part is invalid
	if(strcmp(humanReadablePart, slatepackAddressHumanReadablePart.buf)) {
	
		// Return false
		return false;
	}
	
	// Check if getting address data from bits failed
	uint8_t addressData[(bitsLength * MIMBLEWIMBLE_COIN_BECH32_BITS_PER_CHARACTER + (MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE - 1)) / MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE];
	size_t addressDataLength = 0;
	if(!convert_bits(addressData, &addressDataLength, MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE, bits, bitsLength, MIMBLEWIMBLE_COIN_BECH32_BITS_PER_CHARACTER, false)) {
	
		// Return false
		return false;
	}
	
	// Check if address data length is invalid
	if(addressDataLength != MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if Slatepack address's public key isn't a valid Ed25519 public key
	ge25519 temp;
	if(!ge25519_unpack_negative_vartime(&temp, addressData)) {
	
		// Return false
		return false;
	}
	
	// Check if getting public key
	if(publicKey) {
	
		// Set public key to the Slatepack address's public key
		memcpy(publicKey, addressData, MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE);
	}
	
	// Return true
	return true;
}

// Update Bulletproof challenge
void mimbleWimbleCoinUpdateBulletproofChallenge(uint8_t *challenge, const curve_point *leftPart, const curve_point *rightPart) {

	// Initialize hash
	SHA256_CTX hash;
	sha256_Init(&hash);
	
	// Add challenge to the hash
	sha256_Update(&hash, challenge, SHA256_DIGEST_LENGTH);
	
	// Set parity to if the part's y components aren't quadratic residue
	const uint8_t parity = (!mimbleWimbleCoinIsQuadraticResidue(&leftPart->y) << 1) | !mimbleWimbleCoinIsQuadraticResidue(&rightPart->y);
	
	// Add parity to the hash
	sha256_Update(&hash, &parity, sizeof(parity));
	
	// Add left part's x component to the hash
	uint8_t leftPartXComponents[MIMBLEWIMBLE_COIN_PUBLIC_KEY_COMPONENT_SIZE];
	bn_write_be(&leftPart->x, leftPartXComponents);
	sha256_Update(&hash, leftPartXComponents, sizeof(leftPartXComponents));
	
	// Add right part's x component to the hash
	uint8_t rightPartXComponents[MIMBLEWIMBLE_COIN_PUBLIC_KEY_COMPONENT_SIZE];
	bn_write_be(&rightPart->x, rightPartXComponents);
	sha256_Update(&hash, rightPartXComponents, sizeof(rightPartXComponents));
	
	// Set challenge to the hash
	sha256_Final(&hash, challenge);
}

// Create scalars from ChaCha20
void mimbleWimbleCoinCreateScalarsFromChaCha20(bignum256 *firstScalar, bignum256 *secondScalar, const uint8_t *seed, const uint64_t index, const bool isPrivate) {

	// Initialize couter
	uint64_t counter = 0;
	
	// Initialize ChaCha20 Poly1305 state
	ECRYPT_ctx chaCha20Poly1305State;
	ECRYPT_keysetup(&chaCha20Poly1305State, seed, MIMBLEWIMBLE_COIN_SCALAR_SIZE * MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE, 16);
	
	// Initialize zero block
	uint8_t zeroBlock[MIMBLEWIMBLE_COIN_SCALAR_SIZE + MIMBLEWIMBLE_COIN_SCALAR_SIZE];
	
	// Loop while encrypting zero block with ChaCha20 overflows
	do {
	
		// Clear zero block
		memzero(zeroBlock, sizeof(zeroBlock));
		
		// Update ChaCha20 Poly1305 state
		ECRYPT_ivsetup(&chaCha20Poly1305State, (const uint8_t *)&counter);
		ECRYPT_ctrsetup(&chaCha20Poly1305State, (const uint8_t *)&index);
		
		// Encrypt zero block with ChaCha20
		ECRYPT_encrypt_bytes(&chaCha20Poly1305State, zeroBlock, zeroBlock, sizeof(zeroBlock));
		
		// Get scalars from the result
		bn_read_be(zeroBlock, firstScalar);
		bn_read_be(&zeroBlock[MIMBLEWIMBLE_COIN_SCALAR_SIZE], secondScalar);
		
		// Increment counter
		counter += (uint64_t)1 << (sizeof(uint32_t) * MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE);
		
	} while(!bn_is_less(firstScalar, &secp256k1.order) || !bn_is_less(secondScalar, &secp256k1.order));
	
	// Check if private
	if(isPrivate) {
	
		// Clear zero block
		memzero(zeroBlock, sizeof(zeroBlock));
		
		// Clear ChaCha20 Poly1305 state
		memzero(&chaCha20Poly1305State, sizeof(chaCha20Poly1305State));
	}
}

// Use LR generator
void mimbleWimbleCoinUseLrGenerator(bignum256 *t0, bignum256 *t1, bignum256 *t2, const bignum256 *y, const bignum256 *z, const uint8_t *rewindNonce, const uint64_t value, const mp_obj_t updateProgressObject) {

	// Set yn to one
	bignum256 yn;
	bn_one(&yn);
	
	// Set z22n to z squared
	bignum256 z22n;
	bn_copy(z, &z22n);
	bn_multiply(z, &z22n, &secp256k1.order);
	
	// Set inputs to zero, one, and negative one
	bignum256 inputs[3];
	bn_zero(&inputs[0]);
	bn_one(&inputs[1]);
	mimbleWimbleCoin_bn_submod(&inputs[0], &inputs[1], &inputs[2], &secp256k1.order);
	
	// Set outputs
	bignum256 *outputs[] = {t0, t1, t2};
	
	// Go through all outputs
	for(size_t i = 0; i < sizeof(outputs) / sizeof(outputs[0]); ++i) {
	
		// Set output to zero
		bn_zero(outputs[i]);
	}
	
	// Initialize lout and rout
	bignum256 lout;
	bignum256 rout;
	
	// Initialize sl and sr
	bignum256 sl;
	bignum256 sr;
	
	// Initialize temp lout and rout
	bignum256 tempLout;
	bignum256 tempRout;
	
	// Initialize temp sl and sr
	bignum256 tempSl;
	bignum256 tempSr;
	
	// Go through all bits to prove
	for(uint_fast8_t i = 0; i < MIMBLEWIMBLE_COIN_BITS_TO_PROVE; ++i) {
	
		// Get bit in the value
		const bool bit = (value >> i) & 1;
		
		// Set lout
		bn_read_uint32(bit, &lout);
		
		// Subtract z from lout
		mimbleWimbleCoin_bn_submod(&lout, z, &lout, &secp256k1.order);
		
		// Set rout
		bn_read_uint32(1 - bit, &rout);
		
		// Subtract rout from z
		mimbleWimbleCoin_bn_submod(z, &rout, &rout, &secp256k1.order);
		
		// Create sl and sr from rewind nonce
		mimbleWimbleCoinCreateScalarsFromChaCha20(&sl, &sr, rewindNonce, i + 2, false);
		
		// Go through all outputs
		for(size_t j = 0; j < sizeof(outputs) / sizeof(outputs[0]); ++j) {
		
			// Multiply sl by input
			bn_copy(&sl, &tempSl);
			bn_multiply(&inputs[j], &tempSl, &secp256k1.order);
			
			// Multiply sr by input
			bn_copy(&sr, &tempSr);
			bn_multiply(&inputs[j], &tempSr, &secp256k1.order);
			
			// Update lout
			bn_copy(&lout, &tempLout);
			bn_addmod(&tempLout, &tempSl, &secp256k1.order);
			
			// Update rout
			bn_copy(&rout, &tempRout);
			bn_addmod(&tempRout, &tempSr, &secp256k1.order);
			bn_multiply(&yn, &tempRout, &secp256k1.order);
			bn_addmod(&tempRout, &z22n, &secp256k1.order);
			
			// Update output with lout
			bn_multiply(&tempRout, &tempLout, &secp256k1.order);
			bn_addmod(outputs[j], &tempLout, &secp256k1.order);
		}
		
		// Multipy yn by y
		bn_multiply(y, &yn, &secp256k1.order);
		
		// Double z22n
		bn_addmod(&z22n, &z22n, &secp256k1.order);
	}
	
	// Check if progress is shown
	if(updateProgressObject != mp_const_none) {
	
		// Update shown progress
		mp_call_function_1(updateProgressObject, MP_OBJ_NEW_SMALL_INT(1000 * 12 / 12));
	}
	
	// Go through all outputs
	for(size_t i = 0; i < sizeof(outputs) / sizeof(outputs[0]); ++i) {
	
		// Normalize output
		bn_mod(outputs[i], &secp256k1.order);
	}
}

// Calculate Bulletproof components
bool mimbleWimbleCoinCalculateBulletproofComponents(uint8_t *tauX, uint8_t *tOne, uint8_t *tTwo, const uint64_t value, const uint8_t *blindingFactor, const uint8_t *commitment, const uint8_t *rewindNonce, const uint8_t *privateNonce, const uint8_t *message, const mp_obj_t updateProgressObject) {

	// Initialize challenge
	uint8_t challenge[SHA256_DIGEST_LENGTH] = {0};
	
	// Update challenge with the commitment and generator H
	curve_point commitmentPoint;
	bn_read_be(&commitment[MIMBLEWIMBLE_COIN_PUBLIC_KEY_PREFIX_SIZE], &commitmentPoint.x);
	bn_read_be(&commitment[MIMBLEWIMBLE_COIN_PUBLIC_KEY_PREFIX_SIZE + MIMBLEWIMBLE_COIN_PUBLIC_KEY_COMPONENT_SIZE], &commitmentPoint.y);
	mimbleWimbleCoinUpdateBulletproofChallenge(challenge, &commitmentPoint, &MIMBLEWIMBLE_COIN_GENERATOR_H);
	
	// Set message bytes to contain the value and message
	uint8_t messageBytes[MIMBLEWIMBLE_COIN_SCALAR_SIZE] = {0};
	write_be(&messageBytes[MIMBLEWIMBLE_COIN_SCALAR_SIZE - sizeof(uint32_t)], value);
	write_be(&messageBytes[MIMBLEWIMBLE_COIN_SCALAR_SIZE - sizeof(uint64_t)], value >> (sizeof(uint32_t) * MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE));
	memcpy(&messageBytes[MIMBLEWIMBLE_COIN_SCALAR_SIZE - sizeof(value) - MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_SIZE], message, MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_SIZE);
	
	// Create alpha and rho from rewind nonce
	bignum256 alpha;
	bignum256 rho;
	mimbleWimbleCoinCreateScalarsFromChaCha20(&alpha, &rho, rewindNonce, 0, false);
	
	// Subtract message bytes from alpha
	bignum256 messageBytesBigNumber;
	bn_read_be(messageBytes, &messageBytesBigNumber);
	mimbleWimbleCoin_bn_submod(&alpha, &messageBytesBigNumber, &alpha, &secp256k1.order);
	bn_mod(&alpha, &secp256k1.order);
	
	// Check if alpha or rho is zero
	if(bn_is_zero(&alpha) || bn_is_zero(&rho)) {
		
		// Return false
		return false;
	}
	
	// Check if getting the product of alpha and generator G failed
	curve_point alphaImage;
	if(scalar_multiply(&secp256k1, &alpha, &alphaImage)) {
		
		// Return false
		return false;
	}
	
	// Check if the result is infinity
	if(point_is_infinity(&alphaImage)) {
		
		// Return false
		return false;
	}
	
	// Initialize aterm
	curve_point aterm;
	
	// Go through all bits to prove
	for(uint_fast8_t i = 0; i < MIMBLEWIMBLE_COIN_BITS_TO_PROVE; ++i) {
	
		// Get bit in the value
		const bool bit = (value >> i) & 1;
		
		// Set aterm to the generator
		point_copy(bit ? &MIMBLEWIMBLE_COIN_GENERATORS[i * 2 * MIMBLEWIMBLE_COIN_NUMBER_OF_ODD_GENERATOR_MULTIPLES] : &MIMBLEWIMBLE_COIN_GENERATORS[(i * 2 + 1) * MIMBLEWIMBLE_COIN_NUMBER_OF_ODD_GENERATOR_MULTIPLES], &aterm);
		
		// Check if bit isn't set
		if(!bit) {
		
			// Negate aterm's y component
			bn_cnegate(true, &aterm.y, &secp256k1.prime);
			bn_fast_mod(&aterm.y, &secp256k1.prime);
			bn_mod(&aterm.y, &secp256k1.prime);
		}
		
		// Add aterm to the alpha image
		point_add(&secp256k1, &aterm, &alphaImage);
		
		// Check if the result is infinity
		if(point_is_infinity(&alphaImage)) {
		
			// Return false
			return false;
		}
	}
	
	// Check if progress is shown
	if(updateProgressObject != mp_const_none) {

		// Update shown progress
		mp_call_function_1(updateProgressObject, MP_OBJ_NEW_SMALL_INT(1000 * 1 / 12));
	}
	
	// Check if getting the product of rho and generator G failed
	curve_point rhoImage;
	if(scalar_multiply(&secp256k1, &rho, &rhoImage)) {
		
		// Return false
		return false;
	}
	
	// Check if the result is infinity
	if(point_is_infinity(&rhoImage)) {
		
		// Return false
		return false;
	}
	
	// Initialize sl, sr, and sterm
	bignum256 sl;
	bignum256 sr;
	curve_point sterm;
	
	// Go through all multiexponentiation steps
	for(uint_fast8_t i = 0; i < MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS; ++i) {
	
		// Initialize WNAFs
		int8_t wnafs[MIMBLEWIMBLE_COIN_NUMBER_OF_GENERATORS / MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS][WNAF_SIZE];
		
		// Go through all bits to prove in the multiexponentiation step
		for(uint_fast8_t j = 0; j < MIMBLEWIMBLE_COIN_BITS_TO_PROVE / MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS; ++j) {
		
			// Create sl and sr from rewind nonce
			mimbleWimbleCoinCreateScalarsFromChaCha20(&sl, &sr, rewindNonce, i * (MIMBLEWIMBLE_COIN_BITS_TO_PROVE / MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS) + j + 2, false);
			
			// Check if sl or sr is zero
			if(bn_is_zero(&sl) || bn_is_zero(&sr)) {
			
				// Return false
				return false;
			}
			
			// Create WNAFs from sl and sr
			get_wnaf(&secp256k1, &sl, MIMBLEWIMBLE_COIN_GENERATORS_WINDOW_SIZE, wnafs[j * 2]);
			get_wnaf(&secp256k1, &sr, MIMBLEWIMBLE_COIN_GENERATORS_WINDOW_SIZE, wnafs[j * 2 + 1]);
		}
		
		// Get sterm by performing multiexponentiation with generators and WNAFs
		point_multiexponentiation(&secp256k1, &MIMBLEWIMBLE_COIN_GENERATORS[i * MIMBLEWIMBLE_COIN_NUMBER_OF_GENERATORS / MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS * MIMBLEWIMBLE_COIN_NUMBER_OF_ODD_GENERATOR_MULTIPLES], MIMBLEWIMBLE_COIN_NUMBER_OF_GENERATORS / MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS, wnafs, MIMBLEWIMBLE_COIN_GENERATORS_WINDOW_SIZE, &sterm);
		
		// Check if the result is infinity
		if(point_is_infinity(&sterm)) {
		
			// Return false
			return false;
		}
			
		// Add sterm to the rho image
		point_add(&secp256k1, &sterm, &rhoImage);
		
		// Check if the result is infinity
		if(point_is_infinity(&rhoImage)) {
		
			// Return false
			return false;
		}
		
		// Check if progress is shown
		if(updateProgressObject != mp_const_none) {
		
			// Update shown progress
			mp_call_function_1(updateProgressObject, MP_OBJ_NEW_SMALL_INT((1000 * (i + 1) * (12 - 2) / MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS + (1000 * 1)) / 12));
		}
	}
	
	// Update challenge with the alpha image and rho image
	mimbleWimbleCoinUpdateBulletproofChallenge(challenge, &alphaImage, &rhoImage);
	
	// Get y from challenge
	bignum256 y;
	bn_read_be(challenge, &y);
	
	// Check if y overflows or is zero
	if(!bn_is_less(&y, &secp256k1.order) || bn_is_zero(&y)) {
		
		// Return false
		return false;
	}
	
	// Update challenge with the alpha image and rho image
	mimbleWimbleCoinUpdateBulletproofChallenge(challenge, &alphaImage, &rhoImage);
	
	// Get z from challenge
	bignum256 z;
	bn_read_be(challenge, &z);
	
	// Check if z overflows or is zero
	if(!bn_is_less(&z, &secp256k1.order) || bn_is_zero(&z)) {
		
		// Return false
		return false;
	}
	
	// Get t0, t1, and t2 with LR generator
	bignum256 t0;
	bignum256 t1;
	bignum256 t2;
	mimbleWimbleCoinUseLrGenerator(&t0, &t1, &t2, &y, &z, rewindNonce, value, updateProgressObject);
	
	// Get the difference of t1 and t2
	mimbleWimbleCoin_bn_submod(&t1, &t2, &t1, &secp256k1.order);
	
	// Divide the difference by two
	bn_mult_half(&t1, &secp256k1.order);
	bn_mod(&t1, &secp256k1.order);
	
	// Get the difference of t2 and t0
	mimbleWimbleCoin_bn_submod(&t2, &t0, &t2, &secp256k1.order);
	
	// Add t1 to the difference
	bn_addmod(&t2, &t1, &secp256k1.order);
	bn_mod(&t2, &secp256k1.order);
	
	// Check if t1 or t2 is zero
	if(bn_is_zero(&t1) || bn_is_zero(&t2)) {
		
		// Return false
		return false;
	}
	
	// Check if getting the product of the t1 and generator H failed
	curve_point t1Image;
	if(point_multiply(&secp256k1, &t1, &MIMBLEWIMBLE_COIN_GENERATOR_H, &t1Image)) {
	
		// Return false
		return false;
	}
	
	// Check if the result is infinity
	if(point_is_infinity(&t1Image)) {
	
		// Return false
		return false;
	}
	
	// Create tau1 and tau2 from rewind nonce
	bignum256 tau1;
	bignum256 tau2;
	mimbleWimbleCoinCreateScalarsFromChaCha20(&tau1, &tau2, privateNonce, 1, true);
	
	// Check if tau1 or tau2 is zero
	if(bn_is_zero(&tau1) || bn_is_zero(&tau2)) {
	
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
		
		// Return false
		return false;
	}
	
	// Check if getting the product of tau1 and generator G failed
	curve_point tau1Image;
	if(scalar_multiply(&secp256k1, &tau1, &tau1Image)) {
	
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
	
		// Return false
		return false;
	}
	
	// Check if the result is infinity
	if(point_is_infinity(&tau1Image)) {
	
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
	
		// Return false
		return false;
	}
	
	// Set t one to the result
	compress_coords(&tau1Image, tOne);
	
	// Add tau1 image and t1 image
	point_add(&secp256k1, &tau1Image, &t1Image);
	
	// Check if the result is infinity
	if(point_is_infinity(&t1Image)) {
	
		// Clear t one
		memzero(tOne, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
	
		// Return false
		return false;
	}
	
	// Check if getting the product of the t2 and generator H failed
	curve_point t2Image;
	if(point_multiply(&secp256k1, &t2, &MIMBLEWIMBLE_COIN_GENERATOR_H, &t2Image)) {
	
		// Clear t one
		memzero(tOne, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
		
		// Return false
		return false;
	}
	
	// Check if the result is infinity
	if(point_is_infinity(&t2Image)) {
	
		// Clear t one
		memzero(tOne, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
		
		// Return false
		return false;
	}
	
	// Check if getting the product of tau2 and generator G failed
	curve_point tau2Image;
	if(scalar_multiply(&secp256k1, &tau2, &tau2Image)) {
	
		// Clear t one
		memzero(tOne, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
	
		// Return false
		return false;
	}
	
	// Check if the result is infinity
	if(point_is_infinity(&tau2Image)) {
	
		// Clear t one
		memzero(tOne, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
	
		// Return false
		return false;
	}
	
	// Set t two to the result
	compress_coords(&tau2Image, tTwo);
	
	// Add tau2 image and t2 image
	point_add(&secp256k1, &tau2Image, &t2Image);
	
	// Check if the result is infinity
	if(point_is_infinity(&t2Image)) {
	
		// Clear t two
		memzero(tTwo, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear t one
		memzero(tOne, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
	
		// Return false
		return false;
	}
	
	// Update challenge with the t1 image and rho t2
	mimbleWimbleCoinUpdateBulletproofChallenge(challenge, &t1Image, &t2Image);
	
	// Get x from challenge
	bignum256 x;
	bn_read_be(challenge, &x);
	
	// Check if x overflows or is zero
	if(!bn_is_less(&x, &secp256k1.order) || bn_is_zero(&x)) {
	
		// Clear t two
		memzero(tTwo, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear t one
		memzero(tOne, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
		
		// Return false
		return false;
	}
	
	// Get the product of tau1 and x
	bn_multiply(&x, &tau1, &secp256k1.order);
	
	// Square x
	bn_multiply(&x, &x, &secp256k1.order);
	
	// Get the product of tau2 and x
	bn_multiply(&x, &tau2, &secp256k1.order);
	
	// Add the results
	bn_addmod(&tau1, &tau2, &secp256k1.order);
	
	// Clear tau2
	memzero(&tau2, sizeof(tau2));
	
	// Square z
	bn_multiply(&z, &z, &secp256k1.order);
	
	// Get blinding factor as a big number
	bignum256 blindingFactorBigNumber;
	bn_read_be(blindingFactor, &blindingFactorBigNumber);
	
	// Multiply z by the blinding factor big number
	bn_multiply(&z, &blindingFactorBigNumber, &secp256k1.order);
	
	// Add results
	bn_addmod(&blindingFactorBigNumber, &tau1, &secp256k1.order);
	bn_mod(&blindingFactorBigNumber, &secp256k1.order);
	
	// Clear tau1
	memzero(&tau1, sizeof(tau1));
	
	// Set tau x to the result
	bn_write_be(&blindingFactorBigNumber, tauX);
	
	// Clear blinding factor big number
	memzero(&blindingFactorBigNumber, sizeof(blindingFactorBigNumber));
	
	// Return true
	return true;
}

// Get MQS shared private key
bool mimbleWimbleCoinGetMqsSharedPrivateKey(uint8_t *mqsSharedPrivateKey, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index, const char *address, const uint8_t *salt) {

	// Check if getting the public key from the address failed
	uint8_t publicKey[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	if(!mimbleWimbleCoinGetPublicKeyFromMqsAddress(publicKey, coinInfoObject, address, MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, SECP256K1_NAME)) {
	
		// Return false
		return false;
	}
	
	// Check if creating session key from the address private key and public key failed
	uint8_t sessionKey[MIMBLEWIMBLE_COIN_SECP256K1_UNCOMPRESSED_PUBLIC_KEY_SIZE];
	if(ecdh_multiply(&secp256k1, addressPrivateKey, publicKey, sessionKey)) {
	
		// Clear session key
		memzero(sessionKey, sizeof(sessionKey));
		
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Check if the session key is infinity
	curve_point sessionKeyPoint;
	if(!ecdsa_read_pubkey(&secp256k1, sessionKey, &sessionKeyPoint)) {
	
		// Clear session key
		memzero(&sessionKeyPoint, sizeof(sessionKeyPoint));
		memzero(sessionKey, sizeof(sessionKey));
		
		// Return false
		return false;
	}
	
	// Create MQS shared private key from the session key
	pbkdf2_hmac_sha512(&sessionKey[MIMBLEWIMBLE_COIN_PUBLIC_KEY_PREFIX_SIZE], MIMBLEWIMBLE_COIN_PUBLIC_KEY_COMPONENT_SIZE, salt, MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE, MIMBLEWIMBLE_COIN_MQS_SHARED_PRIVATE_KEY_NUMBER_OF_ITERATIONS, mqsSharedPrivateKey, MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE);
	
	// Clear session key
	memzero(&sessionKeyPoint, sizeof(sessionKeyPoint));
	memzero(sessionKey, sizeof(sessionKey));
	
	// Return if MQS shared private key isn't zero
	return !mimbleWimbleCoinIsZero(mqsSharedPrivateKey, MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE);
}

// Get X25519 private key from Ed25519 private key
bool mimbleWimbleCoinGetX25519PrivateKeyFromEd25519PrivateKey(uint8_t *x25519PrivateKey, const uint8_t *ed25519PrivateKey) {

	// Get hash of the Ed25519 private key
	uint8_t hash[SHA512_DIGEST_LENGTH];
	sha512_Raw(ed25519PrivateKey, MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE, hash);
	
	// Clamp the hash
	hash[0] &= 0b11111000;
	hash[31] &= 0b01111111;
	hash[31] |= 0b01000000;
	
	// Check if hash isn't a valid X25519 private key
	if(!mimbleWimbleCoinIsValidX25519PrivateKey(hash, MIMBLEWIMBLE_COIN_X25519_PRIVATE_KEY_SIZE)) {
	
		// Clear hash
		memzero(hash, sizeof(hash));
	
		// Return false
		return false;
	}
	
	// Set X25519 private key to the hash
	memcpy(x25519PrivateKey, hash, MIMBLEWIMBLE_COIN_X25519_PRIVATE_KEY_SIZE);
	
	// Clear hash
	memzero(hash, sizeof(hash));
	
	// Return true
	return true;
}

// Get X25519 public key from Ed25519 public key
bool mimbleWimbleCoinGetX25519PublicKeyFromEd25519PublicKey(uint8_t *x25519PublicKey, const uint8_t *ed25519PublicKey) {

	// Check if uncompressing the ED25519 public key failed
	ge25519 point;
	if(!ge25519_unpack_negative_vartime(&point, ed25519PublicKey)) {
	
		// Return false
		return false;
	}
	
	// Get one plus y
	bignum25519 onePlusY;
	const bignum25519 one = {1};
	curve25519_add(onePlusY, one, point.y);
	
	// Get one minus y
	bignum25519 oneMinusY;
	curve25519_sub(oneMinusY, one, point.y);
	
	// Check if one minus y is zero
	if(!curve25519_isnonzero(oneMinusY)) {
	
		// Return false
		return false;
	}
	
	// Get one plus y divided by one minus y
	curve25519_recip(oneMinusY, oneMinusY);
	curve25519_mul(onePlusY, onePlusY, oneMinusY);
	
	// Set X25519 public key to the result
	curve25519_contract(x25519PublicKey, onePlusY);
	
	// Check if X25519 public key isn't a valid X25519 public key
	if(!mimbleWimbleCoinIsValidX25519PublicKey(x25519PublicKey, MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE)) {
	
		// Clear X25519 public key
		memzero(x25519PublicKey, MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get Tor shared private key
bool mimbleWimbleCoinGetTorSharedPrivateKey(uint8_t *torSharedPrivateKey, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index, const char *address) {

	// Check if getting the public key from the address failed
	uint8_t publicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
	if(!mimbleWimbleCoinGetPublicKeyFromTorAddress(publicKey, address, MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting X25519 public key from public key failed
	uint8_t x25519PublicKey[MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE];
	if(!mimbleWimbleCoinGetX25519PublicKeyFromEd25519PublicKey(x25519PublicKey, publicKey)) {
	
		// Return false
		return false;
	}
	
	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, ED25519_NAME)) {
	
		// Return false
		return false;
	}
	
	// Check if getting X25519 private key from address private key failed
	uint8_t x25519PrivateKey[MIMBLEWIMBLE_COIN_X25519_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetX25519PrivateKeyFromEd25519PrivateKey(x25519PrivateKey, addressPrivateKey)) {
	
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Get Tor shared private key from X25519 private key and X25519 public key
	curve25519_scalarmult(torSharedPrivateKey, x25519PrivateKey, x25519PublicKey);
	
	// Clear X25519 private key
	memzero(x25519PrivateKey, sizeof(x25519PrivateKey));
	
	// Return if Tor shared private key isn't zero
	return !mimbleWimbleCoinIsZero(torSharedPrivateKey, MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE);
}

// Get Slatepack shared private key
bool mimbleWimbleCoinGetSlatepackSharedPrivateKey(uint8_t *slatepackSharedPrivateKey, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index, const uint8_t *ephemeralX25519PublicKey, const uint8_t *encryptedFileKey, const uint8_t *payloadNonce) {

	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, ED25519_NAME)) {
	
		// Return false
		return false;
	}
	
	// Get address private key's public key
	uint8_t addressPublicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
	ed25519_publickey(addressPrivateKey, addressPublicKey);
	
	// Check if getting X25519 private key from address private key failed
	uint8_t x25519PrivateKey[MIMBLEWIMBLE_COIN_X25519_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetX25519PrivateKeyFromEd25519PrivateKey(x25519PrivateKey, addressPrivateKey)) {
	
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
		// Return false
		return false;
	}
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Check if getting X25519 public key from the address public key failed
	uint8_t x25519PublicKey[MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE];
	if(!mimbleWimbleCoinGetX25519PublicKeyFromEd25519PublicKey(x25519PublicKey, addressPublicKey)) {
	
		// Clear X25519 private key
		memzero(x25519PrivateKey, sizeof(x25519PrivateKey));
		
		// Return false
		return false;
	}
	
	// Get shared private key from X25519 private key and X25519 public key
	uint8_t sharedPrivateKey[MIMBLEWIMBLE_COIN_X25519_PRIVATE_KEY_SIZE];
	curve25519_scalarmult(sharedPrivateKey, x25519PrivateKey, ephemeralX25519PublicKey);
	
	// Clear X25519 private key
	memzero(x25519PrivateKey, sizeof(x25519PrivateKey));
	
	// Check if shared private key is zero
	if(mimbleWimbleCoinIsZero(sharedPrivateKey, sizeof(sharedPrivateKey))) {
	
		// Return false
		return false;
	}
	
	// Create salt from ephemeral X25519 public key and X25519 public key
	uint8_t salt[MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE + sizeof(x25519PublicKey)];
	memcpy(salt, ephemeralX25519PublicKey, MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE);
	memcpy(&salt[MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE], x25519PublicKey, sizeof(x25519PublicKey));
	
	// Create wrap key from shared private key and salt
	uint8_t pseudorandomKey[SHA256_DIGEST_LENGTH];
	hmac_sha256(salt, sizeof(salt), sharedPrivateKey, sizeof(sharedPrivateKey), pseudorandomKey);
	uint8_t wrapKey[SHA256_DIGEST_LENGTH];
	hmac_sha256(pseudorandomKey, sizeof(pseudorandomKey), (const uint8_t *)MIMBLEWIMBLE_COIN_AGE_WRAP_KEY_INFO_AND_COUNTER, sizeof(MIMBLEWIMBLE_COIN_AGE_WRAP_KEY_INFO_AND_COUNTER), wrapKey);
	memzero(pseudorandomKey, sizeof(pseudorandomKey));
	
	// Clear shared private key
	memzero(sharedPrivateKey, sizeof(sharedPrivateKey));
	
	// Decrypt file key with the wrap key
	chacha20poly1305_ctx chaCha20Poly1305Context;
	const uint8_t fileKeyNonce[MIMBLEWIMBLE_COIN_CHACHA20_NONCE_SIZE] = {0};
	rfc7539_init(&chaCha20Poly1305Context, wrapKey, fileKeyNonce);
	uint8_t fileKey[MIMBLEWIMBLE_COIN_AGE_FILE_KEY_SIZE];
	chacha20poly1305_decrypt(&chaCha20Poly1305Context, encryptedFileKey, fileKey, sizeof(fileKey));
	
	// Clear wrap key
	memzero(wrapKey, sizeof(wrapKey));
	
	// Get tag
	uint8_t tag[MIMBLEWIMBLE_COIN_POLY1305_TAG_SIZE];
	rfc7539_finish(&chaCha20Poly1305Context, 0, MIMBLEWIMBLE_COIN_AGE_FILE_KEY_SIZE, tag);
	
	// Clear ChaCha20 Poly1305 context
	memzero(&chaCha20Poly1305Context, sizeof(chaCha20Poly1305Context));
	
	// Check if file key's tag isn't correct
	if(!mimbleWimbleCoinIsEqual(&encryptedFileKey[MIMBLEWIMBLE_COIN_AGE_FILE_KEY_SIZE], tag, sizeof(tag))) {
	
		// Clear tag
		memzero(tag, sizeof(tag));
	
		// Clear file key
		memzero(fileKey, sizeof(fileKey));
	
		// Return false
		return false;
	}
	
	// Clear tag
	memzero(tag, sizeof(tag));
	
	// Create Slatepack shared private key from file key and payload nonce
	hmac_sha256(payloadNonce, MIMBLEWIMBLE_COIN_AGE_PAYLOAD_NONCE_SIZE, fileKey, sizeof(fileKey), pseudorandomKey);
	hmac_sha256(pseudorandomKey, sizeof(pseudorandomKey), (const uint8_t *)MIMBLEWIMBLE_COIN_AGE_PAYLOAD_KEY_INFO_AND_COUNTER, sizeof(MIMBLEWIMBLE_COIN_AGE_PAYLOAD_KEY_INFO_AND_COUNTER), slatepackSharedPrivateKey);
	memzero(pseudorandomKey, sizeof(pseudorandomKey));
	
	// Clear file key
	memzero(fileKey, sizeof(fileKey));
	
	// Return if Slatepack shared private key isn't zero
	return !mimbleWimbleCoinIsZero(slatepackSharedPrivateKey, MIMBLEWIMBLE_COIN_CHACHA20_KEY_SIZE);
}

// Create single-signer nonces
bool mimbleWimbleCoinCreateSingleSignerNonces(uint8_t *secretNonce, uint8_t *publicNonce) {

	// Loop while the secret nonce is zero
	bignum256 secretNonceBigNumber;
	do {
	
		// Create random secret nonce
		random_buffer(secretNonce, MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE);
		
		// Get secret nonce as a big number
		bn_read_be(secretNonce, &secretNonceBigNumber);
		
		// Normalize the secret nonce big number
		bn_fast_mod(&secretNonceBigNumber, &secp256k1.order);
		bn_mod(&secretNonceBigNumber, &secp256k1.order);
		
	} while(bn_is_zero(&secretNonceBigNumber));
	
	// Check if getting the product of the secret nonce and generator G failed
	curve_point gImage;
	if(scalar_multiply(&secp256k1, &secretNonceBigNumber, &gImage)) {
	
		// Clear secret nonce
		memzero(secretNonce, MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE);
	
		// Return false
		return false;
	}
	
	// Check if the result is infinity
	if(point_is_infinity(&gImage)) {
	
		// Clear secret nonce
		memzero(secretNonce, MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE);
		
		// Return false
		return false;
	}
	
	// Check if the result's y component isn't quadratic residue
	if(!mimbleWimbleCoinIsQuadraticResidue(&gImage.y)) {
	
		// Negate the secret nonce and the result's y component
		bn_cnegate(true, &secretNonceBigNumber, &secp256k1.order);
		bn_fast_mod(&secretNonceBigNumber, &secp256k1.order);
		bn_mod(&secretNonceBigNumber, &secp256k1.order);
		
		bn_cnegate(true, &gImage.y, &secp256k1.prime);
		bn_fast_mod(&gImage.y, &secp256k1.prime);
		bn_mod(&gImage.y, &secp256k1.prime);
	}
	
	// Set secret nonce to secret nonce big number
	bn_write_be(&secretNonceBigNumber, secretNonce);
	
	// Clear secret nonce big number
	memzero(&secretNonceBigNumber, sizeof(secretNonceBigNumber));
	
	// Check if creating public nonce
	if(publicNonce) {
	
		// Get the public nonce from the result
		compress_coords(&gImage, publicNonce);
	}
	
	// Return true
	return true;
}

// Update blinding factor sum
bool mimbleWimbleCoinUpdateBlindingFactorSum(uint8_t *blindingFactorSum, const uint8_t *blindingFactor, const bool blindingFactorIsPositive) {

	// Get blinding factor sum and blinding factor as a big number
	bignum256 blindingFactorSumBigNumber;
	bn_read_be(blindingFactorSum, &blindingFactorSumBigNumber);
	bignum256 blindingFactorBigNumber;
	bn_read_be(blindingFactor, &blindingFactorBigNumber);

	// Check if blinding factor isn't positive
	if(blindingFactorIsPositive) {
	
		// Add blinding factor to the blinding factor sum
		bn_addmod(&blindingFactorSumBigNumber, &blindingFactorBigNumber, &secp256k1.order);
	}
	
	// Otherwise
	else {
	
		// Subtract blinding factor from the blinding factor sum
		mimbleWimbleCoin_bn_submod(&blindingFactorSumBigNumber, &blindingFactorBigNumber, &blindingFactorSumBigNumber, &secp256k1.order);
	}
	
	// Set blinding factor sum to the result
	bn_mod(&blindingFactorSumBigNumber, &secp256k1.order);
	bn_write_be(&blindingFactorSumBigNumber, blindingFactorSum);
	
	// Clear blinding factor sum and blinding factor big number
	memzero(&blindingFactorSumBigNumber, sizeof(blindingFactorSumBigNumber));
	memzero(&blindingFactorBigNumber, sizeof(blindingFactorBigNumber));
	
	// Return if blinding factor sum is a valid secp256k1 private key
	return mimbleWimbleCoinIsValidSecp256k1PrivateKey(blindingFactorSum, MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE);
}

// Create single-signer signature
bool mimbleWimbleCoinCreateSingleSignerSignature(uint8_t *signature, const uint8_t *message, const uint8_t *privateKey, const uint8_t *secretNonce, const uint8_t *publicNonce, const uint8_t *publicKey) {

	// Check if getting curve point from public nonce failed
	curve_point point;
	if(!ecdsa_read_pubkey(&secp256k1, publicNonce, &point)) {
	
		// Return false
		return false;
	}
	
	// Get secret nonce as a bignumber
	bignum256 secretNonceBigNumber;
	bn_read_be(secretNonce, &secretNonceBigNumber);
	
	// Check if getting the product of the secret nonce big number and generator G failed
	curve_point gImage;
	if(scalar_multiply(&secp256k1, &secretNonceBigNumber, &gImage)) {
	
		// Clear secret nonce big number
		memzero(&secretNonceBigNumber, sizeof(secretNonceBigNumber));
	
		// Return false
		return false;
	}
	
	// Check if the result is infinity
	if(point_is_infinity(&gImage)) {
	
		// Clear secret nonce big number
		memzero(&secretNonceBigNumber, sizeof(secretNonceBigNumber));
		
		// Return false
		return false;
	}
	
	// Set signature's r component
	bn_write_le(&gImage.x, signature);
	
	// Get hash of public nonce's x component, public key, and message
	SHA256_CTX hashContext;
	sha256_Init(&hashContext);
	sha256_Update(&hashContext, &publicNonce[MIMBLEWIMBLE_COIN_PUBLIC_KEY_PREFIX_SIZE], MIMBLEWIMBLE_COIN_PUBLIC_KEY_COMPONENT_SIZE);
	sha256_Update(&hashContext, publicKey, MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	sha256_Update(&hashContext, message, MIMBLEWIMBLE_COIN_SINGLE_SIGNER_MESSAGE_SIZE);
	uint8_t hash[SHA256_DIGEST_LENGTH];
	sha256_Final(&hashContext, hash);
	
	// Get hash as a big number
	bignum256 hashBigNumber;
	bn_read_be(hash, &hashBigNumber);
	
	// Normalize the hash big number
	bn_fast_mod(&hashBigNumber, &secp256k1.order);
	bn_mod(&hashBigNumber, &secp256k1.order);
	
	// Get private key as a bignumber
	bignum256 privateKeyBigNumber;
	bn_read_be(privateKey, &privateKeyBigNumber);
	
	// Multiply private key by the hash big number
	bn_multiply(&hashBigNumber, &privateKeyBigNumber, &secp256k1.order);
	
	// Check if public nonce's y component is quadratic residue
	if(mimbleWimbleCoinIsQuadraticResidue(&point.y)) {
	
		// Add secret nonce to the result
		bn_addmod(&privateKeyBigNumber, &secretNonceBigNumber, &secp256k1.order);
	}
	
	// Otherwise
	else {
	
		// Subtract secret nonce from the result
		mimbleWimbleCoin_bn_submod(&privateKeyBigNumber, &secretNonceBigNumber, &privateKeyBigNumber, &secp256k1.order);
	}
	
	// Clear secret nonce big number
	memzero(&secretNonceBigNumber, sizeof(secretNonceBigNumber));
	
	// Set signature's s component
	bn_mod(&privateKeyBigNumber, &secp256k1.order);
	bn_write_le(&privateKeyBigNumber, &signature[MIMBLEWIMBLE_COIN_SCALAR_SIZE]);
	
	// Clear private key big number
	memzero(&privateKeyBigNumber, sizeof(privateKeyBigNumber));
	
	// Return true
	return true;
}

// Get AES encrypted data length
size_t mimbleWimbleCoinGetAesEncryptedDataLength(const size_t dataLength) {

	// Return encrypted data length
	return dataLength + ((dataLength % AES_BLOCK_SIZE) ? AES_BLOCK_SIZE - dataLength % AES_BLOCK_SIZE : AES_BLOCK_SIZE);
}

// AES encrypt
bool mimbleWimbleCoinAesEncrypt(uint8_t *encryptedData, const uint8_t *key, const uint8_t *data, const size_t dataLength) {

	// Check if creating AES context with the key failed
	aes_encrypt_ctx aesContext;
	if(aes_encrypt_key256(key, &aesContext)) {
	
		// Clear AES context
		memzero(&aesContext, sizeof(aesContext));
		
		// Return false
		return false;
	}
	
	// Pad the data
	uint8_t paddedData[mimbleWimbleCoinGetAesEncryptedDataLength(dataLength)];
	memcpy(paddedData, data, dataLength);
	memset(&paddedData[dataLength], sizeof(paddedData) - dataLength, sizeof(paddedData) - dataLength);
	
	// Check if AES encrypting the padded data failed
	uint8_t aesIv[MIMBLEWIMBLE_COIN_AES_IV_SIZE] = {0};
	if(aes_cbc_encrypt(paddedData, encryptedData, sizeof(paddedData), aesIv, &aesContext)) {
	
		// Clear encrypted data
		memzero(encryptedData, sizeof(paddedData));
		
		// Clear AES IV
		memzero(aesIv, sizeof(aesIv));
		
		// Clear padded data
		memzero(paddedData, sizeof(paddedData));
		
		// Clear AES context
		memzero(&aesContext, sizeof(aesContext));
		
		// Return false
		return false;
	}
	
	// Clear AES IV
	memzero(aesIv, sizeof(aesIv));
	
	// Clear padded data
	memzero(paddedData, sizeof(paddedData));
	
	// Clear AES context
	memzero(&aesContext, sizeof(aesContext));
	
	// Return true
	return true;
}

// AES decrypt
size_t mimbleWimbleCoinAesDecrypt(uint8_t *data, const uint8_t *key, const uint8_t *encryptedData, const size_t encryptedDataLength) {

	// Check if creating AES context with the key failed
	aes_decrypt_ctx aesContext;
	if(aes_decrypt_key256(key, &aesContext)) {
	
		// Clear AES context
		memzero(&aesContext, sizeof(aesContext));
		
		// Return false
		return false;
	}
	
	// Check if AES decrypting the encrypted data failed
	uint8_t aesIv[MIMBLEWIMBLE_COIN_AES_IV_SIZE] = {0};
	if(aes_cbc_decrypt(encryptedData, data, encryptedDataLength, aesIv, &aesContext)) {
		
		// Clear data
		memzero(data, encryptedDataLength);
		
		// Clear AES IV
		memzero(aesIv, sizeof(aesIv));
		
		// Clear AES context
		memzero(&aesContext, sizeof(aesContext));
		
		// Return zero
		return 0;
	}
	
	// Clear AES IV
	memzero(aesIv, sizeof(aesIv));
	
	// Clear AES context
	memzero(&aesContext, sizeof(aesContext));
	
	// Check if last padding byte is invalid
	if(!data[encryptedDataLength - 1] || data[encryptedDataLength - 1] > AES_BLOCK_SIZE || data[encryptedDataLength - 1] > encryptedDataLength) {
	
		// Clear data
		memzero(data, encryptedDataLength);
		
		// Return zero
		return 0;
	}
	
	// Get data length
	const size_t dataLength = encryptedDataLength - data[encryptedDataLength - 1];
	
	// Initialize invalid padding
	bool invalidPadding = false;
	
	// Go through all decrypted bytes
	for(size_t i = 0; i < encryptedDataLength; ++i) {
	
		// Update invalid padding
		const uint8_t mask = -(i >= dataLength);
		invalidPadding |= data[i] ^ ((data[encryptedDataLength - 1] & mask) | (data[i] & ~mask));
	}
	
	// Check if padding is invalid
	if(invalidPadding) {
	
		// Clear data
		memzero(data, encryptedDataLength);
		
		// Return zero
		return 0;
	}
	
	// Return data length
	return dataLength;
}

// Get payment proof message length
size_t mimbleWimbleCoinGetPaymentProofMessageLength(const mp_obj_t coinInfoObject, const uint64_t value, const char *senderAddress) {

	// Get currency's Slatepack address human-readable part
	mp_buffer_info_t slatepackAddressHumanReadablePart;
	mp_get_buffer(mp_load_attr(coinInfoObject, MP_QSTR_slatepackAddressHumanReadablePart), &slatepackAddressHumanReadablePart, MP_BUFFER_READ);
	
	// Get sender address's length
	const size_t senderAddressLength = strlen(senderAddress);
	
	// Check currency's payment proof message type
	switch(mp_obj_get_int(mp_load_attr(coinInfoObject, MP_QSTR_paymentProofMessageType))) {
	
		// ASCII payment proof message
		case MimbleWimbleCoinPaymentProofMessageType_ASCII_PAYMENT_PROOF_MESSAGE: {
		
			// Get value as a string
			char valueBuffer[MIMBLEWIMBLE_COIN_UINT64_BUFFER_SIZE + sizeof((char)'\0')];
			bn_format_uint64(value, NULL, NULL, 0, 0, false, 0, valueBuffer, sizeof(valueBuffer));
			
			// Return payment proof message length
			return MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE + senderAddressLength + strlen(valueBuffer);
		}
		
		// Binary payment proof message
		case MimbleWimbleCoinPaymentProofMessageType_BINARY_PAYMENT_PROOF_MESSAGE:
		
			// Check sender address length
			switch(senderAddressLength) {
			
				// MQS address size
				case MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE:
				
					// Return payment proof message length
					return sizeof(value) + MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE + MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE;
				
				// Tor address size
				case MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE:
				
					// Return payment proof message length
					return sizeof(value) + MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE + MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE;
				
				// Default
				default:
				
					// Check if sender address length is Slatepack address length
					if(senderAddressLength == MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + slatepackAddressHumanReadablePart.len) {
					
						// Return payment proof message length
						return sizeof(value) + MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE + MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE;
					}
					
					// Break
					break;
			}
		
			// Break
			break;
	}
	
	// Return zero
	return 0;
}

// Get payment proof message
bool mimbleWimbleCoinGetPaymentProofMessage(uint8_t *paymentProofMessage, const mp_obj_t coinInfoObject, uint64_t value, const uint8_t *kernelCommitment, const char *senderAddress) {

	// Get currency's Slatepack address human-readable part
	mp_buffer_info_t slatepackAddressHumanReadablePart;
	mp_get_buffer(mp_load_attr(coinInfoObject, MP_QSTR_slatepackAddressHumanReadablePart), &slatepackAddressHumanReadablePart, MP_BUFFER_READ);
	
	// Get sender address's length
	const size_t senderAddressLength = strlen(senderAddress);
	
	// Check currency's payment proof message type
	switch(mp_obj_get_int(mp_load_attr(coinInfoObject, MP_QSTR_paymentProofMessageType))) {
	
		// ASCII payment proof message
		case MimbleWimbleCoinPaymentProofMessageType_ASCII_PAYMENT_PROOF_MESSAGE: {
		
			// Append kernel commitment as a hex string to the payment proof message
			mimbleWimbleCoinToHexString(kernelCommitment, MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE, (char *)paymentProofMessage);
			
			// Append sender address to the payment proof message
			memcpy(&paymentProofMessage[MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE], senderAddress, senderAddressLength);
			
			// Append value as a string to the payment proof message
			char valueBuffer[MIMBLEWIMBLE_COIN_UINT64_BUFFER_SIZE + sizeof((char)'\0')];
			bn_format_uint64(value, NULL, NULL, 0, 0, false, 0, valueBuffer, sizeof(valueBuffer));
			memcpy(&paymentProofMessage[MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE + senderAddressLength], valueBuffer, strlen(valueBuffer));
			
			// Return true
			return true;
		}
		
		// Binary payment proof message
		case MimbleWimbleCoinPaymentProofMessageType_BINARY_PAYMENT_PROOF_MESSAGE:
		
			// Check sender address length
			switch(senderAddressLength) {
			
				// MQS address size
				case MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE: {
				
					// Check if getting public key from the sender address failed
					uint8_t publicKey[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
					if(!mimbleWimbleCoinGetPublicKeyFromMqsAddress(publicKey, coinInfoObject, senderAddress, senderAddressLength)) {
					
						// Return false
						return false;
					}
					
					// Check if little endian
					#if BYTE_ORDER == LITTLE_ENDIAN
					
						// Make value big endian
						REVERSE64(value, value);
					#endif
					
					// Append value to the payment proof message
					memcpy(paymentProofMessage, &value, sizeof(value));
					
					// Append kernel commitment to the payment proof message
					memcpy(&paymentProofMessage[sizeof(value)], kernelCommitment, MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE);
					
					// Append public key to the payment proof message
					memcpy(&paymentProofMessage[sizeof(value) + MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE], publicKey, sizeof(publicKey));
				
					// Return true
					return true;
				}
				
				// Tor address size
				case MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE: {
				
					// Check if getting public key from the sender address failed
					uint8_t publicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
					if(!mimbleWimbleCoinGetPublicKeyFromTorAddress(publicKey, senderAddress, senderAddressLength)) {
					
						// Return false
						return false;
					}
					
					// Check if little endian
					#if BYTE_ORDER == LITTLE_ENDIAN
					
						// Make value big endian
						REVERSE64(value, value);
					#endif
					
					// Append value to the payment proof message
					memcpy(paymentProofMessage, &value, sizeof(value));
					
					// Append kernel commitment to the payment proof message
					memcpy(&paymentProofMessage[sizeof(value)], kernelCommitment, MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE);
					
					// Append public key to the payment proof message
					memcpy(&paymentProofMessage[sizeof(value) + MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE], publicKey, sizeof(publicKey));
					
					// Return true
					return true;
				}
				
				// Default
				default:
				
					// Check if sender address length is Slatepack address length
					if(senderAddressLength == MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + slatepackAddressHumanReadablePart.len) {
					
						// Check if getting public key from the sender address failed
						uint8_t publicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
						if(!mimbleWimbleCoinGetPublicKeyFromSlatepackAddress(publicKey, coinInfoObject, senderAddress, senderAddressLength)) {
						
							// Return false
							return false;
						}
						
						// Check if little endian
						#if BYTE_ORDER == LITTLE_ENDIAN
						
							// Make value big endian
							REVERSE64(value, value);
						#endif
						
						// Append value to the payment proof message
						memcpy(paymentProofMessage, &value, sizeof(value));
						
						// Append kernel commitment to the payment proof message
						memcpy(&paymentProofMessage[sizeof(value)], kernelCommitment, MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE);
						
						// Append public key to the payment proof message
						memcpy(&paymentProofMessage[sizeof(value) + MIMBLEWIMBLE_COIN_COMPRESSED_COMMITMENT_SIZE], publicKey, sizeof(publicKey));
						
						// Return true
						return true;
					}
					
					// Break
					break;
			}
		
			// Break
			break;
	}
	
	// Return false
	return false;
}

// Verify payment proof message
bool mimbleWimbleCoinVerifyPaymentProofMessage(const uint8_t *paymentProofMessage, const size_t paymentProofMessageLength, const mp_obj_t coinInfoObject, const char *receiverAddress, const uint8_t *paymentProof, const size_t paymentProofLength) {

	// Get currency's Slatepack address human-readable part
	mp_buffer_info_t slatepackAddressHumanReadablePart;
	mp_get_buffer(mp_load_attr(coinInfoObject, MP_QSTR_slatepackAddressHumanReadablePart), &slatepackAddressHumanReadablePart, MP_BUFFER_READ);
	
	// Get receiver address's length
	const size_t receiverAddressLength = strlen(receiverAddress);
	
	// Check receiver address length
	switch(receiverAddressLength) {
	
		// MQS address size
		case MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE: {
		
			// Check if getting receiver public key from receiver address failed
			uint8_t receiverPublicKey[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
			if(!mimbleWimbleCoinGetPublicKeyFromMqsAddress(receiverPublicKey, coinInfoObject, receiverAddress, receiverAddressLength)) {
			
				// Return false
				return false;
			}
			
			// Check if getting payment proof signature from payment proof failed
			uint8_t paymentProofSignature[MIMBLEWIMBLE_COIN_SECP256K1_COMPACT_SIGNATURE_SIZE];
			if(ecdsa_sig_from_der(paymentProof, paymentProofLength, paymentProofSignature)) {
			
				// Return false
				return false;
			}
			
			// Return if payment proof signature verifies the payment proof message
			return !ecdsa_verify(&secp256k1, HASHER_SHA2, receiverPublicKey, paymentProofSignature, paymentProofMessage, paymentProofMessageLength);
		}
		
		// Tor address size
		case MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE: {
		
			// Check if getting receiver public key from receiver address failed
			uint8_t receiverPublicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
			if(!mimbleWimbleCoinGetPublicKeyFromTorAddress(receiverPublicKey, receiverAddress, receiverAddressLength)) {
			
				// Return false
				return false;
			}
			
			// Check if payment proof length is invalid
			if(paymentProofLength != MIMBLEWIMBLE_COIN_ED25519_SIGNATURE_SIZE) {
			
				// Return false
				return false;
			}
			
			// Return if payment proof verifies the payment proof message
			return !ed25519_sign_open(paymentProofMessage, paymentProofMessageLength, receiverPublicKey, paymentProof);
		}
		
		// Default
		default:
		
			// Check if receiver address length is Slatepack address length
			if(receiverAddressLength == MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + slatepackAddressHumanReadablePart.len) {
			
				// Check if getting receiver public key from receiver address failed
				uint8_t receiverPublicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
				if(!mimbleWimbleCoinGetPublicKeyFromSlatepackAddress(receiverPublicKey, coinInfoObject, receiverAddress, receiverAddressLength)) {
				
					// Return false
					return false;
				}
				
				// Check if payment proof length is invalid
				if(paymentProofLength != MIMBLEWIMBLE_COIN_ED25519_SIGNATURE_SIZE) {
				
					// Return false
					return false;
				}
				
				// Return if payment proof verifies the payment proof message
				return !ed25519_sign_open(paymentProofMessage, paymentProofMessageLength, receiverPublicKey, paymentProof);
			}
		
			// Break
			break;
	}
	
	// Return false
	return false;
}

// To hex string
void mimbleWimbleCoinToHexString(const uint8_t *data, const size_t length, char *string) {

	// Go through all bytes in the data
	for(size_t i = 0; i < length; ++i) {
	
		// Set hex characters in string
		string[i * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE] = MIMBLEWIMBLE_COIN_HEX_CHARACTERS[(data[i] >> (MIMBLEWIMBLE_COIN_BITS_IN_A_BYTE / 2)) & 0xF];
		string[i * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE + 1] = MIMBLEWIMBLE_COIN_HEX_CHARACTERS[data[i] & 0xF];
	}
}

// Is zero
bool mimbleWimbleCoinIsZero(const uint8_t *data, const size_t length) {

	// Initialize sum
	uint8_t sum = 0;
	
	// Go through all bytes in the data
	for(size_t i = 0; i < length; ++i) {
	
		// Or byte with the sum
		sum |= data[i];
	}
	
	// Return if sum is zero
	return !sum;
}

// Is valid secp256k1 public key
bool mimbleWimbleCoinIsValidSecp256k1PublicKey(const uint8_t *publicKey, const size_t publicKeyLength) {

	// Check if public key length isn't correct
	if(publicKeyLength != MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if public key's prefix isn't correct
	if(publicKey[0] != MIMBLEWIMBLE_COIN_SECP256k1_EVEN_COMPRESSED_PUBLIC_KEY_PREFIX && publicKey[0] != MIMBLEWIMBLE_COIN_SECP256k1_ODD_COMPRESSED_PUBLIC_KEY_PREFIX) {
	
		// Return false
		return false;
	}
	
	// Return if public key is a valid secp256k1 public key
	curve_point temp;
	return ecdsa_read_pubkey(&secp256k1, publicKey, &temp);
}

// Is valid X25519 public key
bool mimbleWimbleCoinIsValidX25519PublicKey(__attribute__((unused)) const uint8_t *publicKey, const size_t publicKeyLength) {

	// Return if public key length is correct
	return publicKeyLength == MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE;
}

// Is valid secp256k1 private key
bool mimbleWimbleCoinIsValidSecp256k1PrivateKey(const uint8_t *privateKey, const size_t privateKeyLength) {

	// Check if private key length isn't correct
	if(privateKeyLength != MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE) {
	
		// Return false
		return false;
	}
	
	// Get private key as a big number
	bignum256 privateKeyBigNumber;
	bn_read_be(privateKey, &privateKeyBigNumber);
	
	// Set result to if the private key doesn't overflow and isn't zero
	const bool result = bn_is_less(&privateKeyBigNumber, &secp256k1.order) && !bn_is_zero(&privateKeyBigNumber);
	
	// Clear private key big number
	memzero(&privateKeyBigNumber, sizeof(privateKeyBigNumber));
	
	// Return result
	return result;
}

// Get MQS address
bool mimbleWimbleCoinGetMqsAddress(char *mqsAddress, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index) {

	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, SECP256K1_NAME)) {
	
		// Return false
		return false;
	}
	
	// Check if getting address private key's public key failed
	uint8_t addressPublicKey[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	if(!mimbleWimbleCoinGetPublicKeyFromSecp256k1PrivateKey(addressPublicKey, addressPrivateKey)) {
	
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return if getting the MQS address from the public key was successful
	return mimbleWimbleCoinGetMqsAddressFromPublicKey(mqsAddress, coinInfoObject, addressPublicKey);
}

// Get Tor address
bool mimbleWimbleCoinGetTorAddress(char *torAddress, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index) {

	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, ED25519_NAME)) {
	
		// Return false
		return false;
	}
	
	// Get address private key's public key
	uint8_t addressPublicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
	ed25519_publickey(addressPrivateKey, addressPublicKey);
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return if getting the Tor address from the public key was successful
	return mimbleWimbleCoinGetTorAddressFromPublicKey(torAddress, addressPublicKey);
}

// Get Slatepack address
bool mimbleWimbleCoinGetSlatepackAddress(char *slatepackAddress, const HDNode *extendedPrivateKey, const mp_obj_t coinInfoObject, const uint32_t index) {

	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, ED25519_NAME)) {
	
		// Return false
		return false;
	}
	
	// Get address private key's public key
	uint8_t addressPublicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
	ed25519_publickey(addressPrivateKey, addressPublicKey);
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return if getting the Slatepack address from the public key was successful
	return mimbleWimbleCoinGetSlatepackAddressFromPublicKey(slatepackAddress, coinInfoObject, addressPublicKey);
}

// Is leap year
bool mimbleWimbleCoinIsLeapYear(const uint32_t year) {

	// Return if year is a leap year
	return !(year % 4) && (year % 100 || !(year % 400));
}

// Epoch to time
void mimbleWimbleCoinEpochToTime(MimbleWimbleCoinTime *time, const uint64_t epoch) {

	// Based on code by Alexey Frunze and Andre Kampling (https://stackoverflow.com/a/11197532)

	// Get seconds from 1601 to epoch
	uint64_t seconds = epoch + MIMBLEWIMBLE_COIN_SECONDS_FROM_1601_TO_1970;

	// Remove quadricentennials from seconds
	const uint16_t quadricentennials = seconds / MIMBLEWIMBLE_COIN_SECONDS_IN_A_QUADRICENTENNIAL;
	seconds %= MIMBLEWIMBLE_COIN_SECONDS_IN_A_QUADRICENTENNIAL;

	// Remove centennials from seconds
	const uint8_t centennials = MIN(seconds / MIMBLEWIMBLE_COIN_SECONDS_IN_A_CENTENNIAL, MIMBLEWIMBLE_COIN_MAXIMUM_CENTENNIALS);
	seconds -= (uint64_t)centennials * MIMBLEWIMBLE_COIN_SECONDS_IN_A_CENTENNIAL;

	// Remove quadrennials from seconds
	const uint8_t quadrennials = MIN(seconds / MIMBLEWIMBLE_COIN_SECONDS_IN_A_QUADRENNIAL, MIMBLEWIMBLE_COIN_MAXIMUM_QUADRENNIALS);
	seconds -= (uint64_t)quadrennials * MIMBLEWIMBLE_COIN_SECONDS_IN_A_QUADRENNIAL;

	// Remove annuals from seconds
	const uint8_t annuals = MIN(seconds / MIMBLEWIMBLE_COIN_SECONDS_IN_AN_ANNUAL, MIMBLEWIMBLE_COIN_MAXIMUM_ANNUALS);
	seconds -= (uint64_t)annuals * MIMBLEWIMBLE_COIN_SECONDS_IN_AN_ANNUAL;

	// Remove year day from seconds
	const uint16_t yearDay = seconds / MIMBLEWIMBLE_COIN_SECONDS_IN_A_DAY;
	seconds %= MIMBLEWIMBLE_COIN_SECONDS_IN_A_DAY;

	// Set time's hour
	time->hour = seconds / MIMBLEWIMBLE_COIN_SECONDS_IN_AN_HOUR;

	// Remove hour from seconds
	seconds %= MIMBLEWIMBLE_COIN_SECONDS_IN_AN_HOUR;

	// Set time's minute
	time->minute = seconds / MIMBLEWIMBLE_COIN_SECONDS_IN_A_MINUTE;

	// Remove minute from seconds
	seconds %= MIMBLEWIMBLE_COIN_SECONDS_IN_A_MINUTE;

	// Set time's second
	time->second = seconds;

	// Set time's year
	time->year = MIMBLEWIMBLE_COIN_REBASE_YEAR + quadricentennials * MIMBLEWIMBLE_COIN_YEARS_IN_A_QUADRICENTENNIAL + centennials * MIMBLEWIMBLE_COIN_YEARS_IN_A_CENTENNIAL + quadrennials * MIMBLEWIMBLE_COIN_YEARS_IN_A_QUADRENNIAL + annuals;

	// Get if year is a leap year
	const bool leapYear = mimbleWimbleCoinIsLeapYear(time->year);

	// Go through all months
	for(time->day = time->month = 1; time->month <= MIMBLEWIMBLE_COIN_MONTHS_IN_A_YEAR; ++time->month) {

		// Check if year day is in the month
		if(yearDay < MIMBLEWIMBLE_COIN_DAYS_SINCE_JANUARY_FIRST[leapYear ? 1 : 0][time->month]) {

			// Update time's day
			time->day += yearDay - MIMBLEWIMBLE_COIN_DAYS_SINCE_JANUARY_FIRST[leapYear ? 1 : 0][time->month - 1];

			// Break
			break;
		}
	}
}

// Get login private key
bool mimbleWimbleCoinGetLoginPrivateKey(uint8_t *loginPrivateKey, const HDNode *extendedPrivateKey) {

	// Import switch type module
	const mp_obj_t switchTypeModule = mp_import_name(qstr_from_str("trezor.enums.MimbleWimbleCoinSwitchType"), mp_const_empty_tuple, MP_OBJ_NEW_SMALL_INT(0));
	
	// Initialize path
	const uint32_t path[] = {
		0,
		2,
		0
	};
	
	// Check if deriving blinding factor from the path failed
	uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
	if(!mimbleWimbleCoinDeriveBlindingFactor(blindingFactor, extendedPrivateKey, 0, path, sizeof(path) / sizeof(path[0]), mp_load_attr(switchTypeModule, MP_QSTR_NONE))) {
	
		// Return false
		return false;
	}
	
	// Check if getting login private key as the hash of the blinding factor failed
	if(blake2b(blindingFactor, sizeof(blindingFactor), loginPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE)) {
	
		// Clear login private key
		memzero(loginPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE);
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Check if login private key isn't a valid secp256k1 private key
	if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(loginPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE)) {
	
		// Clear login private key
		memzero(loginPrivateKey, MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}
