// Header files
#include "base58.h"
#include "base32.h"
#include "mimblewimble_coin_generators.h"
#include "mimblewimble_coin_generators.c"

/// package: trezorcrypto.mimblewimble_coin
/// from enum import IntEnum, IntFlag
/// from trezorcrypto.bip32 import HDNode
/// from apps.mimblewimble_coin.coins import CoinInfo
/// from trezor.enums import MimbleWimbleCoinSwitchType


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
#define MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS 4

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

// ChaCha 20 nonce size
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

// Address derivation type
/// class AddressDerivationType(IntEnum):
///     """
///     Address derivation type
///     """
///     MWC_ADDRESS_DERIVATION = 0
///     GRIN_ADDRESS_DERIVATION = 1
typedef enum _MimbleWimbleCoinAddressDerivationType {

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
typedef enum _MimbleWimbleCoinPaymentProofMessageType {

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
typedef enum _MimbleWimbleCoinPaymentProofAddressType {

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
typedef enum _MimbleWimbleCoinSlateEncryptionType {

	// MQS slate encryption
	MimbleWimbleCoinSlateEncryptionType_MQS_SLATE_ENCRYPTION = 1 << 0,
	
	// Tor slate encryption
	MimbleWimbleCoinSlateEncryptionType_TOR_SLATE_ENCRYPTION = 1 << 1,
	
	// Slatepack slate encryption
	MimbleWimbleCoinSlateEncryptionType_SLATEPACK_SLATE_ENCRYPTION = 1 << 2

} MimbleWimbleCoinSlateEncryptionType;

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


// Function prototypes

/// mock:global

// Get root public key
/// def getRootPublicKey(extendedPrivateKey: HDNode) -> bytes:
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

// Address derivation type table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_table[] = {

	// MWC address derivation
	{MP_ROM_QSTR(MP_QSTR_MWC_ADDRESS_DERIVATION), MP_ROM_INT(MimbleWimbleCoinAddressDerivationType_MWC_ADDRESS_DERIVATION)},
	
	// GRIN address derivation
	{MP_ROM_QSTR(MP_QSTR_GRIN_ADDRESS_DERIVATION), MP_ROM_INT(MimbleWimbleCoinAddressDerivationType_GRIN_ADDRESS_DERIVATION)}
};

// Address derivation type dictionary
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_dictionary, mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_table);

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
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_PaymentProofMessageType_dictionary, mod_trezorcrypto_mimblewimble_coin_PaymentProofMessageType_table);

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
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_PaymentProofAddressType_dictionary, mod_trezorcrypto_mimblewimble_coin_PaymentProofAddressType_table);

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
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_dictionary, mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_table);

// Slate encryption type type
STATIC const mp_obj_type_t mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_type = {
	.base = {&mp_type_type},
	.name = MP_QSTR_SlateEncryptionType,
	.locals_dict = (mp_obj_dict_t *)&mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_dictionary
};

// Get root public key function
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_getRootPublicKey_function, mod_trezorcrypto_mimblewimble_coin_getRootPublicKey);

// Get MQS address function
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_mimblewimble_coin_getMqsAddress_function, mod_trezorcrypto_mimblewimble_coin_getMqsAddress);

// Get Tor address function
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_mimblewimble_coin_getTorAddress_function, mod_trezorcrypto_mimblewimble_coin_getTorAddress);

// Get Slatepack address function
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_mimblewimble_coin_getSlatepackAddress_function, mod_trezorcrypto_mimblewimble_coin_getSlatepackAddress);

// Get seed cookie function
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_getSeedCookie_function, mod_trezorcrypto_mimblewimble_coin_getSeedCookie);

// Get commitment function
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_getCommitment_function, 4, 4, mod_trezorcrypto_mimblewimble_coin_getCommitment);

// Get Bulletproof components function
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_mimblewimble_coin_getBulletproofComponents_function, 5, 5, mod_trezorcrypto_mimblewimble_coin_getBulletproofComponents);

// Globals table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_globals_table[] = {

	// Name
	{MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_mimblewimble_coin)},
	
	// MQS address size
	{MP_ROM_QSTR(MP_QSTR_MQS_ADDRESS_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE)},
	
	// Identifier depth index
	{MP_ROM_QSTR(MP_QSTR_IDENTIFIER_DEPTH_INDEX), MP_ROM_INT(MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX)},
	
	// Maximum identifier depth
	{MP_ROM_QSTR(MP_QSTR_MAXIMUM_IDENTIFIER_DEPTH), MP_ROM_INT(MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH)},
	
	// Identifier size
	{MP_ROM_QSTR(MP_QSTR_IDENTIFIER_SIZE), MP_ROM_INT(MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE)},
	
	// Address derivation type
	{MP_ROM_QSTR(MP_QSTR_AddressDerivationType), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_AddressDerivationType_type)},
	
	// Payment proof message type
	{MP_ROM_QSTR(MP_QSTR_PaymentProofMessageType), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_PaymentProofMessageType_type)},
	
	// Payment proof address type
	{MP_ROM_QSTR(MP_QSTR_PaymentProofAddressType), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_PaymentProofAddressType_type)},
	
	// Slate encryption type
	{MP_ROM_QSTR(MP_QSTR_SlateEncryptionType), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_SlateEncryptionType_type)},
	
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
	{MP_ROM_QSTR(MP_QSTR_getBulletproofComponents), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getBulletproofComponents_function)}
};

// Globals dictionary
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_globals_dictionary, mod_trezorcrypto_mimblewimble_coin_globals_table);

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
	
	// Initialize root public key
	vstr_t rootPublicKey;
	vstr_init(&rootPublicKey, sizeof(extendedPrivateKey->public_key));
	rootPublicKey.len = sizeof(extendedPrivateKey->public_key);
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
		// Clear extended private key's public key
		memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Set root public key to the extended private key's public key
	memcpy(rootPublicKey.buf, extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Clear extended private key's public key
	memzero(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key));
	
	// Return root public key
	return mp_obj_new_str_from_vstr(&mp_type_bytes, &rootPublicKey);
}

// Get MQS address
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getMqsAddress(const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject, const mp_obj_t indexObject) {

	// Get extended private key
	const HDNode *extendedPrivateKey = &((mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Initialize MQS address
	vstr_t mqsAddress;
	vstr_init_len(&mqsAddress, MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE);
	
	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_SECP256K1_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, SECP256K1_NAME)) {
	
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if getting address private key's public key failed
	uint8_t addressPublicKey[MIMBLEWIMBLE_COIN_SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	if(!mimbleWimbleCoinGetPublicKeyFromSecp256k1PrivateKey(addressPublicKey, addressPrivateKey)) {
	
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Check if getting MQS address from the public key failed
	if(!mimbleWimbleCoinGetMqsAddressFromPublicKey(mqsAddress.buf, coinInfoObject, addressPublicKey)) {
	
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Return MQS address
	return mp_obj_new_str_from_vstr(&mp_type_str, &mqsAddress);
}

// Get Tor address
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getTorAddress(const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject, const mp_obj_t indexObject) {

	// Get extended private key
	const HDNode *extendedPrivateKey = &((mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Initialize Tor address
	vstr_t torAddress;
	vstr_init_len(&torAddress, MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE);
	
	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, ED25519_NAME)) {
	
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Get address private key's public key
	uint8_t addressPublicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
	ed25519_publickey(addressPrivateKey, addressPublicKey);
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Check if getting Tor address from the public key failed
	if(!mimbleWimbleCoinGetTorAddressFromPublicKey(torAddress.buf, addressPublicKey)) {
	
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Return Tor address
	return mp_obj_new_str_from_vstr(&mp_type_str, &torAddress);
}

// Get Slatepack address
mp_obj_t mod_trezorcrypto_mimblewimble_coin_getSlatepackAddress(const mp_obj_t extendedPrivateKeyObject, const mp_obj_t coinInfoObject, const mp_obj_t indexObject) {

	// Get extended private key
	const HDNode *extendedPrivateKey = &((mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
	// Get currency's Slatepack address human-readable part
	mp_buffer_info_t slatepackAddressHumanReadablePart;
	mp_get_buffer(mp_load_attr(coinInfoObject, MP_QSTR_slatepackAddressHumanReadablePart), &slatepackAddressHumanReadablePart, MP_BUFFER_READ);
	
	// Get index
	const uint32_t index = mp_obj_get_int(indexObject);
	
	// Initialize Slatepack address
	vstr_t slatepackAddress;
	vstr_init_len(&slatepackAddress, MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + slatepackAddressHumanReadablePart.len);
	
	// Check if getting address private key failed
	uint8_t addressPrivateKey[MIMBLEWIMBLE_COIN_ED25519_PRIVATE_KEY_SIZE];
	if(!mimbleWimbleCoinGetAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfoObject, index, ED25519_NAME)) {
	
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Get address private key's public key
	uint8_t addressPublicKey[MIMBLEWIMBLE_COIN_ED25519_PUBLIC_KEY_SIZE];
	ed25519_publickey(addressPrivateKey, addressPublicKey);
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Check if getting Slatepack address from the public key failed
	if(!mimbleWimbleCoinGetSlatepackAddressFromPublicKey(slatepackAddress.buf, coinInfoObject, addressPublicKey)) {
	
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
	const HDNode *extendedPrivateKey = &((mp_obj_HDNode_t *)MP_OBJ_TO_PTR(extendedPrivateKeyObject))->hdnode;
	
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
	const uint8_t identifierDepth = ((uint8_t *)identifier.buf)[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &((uint8_t *)identifier.buf)[sizeof(identifierDepth)], MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE - sizeof(identifierDepth));
	
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
	
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if commiting value failed
	if(!mimbleWimbleCoinCommitValue((uint8_t *)commitment.buf, value, blindingFactor, true)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
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
	const uint8_t identifierDepth = ((uint8_t *)identifier.buf)[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &((uint8_t *)identifier.buf)[sizeof(identifierDepth)], MIMBLEWIMBLE_COIN_IDENTIFIER_SIZE - sizeof(identifierDepth));
	
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
	
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Check if commiting value failed
	uint8_t commitment[MIMBLEWIMBLE_COIN_UNCOMPRESSED_COMMITMENT_SIZE];
	if(!mimbleWimbleCoinCommitValue(commitment, value, blindingFactor, false)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
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
		
		// Raise error
		mp_raise_ValueError(NULL);
	}
	
	// Create message
	uint8_t message[MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_SIZE] = {
	
		// Switch type
		[MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_SWITCH_TYPE_INDEX] = mp_obj_get_int(switchTypeObject)
	};
	memcpy(&message[MIMBLEWIMBLE_COIN_BULLETPROOF_MESSAGE_IDENTIFIER_INDEX], identifier.buf, identifier.len);
	
	// Check if calculating Bulletproof components failed
	if(!mimbleWimbleCoinCalculateBulletproofComponents((uint8_t *)tauX.buf, (uint8_t *)tOne.buf, (uint8_t *)tTwo.buf, value, blindingFactor, commitment, rewindNonce, privateNonce, message, updateProgressObject)) {
	
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
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
		
		// Check if time to update progress
		if(!(i % 32)) {
		
			// Check if progress is shown
			if(updateProgressObject != mp_const_none) {
			
				// Update shown progress
				mp_call_function_1(updateProgressObject, mp_obj_new_int(1000 * (i + 64 * 2) / (64 * 3)));
			}
		}
	}
	
	// Go through all outputs
	for(size_t i = 0; i < sizeof(outputs) / sizeof(outputs[0]); ++i) {
	
		// Normalize output
		bn_mod(outputs[i], &secp256k1.order);
	}
	
	// Check if progress is shown
	if(updateProgressObject != mp_const_none) {
	
		// Update shown progress
		mp_call_function_1(updateProgressObject, mp_obj_new_int(1000));
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
		
		// Check if time to update progress
		if(!(i % 32)) {
		
			// Check if progress is shown
			if(updateProgressObject != mp_const_none) {
		
				// Update shown progress
				mp_call_function_1(updateProgressObject, mp_obj_new_int(1000 * i / (64 * 3)));
			}
		}
	}
	
	// Check if progress is shown
	if(updateProgressObject != mp_const_none) {
	
		// Update shown progress
		mp_call_function_1(updateProgressObject, mp_obj_new_int(1000 * 64 / (64 * 3)));
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
			mp_call_function_1(updateProgressObject, mp_obj_new_int(1000 * (i * (MIMBLEWIMBLE_COIN_BITS_TO_PROVE / MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS) + MIMBLEWIMBLE_COIN_BITS_TO_PROVE / MIMBLEWIMBLE_COIN_MULTIEXPONENTIATION_STEPS + 64) / (64 * 3)));
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
		invalidPadding |= data[i] ^ ((i >= dataLength) ? data[encryptedDataLength - 1] : data[i]);
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
