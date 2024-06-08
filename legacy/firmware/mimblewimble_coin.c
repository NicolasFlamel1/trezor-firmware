// Header files
#define __USE_GNU
#define _GNU_SOURCE
#include <string.h>
#undef _GNU_SOURCE
#undef __USE_GNU
#include <ctype.h>
#include "mimblewimble_coin.h"
#include "curves.h"
#include "secp256k1.h"
#include "memzero.h"
#include "crypto.h"
#include "hmac.h"
#include "base58.h"
#include "base32.h"
#include "segwit_addr.h"
#include "chacha20poly1305/rfc7539.h"
#include "mimblewimble_coin_generators.h"
#include "layout.h"
#include "rand.h"
#include "pbkdf2.h"
#include "ed25519-donna/ed25519-donna.h"
#include "aes/aes.h"
#include "config.h"


// Definitions

// Secp256k1 private key size
#define SECP256K1_PRIVATE_KEY_SIZE 32

// Secp256k1 compressed public key size
#define SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE 33

// Secp256k1 uncompressed public key size
#define SECP256K1_UNCOMPRESSED_PUBLIC_KEY_SIZE 65

// Secp256k1 even compressed public key prefix
#define SECP256k1_EVEN_COMPRESSED_PUBLIC_KEY_PREFIX 2

// Secp256k1 odd compressed public key prefix
#define SECP256k1_ODD_COMPRESSED_PUBLIC_KEY_PREFIX 3

// Ed25519 private key size
#define ED25519_PRIVATE_KEY_SIZE 32

// Ed25519 public key size
#define ED25519_PUBLIC_KEY_SIZE 32

// X25519 private key size
#define X25519_PRIVATE_KEY_SIZE 32

// Commitment even prefix
#define COMMITMENT_EVEN_PREFIX 8

// Commitment odd prefix
#define COMMITMENT_ODD_PREFIX 9

// Public key prefix size
#define PUBLIC_KEY_PREFIX_SIZE 1

// Public key component size
#define PUBLIC_KEY_COMPONENT_SIZE 32

// Address private key blinding factor value
#define ADDRESS_PRIVATE_KEY_BLINDING_FACTOR_VALUE 713

// Node size
#define NODE_SIZE 64

// Chain code size
#define CHAIN_CODE_SIZE 32

// Tor address checksum size
#define TOR_ADDRESS_CHECKSUM_SIZE 2

// Bits in a byte
#define BITS_IN_A_BYTE 8

// Bech32 bits per character
#define BECH32_BITS_PER_CHARACTER 5

// Compressed commitment size
#define COMPRESSED_COMMITMENT_SIZE 33

// Uncompressed commitment size
#define UNCOMPRESSED_COMMITMENT_SIZE 65

// Identifier size
#define IDENTIFIER_SIZE (sizeof(uint8_t) + MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH * sizeof(uint32_t))

// Bulletproof message size
#define BULLETPROOF_MESSAGE_SIZE 20

// Bulletproof message switch type index
#define BULLETPROOF_MESSAGE_SWITCH_TYPE_INDEX 2

// Bulletproof message identidier index
#define BULLETPROOF_MESSAGE_IDENTIFIER_INDEX 3

// Bits to prove
#define BITS_TO_PROVE (sizeof(uint64_t) * BITS_IN_A_BYTE)

// Multiexponentiation steps
#define MULTIEXPONENTIATION_STEPS 8

// Secp256k1 compact signature size
#define SECP256K1_COMPACT_SIGNATURE_SIZE 64

// Ed25519 signature size
#define ED25519_SIGNATURE_SIZE 64

// MQS shared private key number of iterations
#define MQS_SHARED_PRIVATE_KEY_NUMBER_OF_ITERATIONS 100

// ChaCha20 key size
#define CHACHA20_KEY_SIZE 32

// ChaCha20 block counter index
#define CHACHA20_BLOCK_COUNTER_INDEX 12

// ChaCha20 nonce size
#define CHACHA20_NONCE_SIZE 12

// ChaCha20 block size
#define CHACHA20_BLOCK_SIZE 64

// Poly1305 tag size
#define POLY1305_TAG_SIZE 16

// AES IV size
#define AES_IV_SIZE 16

// Age file key size
#define AGE_FILE_KEY_SIZE 16

// Age payload nonce size
#define AGE_PAYLOAD_NONCE_SIZE 16

// Scalar size
#define SCALAR_SIZE 32

// Single-signer message size
#define SINGLE_SIGNER_MESSAGE_SIZE 32


// Constants

// Hex characters
static const char HEX_CHARACTERS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

// Generator H
static const curve_point GENERATOR_H = {
	.x = {0x0E803AC0, 0x1DFF74D6, 0x1B25B551, 0x14B41E51, 0x17A5E078, 0x05B01AF4, 0x0552DE2D, 0x0E983409, 0x0050929B},
	.y = {0x13A38904, 0x1861189F, 0x1D9A5A30, 0x158515E2, 0x1F40A36D, 0x11BE58DA, 0x09B81279, 0x10C72E72, 0x0031D3C6}
};

// Generator J
static const curve_point GENERATOR_J = {
	.x = {0x1621155F, 0x100C9C99, 0x0E62E34A, 0x09E936FC, 0x15A2F295, 0x029C1E8D, 0x0FCF085A, 0x0CF2BF80, 0x00B860F5},
	.y = {0x06C5C43A, 0x080D16E5, 0x13D5BF16, 0x0B4D34E9, 0x16A3165A, 0x013A01D2, 0x1D4D08FD, 0x1A659551, 0x00A43F09}
};

// Secp256k1 square root exponent
static const bignum256 SECP256k1_SQUARE_ROOT_EXPONENT = {
	.val = {0x1FFFFF0C, 0x1FFFFFFD, 0x1FFFFFFF, 0x1FFFFFFF, 0x1FFFFFFF, 0x1FFFFFFF, 0x1FFFFFFF, 0x1FFFFFFF, 0x003FFFFF}
};

// Address private key hash key
static const char ADDRESS_PRIVATE_KEY_HASH_KEY[] = {'G', 'r', 'i', 'n', 'b', 'o', 'x', '_', 's', 'e', 'e', 'd'};

// Tor base32 alphabet
static const char *TOR_BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

// Tor address checksum seed
static const char TOR_ADDRESS_CHECKSUM_SEED[] = {'.', 'o', 'n', 'i', 'o', 'n', ' ', 'c', 'h', 'e', 'c', 'k', 's', 'u', 'm'};

// Tor address version
static const uint8_t TOR_ADDRESS_VERSION = 3;

// MQS message part one
static const char MQS_MESSAGE_PART_ONE[] = {'{', '"', 'd', 'e', 's', 't', 'i', 'n', 'a', 't', 'i', 'o', 'n', '"', ':', '{', '"', 'p', 'u', 'b', 'l', 'i', 'c', '_', 'k', 'e', 'y', '"', ':', '"'};

// MQS message part two
static const char MQS_MESSAGE_PART_TWO[] = {'"', ',', '"', 'd', 'o', 'm', 'a', 'i', 'n', '"', ':', '"'};

// MQS message part three
static const char MQS_MESSAGE_PART_THREE[] = {'"', ',', '"', 'p', 'o', 'r', 't', '"', ':'};

// MQS message part four
static const char MQS_MESSAGE_PART_FOUR[] = {'}', ',', '"', 'n', 'o', 'n', 'c', 'e', '"', ':', '"'};

// MQS message part five
static const char MQS_MESSAGE_PART_FIVE[] = {'"', ',', '"', 's', 'a', 'l', 't', '"', ':', '"'};

// MQS message part six
static const char MQS_MESSAGE_PART_SIX[] = {'"', ',', '"', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'e', 'd', '_', 'm', 'e', 's', 's', 'a', 'g', 'e', '"', ':', '"'};

// MQS message part seven
static const char MQS_MESSAGE_PART_SEVEN[] = {'"', '}'};

// MQS message no port
static const char MQS_MESSAGE_NO_PORT[] = {'n', 'u', 'l', 'l'};

// Age wrap key info and counter
static const char AGE_WRAP_KEY_INFO_AND_COUNTER[] = {'a', 'g', 'e', '-', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n', '.', 'o', 'r', 'g', '/', 'v', '1', '/', 'X', '2', '5', '5', '1', '9', '\x01'};

// Age payload key info
static const char AGE_PAYLOAD_KEY_INFO_AND_COUNTER[] = {'p', 'a', 'y', 'l', 'o', 'a', 'd', '\x01'};


// Function prototypes

// Is equal
static bool isEqual(const uint8_t *dataOne, const uint8_t *dataTwo, const size_t length);

// Big number subtract modulo
static void bn_submod(const bignum256 *minuend, const bignum256 *subtrahend, bignum256 *result, const bignum256 *prime);

// Get public key from secp256k1 private key
static bool getPublicKeyFromSecp256k1PrivateKey(uint8_t *publicKey, const uint8_t *privateKey);

// Is valid Ed25519 private key
static bool isValidEd25519PrivateKey(const uint8_t *privateKey, const size_t privateKeyLength);

// Is valid X25519 private key
static bool isValidX25519PrivateKey(const uint8_t *privateKey, const size_t privateKeyLength);

// Is quadratic residue
static bool isQuadraticResidue(const bignum256 *component);

// Derive child private key
static bool deriveChildPrivateKey(uint8_t *childPrivateKey, const HDNode *extendedPrivateKey, const uint32_t *path, const size_t pathLength);

// Commit value
static bool commitValue(uint8_t *commitment, const uint64_t value, const uint8_t *blindingFactor, const bool compress);

// Derive blinding factor
static bool deriveBlindingFactor(uint8_t *blindingFactor, const HDNode *extendedPrivateKey, const uint64_t value, const uint32_t *path, const size_t pathLength, const MimbleWimbleCoinSwitchType switchType);

// Get address private key
static bool getAddressPrivateKey(uint8_t *addressPrivateKey, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *curveName);

// Get MQS address from public key
static bool getMqsAddressFromPublicKey(char *mqsAddress, const MimbleWimbleCoinCoinInfo *coinInfo, const uint8_t *publicKey);

// Get public key from MQS address
static bool getPublicKeyFromMqsAddress(uint8_t *publicKey, const MimbleWimbleCoinCoinInfo *coinInfo, const char *mqsAddress, const size_t mqsAddressLength);

// Get Tor address checksum
static void getTorAddressChecksum(uint8_t *checksum, const uint8_t *publicKey);

// Get Tor address from public key
static bool getTorAddressFromPublicKey(char *torAddress, const uint8_t *publicKey);

// Get public key from Tor address
static bool getPublicKeyFromTorAddress(uint8_t *publicKey, const char *torAddress, const size_t torAddressLength);

// Get Slatepack address from public key
static bool getSlatepackAddressFromPublicKey(char *slatepackAddress, const MimbleWimbleCoinCoinInfo *coinInfo, const uint8_t *publicKey);

// Get public key from Slatepack address
static bool getPublicKeyFromSlatepackAddress(uint8_t *publicKey, const MimbleWimbleCoinCoinInfo *coinInfo, const char *slatepackAddress, const size_t slatepackAddressLength);

// Update Bulletproof challenge
static void updateBulletproofChallenge(uint8_t *challenge, const curve_point *leftPart, const curve_point *rightPart);

// Create scalars from ChaCha20
static void createScalarsFromChaCha20(bignum256 *firstScalar, bignum256 *secondScalar, const uint8_t *seed, const uint64_t index, const bool isPrivate);

// Use LR generator
static void useLrGenerator(bignum256 *t0, bignum256 *t1, bignum256 *t2, const bignum256 *y, const bignum256 *z, const uint8_t *rewindNonce, const uint64_t value, const char *displayMessage);

// Calculate Bulletproof components
static bool calculateBulletproofComponents(uint8_t *tauX, uint8_t *tOne, uint8_t *tTwo, const uint64_t value, const uint8_t *blindingFactor, const uint8_t *commitment, const uint8_t *rewindNonce, const uint8_t *privateNonce, const uint8_t *message, const char *displayMessage);

// Get MQS shared private key
static bool getMqsSharedPrivateKey(uint8_t *mqsSharedPrivateKey, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *recipientAddress, const uint8_t *salt);

// Get X25519 private key from Ed25519 private key
static bool getX25519PrivateKeyFromEd25519PrivateKey(uint8_t *x25519PrivateKey, const uint8_t *ed25519PrivateKey);

// Get X25519 public key from Ed25519 public key
static bool getX25519PublicKeyFromEd25519PublicKey(uint8_t *x25519PublicKey, const uint8_t *ed25519PublicKey);

// Get Tor shared private key
static bool getTorSharedPrivateKey(uint8_t *torSharedPrivateKey, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *recipientAddress);

// Get Slatepack shared private key
static bool getSlatepackSharedPrivateKey(uint8_t *slatepackSharedPrivateKey, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const uint8_t *ephemeralX25519PublicKey, const uint8_t *encryptedFileKey, const uint8_t *payloadNonce);

// Create single-signer nonces
static bool createSingleSignerNonces(uint8_t *secretNonce, uint8_t *publicNonce);

// Update blinding factor sum
static bool updateBlindingFactorSum(uint8_t *blindingFactorSum, const uint8_t *blindingFactor, const bool blindingFactorIsPositive);

// Create single-signer signature
static bool createSingleSignerSignature(uint8_t *signature, const uint8_t *message, const uint8_t *privateKey, const uint8_t *secretNonce, const uint8_t *publicNonce, const uint8_t *publicKey);

// Get AES encrypted data length
static size_t getAesEncryptedDataLength(const size_t dataLength);

// AES encrypt
static bool aesEncrypt(uint8_t *encryptedData, const uint8_t *key, const uint8_t *data, const size_t dataLength);

// AES decrypt
static size_t aesDecrypt(uint8_t *data, const uint8_t *key, const uint8_t *encryptedData, const size_t encryptedDataLength);

// Get payment proof message length
static size_t getPaymentProofMessageLength(const MimbleWimbleCoinCoinInfo *coinInfo, const uint64_t value, const char *senderAddress);

// Get payment proof message
static bool getPaymentProofMessage(uint8_t *paymentProofMessage, const MimbleWimbleCoinCoinInfo *coinInfo, uint64_t value, const uint8_t *kernelCommitment, const char *senderAddress);

// Verify payment proof message
static bool verifyPaymentProofMessage(const uint8_t *paymentProofMessage, const size_t paymentProofMessageLength, const MimbleWimbleCoinCoinInfo *coinInfo, const char *receiverAddress, const uint8_t *paymentProof, const size_t paymentProofLength);

// Get login private key
static bool getLoginPrivateKey(uint8_t *loginPrivateKey, const HDNode *extendedPrivateKey);


// Supporting function implementation

// To hex string
void mimbleWimbleCoinToHexString(const uint8_t *data, const size_t length, char *string) {

	// Go through all bytes in the data
	for(size_t i = 0; i < length; ++i) {
	
		// Set hex characters in string
		string[i * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE] = HEX_CHARACTERS[(data[i] >> (BITS_IN_A_BYTE / 2)) & 0xF];
		string[i * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE + 1] = HEX_CHARACTERS[data[i] & 0xF];
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

// Is valid UTF-8 string
bool mimbleWimbleCoinisValidUtf8String(const char *string, const size_t length) {

	// Go through all UTF-8 code points in the string
	for(size_t i = 0; i < length;) {
	
		// Check if UTF-8 code point is a printable ASCII character
		if(string[i] == '\t' || string[i] == '\n' || string[i] == '\r' || (string[i] >= ' ' && string[i] <= '~')) {
		
			// Go to next UTF-8 code point
			++i;
		}
		
		// Otherwise check if UTF-8 code point is a non-overlong two byte character
		else if(length >= 1 && i < length - 1 && (uint8_t)string[i] >= 0xC2 && (uint8_t)string[i] <= 0xDF && (uint8_t)string[i + 1] >= 0x80 && (uint8_t)string[i + 1] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 2;
		}
		
		// Otherwise check if UTF-8 code point is an excluding overlongs character
		else if(length >= 2 && i < length - 2 && (uint8_t)string[i] == 0xE0 && (uint8_t)string[i + 1] >= 0xA0 && (uint8_t)string[i + 1] <= 0xBF && (uint8_t)string[i + 2] >= 0x80 && (uint8_t)string[i + 2] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 3;
		}
		
		// Otherwise check if UTF-8 code point is a straight three byte character
		else if(length >= 2 && i < length - 2 && (((uint8_t)string[i] >= 0xE1 && (uint8_t)string[i] <= 0xEC) || (uint8_t)string[i] == 0xEE || (uint8_t)string[i] == 0xEF) && (uint8_t)string[i + 1] >= 0x80 && (uint8_t)string[i + 1] <= 0xBF && (uint8_t)string[i + 2] >= 0x80 && (uint8_t)string[i + 2] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 3;
		}
		
		// Otherwise check if UTF-8 code point is an excluding surrogates character
		else if(length >= 2 && i < length - 2 && (uint8_t)string[i] == 0xED && (uint8_t)string[i + 1] >= 0x80 && (uint8_t)string[i + 1] <= 0x9F && (uint8_t)string[i + 2] >= 0x80 && (uint8_t)string[i + 2] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 3;
		}
		
		// Otherwise check if UTF-8 code point is a planes one to three character
		else if(length >= 3 && i < length - 3 && (uint8_t)string[i] == 0xF0 && (uint8_t)string[i + 1] >= 0x90 && (uint8_t)string[i + 1] <= 0xBF && (uint8_t)string[i + 2] >= 0x80 && (uint8_t)string[i + 2] <= 0xBF && (uint8_t)string[i + 3] >= 0x80 && (uint8_t)string[i + 3] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 4;
		}
		
		// Otherwise check if UTF-8 code point is a planes four to fifteen character
		else if(length >= 3 && i < length - 3 && (uint8_t)string[i] >= 0xF1 && (uint8_t)string[i] <= 0xF3 && (uint8_t)string[i + 1] >= 0x80 && (uint8_t)string[i + 1] <= 0xBF && (uint8_t)string[i + 2] >= 0x80 && (uint8_t)string[i + 2] <= 0xBF && (uint8_t)string[i + 3] >= 0x80 && (uint8_t)string[i + 3] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 4;
		}
		
		// Otherwise check if UTF-8 code point is a plane sixteen character
		else if(length >= 3 && i < length - 3 && (uint8_t)string[i] == 0xF4 && (uint8_t)string[i + 1] >= 0x80 && (uint8_t)string[i + 1] <= 0x8F && (uint8_t)string[i + 2] >= 0x80 && (uint8_t)string[i + 2] <= 0xBF && (uint8_t)string[i + 3] >= 0x80 && (uint8_t)string[i + 3] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 4;
		}
		
		// Otherwise
		else {
		
			// Return false
			return false;
		}
	}
	
	// Return true
	return true;
}

// Get MQS address
bool mimbleWimbleCoinGetMqsAddress(char *mqsAddress, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index) {

	// Check if getting address private key failed
	uint8_t addressPrivateKey[SECP256K1_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, index, SECP256K1_NAME)) {
	
		// Return false
		return false;
	}
	
	// Check if getting address private key's public key failed
	uint8_t addressPublicKey[SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	if(!getPublicKeyFromSecp256k1PrivateKey(addressPublicKey, addressPrivateKey)) {
	
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return if getting the MQS address from the public key was successful
	return getMqsAddressFromPublicKey(mqsAddress, coinInfo, addressPublicKey);
}

// Get Tor address
bool mimbleWimbleCoinGetTorAddress(char *torAddress, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index) {

	// Check if getting address private key failed
	uint8_t addressPrivateKey[ED25519_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, index, ED25519_NAME)) {
	
		// Return false
		return false;
	}
	
	// Get address private key's public key
	uint8_t addressPublicKey[ED25519_PUBLIC_KEY_SIZE];
	ed25519_publickey(addressPrivateKey, addressPublicKey);
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return if getting the Tor address from the public key was successful
	return getTorAddressFromPublicKey(torAddress, addressPublicKey);
}

// Get Slatepack address
bool mimbleWimbleCoinGetSlatepackAddress(char *slatepackAddress, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index) {

	// Check if getting address private key failed
	uint8_t addressPrivateKey[ED25519_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, index, ED25519_NAME)) {
	
		// Return false
		return false;
	}
	
	// Get address private key's public key
	uint8_t addressPublicKey[ED25519_PUBLIC_KEY_SIZE];
	ed25519_publickey(addressPrivateKey, addressPublicKey);
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return if getting the Slatepack address from the public key was successful
	return getSlatepackAddressFromPublicKey(slatepackAddress, coinInfo, addressPublicKey);
}

// Get seed cookie
void mimbleWimbleCoinGetSeedCookie(uint8_t *seedCookie, const HDNode *extendedPrivateKey) {

	// Get seed cookie from the hash of the extended private key's public key
	sha512_Raw(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key), seedCookie);
}

// Get commitment
bool mimbleWimbleCoinGetCommitment(uint8_t *commitment, const HDNode *extendedPrivateKey, const uint64_t value, const uint8_t *identifier, const MimbleWimbleCoinSwitchType switchType) {

	// Get identifier depth
	const uint8_t identifierDepth = identifier[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &identifier[sizeof(identifierDepth)], IDENTIFIER_SIZE - sizeof(identifierDepth));
	
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
	if(!deriveBlindingFactor(blindingFactor, extendedPrivateKey, value, identifierPath, identifierDepth, switchType)) {
	
		// Return false
		return false;
	}
	
	// Check if commiting value failed
	if(!commitValue(commitment, value, blindingFactor, true)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Return true
	return true;
}

// Get Bulletproof components
bool mimbleWimbleCoinGetBulletproofComponents(uint8_t *tauX, uint8_t *tOne, uint8_t *tTwo, const HDNode *extendedPrivateKey, const uint64_t value, const uint8_t *identifier, const MimbleWimbleCoinSwitchType switchType, const char *displayMessage) {

	// Get identifier depth
	const uint8_t identifierDepth = identifier[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &identifier[sizeof(identifierDepth)], IDENTIFIER_SIZE - sizeof(identifierDepth));
	
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
	if(!deriveBlindingFactor(blindingFactor, extendedPrivateKey, value, identifierPath, identifierDepth, switchType)) {
	
		// Return false
		return false;
	}
	
	// Check if commiting value failed
	uint8_t commitment[UNCOMPRESSED_COMMITMENT_SIZE];
	if(!commitValue(commitment, value, blindingFactor, false)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if getting private hash as the hash of the extended private key's private key failed
	uint8_t privateHash[SCALAR_SIZE];
	if(blake2b(extendedPrivateKey->private_key, sizeof(extendedPrivateKey->private_key), privateHash, sizeof(privateHash))) {
	
		// Clear private hash
		memzero(privateHash, sizeof(privateHash));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if getting private nonce as the hash of the private hash and commitment failed
	uint8_t privateNonce[SCALAR_SIZE];
	if(blake2b_Key(privateHash, sizeof(privateHash), commitment, COMPRESSED_COMMITMENT_SIZE, privateNonce, sizeof(privateNonce))) {
	
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear private hash
		memzero(privateHash, sizeof(privateHash));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Clear private hash
	memzero(privateHash, sizeof(privateHash));
	
	// Check if private nonce isn't a valid secp256k1 private key
	if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(privateNonce, sizeof(privateNonce))) {
	
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if getting rewind hash as the hash of the extended private key's public key failed
	uint8_t rewindHash[SCALAR_SIZE];
	if(blake2b(extendedPrivateKey->public_key, sizeof(extendedPrivateKey->public_key), rewindHash, sizeof(rewindHash))) {
	
		// Clear rewind hash
		memzero(rewindHash, sizeof(rewindHash));
		
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if getting rewind nonce as the hash of the rewind hash and commitment failed
	uint8_t rewindNonce[SCALAR_SIZE];
	if(blake2b_Key(rewindHash, sizeof(rewindHash), commitment, COMPRESSED_COMMITMENT_SIZE, rewindNonce, sizeof(rewindNonce))) {
	
		// Clear rewind hash
		memzero(rewindHash, sizeof(rewindHash));
		
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Clear rewind hash
	memzero(rewindHash, sizeof(rewindHash));
	
	// Check if rewind nonce isn't a valid secp256k1 private key
	if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(rewindNonce, sizeof(rewindNonce))) {
	
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Create message
	uint8_t message[BULLETPROOF_MESSAGE_SIZE] = {
	
		// Switch type
		[BULLETPROOF_MESSAGE_SWITCH_TYPE_INDEX] = switchType
	};
	memcpy(&message[BULLETPROOF_MESSAGE_IDENTIFIER_INDEX], identifier, IDENTIFIER_SIZE);
	
	// Check if calculating Bulletproof components failed
	if(!calculateBulletproofComponents(tauX, tOne, tTwo, value, blindingFactor, commitment, rewindNonce, privateNonce, message, displayMessage)) {
	
		// Clear private nonce
		memzero(privateNonce, sizeof(privateNonce));
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Clear private nonce
	memzero(privateNonce, sizeof(privateNonce));
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Return true
	return true;
}

// Is valid MQS address
bool mimbleWimbleCoinIsValidMqsAddress(const char *mqsAddress, const MimbleWimbleCoinCoinInfo *coinInfo, const size_t mqsAddressLength) {

	// Return if getting the public key from the MQS address was successful
	return getPublicKeyFromMqsAddress(NULL, coinInfo, mqsAddress, mqsAddressLength);
}

// Is valid Tor address
bool mimbleWimbleCoinIsValidTorAddress(const char *torAddress, const size_t torAddressLength) {

	// Return if getting the public key from the Tor address was successful
	return getPublicKeyFromTorAddress(NULL, torAddress, torAddressLength);
}

// Is valid Slatepack address
bool mimbleWimbleCoinIsValidSlatepackAddress(const char *slatepackAddress, const MimbleWimbleCoinCoinInfo *coinInfo, const size_t slatepackAddressLength) {

	// Return if getting the public key from the Slatepack address was successful
	return getPublicKeyFromSlatepackAddress(NULL, coinInfo, slatepackAddress, slatepackAddressLength);
}

// Is valid MQS address domain
bool mimbleWimbleCoinIsValidMqsAddressDomain(const char *mqsAddressDomain, const size_t mqsAddressDomainLength) {

	// Check if MQS address domain is empty
	if(!mqsAddressDomainLength) {
	
		// Return false
		return false;
	}
	
	// Go through all characters in the MQS address domain
	for(size_t i = 0; i < mqsAddressDomainLength; ++i) {
	
		// Check if character isn't alphanumeric or a period not as the first or last character
		if(!isalnum((int)mqsAddressDomain[i]) && (mqsAddressDomain[i] != '.' || i == 0 || i == mqsAddressDomainLength - 1)) {
		
			// Check if at the MQS address domain's port, not at the first or last character, and not following a period
			if(mqsAddressDomain[i] == ':' && i != 0 && i != mqsAddressDomainLength - 1 && mqsAddressDomain[i - 1] != '.') {
			
				// Set port to zero
				unsigned int port = 0;
				
				// Go through the remaining characters in the MQS address domain
				for(size_t j = i + 1; j < mqsAddressDomainLength; ++j) {
				
					// Check if character isn't a digit or a zero at the first character
					if(!isdigit((int)mqsAddressDomain[j]) || (mqsAddressDomain[j] == '0' && j == i + 1)) {
					
						// Return false;
						return false;
					}
					
					// Update port with character
					port *= 10;
					port += mqsAddressDomain[j] - '0';
					
					// Check if port is invalid
					if(port > UINT16_MAX) {
					
						// Return false
						return false;
					}
				}
				
				// Break
				break;
			}
			
			// Otherwise
			else {
			
				// Return false;
				return false;
			}
		}
	}
	
	// Return true
	return true;
}

// Is valid secp256k1 public key
bool mimbleWimbleCoinIsValidSecp256k1PublicKey(const uint8_t *publicKey, const size_t publicKeyLength) {

	// Check if public key length isn't correct
	if(publicKeyLength != SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if public key's prefix isn't correct
	if(publicKey[0] != SECP256k1_EVEN_COMPRESSED_PUBLIC_KEY_PREFIX && publicKey[0] != SECP256k1_ODD_COMPRESSED_PUBLIC_KEY_PREFIX) {
	
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

// Is valid commitment
bool mimbleWimbleCoinIsValidCommitment(const uint8_t *commitment, const size_t commitmentLength) {

	// Check if commitment length isn't correct
	if(commitmentLength != COMPRESSED_COMMITMENT_SIZE) {
	
		// Return false
		return false;
	}
	
	// Copy commitment
	uint8_t copy[commitmentLength];
	memcpy(copy, commitment, commitmentLength);
	
	// Change copy's prefix to its corresponding secp256k1 public key prefix
	copy[0] -= COMMITMENT_EVEN_PREFIX - SECP256k1_EVEN_COMPRESSED_PUBLIC_KEY_PREFIX;
	
	// Return if copy is a valid secp256k1 public key
	return mimbleWimbleCoinIsValidSecp256k1PublicKey(copy, sizeof(copy));
}

// Start MQS encryption
bool mimbleWimbleCoinStartMqsEncryption(uint8_t *nonce, uint8_t *salt, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *recipientAddress, const char *recipientAddressDomain, const size_t recipientAddressDomainLength) {
	
	// Create random salt
	random_buffer(salt, MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE);
	
	// Check if getting MQS shared private key failed
	uint8_t mqsSharedPrivateKey[CHACHA20_KEY_SIZE];
	if(!getMqsSharedPrivateKey(mqsSharedPrivateKey, extendedPrivateKey, coinInfo, index, recipientAddress, salt)) {
	
		// Clear salt
		memzero(salt, MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE);
		
		// Return false
		return false;
	}
	
	// Create random nonce
	random_buffer(nonce, CHACHA20_NONCE_SIZE);
	
	// Initialize encryption and decryption context's ChaCha20 Poly1305 context with the MQS shared private key and nonce
	rfc7539_init(&encryptionAndDecryptionContext->chaCha20Poly1305Context, mqsSharedPrivateKey, nonce);
	
	// Clear MQS shared private key
	memzero(mqsSharedPrivateKey, sizeof(mqsSharedPrivateKey));
	
	// Initialize encryption and decryption context's message hash context
	sha256_Init(&encryptionAndDecryptionContext->messageHashContext);
	
	// Set encryption and decryption context's message hash context initialized
	encryptionAndDecryptionContext->messageHashContextInitialized = true;
	
	// Add MQS message part one to the encryption and decryption context's message hash context
	sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_PART_ONE, sizeof(MQS_MESSAGE_PART_ONE));
	
	// Add recipient address to the encryption and decryption context's message hash context
	sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)recipientAddress, MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE);
	
	// Add MQS message part two to the encryption and decryption context's message hash context
	sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_PART_TWO, sizeof(MQS_MESSAGE_PART_TWO));
	
	// Check if recipient address has a domain
	if(recipientAddressDomain) {
	
		// Get recipient address domain port
		const char *recipientAddressDomainPort = memchr(recipientAddressDomain, ':', recipientAddressDomainLength);
		
		// Check if recipient address domain has a port
		if(recipientAddressDomainPort) {
		
			// Add recipient address domain without port to the encryption and decryption context's message hash context
			sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)recipientAddressDomain, recipientAddressDomainPort - recipientAddressDomain);
			
			// Add MQS message part three to the encryption and decryption context's message hash context
			sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_PART_THREE, sizeof(MQS_MESSAGE_PART_THREE));
			
			// Add recipient address domain port to the encryption and decryption context's message hash context
			sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)&recipientAddressDomainPort[sizeof((char)':')], recipientAddressDomainLength - (recipientAddressDomainPort - recipientAddressDomain + sizeof((char)':')));
		}
		
		// Otherwise
		else {
		
			// Add recipient address domain to the encryption and decryption context's message hash context
			sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)recipientAddressDomain, recipientAddressDomainLength);
			
			// Add MQS message part three to the encryption and decryption context's message hash context
			sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_PART_THREE, sizeof(MQS_MESSAGE_PART_THREE));
			
			// Add MQS message no port to the encryption and decryption context's message hash context
			sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_NO_PORT, sizeof(MQS_MESSAGE_NO_PORT));
		}
	}
	
	// Otherwise
	else {
	
		// Add MQS message part three to the encryption and decryption context's message hash context
		sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_PART_THREE, sizeof(MQS_MESSAGE_PART_THREE));
		
		// Add MQS message no port to the encryption and decryption context's message hash context
		sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_NO_PORT, sizeof(MQS_MESSAGE_NO_PORT));
	}
	
	// Add MQS message part four to the encryption and decryption context's message hash context
	sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_PART_FOUR, sizeof(MQS_MESSAGE_PART_FOUR));
	
	// Add nonce to the encryption and decryption context's message hash context
	char nonceBuffer[CHACHA20_NONCE_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE];
	mimbleWimbleCoinToHexString(nonce, CHACHA20_NONCE_SIZE, nonceBuffer);
	sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)nonceBuffer, sizeof(nonceBuffer));
	
	// Add MQS message part five to the encryption and decryption context's message hash context
	sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_PART_FIVE, sizeof(MQS_MESSAGE_PART_FIVE));
	
	// Add salt to the encryption and decryption context's message hash context
	char saltBuffer[MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE];
	mimbleWimbleCoinToHexString(salt, MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE, saltBuffer);
	sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)saltBuffer, sizeof(saltBuffer));
	
	// Add MQS message part six to the encryption and decryption context's message hash context
	sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_PART_SIX, sizeof(MQS_MESSAGE_PART_SIX));
	
	// Set encryption and decryption context's index
	encryptionAndDecryptionContext->index = index;
	
	// Set encryption and decryption context's encrypting state to ready
	encryptionAndDecryptionContext->encryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Return true
	return true;
}

// Start Tor encryption
bool mimbleWimbleCoinStartTorEncryption(uint8_t *nonce, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *recipientAddress) {

	// Check if getting Tor shared private key failed
	uint8_t torSharedPrivateKey[CHACHA20_KEY_SIZE];
	if(!getTorSharedPrivateKey(torSharedPrivateKey, extendedPrivateKey, coinInfo, index, recipientAddress)) {
	
		// Return false
		return false;
	}
	
	// Create random nonce
	random_buffer(nonce, CHACHA20_NONCE_SIZE);
	
	// Initialize encryption and decryption context's ChaCha20 Poly1305 context with the Tor shared private key and nonce
	rfc7539_init(&encryptionAndDecryptionContext->chaCha20Poly1305Context, torSharedPrivateKey, nonce);
	
	// Clear Tor shared private key
	memzero(torSharedPrivateKey, sizeof(torSharedPrivateKey));
	
	// Set encryption and decryption context's index
	encryptionAndDecryptionContext->index = index;
	
	// Set encryption and decryption context's encrypting state to ready
	encryptionAndDecryptionContext->encryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Return true
	return true;
}

// Encrypt data
bool mimbleWimbleCoinEncryptData(uint8_t *encryptedData, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const uint8_t *data, const size_t dataLength) {

	// Check if data length or block counter will overflow
	if((size_t)UINT64_MAX - encryptionAndDecryptionContext->dataLength < dataLength || encryptionAndDecryptionContext->chaCha20Poly1305Context.chacha20.input[CHACHA20_BLOCK_COUNTER_INDEX] == UINT32_MAX) {
	
		// Return false
		return false;
	}
	
	// Encrypt data
	chacha20poly1305_encrypt(&encryptionAndDecryptionContext->chaCha20Poly1305Context, data, encryptedData, dataLength);
	
	// Update encryption and decryption context's data length
	encryptionAndDecryptionContext->dataLength += dataLength;
	
	// Check if the encryption and decryption context's message hash context is initialized
	if(encryptionAndDecryptionContext->messageHashContextInitialized) {
	
		// Add encrypted data to the encryption and decryption context's message hash context
		char encryptedDataBuffer[dataLength * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE];
		mimbleWimbleCoinToHexString(encryptedData, dataLength, encryptedDataBuffer);
		sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)encryptedDataBuffer, sizeof(encryptedDataBuffer));
	}
	
	// Check if at the last data
	if(dataLength < CHACHA20_BLOCK_SIZE) {
	
		// Set encryption and decryption context's encrypting state to complete
		encryptionAndDecryptionContext->encryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_COMPLETE_STATE;
	}
	
	// Otherwise
	else {
	
		// Set encryption and decryption context's encrypting state to active
		encryptionAndDecryptionContext->encryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE;
	}
	
	// Return true
	return true;
}

// Finish encryption
size_t mimbleWimbleCoinFinishEncryption(uint8_t *tag, uint8_t *mqsMessageSignature, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo) {

	// Get encrypted data tag
	rfc7539_finish(&encryptionAndDecryptionContext->chaCha20Poly1305Context, 0, encryptionAndDecryptionContext->dataLength, tag);
	
	// Check if the encryption and decryption context's message hash context is initialized
	if(encryptionAndDecryptionContext->messageHashContextInitialized) {
	
		// Add tag to the encryption and decryption context's message hash context
		char tagBuffer[POLY1305_TAG_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE];
		mimbleWimbleCoinToHexString(tag, POLY1305_TAG_SIZE, tagBuffer);
		sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)tagBuffer, sizeof(tagBuffer));
		
		// Add MQS message part seven to the encryption and decryption context's message hash context
		sha256_Update(&encryptionAndDecryptionContext->messageHashContext, (const uint8_t *)MQS_MESSAGE_PART_SEVEN, sizeof(MQS_MESSAGE_PART_SEVEN));
		
		// Get MQS message's hash
		uint8_t mqsMessageHash[SHA256_DIGEST_LENGTH];
		sha256_Final(&encryptionAndDecryptionContext->messageHashContext, mqsMessageHash);
		
		// Check if getting address private key failed
		uint8_t addressPrivateKey[SECP256K1_PRIVATE_KEY_SIZE];
		if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, encryptionAndDecryptionContext->index, SECP256K1_NAME)) {
		
			// Return zero
			return 0;
		}
		
		// Check if getting signature of the MQS message failed
		uint8_t signature[SECP256K1_COMPACT_SIGNATURE_SIZE];
		if(ecdsa_sign_digest(&secp256k1, addressPrivateKey, mqsMessageHash, signature, NULL, NULL)) {
		
			// Clear address private key
			memzero(addressPrivateKey, sizeof(addressPrivateKey));
			
			// Return zero
			return 0;
		}
		
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Get signature in DER format and return its size
		return ecdsa_sig_to_der(signature, mqsMessageSignature);
	}
	
	// Return not zero
	return !0;
}

// Start MQS decryption
bool mimbleWimbleCoinStartMqsDecryption(MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *senderAddress, const uint8_t *nonce, const uint8_t *salt) {

	// Check if getting MQS shared private key failed
	uint8_t mqsSharedPrivateKey[CHACHA20_KEY_SIZE];
	if(!getMqsSharedPrivateKey(mqsSharedPrivateKey, extendedPrivateKey, coinInfo, index, senderAddress, salt)) {
	
		// Return false
		return false;
	}
	
	// Initialize encryption and decryption context's ChaCha20 Poly1305 context with the MQS shared private key and nonce
	rfc7539_init(&encryptionAndDecryptionContext->chaCha20Poly1305Context, mqsSharedPrivateKey, nonce);
	
	// Clear MQS shared private key
	memzero(mqsSharedPrivateKey, sizeof(mqsSharedPrivateKey));
	
	// Create random encryption and decryption context's AES key
	random_buffer(encryptionAndDecryptionContext->aesKey, sizeof(encryptionAndDecryptionContext->aesKey));
	
	// Set encryption and decryption context's decrypting state to ready
	encryptionAndDecryptionContext->decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Return true
	return true;
}

// Start Tor decryption
bool mimbleWimbleCoinStartTorDecryption(MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *senderAddress, const uint8_t *nonce) {

	// Check if getting Tor shared private key failed
	uint8_t torSharedPrivateKey[CHACHA20_KEY_SIZE];
	if(!getTorSharedPrivateKey(torSharedPrivateKey, extendedPrivateKey, coinInfo, index, senderAddress)) {
	
		// Return false
		return false;
	}
	
	// Initialize encryption and decryption context's ChaCha20 Poly1305 context with the Tor shared private key and nonce
	rfc7539_init(&encryptionAndDecryptionContext->chaCha20Poly1305Context, torSharedPrivateKey, nonce);
	
	// Clear Tor shared private key
	memzero(torSharedPrivateKey, sizeof(torSharedPrivateKey));
	
	// Create random encryption and decryption context's AES key
	random_buffer(encryptionAndDecryptionContext->aesKey, sizeof(encryptionAndDecryptionContext->aesKey));
	
	// Set encryption and decryption context's decrypting state to ready
	encryptionAndDecryptionContext->decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Return true
	return true;
}

// Start Slatepack decryption
bool mimbleWimbleCoinStartSlatepackDecryption(MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const uint8_t *ephemeralX25519PublicKey, const uint8_t *nonce, const uint8_t *encryptedFileKey, const uint8_t *payloadNonce) {

	// Check if getting Slatepack shared private key failed
	uint8_t slatepackSharedPrivateKey[CHACHA20_KEY_SIZE];
	if(!getSlatepackSharedPrivateKey(slatepackSharedPrivateKey, extendedPrivateKey, coinInfo, index, ephemeralX25519PublicKey, encryptedFileKey, payloadNonce)) {
	
		// Return false
		return false;
	}
	
	// Initialize encryption and decryption context's ChaCha20 Poly1305 context with the Slatepack shared private key and nonce
	rfc7539_init(&encryptionAndDecryptionContext->chaCha20Poly1305Context, slatepackSharedPrivateKey, nonce);
	
	// Clear Slatepack shared private key
	memzero(slatepackSharedPrivateKey, sizeof(slatepackSharedPrivateKey));
	
	// Create random encryption and decryption context's AES key
	random_buffer(encryptionAndDecryptionContext->aesKey, sizeof(encryptionAndDecryptionContext->aesKey));
	
	// Set encryption and decryption context's decrypting state to ready
	encryptionAndDecryptionContext->decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_READY_STATE;
	
	// Return true
	return true;
}

// Decrypt data
size_t mimbleWimbleCoinDecryptData(uint8_t *data, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const uint8_t *encryptedData, const size_t encryptedDataLength) {

	// Check if data length or block counter will overflow
	if((size_t)UINT64_MAX - encryptionAndDecryptionContext->dataLength < encryptedDataLength || encryptionAndDecryptionContext->chaCha20Poly1305Context.chacha20.input[CHACHA20_BLOCK_COUNTER_INDEX] == UINT32_MAX) {
	
		// Return zero
		return 0;
	}
	
	// Decrypt data
	uint8_t decryptedData[encryptedDataLength];
	chacha20poly1305_decrypt(&encryptionAndDecryptionContext->chaCha20Poly1305Context, encryptedData, decryptedData, sizeof(decryptedData));
	
	// Update encryption and decryption context's data length
	encryptionAndDecryptionContext->dataLength += encryptedDataLength;
	
	// Check if at the last data
	if(encryptedDataLength < CHACHA20_BLOCK_SIZE) {
	
		// Set encryption and decryption context's decrypting state to complete
		encryptionAndDecryptionContext->decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_COMPLETE_STATE;
	}
	
	// Otherwise
	else {
	
		// Set encryption and decryption context's decrypting state to active
		encryptionAndDecryptionContext->decryptingState = MimbleWimbleCoinEncryptingOrDecryptingState_ACTIVE_STATE;
	}
	
	// Check if AES encrypting the decrypted data with the encryption and decryption context's AES key failed
	if(!aesEncrypt(data, encryptionAndDecryptionContext->aesKey, decryptedData, sizeof(decryptedData))) {
	
		// Clear decrypted data
		memzero(decryptedData, sizeof(decryptedData));
		
		// Return zero
		return 0;
	}
	
	// Clear decrypted data
	memzero(decryptedData, sizeof(decryptedData));
	
	// Return size of the AES encrypted data
	return getAesEncryptedDataLength(sizeof(decryptedData));
}

// Finish decryption
bool mimbleWimbleCoinFinishDecryption(uint8_t *aesKey, MimbleWimbleCoinEncryptionAndDecryptionContext *encryptionAndDecryptionContext, const uint8_t *tag) {

	// Get decrypted data tags
	uint8_t decryptedDataTag[POLY1305_TAG_SIZE];
	rfc7539_finish(&encryptionAndDecryptionContext->chaCha20Poly1305Context, 0, encryptionAndDecryptionContext->dataLength, decryptedDataTag);
	
	// Check if tag is invalid
	if(!isEqual(tag, decryptedDataTag, sizeof(decryptedDataTag))) {
	
		// Clear decrypted data tag
		memzero(decryptedDataTag, sizeof(decryptedDataTag));
		
		// Return false
		return false;
	}
	
	// Clear decrypted data tag
	memzero(decryptedDataTag, sizeof(decryptedDataTag));
	
	// Set AES key to the encryption and decryption context's AES key
	memcpy(aesKey, encryptionAndDecryptionContext->aesKey, sizeof(encryptionAndDecryptionContext->aesKey));
	
	// Return true
	return true;
}

// Start transaction
bool mimbleWimbleCoinStartTransaction(MimbleWimbleCoinTransactionContext *transactionContext, const uint32_t index, const uint64_t output, const uint64_t input, const uint64_t fee, const uint8_t secretNonceIndex, const char *address, const size_t addressLength) {

	// Check if an input exists
	if(input) {
	
		// Set transaction context's remaining input
		transactionContext->remainingInput = input + fee;
		
		// Set transaction context's send
		transactionContext->send = input - output;
		
		// Set transaction context's secret nonce index
		transactionContext->secretNonceIndex = secretNonceIndex;
	}
	
	// Otherwise
	else {
	
		// Check if creating transaction context's secret nonce failed
		if(!createSingleSignerNonces(transactionContext->secretNonce, NULL)) {
		
			// Return false
			return false;
		}
		
		// Set transaction context's receive
		transactionContext->receive = output;
	}
	
	// Set transaction context's index
	transactionContext->index = index;
	
	// Set transaction context's remaining output
	transactionContext->remainingOutput = output;
	
	// Set transaction context's fee
	transactionContext->fee = fee;
	
	// Check if address exists
	if(address) {
	
		// Set transaction context's address
		memcpy(transactionContext->address, address, addressLength);
	}
	
	// Set that transaction context has been started
	transactionContext->started = true;
	
	// Return true
	return true;
}

// Include output in transaction
bool mimbleWimbleCoinIncludeOutputInTransaction(MimbleWimbleCoinTransactionContext *transactionContext, const HDNode *extendedPrivateKey, const uint64_t value, const uint8_t *identifier, const MimbleWimbleCoinSwitchType switchType) {

	// Get identifier depth
	const uint8_t identifierDepth = identifier[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &identifier[sizeof(identifierDepth)], IDENTIFIER_SIZE - sizeof(identifierDepth));
	
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
	if(!deriveBlindingFactor(blindingFactor, extendedPrivateKey, value, identifierPath, identifierDepth, switchType)) {
	
		// Return false
		return false;
	}
	
	// Check if updating the transaction's blinding factor failed
	if(!updateBlindingFactorSum(transactionContext->blindingFactor, blindingFactor, true)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Remove value from the transaction context's remaining output
	transactionContext->remainingOutput -= value;
	
	// Return true
	return true;
}

// Include input in transaction
bool mimbleWimbleCoinIncludeInputInTransaction(MimbleWimbleCoinTransactionContext *transactionContext, const HDNode *extendedPrivateKey, const uint64_t value, const uint8_t *identifier, const MimbleWimbleCoinSwitchType switchType) {

	// Get identifier depth
	const uint8_t identifierDepth = identifier[MIMBLEWIMBLE_COIN_IDENTIFIER_DEPTH_INDEX];
	
	// Get identifier path
	uint32_t identifierPath[MIMBLEWIMBLE_COIN_MAXIMUM_IDENTIFIER_DEPTH];
	memcpy(identifierPath, &identifier[sizeof(identifierDepth)], IDENTIFIER_SIZE - sizeof(identifierDepth));
	
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
	if(!deriveBlindingFactor(blindingFactor, extendedPrivateKey, value, identifierPath, identifierDepth, switchType)) {
	
		// Return false
		return false;
	}
	
	// Check if updating the transaction's blinding factor failed
	if(!updateBlindingFactorSum(transactionContext->blindingFactor, blindingFactor, false)) {
	
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Remove value from the transaction context's remaining input
	transactionContext->remainingInput -= value;
	
	// Return true
	return true;
}

// Apply offset to transaction
uint8_t mimbleWimbleCoinApplyOffsetToTransaction(MimbleWimbleCoinTransactionContext *transactionContext, const uint8_t *offset) {

	// Check if updating the transaction's blinding factor failed
	if(!updateBlindingFactorSum(transactionContext->blindingFactor, offset, false)) {
	
		// Return zero
		return 0;
	}
	
	// Set that transaction context's offset was applied
	transactionContext->offsetApplied = true;
	
	// Check if transaction context is sending
	if(transactionContext->send) {
	
		// Check if transaction context doesn't have a secret nonce index
		if(!transactionContext->secretNonceIndex) {
		
			// Check if creating transaction context's secret nonce failed
			if(!createSingleSignerNonces(transactionContext->secretNonce, NULL)) {
			
				// Return zero
				return 0;
			}
			
			// Check if AES encrypting the transaction context's secret nonce with the transaction context's blinding factor failed
			uint8_t encryptedTransactionSecretNonce[MIMBLEWIMBLE_COIN_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE];
			if(!aesEncrypt(encryptedTransactionSecretNonce, transactionContext->blindingFactor, transactionContext->secretNonce, sizeof(transactionContext->secretNonce))) {
			
				// Return zero
				return 0;
			}
			
			// Check if the encrypted transaction secret nonce is invalid
			if(mimbleWimbleCoinIsZero(encryptedTransactionSecretNonce, sizeof(encryptedTransactionSecretNonce))) {
			
				// Return zero
				return 0;
			}
			
			// Check if getting current transaction secret nonce index from storage failed
			uint32_t currentTransactionSecretNonceIndex;
			if(!config_getMimbleWimbleCoinCurrentTransactionSecretNonceIndex(&currentTransactionSecretNonceIndex)) {
			
				// Return zero
				return 0;
			}
			
			// Check if saving the encrypted transaction secret nonce at the current transaction secret nonce index in storage failed
			if(!config_setMimbleWimbleCoinTransactionSecretNonce(encryptedTransactionSecretNonce, currentTransactionSecretNonceIndex)) {
			
				// Return zero
				return 0;
			}
			
			// Set transaction context's secret nonce index
			transactionContext->secretNonceIndex = currentTransactionSecretNonceIndex + 1;
			
			// Check if incrementing current transaction secret nonce index in storage failed
			if(!config_setMimbleWimbleCoinCurrentTransactionSecretNonceIndex((currentTransactionSecretNonceIndex + 1) % MIMBLEWIMBLE_COIN_NUMBER_OF_TRANSACTION_SECRET_NONCES)) {
			
				// Return zero
				return 0;
			}
			
			// Return transaction context's secret nonce index
			return transactionContext->secretNonceIndex;
		}
		
		// Otherwise
		else {
		
			// Check if getting the encrypted transaction secret nonce at the transaction context's secret nonce index from storage failed
			uint8_t encryptedTransactionSecretNonce[MIMBLEWIMBLE_COIN_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE];
			if(!config_getMimbleWimbleCoinTransactionSecretNonce(encryptedTransactionSecretNonce, transactionContext->secretNonceIndex - 1)) {
			
				// Return zero
				return 0;
			}
			
			// Check if encrypted transaction secret nonce is invalid
			if(mimbleWimbleCoinIsZero(encryptedTransactionSecretNonce, sizeof(encryptedTransactionSecretNonce))) {
			
				// Return zero
				return 0;
			}
			
			// Check if AES decrypting the encrypted transaction secret nonce with the transaction context's blinding factor failed
			uint8_t transactionSecretNonce[sizeof(encryptedTransactionSecretNonce)];
			const size_t transactionSecretNonceLength = aesDecrypt(transactionSecretNonce, transactionContext->blindingFactor, encryptedTransactionSecretNonce, sizeof(encryptedTransactionSecretNonce));
			if(!transactionSecretNonceLength) {
			
				// Return zero
				return 0;
			}
			
			// Check if transaction secret nonce length is invalid
			if(transactionSecretNonceLength != sizeof(transactionContext->secretNonce)) {
			
				// Clear transaction secret nonce
				memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
				
				// Return zero
				return 0;
			}
			
			// Set transaction context's secret nonce to the transaction secret nonce
			memcpy(transactionContext->secretNonce, transactionSecretNonce, transactionSecretNonceLength);
			
			// Clear transaction secret nonce
			memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
		}
	}
	
	// Return not zero
	return !0;
}

// Get transaction public key
bool mimbleWimbleCoinGetTransactionPublicKey(uint8_t *publicKey, const MimbleWimbleCoinTransactionContext *transactionContext) {

	// Return if getting the pubic key of the transaction context's blinding factor was successful
	return getPublicKeyFromSecp256k1PrivateKey(publicKey, transactionContext->blindingFactor);
}

// Get transaction public nonce
bool mimbleWimbleCoinGetTransactionPublicNonce(uint8_t *publicNonce, const MimbleWimbleCoinTransactionContext *transactionContext) {

	// Return if getting the pubic key of the transaction context's secret nonce was successful
	return getPublicKeyFromSecp256k1PrivateKey(publicNonce, transactionContext->secretNonce);
}

// Get transaction message signature
bool mimbleWimbleCoinGetTransactionMessageSignature(uint8_t *messageSignature, MimbleWimbleCoinTransactionContext *transactionContext, const char *message, const size_t messageLength) {

	// Check if getting message hash failed
	uint8_t messageHash[SINGLE_SIGNER_MESSAGE_SIZE];
	if(blake2b((const uint8_t *)message, messageLength, messageHash, sizeof(messageHash))) {
			
		// Return false
		return false;
	}
	
	// Check if getting the public key of the transaction context's blinding factor failed
	uint8_t publicKey[SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	if(!getPublicKeyFromSecp256k1PrivateKey(publicKey, transactionContext->blindingFactor)) {
	
		// Return false
		return false;
	}
	
	// Loop while secret nonce is the same as the transaction context's secret nonce
	uint8_t secretNonce[MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_SIZE];
	uint8_t publicNonce[SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	do {
	
		// Check if creating secret nonce and public nonce failed
		if(!createSingleSignerNonces(secretNonce, publicNonce)) {
		
			// Return false
			return false;
		}
		
	} while(isEqual(secretNonce, transactionContext->secretNonce, sizeof(transactionContext->secretNonce)));
	
	// Check if creating single-signer signature failed
	if(!createSingleSignerSignature(messageSignature, messageHash, transactionContext->blindingFactor, secretNonce, publicNonce, publicKey)) {
	
		// Clear secret nonce
		memzero(secretNonce, sizeof(secretNonce));
		
		// Return false
		return false;
	}
	
	// Clear secret nonce
	memzero(secretNonce, sizeof(secretNonce));
	
	// Set that transaction context has signed a message
	transactionContext->messageSigned = true;
	
	// Return true
	return true;
}

// Verify transaction payment proof
bool mimbleWimbleCoinVerifyTransactionPaymentProof(const MimbleWimbleCoinTransactionContext *transactionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const MimbleWimbleCoinAddressType addressType, const uint8_t *kernelCommitment, const uint8_t *paymentProof, const size_t paymentProofLength) {

	// Check address type
	switch(addressType) {
	
		// MQS
		case MimbleWimbleCoinAddressType_MQS: {
		
			// Check if getting MQS address failed
			char mqsAddress[MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE + sizeof((char)'\0')];
			if(!mimbleWimbleCoinGetMqsAddress(mqsAddress, extendedPrivateKey, coinInfo, transactionContext->index)) {
			
				// Return false
				return false;
			}
			
			// Check if getting payment proof message length failed
			const size_t paymentProofMessageLength = getPaymentProofMessageLength(coinInfo, transactionContext->send, mqsAddress);
			if(!paymentProofMessageLength) {
			
				// Return false
				return false;
			}

			// Check if getting payment proof message failed
			uint8_t paymentProofMessage[paymentProofMessageLength];
			if(!getPaymentProofMessage(paymentProofMessage, coinInfo, transactionContext->send, kernelCommitment, mqsAddress)) {
			
				// Return false
				return false;
			}
			
			// Return if verifying payment proof message was successful
			return verifyPaymentProofMessage(paymentProofMessage, sizeof(paymentProofMessage), coinInfo, transactionContext->address, paymentProof, paymentProofLength);
		}
		
		// Tor
		case MimbleWimbleCoinAddressType_TOR: {
		
			// Check if getting Tor address failed
			char torAddress[MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE + sizeof((char)'\0')];
			if(!mimbleWimbleCoinGetTorAddress(torAddress, extendedPrivateKey, coinInfo, transactionContext->index)) {
			
				// Return false
				return false;
			}
			
			// Check if getting payment proof message length failed
			const size_t paymentProofMessageLength = getPaymentProofMessageLength(coinInfo, transactionContext->send, torAddress);
			if(!paymentProofMessageLength) {
			
				// Return false
				return false;
			}

			// Check if getting payment proof message failed
			uint8_t paymentProofMessage[paymentProofMessageLength];
			if(!getPaymentProofMessage(paymentProofMessage, coinInfo, transactionContext->send, kernelCommitment, torAddress)) {
			
				// Return false
				return false;
			}
			
			// Return if verifying payment proof message was successful
			return verifyPaymentProofMessage(paymentProofMessage, sizeof(paymentProofMessage), coinInfo, transactionContext->address, paymentProof, paymentProofLength);
		}
		
		// Slatepack
		case MimbleWimbleCoinAddressType_SLATEPACK: {
		
			// Check if getting Slatepack address failed
			char slatepackAddress[MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + strlen(coinInfo->slatepackAddressHumanReadablePart) + sizeof((char)'\0')];
			if(!mimbleWimbleCoinGetSlatepackAddress(slatepackAddress, extendedPrivateKey, coinInfo, transactionContext->index)) {
			
				// Return false
				return false;
			}
			
			// Check if getting payment proof message length failed
			const size_t paymentProofMessageLength = getPaymentProofMessageLength(coinInfo, transactionContext->send, slatepackAddress);
			if(!paymentProofMessageLength) {
			
				// Return false
				return false;
			}

			// Check if getting payment proof message failed
			uint8_t paymentProofMessage[paymentProofMessageLength];
			if(!getPaymentProofMessage(paymentProofMessage, coinInfo, transactionContext->send, kernelCommitment, slatepackAddress)) {
			
				// Return false
				return false;
			}
			
			// Return if verifying payment proof message was successful
			return verifyPaymentProofMessage(paymentProofMessage, sizeof(paymentProofMessage), coinInfo, transactionContext->address, paymentProof, paymentProofLength);
		}
	}
	
	// Return false
	return false;
}

// Finish transaction
size_t mimbleWimbleCoinFinishTransaction(uint8_t *signature, uint8_t *paymentProof, const MimbleWimbleCoinTransactionContext *transactionContext, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const MimbleWimbleCoinAddressType addressType, const uint8_t *publicNonce, const uint8_t *publicKey, const uint8_t *kernelInformation, const uint8_t *kernelCommitment) {

	// Check if transaction context is sending
	if(transactionContext->send) {
	
		// Check if getting the encrypted transaction secret nonce at the transaction context's secret nonce index from storage failed
		uint8_t encryptedTransactionSecretNonce[MIMBLEWIMBLE_COIN_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE];
		if(!config_getMimbleWimbleCoinTransactionSecretNonce(encryptedTransactionSecretNonce, transactionContext->secretNonceIndex - 1)) {
		
			// Return zero
			return 0;
		}
		
		// Check if encrypted transaction secret nonce is invalid
		if(mimbleWimbleCoinIsZero(encryptedTransactionSecretNonce, sizeof(encryptedTransactionSecretNonce))) {
		
			// Return zero
			return 0;
		}
		
		// Check if AES decrypting the encrypted transaction secret nonce with the transaction context's blinding factor failed
		uint8_t transactionSecretNonce[sizeof(encryptedTransactionSecretNonce)];
		const size_t transactionSecretNonceLength = aesDecrypt(transactionSecretNonce, transactionContext->blindingFactor, encryptedTransactionSecretNonce, sizeof(encryptedTransactionSecretNonce));
		if(!transactionSecretNonceLength) {
		
			// Return zero
			return 0;
		}
		
		// Check if transaction secret nonce length is invalid
		if(transactionSecretNonceLength != sizeof(transactionContext->secretNonce)) {
		
			// Clear transaction secret nonce
			memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
			
			// Return zero
			return 0;
		}
		
		// Check if the transaction context's secret nonce isn't the transaction secret nonce
		if(!isEqual(transactionContext->secretNonce, transactionSecretNonce, transactionSecretNonceLength)) {
		
			// Clear transaction secret nonce
			memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
			
			// Return zero
			return 0;
		}
		
		// Clear transaction secret nonce
		memzero(transactionSecretNonce, sizeof(transactionSecretNonce));
	
		// Check if erasing the encrypted transaction secret nonce at the transaction context's secret nonce index in storage failed
		const uint8_t noEncryptedTransactionSecretNonce[MIMBLEWIMBLE_COIN_ENCRYPTED_TRANSACTION_SECRET_NONCE_SIZE] = {0};
		if(!config_setMimbleWimbleCoinTransactionSecretNonce(noEncryptedTransactionSecretNonce, transactionContext->secretNonceIndex - 1)) {
			
			// Return zero
			return 0;
		}
	}
	
	// Check if initializing hash context failed
	BLAKE2B_CTX hashContext;
	if(blake2b_Init(&hashContext, SINGLE_SIGNER_MESSAGE_SIZE)) {
	
		// Return zero
		return 0;
	}
	// Check if adding kernel information's features to the hash context failed
	if(blake2b_Update(&hashContext, &kernelInformation[0], sizeof(kernelInformation[0]))) {
	
		// Return zero
		return 0;
	}
	
	// Check kernel information's features
	switch(kernelInformation[0]) {
	
		// Plain features
		case MimbleWimbleCoinKernelFeatures_PLAIN_FEATURES: {
		
			// Get transaction context's fee
			uint64_t fee = transactionContext->fee;
			
			// Check if little endian
			#if BYTE_ORDER == LITTLE_ENDIAN
			
				// Make fee big endian
				REVERSE64(fee, fee);
			#endif
			
			// Check if adding fee to the hash context failed
			if(blake2b_Update(&hashContext, &fee, sizeof(fee))) {
			
				// Return zero
				return 0;
			}
		
			// Break
			break;
		}
		
		// Height locked features
		case MimbleWimbleCoinKernelFeatures_HEIGHT_LOCKED_FEATURES: {
		
			// Get transaction context's fee
			uint64_t fee = transactionContext->fee;
			
			// Check if little endian
			#if BYTE_ORDER == LITTLE_ENDIAN
			
				// Make fee big endian
				REVERSE64(fee, fee);
			#endif
			
			// Check if adding fee to the hash context failed
			if(blake2b_Update(&hashContext, &fee, sizeof(fee))) {
			
				// Return zero
				return 0;
			}
			
			// Get lock height from kernel information
			uint64_t lockHeight;
			memcpy(&lockHeight, &kernelInformation[sizeof(kernelInformation[0])], sizeof(lockHeight));
			
			// Make lock height big endian
			REVERSE64(lockHeight, lockHeight);
			
			// Check if adding lock height to the hash context failed
			if(blake2b_Update(&hashContext, &lockHeight, sizeof(lockHeight))) {
			
				// Return zero
				return 0;
			}
			
			// Break
			break;
		}
		
		// No recent duplicate features
		case MimbleWimbleCoinKernelFeatures_NO_RECENT_DUPLICATE_FEATURES: {
		
			// Get transaction context's fee
			uint64_t fee = transactionContext->fee;
			
			// Check if little endian
			#if BYTE_ORDER == LITTLE_ENDIAN
			
				// Make fee big endian
				REVERSE64(fee, fee);
			#endif
			
			// Check if adding fee to the hash context failed
			if(blake2b_Update(&hashContext, &fee, sizeof(fee))) {
			
				// Return zero
				return 0;
			}
			
			// Get relative height from kernel information
			uint16_t relativeHeight;
			memcpy(&relativeHeight, &kernelInformation[sizeof(kernelInformation[0])], sizeof(relativeHeight));
			
			// Make relative height big endian
			REVERSE16(relativeHeight, relativeHeight);
			
			// Check if adding relative height to the hash context failed
			if(blake2b_Update(&hashContext, &relativeHeight, sizeof(relativeHeight))) {
			
				// Return zero
				return 0;
			}
			
			// Break
			break;
		}
	}
	
	// Check if getting message hash from the hash context failed
	uint8_t messageHash[SINGLE_SIGNER_MESSAGE_SIZE];
	if(blake2b_Final(&hashContext, messageHash, sizeof(messageHash))) {
	
		// Return zero
		return 0;
	}
	
	// Check if creating single-signer signature failed
	if(!createSingleSignerSignature(signature, messageHash, transactionContext->blindingFactor, transactionContext->secretNonce, publicNonce, publicKey)) {
	
		// Return zero
		return 0;
	}
	
	// Check if transaction context is receiving and kernel commitment exists
	if(transactionContext->receive && kernelCommitment) {
	
		// Check if getting payment proof message length failed
		const size_t paymentProofMessageLength = getPaymentProofMessageLength(coinInfo, transactionContext->receive, transactionContext->address);
		if(!paymentProofMessageLength) {
		
			// Return zero
			return 0;
		}
	
		// Check if getting payment proof message failed
		uint8_t paymentProofMessage[paymentProofMessageLength];
		if(!getPaymentProofMessage(paymentProofMessage, coinInfo, transactionContext->receive, kernelCommitment, transactionContext->address)) {
		
			// Return zero
			return 0;
		}
		
		// Check address type
		switch(addressType) {
		
			// MQS
			case MimbleWimbleCoinAddressType_MQS: {
			
				// Check if getting address private key failed
				uint8_t addressPrivateKey[SECP256K1_PRIVATE_KEY_SIZE];
				if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, transactionContext->index, SECP256K1_NAME)) {
				
					// Return zero
					return 0;
				}
				
				// Check if getting address private key's public key failed
				uint8_t addressPublicKey[SECP256K1_UNCOMPRESSED_PUBLIC_KEY_SIZE];
				if(ecdsa_get_public_key65(&secp256k1, addressPrivateKey, addressPublicKey)) {
				
					// Clear address private key
					memzero(addressPrivateKey, sizeof(addressPrivateKey));
					
					// Return zero
					return 0;
				}
				
				// Check if address public key isn't a valid secp256k1 public key
				curve_point temp;
				if(!ecdsa_read_pubkey(&secp256k1, addressPublicKey, &temp)) {
				
					// Clear address private key
					memzero(addressPrivateKey, sizeof(addressPrivateKey));
					
					// Return zero
					return 0;
				}
				
				// Check if the address public key is in the payment proof message
				if(memmem(paymentProofMessage, sizeof(paymentProofMessage), addressPublicKey, sizeof(addressPublicKey))) {
				
					// Clear address private key
					memzero(addressPrivateKey, sizeof(addressPrivateKey));
					
					// Return zero
					return 0;
				}
				
				// Compress the address public key
				addressPublicKey[0] = (addressPublicKey[sizeof(addressPublicKey) - 1] & 1) ? SECP256k1_ODD_COMPRESSED_PUBLIC_KEY_PREFIX : SECP256k1_EVEN_COMPRESSED_PUBLIC_KEY_PREFIX;
				
				// Check if the compressed address public key is in the payment proof message
				if(memmem(paymentProofMessage, sizeof(paymentProofMessage), addressPublicKey, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE)) {
				
					// Clear address private key
					memzero(addressPrivateKey, sizeof(addressPrivateKey));
					
					// Return zero
					return 0;
				}			
				
				// Check if getting signature of the payment proof message failed
				uint8_t paymentProofSignature[SECP256K1_COMPACT_SIGNATURE_SIZE];
				if(ecdsa_sign(&secp256k1, HASHER_SHA2, addressPrivateKey, paymentProofMessage, sizeof(paymentProofMessage), paymentProofSignature, NULL, NULL)) {
				
					// Clear address private key
					memzero(addressPrivateKey, sizeof(addressPrivateKey));
					
					// Return zero
					return 0;
				}
				
				// Clear address private key
				memzero(addressPrivateKey, sizeof(addressPrivateKey));
				
				// Get payment proof signature in DER format and return its size
				return ecdsa_sig_to_der(paymentProofSignature, paymentProof);
			}
			
			// Tor or Slatepack
			case MimbleWimbleCoinAddressType_TOR:
			case MimbleWimbleCoinAddressType_SLATEPACK: {
				
				// Check if getting address private key failed
				uint8_t addressPrivateKey[ED25519_PRIVATE_KEY_SIZE];
				if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, transactionContext->index, ED25519_NAME)) {
				
					// Return zero
					return 0;
				}
				
				// Get address private key's public key
				uint8_t addressPublicKey[ED25519_PUBLIC_KEY_SIZE];
				ed25519_publickey(addressPrivateKey, addressPublicKey);
				
				// Check if the address public key is in the payment proof message
				if(memmem(paymentProofMessage, sizeof(paymentProofMessage), addressPublicKey, sizeof(addressPublicKey))) {
				
					// Clear address private key
					memzero(addressPrivateKey, sizeof(addressPrivateKey));
					
					// Return zero
					return 0;
				}
				
				// Get signature of the payment proof message
				ed25519_sign(paymentProofMessage, sizeof(paymentProofMessage), addressPrivateKey, paymentProof);
				
				// Clear address private key
				memzero(addressPrivateKey, sizeof(addressPrivateKey));
				
				// Return payment proof signature size
				return ED25519_SIGNATURE_SIZE;
			}
		}
	}
	
	// Return not zero
	return !0;
}

// Get MQS challenge signature
size_t mimbleWimbleCoinGetMqsChallengeSignature(uint8_t *mqsChallengeSignature, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *challenge) {

	// Check if getting address private key failed
	uint8_t addressPrivateKey[SECP256K1_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, index, SECP256K1_NAME)) {
	
		// Return zero
		return 0;
	}
	
	// Check if getting signature of the challenge failed
	uint8_t signature[SECP256K1_COMPACT_SIGNATURE_SIZE];
	if(ecdsa_sign(&secp256k1, HASHER_SHA2, addressPrivateKey, (const uint8_t *)challenge, strlen(challenge), signature, NULL, NULL)) {
	
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return zero
		return 0;
	}
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Get signature in DER format and return its size
	return ecdsa_sig_to_der(signature, mqsChallengeSignature);
}

// Get login challenge signature
size_t mimbleWimbleCoinGetLoginChallengeSignature(uint8_t *loginPublicKey, uint8_t *loginChallengeSignature, const HDNode *extendedPrivateKey, const uint8_t *identifier, const size_t identifierLength, const char *challenge) {

	// Get hash of challenge and identifier
	SHA256_CTX hashContext;
	sha256_Init(&hashContext);
	sha256_Update(&hashContext, (const uint8_t *)challenge, strlen(challenge));
	sha256_Update(&hashContext, (const uint8_t *)" ", sizeof(" ") - sizeof((char)'\0'));
	sha256_Update(&hashContext, identifier, identifierLength);
	uint8_t hash[SHA256_DIGEST_LENGTH];
	sha256_Final(&hashContext, hash);
	
	// Check if getting login private key failed
	uint8_t loginPrivateKey[SECP256K1_PRIVATE_KEY_SIZE];
	if(!getLoginPrivateKey(loginPrivateKey, extendedPrivateKey)) {
	
		// Return zero
		return 0;
	}
	
	// Check if getting signature of the hash failed
	uint8_t signature[SECP256K1_COMPACT_SIGNATURE_SIZE];
	if(ecdsa_sign_digest(&secp256k1, loginPrivateKey, hash, signature, NULL, NULL)) {
	
		// Clear login private key
		memzero(loginPrivateKey, sizeof(loginPrivateKey));
		
		// Return zero
		return 0;
	}
	
	// Check ig getting the login private key's public key failed
	if(!getPublicKeyFromSecp256k1PrivateKey(loginPublicKey, loginPrivateKey)) {
	
		// Clear login private key
		memzero(loginPrivateKey, sizeof(loginPrivateKey));
		
		// Return zero
		return 0;
	}
	
	// Clear login private key
	memzero(loginPrivateKey, sizeof(loginPrivateKey));
	
	// Get signature in DER format and return its size
	return ecdsa_sig_to_der(signature, loginChallengeSignature);
}

// Is equal
bool isEqual(const uint8_t *dataOne, const uint8_t *dataTwo, const size_t length) {

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
void bn_submod(const bignum256 *minuend, const bignum256 *subtrahend, bignum256 *result, const bignum256 *prime) {

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
bool getPublicKeyFromSecp256k1PrivateKey(uint8_t *publicKey, const uint8_t *privateKey) {

	// Check if getting private key's public key failed
	if(ecdsa_get_public_key33(&secp256k1, privateKey, publicKey)) {
	
		// Clear public key
		memzero(publicKey, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Check if public key isn't a valid secp256k1 public key
	if(!mimbleWimbleCoinIsValidSecp256k1PublicKey(publicKey, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE)) {
	
		// Clear public key
		memzero(publicKey, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid secp256k1 private key
bool mimbleWimbleCoinIsValidSecp256k1PrivateKey(const uint8_t *privateKey, const size_t privateKeyLength) {

	// Check if private key length isn't correct
	if(privateKeyLength != SECP256K1_PRIVATE_KEY_SIZE) {
	
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

// Is valid Ed25519 private key
bool isValidEd25519PrivateKey(__attribute__((unused)) const uint8_t *privateKey, const size_t privateKeyLength) {

	// Return if private key length is correct
	return privateKeyLength == ED25519_PRIVATE_KEY_SIZE;
}

// Is valid X25519 private key
bool isValidX25519PrivateKey(__attribute__((unused)) const uint8_t *privateKey, const size_t privateKeyLength) {

	// Return if private key length is correct
	return privateKeyLength == X25519_PRIVATE_KEY_SIZE;
}

// Is quadratic residue
bool isQuadraticResidue(const bignum256 *component) {

	// Get the square root squared of the component
	bignum256 squareRootSquared;
	bn_power_mod(component, &SECP256k1_SQUARE_ROOT_EXPONENT, &secp256k1.prime, &squareRootSquared);
	bn_multiply(&squareRootSquared, &squareRootSquared, &secp256k1.prime);
	bn_mod(&squareRootSquared, &secp256k1.prime);
	
	// Return if the result is equal to the component
	return bn_is_equal(&squareRootSquared, component);
}

// Derive child private key
bool deriveChildPrivateKey(uint8_t *childPrivateKey, const HDNode *extendedPrivateKey, const uint32_t *path, const size_t pathLength) {

	// Set child private key to the extended private key's private key
	memcpy(childPrivateKey, extendedPrivateKey->private_key, sizeof(extendedPrivateKey->private_key));
	
	// Set chain code to the extended private key's chain code
	uint8_t chainCode[sizeof(extendedPrivateKey->chain_code)];
	memcpy(chainCode, extendedPrivateKey->chain_code, sizeof(extendedPrivateKey->chain_code));
	
	// Initialize data
	uint8_t data[SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE + sizeof(uint32_t)];
	
	// Go through the path
	for(size_t i = 0; i < pathLength; ++i) {
	
		// Check if path is hardened
		if(path[i] & PATH_HARDENED) {
		
			// Set the first part of data to zero
			data[0] = 0;
			
			// Append child private key to the data
			memcpy(&data[sizeof(data[0])], childPrivateKey, sizeof(extendedPrivateKey->private_key));
		}
		
		// Otherwise
		else {
		
			// Check if setting data to the child private key's compressed public key failed
			if(!getPublicKeyFromSecp256k1PrivateKey(data, childPrivateKey)) {
			
				// Clear child private key
				memzero(childPrivateKey, sizeof(extendedPrivateKey->private_key));
				
				// Clear chain code
				memzero(chainCode, sizeof(chainCode));
				
				// Return false
				return false;
			}
		}
		
		// Append path to data
		write_be(&data[SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE], path[i]);
		
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
bool commitValue(uint8_t *commitment, const uint64_t value, const uint8_t *blindingFactor, const bool compress) {

	// Get value as a big number
	bignum256 valueBigNumber;
	bn_read_uint64(value, &valueBigNumber);
	
	// Check if getting the product of the value big number and generator H failed
	curve_point hImage;
	if(point_multiply(&secp256k1, &valueBigNumber, &GENERATOR_H, &hImage)) {
	
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
	commitment[0] = isQuadraticResidue(&gImage.y) ? COMMITMENT_EVEN_PREFIX : COMMITMENT_ODD_PREFIX;
	
	// Copy result's x component to the commitment
	bn_write_be(&gImage.x, &commitment[PUBLIC_KEY_PREFIX_SIZE]);
	
	// Check if not compressing
	if(!compress) {
	
		// Copy result's y component to the commitment
		bn_write_be(&gImage.y, &commitment[PUBLIC_KEY_PREFIX_SIZE + PUBLIC_KEY_COMPONENT_SIZE]);
	}
	
	// Return true
	return true;
}

// Derive blinding factor
bool deriveBlindingFactor(uint8_t *blindingFactor, const HDNode *extendedPrivateKey, const uint64_t value, const uint32_t *path, const size_t pathLength, const MimbleWimbleCoinSwitchType switchType) {

	// Check if deriving the extended private key's child private key failed
	uint8_t childPrivateKey[SECP256K1_PRIVATE_KEY_SIZE];
	if(!deriveChildPrivateKey(childPrivateKey, extendedPrivateKey, path, pathLength)) {
	
		// Return false
		return false;
	}
	
	// Check switch type
	switch(switchType) {
	
		// None
		case MimbleWimbleCoinSwitchType_NONE:
		
			// Set blinding factor to the child private key
			memcpy(blindingFactor, childPrivateKey, sizeof(childPrivateKey));
			
			// Clear child private key
			memzero(childPrivateKey, sizeof(childPrivateKey));
			
			// Break
			break;
		
		// Regular
		case MimbleWimbleCoinSwitchType_REGULAR: {
		
			// Check if getting commitment from value and child private key failed
			uint8_t commitment[COMPRESSED_COMMITMENT_SIZE];
			if(!commitValue(commitment, value, childPrivateKey, true)) {
			
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
			if(point_multiply(&secp256k1, &childPrivateKeyBigNumber, &GENERATOR_J, &jImage)) {
			
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
			uint8_t jImagePublicKey[SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
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
			
			// Break
			break;
		}
	}
	
	// Return true
	return true;
}

// Get address private key
bool getAddressPrivateKey(uint8_t *addressPrivateKey, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *curveName) {

	// Check currency's address derivation type
	switch(coinInfo->addressDerivationType) {
	
		// MWC address derivation
		case MimbleWimbleCoinAddressDerivationType_MWC_ADDRESS_DERIVATION: {
		
			// Check if deriving blinding factor from the address private key blinding factor value and root path failed
			uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
			if(!deriveBlindingFactor(blindingFactor, extendedPrivateKey, ADDRESS_PRIVATE_KEY_BLINDING_FACTOR_VALUE, NULL, 0, MimbleWimbleCoinSwitchType_REGULAR)) {
			
				// Return false
				return false;
			}
			
			// Get the node as the HMAC-SHA512 of the blinding factor with the addres private key hash key as the key
			uint8_t node[NODE_SIZE];
			hmac_sha512((const uint8_t *)ADDRESS_PRIVATE_KEY_HASH_KEY, sizeof(ADDRESS_PRIVATE_KEY_HASH_KEY), blindingFactor, sizeof(blindingFactor), node);
			
			// Clear blinding factor
			memzero(blindingFactor, sizeof(blindingFactor));
			
			// Check if node private key isn't a valid secp256k1 private key
			if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(node, SECP256K1_PRIVATE_KEY_SIZE)) {
			
				// Clear node
				memzero(node, sizeof(node));
				
				// Return false
				return false;
			}
			
			// Create current extended private key from the node
			HDNode currentExtendedPrivateKey;
			memcpy(currentExtendedPrivateKey.private_key, node, SECP256K1_PRIVATE_KEY_SIZE);
			memcpy(currentExtendedPrivateKey.chain_code, &node[SECP256K1_PRIVATE_KEY_SIZE], CHAIN_CODE_SIZE);
			
			// Clear node
			memzero(node, sizeof(node));
			
			// Check if derive the address private key from the current extended private key at the index failed
			if(!deriveChildPrivateKey(addressPrivateKey, &currentExtendedPrivateKey, &index, 1)) {
			
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
			if(!deriveBlindingFactor(blindingFactor, extendedPrivateKey, 0, path, sizeof(path) / sizeof(path[0]), MimbleWimbleCoinSwitchType_NONE)) {
			
				// Return false
				return false;
			}
			
			// Check if getting address private key as the hash of the blinding factor failed
			if(blake2b(blindingFactor, sizeof(blindingFactor), addressPrivateKey, SECP256K1_PRIVATE_KEY_SIZE)) {
			
				// Clear address private key
				memzero(addressPrivateKey, SECP256K1_PRIVATE_KEY_SIZE);
				
				// Clear blinding factor
				memzero(blindingFactor, sizeof(blindingFactor));
				
				// Return false
				return false;
			}
			
			// Clear blinding factor
			memzero(blindingFactor, sizeof(blindingFactor));
			
			// Check if address private key isn't a valid secp256k1 private key
			if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(addressPrivateKey, SECP256K1_PRIVATE_KEY_SIZE)) {
			
				// Clear address private key
				memzero(addressPrivateKey, SECP256K1_PRIVATE_KEY_SIZE);
				
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
		if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(addressPrivateKey, SECP256K1_PRIVATE_KEY_SIZE)) {
		
			// Clear address private key
			memzero(addressPrivateKey, SECP256K1_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
	}
	
	// Otherwise check if curve is Ed25519
	else if(!strcmp(curveName, ED25519_NAME)) {
	
		// Check if address private key isn't a valid Ed25519 private key
		if(!isValidEd25519PrivateKey(addressPrivateKey, ED25519_PRIVATE_KEY_SIZE)) {
		
			// Clear address private key
			memzero(addressPrivateKey, ED25519_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
	}
	
	// Otherwise
	else {
	
		// Clear address private key
		memzero(addressPrivateKey, SECP256K1_PRIVATE_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get MQS address from public key
bool getMqsAddressFromPublicKey(char *mqsAddress, const MimbleWimbleCoinCoinInfo *coinInfo, const uint8_t *publicKey) {

	// Create address data from version and public key
	uint8_t addressData[sizeof(coinInfo->mqsVersion) + SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	memcpy(addressData, coinInfo->mqsVersion, sizeof(coinInfo->mqsVersion));
	memcpy(&addressData[sizeof(coinInfo->mqsVersion)], publicKey, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	
	// Return if getting the MQS address by base58 encoding the address data was successful
	return base58_encode_check(addressData, sizeof(addressData), HASHER_SHA2D, mqsAddress, MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE + sizeof((char)'\0'));
}

// Get public key from MQS address
bool getPublicKeyFromMqsAddress(uint8_t *publicKey, const MimbleWimbleCoinCoinInfo *coinInfo, const char *mqsAddress, const size_t mqsAddressLength) {

	// Check if MQS address's length is invalid
	if(mqsAddressLength != MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if decoding MQS address failed
	char mqsAddressString[mqsAddressLength + sizeof((char)'\0')];
	memcpy(mqsAddressString, mqsAddress, mqsAddressLength);
	mqsAddressString[mqsAddressLength] = '\0';
	uint8_t addressData[sizeof(coinInfo->mqsVersion) + SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	if(!base58_decode_check(mqsAddressString, HASHER_SHA2D, addressData, sizeof(addressData))) {
	
		// Return false
		return false;
	}
	
	// Check if MQS address's version is invalid
	if(memcmp(addressData, coinInfo->mqsVersion, sizeof(coinInfo->mqsVersion))) {
	
		// Return false
		return false;
	}
	
	// Check if MQS address's public key isn't a valid secp256k1 public key
	if(!mimbleWimbleCoinIsValidSecp256k1PublicKey(&addressData[sizeof(coinInfo->mqsVersion)], SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting public key
	if(publicKey) {
	
		// Set public key to the MQS address's public key
		memcpy(publicKey, &addressData[sizeof(coinInfo->mqsVersion)], SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	}
	
	// Return true
	return true;
}

// Get Tor address checksum
void getTorAddressChecksum(uint8_t *checksum, const uint8_t *publicKey) {

	// Create address data from checksum seed, public key, and version
	uint8_t addressData[sizeof(TOR_ADDRESS_CHECKSUM_SEED) + ED25519_PUBLIC_KEY_SIZE + sizeof(TOR_ADDRESS_VERSION)];
	memcpy(addressData, TOR_ADDRESS_CHECKSUM_SEED, sizeof(TOR_ADDRESS_CHECKSUM_SEED));
	memcpy(&addressData[sizeof(TOR_ADDRESS_CHECKSUM_SEED)], publicKey, ED25519_PUBLIC_KEY_SIZE);
	addressData[sizeof(TOR_ADDRESS_CHECKSUM_SEED) + ED25519_PUBLIC_KEY_SIZE] = TOR_ADDRESS_VERSION;
	
	// Get hash of address data
	uint8_t hash[sha3_256_hash_size];
	sha3_256(addressData, sizeof(addressData), hash);
	
	// Get checksum from the hash
	memcpy(checksum, hash, TOR_ADDRESS_CHECKSUM_SIZE);
}

// Get Tor address from public key
bool getTorAddressFromPublicKey(char *torAddress, const uint8_t *publicKey) {

	// Get checksum
	uint8_t checksum[TOR_ADDRESS_CHECKSUM_SIZE];
	getTorAddressChecksum(checksum, publicKey);
	
	// Get address data from public key and checksum
	uint8_t addressData[ED25519_PUBLIC_KEY_SIZE + sizeof(checksum) + sizeof(TOR_ADDRESS_VERSION)];
	memcpy(addressData, publicKey, ED25519_PUBLIC_KEY_SIZE);
	memcpy(&addressData[ED25519_PUBLIC_KEY_SIZE], checksum, sizeof(checksum));
	addressData[ED25519_PUBLIC_KEY_SIZE + sizeof(checksum)] = TOR_ADDRESS_VERSION;
	
	// Return if getting the Tor address by base32 encoding the address data was successful
	return base32_encode(addressData, sizeof(addressData), torAddress, MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE + sizeof((char)'\0'), TOR_BASE32_ALPHABET);
}

// Get public key from Tor address
bool getPublicKeyFromTorAddress(uint8_t *publicKey, const char *torAddress, const size_t torAddressLength) {

	// Check if Tor address's length is invalid
	if(torAddressLength != MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if decoding Tor address failed
	uint8_t addressData[ED25519_PUBLIC_KEY_SIZE + TOR_ADDRESS_CHECKSUM_SIZE + sizeof(TOR_ADDRESS_VERSION)];
	if(!base32_decode(torAddress, torAddressLength, addressData, sizeof(addressData), TOR_BASE32_ALPHABET)) {
	
		// Return false
		return false;
	}
	
	// Check if Tor address's version is invalid
	if(addressData[ED25519_PUBLIC_KEY_SIZE + TOR_ADDRESS_CHECKSUM_SIZE] != TOR_ADDRESS_VERSION) {
	
		// Return false
		return false;
	}
	
	// Check if Tor address's checksum is invalid
	uint8_t checksum[TOR_ADDRESS_CHECKSUM_SIZE];
	getTorAddressChecksum(checksum, addressData);
	if(memcmp(&addressData[ED25519_PUBLIC_KEY_SIZE], checksum, sizeof(checksum))) {
	
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
		memcpy(publicKey, addressData, ED25519_PUBLIC_KEY_SIZE);
	}
	
	// Return true
	return true;
}

// Get Slatepack address from public key
bool getSlatepackAddressFromPublicKey(char *slatepackAddress, const MimbleWimbleCoinCoinInfo *coinInfo, const uint8_t *publicKey) {

	// Check if converting public key to bits failed
	uint8_t bits[(ED25519_PUBLIC_KEY_SIZE * BITS_IN_A_BYTE + (BECH32_BITS_PER_CHARACTER - 1)) / BECH32_BITS_PER_CHARACTER];
	size_t bitsLength = 0;
	if(!convert_bits(bits, &bitsLength, BECH32_BITS_PER_CHARACTER, publicKey, ED25519_PUBLIC_KEY_SIZE, BITS_IN_A_BYTE, true)) {
	
		// Return false
		return false;
	}
	
	// Return if getting the Slatepack address by Bech32 encoding the address data was successful
	return bech32_encode(slatepackAddress, coinInfo->slatepackAddressHumanReadablePart, bits, bitsLength, BECH32_ENCODING_BECH32);
}

// Get public key from Slatepack address
bool getPublicKeyFromSlatepackAddress(uint8_t *publicKey, const MimbleWimbleCoinCoinInfo *coinInfo, const char *slatepackAddress, const size_t slatepackAddressLength) {

	// Check if Slatepack address's length is invalid
	if(slatepackAddressLength != MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + strlen(coinInfo->slatepackAddressHumanReadablePart)) {
	
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
	if(bitsLength != (ED25519_PUBLIC_KEY_SIZE * BITS_IN_A_BYTE + (BECH32_BITS_PER_CHARACTER - 1)) / BECH32_BITS_PER_CHARACTER) {
	
		// Return false
		return false;
	}
	
	// Check if Slatepack address's human-readable part is invalid
	if(strcmp(humanReadablePart, coinInfo->slatepackAddressHumanReadablePart)) {
	
		// Return false
		return false;
	}
	
	// Check if getting address data from bits failed
	uint8_t addressData[(bitsLength * BECH32_BITS_PER_CHARACTER + (BITS_IN_A_BYTE - 1)) / BITS_IN_A_BYTE];
	size_t addressDataLength = 0;
	if(!convert_bits(addressData, &addressDataLength, BITS_IN_A_BYTE, bits, bitsLength, BECH32_BITS_PER_CHARACTER, false)) {
	
		// Return false
		return false;
	}
	
	// Check if address data length is invalid
	if(addressDataLength != ED25519_PUBLIC_KEY_SIZE) {
	
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
		memcpy(publicKey, addressData, ED25519_PUBLIC_KEY_SIZE);
	}
	
	// Return true
	return true;
}

// Update Bulletproof challenge
void updateBulletproofChallenge(uint8_t *challenge, const curve_point *leftPart, const curve_point *rightPart) {

	// Initialize hash
	SHA256_CTX hash;
	sha256_Init(&hash);
	
	// Add challenge to the hash
	sha256_Update(&hash, challenge, SHA256_DIGEST_LENGTH);
	
	// Set parity to if the part's y components aren't quadratic residue
	const uint8_t parity = (!isQuadraticResidue(&leftPart->y) << 1) | !isQuadraticResidue(&rightPart->y);
	
	// Add parity to the hash
	sha256_Update(&hash, &parity, sizeof(parity));
	
	// Add left part's x component to the hash
	uint8_t leftPartXComponents[PUBLIC_KEY_COMPONENT_SIZE];
	bn_write_be(&leftPart->x, leftPartXComponents);
	sha256_Update(&hash, leftPartXComponents, sizeof(leftPartXComponents));
	
	// Add right part's x component to the hash
	uint8_t rightPartXComponents[PUBLIC_KEY_COMPONENT_SIZE];
	bn_write_be(&rightPart->x, rightPartXComponents);
	sha256_Update(&hash, rightPartXComponents, sizeof(rightPartXComponents));
	
	// Set challenge to the hash
	sha256_Final(&hash, challenge);
}

// Create scalars from ChaCha20
void createScalarsFromChaCha20(bignum256 *firstScalar, bignum256 *secondScalar, const uint8_t *seed, const uint64_t index, const bool isPrivate) {

	// Initialize couter
	uint64_t counter = 0;
	
	// Initialize ChaCha20 Poly1305 state
	ECRYPT_ctx chaCha20Poly1305State;
	ECRYPT_keysetup(&chaCha20Poly1305State, seed, SCALAR_SIZE * BITS_IN_A_BYTE, 16);
	
	// Initialize zero block
	uint8_t zeroBlock[SCALAR_SIZE + SCALAR_SIZE];
	
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
		bn_read_be(&zeroBlock[SCALAR_SIZE], secondScalar);
		
		// Increment counter
		counter += (uint64_t)1 << (sizeof(uint32_t) * BITS_IN_A_BYTE);
		
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
void useLrGenerator(bignum256 *t0, bignum256 *t1, bignum256 *t2, const bignum256 *y, const bignum256 *z, const uint8_t *rewindNonce, const uint64_t value, const char *displayMessage) {

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
	bn_submod(&inputs[0], &inputs[1], &inputs[2], &secp256k1.order);
	
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
	for(uint_fast8_t i = 0; i < BITS_TO_PROVE; ++i) {
	
		// Get bit in the value
		const bool bit = (value >> i) & 1;
		
		// Set lout
		bn_read_uint32(bit, &lout);
		
		// Subtract z from lout
		bn_submod(&lout, z, &lout, &secp256k1.order);
		
		// Set rout
		bn_read_uint32(1 - bit, &rout);
		
		// Subtract rout from z
		bn_submod(z, &rout, &rout, &secp256k1.order);
		
		// Create sl and sr from rewind nonce
		createScalarsFromChaCha20(&sl, &sr, rewindNonce, i + 2, false);
		
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
	
	// Update shown progress
	layoutProgress(displayMessage, 1000 * 12 / 12);
	
	// Go through all outputs
	for(size_t i = 0; i < sizeof(outputs) / sizeof(outputs[0]); ++i) {
	
		// Normalize output
		bn_mod(outputs[i], &secp256k1.order);
	}
}

// Calculate Bulletproof components
bool calculateBulletproofComponents(uint8_t *tauX, uint8_t *tOne, uint8_t *tTwo, const uint64_t value, const uint8_t *blindingFactor, const uint8_t *commitment, const uint8_t *rewindNonce, const uint8_t *privateNonce, const uint8_t *message, const char *displayMessage) {

	// Initialize challenge
	uint8_t challenge[SHA256_DIGEST_LENGTH] = {0};
	
	// Update challenge with the commitment and generator H
	curve_point commitmentPoint;
	bn_read_be(&commitment[PUBLIC_KEY_PREFIX_SIZE], &commitmentPoint.x);
	bn_read_be(&commitment[PUBLIC_KEY_PREFIX_SIZE + PUBLIC_KEY_COMPONENT_SIZE], &commitmentPoint.y);
	updateBulletproofChallenge(challenge, &commitmentPoint, &GENERATOR_H);
	
	// Set message bytes to contain the value and message
	uint8_t messageBytes[SCALAR_SIZE] = {0};
	write_be(&messageBytes[SCALAR_SIZE - sizeof(uint32_t)], value);
	write_be(&messageBytes[SCALAR_SIZE - sizeof(uint64_t)], value >> (sizeof(uint32_t) * BITS_IN_A_BYTE));
	memcpy(&messageBytes[SCALAR_SIZE - sizeof(value) - BULLETPROOF_MESSAGE_SIZE], message, BULLETPROOF_MESSAGE_SIZE);
	
	// Create alpha and rho from rewind nonce
	bignum256 alpha;
	bignum256 rho;
	createScalarsFromChaCha20(&alpha, &rho, rewindNonce, 0, false);
	
	// Subtract message bytes from alpha
	bignum256 messageBytesBigNumber;
	bn_read_be(messageBytes, &messageBytesBigNumber);
	bn_submod(&alpha, &messageBytesBigNumber, &alpha, &secp256k1.order);
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
	for(uint_fast8_t i = 0; i < BITS_TO_PROVE; ++i) {
	
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
	
	// Update shown progress
	layoutProgress(displayMessage, 1000 * 1 / 12);
	
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
	for(uint_fast8_t i = 0; i < MULTIEXPONENTIATION_STEPS; ++i) {
	
		// Initialize WNAFs
		int8_t wnafs[MIMBLEWIMBLE_COIN_NUMBER_OF_GENERATORS / MULTIEXPONENTIATION_STEPS][WNAF_SIZE];
		
		// Go through all bits to prove in the multiexponentiation step
		for(uint_fast8_t j = 0; j < BITS_TO_PROVE / MULTIEXPONENTIATION_STEPS; ++j) {
		
			// Create sl and sr from rewind nonce
			createScalarsFromChaCha20(&sl, &sr, rewindNonce, i * (BITS_TO_PROVE / MULTIEXPONENTIATION_STEPS) + j + 2, false);
			
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
		point_multiexponentiation(&secp256k1, &MIMBLEWIMBLE_COIN_GENERATORS[i * MIMBLEWIMBLE_COIN_NUMBER_OF_GENERATORS / MULTIEXPONENTIATION_STEPS * MIMBLEWIMBLE_COIN_NUMBER_OF_ODD_GENERATOR_MULTIPLES], MIMBLEWIMBLE_COIN_NUMBER_OF_GENERATORS / MULTIEXPONENTIATION_STEPS, wnafs, MIMBLEWIMBLE_COIN_GENERATORS_WINDOW_SIZE, &sterm);
		
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
		
		// Update shown progress
		layoutProgress(displayMessage, (1000 * (i + 1) * (12 - 2) / MULTIEXPONENTIATION_STEPS + (1000 * 1)) / 12);
	}
	
	// Update challenge with the alpha image and rho image
	updateBulletproofChallenge(challenge, &alphaImage, &rhoImage);
	
	// Get y from challenge
	bignum256 y;
	bn_read_be(challenge, &y);
	
	// Check if y overflows or is zero
	if(!bn_is_less(&y, &secp256k1.order) || bn_is_zero(&y)) {
		
		// Return false
		return false;
	}
	
	// Update challenge with the alpha image and rho image
	updateBulletproofChallenge(challenge, &alphaImage, &rhoImage);
	
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
	useLrGenerator(&t0, &t1, &t2, &y, &z, rewindNonce, value, displayMessage);
	
	// Get the difference of t1 and t2
	bn_submod(&t1, &t2, &t1, &secp256k1.order);
	
	// Divide the difference by two
	bn_mult_half(&t1, &secp256k1.order);
	bn_mod(&t1, &secp256k1.order);
	
	// Get the difference of t2 and t0
	bn_submod(&t2, &t0, &t2, &secp256k1.order);
	
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
	if(point_multiply(&secp256k1, &t1, &GENERATOR_H, &t1Image)) {
	
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
	createScalarsFromChaCha20(&tau1, &tau2, privateNonce, 1, true);
	
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
		memzero(tOne, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
	
		// Return false
		return false;
	}
	
	// Check if getting the product of the t2 and generator H failed
	curve_point t2Image;
	if(point_multiply(&secp256k1, &t2, &GENERATOR_H, &t2Image)) {
	
		// Clear t one
		memzero(tOne, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
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
		memzero(tOne, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
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
		memzero(tOne, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
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
		memzero(tOne, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
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
		memzero(tTwo, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear t one
		memzero(tOne, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear tau1
		memzero(&tau1, sizeof(tau1));
		
		// Clear tau2
		memzero(&tau2, sizeof(tau2));
	
		// Return false
		return false;
	}
	
	// Update challenge with the t1 image and rho t2
	updateBulletproofChallenge(challenge, &t1Image, &t2Image);
	
	// Get x from challenge
	bignum256 x;
	bn_read_be(challenge, &x);
	
	// Check if x overflows or is zero
	if(!bn_is_less(&x, &secp256k1.order) || bn_is_zero(&x)) {
	
		// Clear t two
		memzero(tTwo, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
		// Clear t one
		memzero(tOne, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
		
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
bool getMqsSharedPrivateKey(uint8_t *mqsSharedPrivateKey, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *address, const uint8_t *salt) {

	// Check if getting the public key from the address failed
	uint8_t publicKey[SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
	if(!getPublicKeyFromMqsAddress(publicKey, coinInfo, address, MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting address private key failed
	uint8_t addressPrivateKey[SECP256K1_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, index, SECP256K1_NAME)) {
	
		// Return false
		return false;
	}
	
	// Check if creating session key from the address private key and public key failed
	uint8_t sessionKey[SECP256K1_UNCOMPRESSED_PUBLIC_KEY_SIZE];
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
	pbkdf2_hmac_sha512(&sessionKey[PUBLIC_KEY_PREFIX_SIZE], PUBLIC_KEY_COMPONENT_SIZE, salt, MIMBLEWIMBLE_COIN_MQS_ENCRYPTION_SALT_SIZE, MQS_SHARED_PRIVATE_KEY_NUMBER_OF_ITERATIONS, mqsSharedPrivateKey, CHACHA20_KEY_SIZE);
	
	// Clear session key
	memzero(&sessionKeyPoint, sizeof(sessionKeyPoint));
	memzero(sessionKey, sizeof(sessionKey));
	
	// Return if MQS shared private key isn't zero
	return !mimbleWimbleCoinIsZero(mqsSharedPrivateKey, CHACHA20_KEY_SIZE);
}

// Get X25519 private key from Ed25519 private key
bool getX25519PrivateKeyFromEd25519PrivateKey(uint8_t *x25519PrivateKey, const uint8_t *ed25519PrivateKey) {

	// Get hash of the Ed25519 private key
	uint8_t hash[SHA512_DIGEST_LENGTH];
	sha512_Raw(ed25519PrivateKey, ED25519_PRIVATE_KEY_SIZE, hash);
	
	// Clamp the hash
	hash[0] &= 0b11111000;
	hash[31] &= 0b01111111;
	hash[31] |= 0b01000000;
	
	// Check if hash isn't a valid X25519 private key
	if(!isValidX25519PrivateKey(hash, X25519_PRIVATE_KEY_SIZE)) {
	
		// Clear hash
		memzero(hash, sizeof(hash));
	
		// Return false
		return false;
	}
	
	// Set X25519 private key to the hash
	memcpy(x25519PrivateKey, hash, X25519_PRIVATE_KEY_SIZE);
	
	// Clear hash
	memzero(hash, sizeof(hash));
	
	// Return true
	return true;
}

// Get X25519 public key from Ed25519 public key
bool getX25519PublicKeyFromEd25519PublicKey(uint8_t *x25519PublicKey, const uint8_t *ed25519PublicKey) {

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
bool getTorSharedPrivateKey(uint8_t *torSharedPrivateKey, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const char *address) {

	// Check if getting the public key from the address failed
	uint8_t publicKey[ED25519_PUBLIC_KEY_SIZE];
	if(!getPublicKeyFromTorAddress(publicKey, address, MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting X25519 public key from public key failed
	uint8_t x25519PublicKey[MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE];
	if(!getX25519PublicKeyFromEd25519PublicKey(x25519PublicKey, publicKey)) {
	
		// Return false
		return false;
	}
	
	// Check if getting address private key failed
	uint8_t addressPrivateKey[ED25519_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, index, ED25519_NAME)) {
	
		// Return false
		return false;
	}
	
	// Check if getting X25519 private key from address private key failed
	uint8_t x25519PrivateKey[X25519_PRIVATE_KEY_SIZE];
	if(!getX25519PrivateKeyFromEd25519PrivateKey(x25519PrivateKey, addressPrivateKey)) {
	
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
	return !mimbleWimbleCoinIsZero(torSharedPrivateKey, CHACHA20_KEY_SIZE);
}

// Get Slatepack shared private key
bool getSlatepackSharedPrivateKey(uint8_t *slatepackSharedPrivateKey, const HDNode *extendedPrivateKey, const MimbleWimbleCoinCoinInfo *coinInfo, const uint32_t index, const uint8_t *ephemeralX25519PublicKey, const uint8_t *encryptedFileKey, const uint8_t *payloadNonce) {

	// Check if getting address private key failed
	uint8_t addressPrivateKey[ED25519_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, extendedPrivateKey, coinInfo, index, ED25519_NAME)) {
	
		// Return false
		return false;
	}
	
	// Get address private key's public key
	uint8_t addressPublicKey[ED25519_PUBLIC_KEY_SIZE];
	ed25519_publickey(addressPrivateKey, addressPublicKey);
	
	// Check if getting X25519 private key from address private key failed
	uint8_t x25519PrivateKey[X25519_PRIVATE_KEY_SIZE];
	if(!getX25519PrivateKeyFromEd25519PrivateKey(x25519PrivateKey, addressPrivateKey)) {
	
		// Clear address private key
		memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
		// Return false
		return false;
	}
	
	// Clear address private key
	memzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Check if getting X25519 public key from the address public key failed
	uint8_t x25519PublicKey[MIMBLEWIMBLE_COIN_X25519_PUBLIC_KEY_SIZE];
	if(!getX25519PublicKeyFromEd25519PublicKey(x25519PublicKey, addressPublicKey)) {
	
		// Clear X25519 private key
		memzero(x25519PrivateKey, sizeof(x25519PrivateKey));
		
		// Return false
		return false;
	}
	
	// Get shared private key from X25519 private key and X25519 public key
	uint8_t sharedPrivateKey[X25519_PRIVATE_KEY_SIZE];
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
	hmac_sha256(pseudorandomKey, sizeof(pseudorandomKey), (const uint8_t *)AGE_WRAP_KEY_INFO_AND_COUNTER, sizeof(AGE_WRAP_KEY_INFO_AND_COUNTER), wrapKey);
	memzero(pseudorandomKey, sizeof(pseudorandomKey));
	
	// Clear shared private key
	memzero(sharedPrivateKey, sizeof(sharedPrivateKey));
	
	// Decrypt file key with the wrap key
	chacha20poly1305_ctx chaCha20Poly1305Context;
	const uint8_t fileKeyNonce[CHACHA20_NONCE_SIZE] = {0};
	rfc7539_init(&chaCha20Poly1305Context, wrapKey, fileKeyNonce);
	uint8_t fileKey[AGE_FILE_KEY_SIZE];
	chacha20poly1305_decrypt(&chaCha20Poly1305Context, encryptedFileKey, fileKey, sizeof(fileKey));
	
	// Clear wrap key
	memzero(wrapKey, sizeof(wrapKey));
	
	// Get tag
	uint8_t tag[POLY1305_TAG_SIZE];
	rfc7539_finish(&chaCha20Poly1305Context, 0, AGE_FILE_KEY_SIZE, tag);
	
	// Clear ChaCha20 Poly1305 context
	memzero(&chaCha20Poly1305Context, sizeof(chaCha20Poly1305Context));
	
	// Check if file key's tag isn't correct
	if(!isEqual(&encryptedFileKey[AGE_FILE_KEY_SIZE], tag, sizeof(tag))) {
	
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
	hmac_sha256(payloadNonce, AGE_PAYLOAD_NONCE_SIZE, fileKey, sizeof(fileKey), pseudorandomKey);
	hmac_sha256(pseudorandomKey, sizeof(pseudorandomKey), (const uint8_t *)AGE_PAYLOAD_KEY_INFO_AND_COUNTER, sizeof(AGE_PAYLOAD_KEY_INFO_AND_COUNTER), slatepackSharedPrivateKey);
	memzero(pseudorandomKey, sizeof(pseudorandomKey));
	
	// Clear file key
	memzero(fileKey, sizeof(fileKey));
	
	// Return if Slatepack shared private key isn't zero
	return !mimbleWimbleCoinIsZero(slatepackSharedPrivateKey, CHACHA20_KEY_SIZE);
}

// Create single-signer nonces
bool createSingleSignerNonces(uint8_t *secretNonce, uint8_t *publicNonce) {

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
	if(!isQuadraticResidue(&gImage.y)) {
	
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
bool updateBlindingFactorSum(uint8_t *blindingFactorSum, const uint8_t *blindingFactor, const bool blindingFactorIsPositive) {

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
		bn_submod(&blindingFactorSumBigNumber, &blindingFactorBigNumber, &blindingFactorSumBigNumber, &secp256k1.order);
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
bool createSingleSignerSignature(uint8_t *signature, const uint8_t *message, const uint8_t *privateKey, const uint8_t *secretNonce, const uint8_t *publicNonce, const uint8_t *publicKey) {

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
	sha256_Update(&hashContext, &publicNonce[PUBLIC_KEY_PREFIX_SIZE], PUBLIC_KEY_COMPONENT_SIZE);
	sha256_Update(&hashContext, publicKey, SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE);
	sha256_Update(&hashContext, message, SINGLE_SIGNER_MESSAGE_SIZE);
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
	if(isQuadraticResidue(&point.y)) {
	
		// Add secret nonce to the result
		bn_addmod(&privateKeyBigNumber, &secretNonceBigNumber, &secp256k1.order);
	}
	
	// Otherwise
	else {
	
		// Subtract secret nonce from the result
		bn_submod(&privateKeyBigNumber, &secretNonceBigNumber, &privateKeyBigNumber, &secp256k1.order);
	}
	
	// Clear secret nonce big number
	memzero(&secretNonceBigNumber, sizeof(secretNonceBigNumber));
	
	// Set signature's s component
	bn_mod(&privateKeyBigNumber, &secp256k1.order);
	bn_write_le(&privateKeyBigNumber, &signature[SCALAR_SIZE]);
	
	// Clear private key big number
	memzero(&privateKeyBigNumber, sizeof(privateKeyBigNumber));
	
	// Return true
	return true;
}

// Get AES encrypted data length
size_t getAesEncryptedDataLength(const size_t dataLength) {

	// Return encrypted data length
	return dataLength + ((dataLength % AES_BLOCK_SIZE) ? AES_BLOCK_SIZE - dataLength % AES_BLOCK_SIZE : AES_BLOCK_SIZE);
}

// AES encrypt
bool aesEncrypt(uint8_t *encryptedData, const uint8_t *key, const uint8_t *data, const size_t dataLength) {

	// Check if creating AES context with the key failed
	aes_encrypt_ctx aesContext;
	if(aes_encrypt_key256(key, &aesContext)) {
	
		// Clear AES context
		memzero(&aesContext, sizeof(aesContext));
		
		// Return false
		return false;
	}
	
	// Pad the data
	uint8_t paddedData[getAesEncryptedDataLength(dataLength)];
	memcpy(paddedData, data, dataLength);
	memset(&paddedData[dataLength], sizeof(paddedData) - dataLength, sizeof(paddedData) - dataLength);
	
	// Check if AES encrypting the padded data failed
	uint8_t aesIv[AES_IV_SIZE] = {0};
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
size_t aesDecrypt(uint8_t *data, const uint8_t *key, const uint8_t *encryptedData, const size_t encryptedDataLength) {

	// Check if creating AES context with the key failed
	aes_decrypt_ctx aesContext;
	if(aes_decrypt_key256(key, &aesContext)) {
	
		// Clear AES context
		memzero(&aesContext, sizeof(aesContext));
		
		// Return false
		return false;
	}
	
	// Check if AES decrypting the encrypted data failed
	uint8_t aesIv[AES_IV_SIZE] = {0};
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
size_t getPaymentProofMessageLength(const MimbleWimbleCoinCoinInfo *coinInfo, const uint64_t value, const char *senderAddress) {

	// Get sender address's length
	const size_t senderAddressLength = strlen(senderAddress);
	
	// Check currency's payment proof message type
	switch(coinInfo->paymentProofMessageType) {
	
		// ASCII payment proof message
		case MimbleWimbleCoinPaymentProofMessageType_ASCII_PAYMENT_PROOF_MESSAGE: {
		
			// Get value as a string
			char valueBuffer[MIMBLEWIMBLE_COIN_UINT64_BUFFER_SIZE + sizeof((char)'\0')];
			bn_format_uint64(value, NULL, NULL, 0, 0, false, 0, valueBuffer, sizeof(valueBuffer));
			
			// Return payment proof message length
			return COMPRESSED_COMMITMENT_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE + senderAddressLength + strlen(valueBuffer);
		}
		
		// Binary payment proof message
		case MimbleWimbleCoinPaymentProofMessageType_BINARY_PAYMENT_PROOF_MESSAGE:
		
			// Check sender address length
			switch(senderAddressLength) {
			
				// MQS address size
				case MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE:
				
					// Return payment proof message length
					return sizeof(value) + COMPRESSED_COMMITMENT_SIZE + SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE;
				
				// Tor address size
				case MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE:
				
					// Return payment proof message length
					return sizeof(value) + COMPRESSED_COMMITMENT_SIZE + ED25519_PUBLIC_KEY_SIZE;
				
				// Default
				default:
				
					// Check if sender address length is Slatepack address length
					if(senderAddressLength == MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + strlen(coinInfo->slatepackAddressHumanReadablePart)) {
					
						// Return payment proof message length
						return sizeof(value) + COMPRESSED_COMMITMENT_SIZE + ED25519_PUBLIC_KEY_SIZE;
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
bool getPaymentProofMessage(uint8_t *paymentProofMessage, const MimbleWimbleCoinCoinInfo *coinInfo, uint64_t value, const uint8_t *kernelCommitment, const char *senderAddress) {

	// Get sender address's length
	const size_t senderAddressLength = strlen(senderAddress);
	
	// Check currency's payment proof message type
	switch(coinInfo->paymentProofMessageType) {
	
		// ASCII payment proof message
		case MimbleWimbleCoinPaymentProofMessageType_ASCII_PAYMENT_PROOF_MESSAGE: {
		
			// Append kernel commitment as a hex string to the payment proof message
			mimbleWimbleCoinToHexString(kernelCommitment, COMPRESSED_COMMITMENT_SIZE, (char *)paymentProofMessage);
			
			// Append sender address to the payment proof message
			memcpy(&paymentProofMessage[COMPRESSED_COMMITMENT_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE], senderAddress, senderAddressLength);
			
			// Append value as a string to the payment proof message
			char valueBuffer[MIMBLEWIMBLE_COIN_UINT64_BUFFER_SIZE + sizeof((char)'\0')];
			bn_format_uint64(value, NULL, NULL, 0, 0, false, 0, valueBuffer, sizeof(valueBuffer));
			memcpy(&paymentProofMessage[COMPRESSED_COMMITMENT_SIZE * MIMBLEWIMBLE_COIN_HEX_CHARACTER_SIZE + senderAddressLength], valueBuffer, strlen(valueBuffer));
			
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
					uint8_t publicKey[SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
					if(!getPublicKeyFromMqsAddress(publicKey, coinInfo, senderAddress, senderAddressLength)) {
					
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
					memcpy(&paymentProofMessage[sizeof(value)], kernelCommitment, COMPRESSED_COMMITMENT_SIZE);
					
					// Append public key to the payment proof message
					memcpy(&paymentProofMessage[sizeof(value) + COMPRESSED_COMMITMENT_SIZE], publicKey, sizeof(publicKey));
				
					// Return true
					return true;
				}
				
				// Tor address size
				case MIMBLEWIMBLE_COIN_TOR_ADDRESS_SIZE: {
				
					// Check if getting public key from the sender address failed
					uint8_t publicKey[ED25519_PUBLIC_KEY_SIZE];
					if(!getPublicKeyFromTorAddress(publicKey, senderAddress, senderAddressLength)) {
					
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
					memcpy(&paymentProofMessage[sizeof(value)], kernelCommitment, COMPRESSED_COMMITMENT_SIZE);
					
					// Append public key to the payment proof message
					memcpy(&paymentProofMessage[sizeof(value) + COMPRESSED_COMMITMENT_SIZE], publicKey, sizeof(publicKey));
					
					// Return true
					return true;
				}
				
				// Default
				default:
				
					// Check if sender address length is Slatepack address length
					if(senderAddressLength == MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + strlen(coinInfo->slatepackAddressHumanReadablePart)) {
					
						// Check if getting public key from the sender address failed
						uint8_t publicKey[ED25519_PUBLIC_KEY_SIZE];
						if(!getPublicKeyFromSlatepackAddress(publicKey, coinInfo, senderAddress, senderAddressLength)) {
						
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
						memcpy(&paymentProofMessage[sizeof(value)], kernelCommitment, COMPRESSED_COMMITMENT_SIZE);
						
						// Append public key to the payment proof message
						memcpy(&paymentProofMessage[sizeof(value) + COMPRESSED_COMMITMENT_SIZE], publicKey, sizeof(publicKey));
						
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
bool verifyPaymentProofMessage(const uint8_t *paymentProofMessage, const size_t paymentProofMessageLength, const MimbleWimbleCoinCoinInfo *coinInfo, const char *receiverAddress, const uint8_t *paymentProof, const size_t paymentProofLength) {

	// Get receiver address's length
	const size_t receiverAddressLength = strlen(receiverAddress);
	
	// Check receiver address length
	switch(receiverAddressLength) {
	
		// MQS address size
		case MIMBLEWIMBLE_COIN_MQS_ADDRESS_SIZE: {
		
			// Check if getting receiver public key from receiver address failed
			uint8_t receiverPublicKey[SECP256K1_COMPRESSED_PUBLIC_KEY_SIZE];
			if(!getPublicKeyFromMqsAddress(receiverPublicKey, coinInfo, receiverAddress, receiverAddressLength)) {
			
				// Return false
				return false;
			}
			
			// Check if getting payment proof signature from payment proof failed
			uint8_t paymentProofSignature[SECP256K1_COMPACT_SIGNATURE_SIZE];
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
			uint8_t receiverPublicKey[ED25519_PUBLIC_KEY_SIZE];
			if(!getPublicKeyFromTorAddress(receiverPublicKey, receiverAddress, receiverAddressLength)) {
			
				// Return false
				return false;
			}
			
			// Check if payment proof length is invalid
			if(paymentProofLength != ED25519_SIGNATURE_SIZE) {
			
				// Return false
				return false;
			}
			
			// Return if payment proof verifies the payment proof message
			return !ed25519_sign_open(paymentProofMessage, paymentProofMessageLength, receiverPublicKey, paymentProof);
		}
		
		// Default
		default:
		
			// Check if receiver address length is Slatepack address length
			if(receiverAddressLength == MIMBLEWIMBLE_COIN_SLATEPACK_ADDRESS_SIZE_WITHOUT_HUMAN_READABLE_PART + strlen(coinInfo->slatepackAddressHumanReadablePart)) {
			
				// Check if getting receiver public key from receiver address failed
				uint8_t receiverPublicKey[ED25519_PUBLIC_KEY_SIZE];
				if(!getPublicKeyFromSlatepackAddress(receiverPublicKey, coinInfo, receiverAddress, receiverAddressLength)) {
				
					// Return false
					return false;
				}
				
				// Check if payment proof length is invalid
				if(paymentProofLength != ED25519_SIGNATURE_SIZE) {
				
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

// Get login private key
bool getLoginPrivateKey(uint8_t *loginPrivateKey, const HDNode *extendedPrivateKey) {

	// Initialize path
	const uint32_t path[] = {
		0,
		2,
		0
	};
	
	// Check if deriving blinding factor from the path failed
	uint8_t blindingFactor[MIMBLEWIMBLE_COIN_BLINDING_FACTOR_SIZE];
	if(!deriveBlindingFactor(blindingFactor, extendedPrivateKey, 0, path, sizeof(path) / sizeof(path[0]), MimbleWimbleCoinSwitchType_NONE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting login private key as the hash of the blinding factor failed
	if(blake2b(blindingFactor, sizeof(blindingFactor), loginPrivateKey, SECP256K1_PRIVATE_KEY_SIZE)) {
	
		// Clear login private key
		memzero(loginPrivateKey, SECP256K1_PRIVATE_KEY_SIZE);
		
		// Clear blinding factor
		memzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Clear blinding factor
	memzero(blindingFactor, sizeof(blindingFactor));
	
	// Check if login private key isn't a valid secp256k1 private key
	if(!mimbleWimbleCoinIsValidSecp256k1PrivateKey(loginPrivateKey, SECP256K1_PRIVATE_KEY_SIZE)) {
	
		// Clear login private key
		memzero(loginPrivateKey, SECP256K1_PRIVATE_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}
