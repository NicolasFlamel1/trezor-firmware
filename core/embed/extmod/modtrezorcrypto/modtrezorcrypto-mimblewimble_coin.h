#include "py/objstr.h"
#include "hdnode.h"


/// package: trezorcrypto.mimblewimble_coin
/// from trezorcrypto.bip32 import HDNode


/// def getRootPublicKey(node: HDNode) -> bytes:
///     """
///     Get a node's root public key
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getRootPublicKey(mp_obj_t node) {

	// Get extended private key
	HDNode *extendedPrivateKey = &((mp_obj_HDNode_t *)node)->hdnode;
	
	// Initialize root public key
	vstr_t rootPublicKey;
	vstr_init_len(&rootPublicKey, sizeof(extendedPrivateKey->public_key));
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
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

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_getRootPublicKey_obj, mod_trezorcrypto_mimblewimble_coin_getRootPublicKey);

/// def getSeedCookie(node: HDNode) -> bytes:
///     """
///     Get a node's seed cookie
///     """
STATIC mp_obj_t mod_trezorcrypto_mimblewimble_coin_getSeedCookie(mp_obj_t node) {

	// Get extended private key
	HDNode *extendedPrivateKey = &((mp_obj_HDNode_t *)node)->hdnode;
	
	// Initialize seed cookie
	vstr_t seedCookie;
	vstr_init_len(&seedCookie, SHA512_DIGEST_LENGTH);
	
	// Check if getting extended private key's public key failed
	if(hdnode_fill_public_key(extendedPrivateKey)) {
	
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

STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_mimblewimble_coin_getSeedCookie_obj, mod_trezorcrypto_mimblewimble_coin_getSeedCookie);


// Global table
STATIC const mp_rom_map_elem_t mod_trezorcrypto_mimblewimble_coin_globals_table[] = {

	// Name
	{MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_mimblewimble_coin)},
	
	// Get root public key
	{MP_ROM_QSTR(MP_QSTR_getRootPublicKey), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getRootPublicKey_obj)},
	
	// Get seed cookie
	{MP_ROM_QSTR(MP_QSTR_getSeedCookie), MP_ROM_PTR(&mod_trezorcrypto_mimblewimble_coin_getSeedCookie_obj)}
};

STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_mimblewimble_coin_globals, mod_trezorcrypto_mimblewimble_coin_globals_table);

// Module
STATIC const mp_obj_module_t mod_trezorcrypto_mimblewimble_coin_module = {

	// Base
	.base = {&mp_type_module},
	
	// Globals
	.globals = (mp_obj_dict_t *)&mod_trezorcrypto_mimblewimble_coin_globals
};
