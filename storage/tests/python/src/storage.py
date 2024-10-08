import hashlib
import sys

from . import consts, crypto, helpers, prng


class Storage:
    def __init__(self, norcow_class):
        self.initialized = False
        self.unlocked = False
        self.dek = None
        self.sak = None
        self.nc = norcow_class()
        self.pin_log = self.nc.get_pin_log()

    def init(self, hardware_salt: bytes = b""):
        """
        Initializes storage. Normally we would check if EDEK is already present,
        but we simplify things in the python version and suppose we are starting
        a new storage each time.
        """
        self.nc.init()
        self.initialized = True
        self.hw_salt_hash = hashlib.sha256(hardware_salt).digest()

        edek_esak_pvc = self.nc.get(consts.EDEK_ESEK_PVC_KEY)
        if edek_esak_pvc is None:
            self._init_pin()

    def _init_pin(self):
        """
        Initalizes PIN counters, generates random
        Data Encryption Key and Storage Authentication Key
        """
        self.dek = prng.random_buffer(consts.DEK_SIZE)
        self.sak = prng.random_buffer(consts.SAK_SIZE)

        self.nc.set(consts.SAT_KEY, crypto.init_hmacs(self.sak))
        self._set_encrypt(consts.VERSION_KEY, consts.NORCOW_VERSION)
        self.nc.set(consts.UNAUTH_VERSION_KEY, consts.NORCOW_VERSION)
        self.nc.set(consts.STORAGE_UPGRADED_KEY, consts.FALSE_WORD)
        self.pin_log.init()
        self._set_wipe_code(consts.WIPE_CODE_EMPTY)
        self._set_pin(consts.PIN_EMPTY)
        self.unlocked = True

    def _set_pin(self, pin: str):
        random_salt = prng.random_buffer(consts.PIN_SALT_SIZE)
        salt = self.hw_salt_hash + random_salt
        kek, keiv = crypto.derive_kek_keiv(salt, pin)

        # Encrypted Data Encryption Key and Encrypted Storage Authentication Key
        edek_esak, tag = crypto.chacha_poly_encrypt(kek, keiv, self.dek + self.sak)
        # Pin Verification Code
        pvc = tag[: consts.PVC_SIZE]

        self.nc.set(consts.EDEK_ESEK_PVC_KEY, random_salt + edek_esak + pvc)
        if pin == consts.PIN_EMPTY:
            self._set_bool(consts.PIN_NOT_SET_KEY, True)
        else:
            self._set_bool(consts.PIN_NOT_SET_KEY, False)

    def _set_wipe_code(self, wipe_code: str):
        if wipe_code == consts.PIN_EMPTY:
            wipe_code = consts.WIPE_CODE_EMPTY
        wipe_code_bytes = wipe_code.encode()
        salt = prng.random_buffer(consts.WIPE_CODE_SALT_SIZE)
        tag = crypto._hmac(salt, wipe_code_bytes)[: consts.WIPE_CODE_TAG_SIZE]
        self.nc.set(consts.WIPE_CODE_DATA_KEY, wipe_code_bytes + salt + tag)

    def wipe(self):
        self.nc.wipe()
        self._init_pin()

    def check_pin(self, pin: str) -> bool:
        self.pin_log.write_attempt()

        data = self.nc.get(consts.EDEK_ESEK_PVC_KEY)
        salt = self.hw_salt_hash + data[: consts.PIN_SALT_SIZE]
        edek_esak = data[consts.PIN_SALT_SIZE : -consts.PVC_SIZE]
        pvc = data[-consts.PVC_SIZE :]

        try:
            dek, sak = crypto.decrypt_edek_esak(pin, salt, edek_esak, pvc)
            self.pin_log.write_success()
            self.dek = dek
            self.sak = sak
            return True
        except crypto.InvalidPinError:
            fails = self.pin_log.get_failures_count()
            if fails >= consts.PIN_MAX_TRIES:
                self.wipe()
            return False

    def lock(self) -> None:
        self.unlocked = False

    def unlock(self, pin: str) -> bool:
        if not self.initialized or not self.check_pin(pin):
            return False

        version = self._decrypt(consts.VERSION_KEY)
        if version != consts.NORCOW_VERSION:
            return False

        self.unlocked = True
        return True

    def has_pin(self) -> bool:
        val = self.nc.get(consts.PIN_NOT_SET_KEY)
        return val != consts.TRUE_BYTE

    def get_pin_rem(self) -> int:
        return consts.PIN_MAX_TRIES - self.pin_log.get_failures_count()

    def change_pin(self, oldpin: str, newpin: str) -> bool:
        if not self.initialized or not self.unlocked:
            return False
        if not self.check_pin(oldpin):
            return False
        self._set_pin(newpin)
        return True

    def get(self, key: int) -> bytes:
        app = key >> 8
        if not self.initialized or consts.is_app_private(app):
            raise RuntimeError("Storage not initialized or app is private")
        if not self.unlocked and not consts.is_app_public(app):
            # public fields can be read from an unlocked device
            raise RuntimeError("Storage locked")
        if consts.is_app_public(app):
            value = self.nc.get(key)
        else:
            value = self._get_encrypted(key)
        if value is None:
            raise RuntimeError("Failed to find key in storage.")
        return value

    def set(self, key: int, val: bytes) -> bool:
        app = key >> 8
        self._check_lock(app)
        if consts.is_app_public(app):
            return self.nc.set(key, val)
        return self._set_encrypt(key, val)

    def set_counter(self, key: int, val: int):
        app = key >> 8
        if not consts.is_app_public(app):
            raise RuntimeError("Counter can be set only for public items")

        if val > consts.UINT32_MAX:
            raise RuntimeError("Failed to set value in storage.")

        counter = val.to_bytes(4, sys.byteorder)

        if self.nc.is_byte_access():
            counter += bytearray(b"\xFF" * consts.COUNTER_TAIL_SIZE)
        self.set(key, counter)

    def next_counter(self, key: int) -> int:
        app = key >> 8
        self._check_lock(app)

        current = self.nc.get(key)
        if current is None:
            self.set_counter(key, 0)
            return 0

        base = int.from_bytes(current[:4], sys.byteorder)

        if self.nc.is_byte_access():
            base = int.from_bytes(current[:4], sys.byteorder)
            tail = helpers.to_int_by_words(current[4:])
            tail_count = f"{tail:064b}".count("0")
            increased_count = base + tail_count + 1
            if increased_count > consts.UINT32_MAX:
                raise RuntimeError("Failed to set value in storage.")

            if tail_count == consts.COUNTER_MAX_TAIL:
                self.set_counter(key, increased_count)
                return increased_count

            self.set(
                key,
                current[:4]
                + helpers.to_bytes_by_words(tail >> 1, consts.COUNTER_TAIL_SIZE),
            )
        else:
            increased_count = base + 1
            if increased_count > consts.UINT32_MAX:
                raise RuntimeError("Failed to set value in storage.")

            self.set_counter(key, increased_count)
        return increased_count

    def delete(self, key: int) -> bool:
        app = key >> 8
        self._check_lock(app)
        ret = self.nc.delete(key)
        if consts.is_app_protected(app):
            sat = self._calculate_authentication_tag()
            self.nc.set(consts.SAT_KEY, sat)
        return ret

    def _check_lock(self, app: int):
        if not self.initialized or consts.is_app_private(app):
            raise RuntimeError("Storage not initialized or app is private")
        if not self.unlocked and not consts.is_app_lock_writable(app):
            raise RuntimeError("Storage locked and app is not public-writable")

    def _get_encrypted(self, key: int) -> bytes:
        if not consts.is_app_protected(key >> 8):
            raise RuntimeError("Only protected values are encrypted")
        sat = self.nc.get(consts.SAT_KEY)
        if sat is None:
            raise RuntimeError("SAT not found")
        if sat != self._calculate_authentication_tag():
            raise RuntimeError("Storage authentication tag mismatch")
        return self._decrypt(key)

    def _decrypt(self, key: int) -> bytes:
        data = self.nc.get(key)
        if data is None:
            raise RuntimeError("Key not found")
        iv = data[: consts.CHACHA_IV_SIZE]
        # cipher text with MAC

        tag = data[len(data) - consts.POLY1305_MAC_SIZE :]
        ciphertext = data[consts.CHACHA_IV_SIZE : len(data) - consts.POLY1305_MAC_SIZE]
        return crypto.chacha_poly_decrypt(
            self.dek, key, iv, ciphertext + tag, key.to_bytes(2, sys.byteorder)
        )

    def _set_encrypt(self, key: int, val: bytes):
        # In C, data are preallocated beforehand for encrypted values,
        # to match the behaviour we do the same.
        preallocate = b"\xFF" * (
            consts.CHACHA_IV_SIZE + len(val) + consts.POLY1305_MAC_SIZE
        )
        self.nc.set(key, preallocate)
        if consts.is_app_protected(key >> 8):
            sat = self._calculate_authentication_tag()
            self.nc.set(consts.SAT_KEY, sat)

        iv = prng.random_buffer(consts.CHACHA_IV_SIZE)
        cipher_text, tag = crypto.chacha_poly_encrypt(
            self.dek, iv, val, key.to_bytes(2, sys.byteorder)
        )
        return self.nc.replace(key, iv + cipher_text + tag)

    def _calculate_authentication_tag(self) -> bytes:
        keys = []
        for key in self.nc._get_all_keys():
            if consts.is_app_protected(key >> 8):
                keys.append(key.to_bytes(2, sys.byteorder))
        if not keys:
            return crypto.init_hmacs(self.sak)
        return crypto.calculate_hmacs(self.sak, keys)

    def _set_bool(self, key: int, val: bool) -> bool:
        if val:
            return self.nc.set(key, consts.TRUE_BYTE)
        # False is stored as an empty value
        return self.nc.set(key, consts.FALSE_BYTE)

    def _dump(self) -> bytes:
        return self.nc._dump()

    def _get_active_sector(self) -> int:
        return self.nc.active_sector
