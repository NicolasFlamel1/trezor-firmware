## Message

This firmware supports the following additional messages.

| Wire Identifier | Name                                         | Description |
|-----------------|----------------------------------------------|-------------|
| 0xC700          | `GET_ROOT_PUBLIC_KEY`                        | Requests an account's root public key |
| 0xC780          | `ROOT_PUBLIC_KEY`                            | Response to a `GET_ROOT_PUBLIC_KEY` request |
| 0xC701          | `GET_ADDRESS`                                | Requests an account's address at a provided index |
| 0xC781          | `ADDRESS`                                    | Response to a `GET_ADDRESS` request |
| 0xC702          | `GET_SEED_COOKIE`                            | Requests an account's seed cookie |
| 0xC782          | `SEED_COOKIE`                                | Response to a `GET_SEED_COOKIE` request |
| 0xC703          | `GET_COMMITMENT`                             | Requests an account's commitment for a provided identifier, value, and switch type |
| 0xC783          | `COMMITMENT`                                 | Response to a `GET_COMMITMENT` request |
| 0xC704          | `GET_BULLETPROOF_COMPONENTS`                 | Requests an account's bulletproof components for a provided identifier, value, and switch type |
| 0xC785          | `BULLETPROOF_COMPONENTS`                     | Response to a `GET_BULLETPROOF_COMPONENTS` request |
| 0xC705          | `VERIFY_ROOT_PUBLIC_KEY`                     | Requests if the user verifies that an account's root public key is valid |
| 0xC706          | `VERIFY_ADDRESS`                             | Requests if the user verifies that an account's address at a provided index is valid |
| 0xC707          | `START_ENCRYPTING_SLATE`                     | Requests a random nonce and optional salt that will be used to encrypt data that will be provided later for an account at a provided index |
| 0xC787          | `ENCRYPTED_SLATE_NONCE_AND_SALT`             | Response to a `START_ENCRYPTING_SLATE` request |
| 0xC708          | `CONTINUE_ENCRYPTING_SLATE`                  | Requests the encrypted version of the provided data |
| 0xC788          | `ENCRYPTED_SLATE_DATA`                       | Response to a `CONTINUE_ENCRYPTING_SLATE` request |
| 0xC709          | `FINISH_ENCRYPTING_SLATE`                    | Requests the tag of the data that was encrypted and an optional signature for the message |
| 0xC789          | `ENCRYPTED_SLATE_TAG_AND_SIGNATURE`          | Response to a `FINISH_ENCRYPTING_SLATE` request |
| 0xC70A          | `START_DECRYPTING_SLATE`                     | Requests to prepare to start decrypted data that will be provided later with a provided nonce and optional salt for an account at a provided index |
| 0xC70B          | `CONTINUE_DECRYPTING_SLATE`                  | Requests the decrypted version of the provided data that has then been encrypted with a random AES key |
| 0xC78B          | `DECRYPTED_SLATE_DATA`                       | Response to a `CONTINUE_DECRYPTING_DATA` request |
| 0xC70C          | `FINISH_DECRYPTING_SLATE`                    | Requests the random AES key used to decrypted the data that was previously returned if a valid tag is provided |
| 0xC78C          | `DECRYPTED_SLATE_AES_KEY`                    | Response to a `FINISH_DECRYPTING_SLATE` request |
| 0xC70D          | `START_TRANSACTION`                          | Requests to start a transaction for provided output, input, and fee values for an account at a provided index |
| 0xC70E          | `CONTINUE_TRANSACTION_INCLUDE_OUTPUT`        | Requests to include the output for a provided identifier, value, and switch type in the transaction |
| 0xC70F          | `CONTINUE_TRANSACTION_INCLUDE_INPUT`         | Requests to include the input for a provided identifier, value, and switch type in the transaction |
| 0xC710          | `CONTINUE_TRANSACTION_APPLY_OFFSET`          | Requests to apply an offset to the transaction's blinding factor |
| 0xC790          | `TRANSACTION_SECRET_NONCE_INDEX`             | Response to a `CONTINUE_TRANSACTION_APPLY_OFFSET` request |
| 0xC711          | `CONTINUE_TRANSACTION_GET_PUBLIC_KEY`        | Requests the transaction's blinding factor's public key |
| 0xC791          | `TRANSACTION_PUBLIC_KEY`                     | Response to a `CONTINUE_TRANSACTION_GET_PUBLIC_KEY` request |
| 0xC712          | `CONTINUE_TRANSACTION_GET_PUBLIC_NONCE`      | Requests the transaction's public nonce |
| 0xC792          | `TRANSACTION_PUBLIC_NONCE`                   | Response to a `TRANSACTION_PUBLIC_NONCE` request |
| 0xC713          | `CONTINUE_TRANSACTION_GET_MESSAGE_SIGNATURE` | Requests the signature for a provided message and public key signed with the transaction's blinding factor |
| 0xC793          | `TRANSACTION_MESSAGE_SIGNATURE`              | Response to a `CONTINUE_TRANSACTION_GET_MESSAGE_SIGNATURE` request |
| 0xC714          | `FINISH_TRANSACTION`                         | Requests the signature for the provided kernel information signed with the transaction's blinding factor |
| 0xC794          | `TRANSACTION_SIGNATURE_AND_PAYMENT_PROOF`    | Response to a `FINISH_TRANSACTION` request |
| 0xC715          | `GET_MQS_CHALLENGE_SIGNATURE`                | Requests the signature for a provided challenge signed with an account's MQS private key at a provided index |
| 0xC795          | `MQS_CHALLENGE_SIGNATURE`                    | Response to a `GET_MQS_CHALLENGE_SIGNATURE` request |

\* Response messages have a wire identifier that is the request's wire identifier with the 0x0080 bit set.

\* If a request doesn't succeed, it will respond with a failure message response that has a 0x0003 wire identifier.

### GET_ROOT_PUBLIC_KEY

#### Description

Requests an account's root public key after displaying a message on the device's screen to obtain the user's approval. The root public key can be used to create a view key. Returns a `ROOT_PUBLIC_KEY` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC700          |

#### Fields

| Type     | Name           | Description |
|----------|----------------|-------------|
| `enum`   | `coin_type`    | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type` | 0x00 for mainnet, 0x01 for testnet/floonet |
| `uint32` | `account`      | Account number (max 0x7FFFFFFF) |

### ROOT_PUBLIC_KEY

#### Description

Response to a `GET_ROOT_PUBLIC_KEY` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC780          |

#### Fields

| Type    | Name              | Description |
|---------|-------------------|-------------|
| `bytes` | `root_public_key` | The compressed root public key for the provided account (size 33 bytes) |

### GET_ADDRESS

#### Description

Requests an account's MQS, Tor, or Slatepack address at a provided index. This address is also the account's payment proof address at the provided index. Returns an `ADDRESS` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC701          |

#### Fields

| Type     | Name           | Description |
|----------|----------------|-------------|
| `enum`   | `coin_type`    | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type` | 0x00 for mainnet, 0x01 for testnet/floonet |
| `enum`   | `address_type` | 0x00 for MQS, 0x01 for Tor, or 0x02 for Slatepack |
| `uint32` | `account`      | Account number (max 0x7FFFFFFF) |
| `uint32` | `index`        | Index number |

### ADDRESS

#### Description

Response to a `GET_ADDRESS` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC781          |

#### Fields

| Type     | Name      | Description |
|----------|-----------|-------------|
| `string` | `address` | The account's MQS, Tor, or Slatepack address at the provided index |

### GET_SEED_COOKIE

#### Description

Requests the SHA512 hash of the account's root public key. This hash can be used to determine if a connected hardware wallet corresponds to a previously obtained root public key. Returns a `SEED_COOKIE` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC702          |

#### Fields

| Type     | Name           | Description |
|----------|----------------|-------------|
| `enum`   | `coin_type`    | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type` | 0x00 for mainnet, 0x01 for testnet/floonet |
| `uint32` | `account`      | Account number (max 0x7FFFFFFF) |

### SEED_COOKIE

#### Description

Response to a `GET_SEED_COOKIE` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC782          |

#### Fields

| Type    | Name          | Description |
|---------|---------------|-------------|
| `bytes` | `seed_cookie` | The SHA512 hash of the account's root public key |

### GET_COMMITMENT

#### Description

Requests the account's commitment for the provided identifier, value, and switch type. Returns a `COMMITMENT` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC703          |

#### Fields

| Type     | Name           | Description |
|----------|----------------|-------------|
| `enum`   | `coin_type`    | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type` | 0x00 for mainnet, 0x01 for testnet/floonet |
| `uint32` | `account`      | Account number (max 0x7FFFFFFF) |
| `bytes`  | `identifier`   | Identifier  (size 17 bytes) |
| `uint64` | `value`        | Value to commit |
| `enum`   | `switch_type`  | 0x01 for regular |

### COMMITMENT

#### Description

Response to a `GET_COMMITMENT` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC783          |

#### Fields

| Type    | Name         | Description |
|---------|--------------|-------------|
| `bytes` | `commitment` | The account's commitment for the provided identifier, value, and switch type |

### GET_BULLETPROOF_COMPONENTS

#### Description

Requests the account's bulletproof components tau x, t one, and t two for the provided identifier, value, and switch type. These bulletproof components can be used to create a bulletproof. A processing message is displayed on the device for the duration of this message that shows either sending transaction, receiving transaction, or creating coinbase depending on the parameter provided. Returns a `BULLETPROOF_COMPONENTS` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC704          |

#### Fields

| Type     | Name           | Description |
|----------|----------------|-------------|
| `enum`   | `coin_type`    | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type` | 0x00 for mainnet, 0x01 for testnet/floonet |
| `enum`   | `message_type` | 0x00 for sending transaction, 0x01 for receiving transaction, or 0x02 for creating coinbase |
| `uint32` | `account`      | Account number (max 0x7FFFFFFF) |
| `bytes`  | `identifier`   | Identifier  (size 17 bytes) |
| `uint64` | `value`        | Value to commit |
| `enum`   | `switch_type`  | 0x01 for regular |

### BULLETPROOF_COMPONENTS

#### Description

Response to a `BULLETPROOF_COMPONENTS` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC784          |

#### Fields

| Type    | Name    | Description |
|---------|---------|-------------|
| `bytes` | `tau_x` | The tau x bulletproof component |
| `bytes` | `t_one` | The t one bulletproof component |
| `bytes` | `t_two` | The t two bulletproof component |

### VERIFY_ROOT_PUBLIC_KEY

#### Description

Requests to display the account's root public key on the device and returns if the user verifies if the root public key is valid. Returns a success message response that has a 0x0002 wire identifier on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC705          |

#### Fields

| Type     | Name           | Description |
|----------|----------------|-------------|
| `enum`   | `coin_type`    | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type` | 0x00 for mainnet, 0x01 for testnet/floonet |
| `uint32` | `account`      | Account number (max 0x7FFFFFFF) |

### VERIFY_ADDRESS

#### Description

Requests to display the account's MQS, Tor, or Slatepack address at a provided index on the device and returns if the user verifies if the address is valid.  Returns a success message response that has a 0x0002 wire identifier on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC706          |

#### Fields

| Type     | Name           | Description |
|----------|----------------|-------------|
| `enum`   | `coin_type`    | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type` | 0x00 for mainnet, 0x01 for testnet/floonet |
| `enum`   | `address_type` | 0x00 for MQS, 0x01 for Tor, or 0x02 for Slatepack |
| `uint32` | `account`      | Account number (max 0x7FFFFFFF) |
| `uint32` | `index`        | Index number |

### START_ENCRYPTING_SLATE

#### Description

Requests to prepare the session's slate state to be able to encrypt data that will be provided later as an account at a provided index that can be decrypted by a provided address. An MQS recipient address can include an optional domain and port. Returns an `ENCRYPTED_SLATE_NONCE_AND_SALT` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC707          |

#### Fields

| Type     | Name                | Description |
|----------|---------------------|-------------|
| `enum`   | `coin_type`         | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type`      | 0x00 for mainnet, 0x01 for testnet/floonet |
| `uint32` | `account`           | Account number (max 0x7FFFFFFF) |
| `uint32` | `index`             | Index number |
| `bytes`  | `recipient_address` | Address that will be able to decrypt the data  (max size 247 bytes) |

### ENCRYPTED_SLATE_NONCE_AND_SALT

#### Description

Response to a `START_ENCRYPTING_SLATE` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC787          |

#### Fields

| Type    | Name    | Description |
|---------|---------|-------------|
| `bytes` | `nonce` | Random nonce used to encrypt the data |
| `bytes` | `salt`  | Optional random salt to encrypt the data that is used when the `recipient_address` is an MQS address |

### CONTINUE_ENCRYPTING_SLATE

#### Description

Requests to encrypt the provided data using the session's slate state and returns it. The data must be provided in chunks of 64 bytes with the last chunk allowed to be less than 64 bytes. Returns an `ENCRYPTED_SLATE_DATA` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC708          |

#### Fields

| Type    | Name   | Description |
|---------|--------|-------------|
| `bytes` | `data` | Data chunk to encrypt  (max size 64 bytes) |

### ENCRYPTED_SLATE_DATA

#### Description

Response to a `CONTINUE_ENCRYPTING_SLATE` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC788          |

#### Fields

| Type    | Name             | Description |
|---------|------------------|-------------|
| `bytes` | `encrypted_data` | Encrypted version of the provided data chunk that is the same size as the provided data chunk |

### FINISH_ENCRYPTING_SLATE

#### Description

Requests the tag for all the data that was encrypted. Returns an `ENCRYPTED_SLATE_TAG_AND_SIGNATURE` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC709          |

#### Fields

| Type | Name | Description |
|------|------|-------------|
| N/A  |      | |

### ENCRYPTED_SLATE_TAG_AND_SIGNATURE

#### Description

Response to a `FINISH_ENCRYPTING_SLATE` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC789          |

#### Fields

| Type    | Name                    | Description |
|---------|-------------------------|-------------|
| `bytes` | `tag`                   | Tag for all the data that was encrypted |
| `bytes` | `mqs_message_signature` | Optional DER signature of the message if the data was encrypted for MQS transport |

### START_DECRYPTING_SLATE

#### Description

Requests to prepare the session's slate state to be able to decrypt data that will be provided later as an account at a provided index using a provided nonce and optional salt, ephemeral X25519 public key, encrypted file key, and payload nonce that was encrypted by a provided address or payload key. Returns a success message response that has a 0x0002 wire identifier on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC70A          |

#### Fields

| Type     | Name                                            | Description |
|----------|-------------------------------------------------|-------------|
| `enum`   | `coin_type`                                     | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type`                                  | 0x00 for mainnet, 0x01 for testnet/floonet |
| `uint32` | `account`                                       | Account number (max 0x7FFFFFFF) |
| `uint32` | `index`                                         | Index number |
| `bytes`  | `nonce`                                         | Nonce that was used to encrypt the data  (size 12 bytes) |
| `bytes`  | `sender_address_or_ephemeral_x25519_public_key` | Address or ephemeral X25519 public key that will be able to decrypt the data  (max size 56 bytes) |
| `bytes`  | `salt_or_encrypted_file_key`                    | Optional salt that was used to encrypt the data if the `sender_address_or_ephemeral_x25519_public_key` is an MQS address or encrypted file key that was used to encrypt the data if the `sender_address_or_ephemeral_x25519_public_key` is an ephemeral X25519 public key  (max size 32 bytes) |
| `bytes`  | `payload_nonce`                                 | Optional payload nonce that was used to encrypt the data if the `sender_address_or_ephemeral_x25519_public_key` is an ephemeral X25519 public key  (size 16 bytes) |

### CONTINUE_DECRYPTING_SLATE

#### Description

Requests to decrypt the provided data using the session's slate state and returns it encrypted with a random AES key. The data must be provided in chunks of 64 bytes with the last chunk allowed to be less than 64 bytes. Returns a `DECRYPTED_SLATE_DATA` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC70B          |

#### Fields

| Type    | Name             | Description |
|---------|------------------|-------------|
| `bytes` | `encrypted_data` | Data chunk to decrypt (max size 64 bytes) |

### DECRYPTED_SLATE_DATA

#### Description

Response to a `CONTINUE_DECRYPTING_SLATE` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC78B          |

#### Fields

| Type    | Name   | Description |
|---------|--------|-------------|
| `bytes` | `data` | Decrypted version of the provided data chunk encrypted with a random AES key which results in the size being the size of the `encrypted_data` ceil to the next 16 byte boundary |

### FINISH_DECRYPTING_SLATE

#### Description

Requests the AES key used to encrypt the decrypted data chunks if a valid tag is provided. Returns a `DECRYPTED_SLATE_AES_KEY` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC70C          |

#### Fields

| Type    | Name  | Description |
|---------|-------|-------------|
| `bytes` | `tag` | Tag for the encrypted data (size 16 bytes) |

### DECRYPTED_SLATE_AES_KEY

#### Description

Response to a `FINISH_DECRYPTING_SLATE` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC78C          |

#### Fields

| Type    | Name      | Description |
|---------|-----------|-------------|
| `bytes` | `aes_key` | AES key that can decrypt the data returned by the `CONTINUE_DECRYPTING_SLATE` message |

### START_TRANSACTION

#### Description

Requests to prepare the session's transaction state to be able to process a transaction that will be provided later as an account at a provided index using a provided output, input, fee, and secret nonce index. The secret nonce index select which previously generated secret nonce to use when sending. An optional sender or recipient address depending on if the transaction is received or sent can be provided if this transaction contains a payment proof. Returns a success message response that has a 0x0002 wire identifier on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC70D          |

#### Fields

| Type     | Name           | Description |
|----------|----------------|-------------|
| `enum`   | `coin_type`          | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type`       | 0x00 for mainnet, 0x01 for testnet/floonet |
| `uint32` | `account`            | Account number (max 0x7FFFFFFF) |
| `uint32` | `index`              | Index number |
| `uint64` | `output`             | Output value |
| `uint64` | `input`              | Input value |
| `uint64` | `fee`                | Fee value|
| `uint32` | `secret_nonce_index` | Index of the secret nonce to use or 0 to create secret nonce (max 30) |
| `bytes`  | `address`            | Optional sender or recipient address of the transaction  (max size 64 bytes) |

### CONTINUE_TRANSACTION_INCLUDE_OUTPUT

#### Description

Requests to include the output for a provided identifier, value, and switch type in the transaction in the session's transaction state. Returns a success message response that has a 0x0002 wire identifier on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC70E          |

#### Fields

| Type     | Name          | Description |
|----------|---------------|-------------|
| `bytes`  | `identifier`  | Identifier (size 17 bytes) |
| `uint64` | `value`       | Value to commit |
| `enum`   | `switch_type` | 0x01 for regular |

### CONTINUE_TRANSACTION_INCLUDE_INPUT

#### Description

Requests to include the input for a provided identifier, value, and switch type in the transaction in the session's transaction state. Returns a success message response that has a 0x0002 wire identifier on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC70F          |

#### Fields

| Type     | Name          | Description |
|----------|---------------|-------------|
| `bytes`  | `identifier`  | Identifier (size 17 bytes) |
| `uint64` | `value`       | Value to commit |
| `enum`   | `switch_type` | 0x01 for regular |

### CONTINUE_TRANSACTION_APPLY_OFFSET

#### Description

Requests to apply an offset to the transaction's blinding factor in the session's transaction state. Returns the secret nonce index if transaction is send and doesn't have a secret nonce.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC710          |

#### Fields

| Type    | Name     | Description |
|---------|----------|-------------|
| `bytes` | `offset` | Offset (size 32 bytes) |

### TRANSACTION_SECRET_NONCE_INDEX

#### Description

Response to a `CONTINUE_TRANSACTION_APPLY_OFFSET` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC790          |

#### Fields

| Type     | Name                 | Description |
|----------|----------------------|-------------|
| `uint32` | `secret_nonce_index` | Optional secret nonce index for the send transaction to use |

### CONTINUE_TRANSACTION_GET_PUBLIC_KEY

#### Description

Requests the session's transaction state's blinding factor's public key. Returns a `TRANSACTION_PUBLIC_KEY` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC711          |

#### Fields

| Type | Name | Description |
|------|------|-------------|
| N/A  |      | |

### TRANSACTION_PUBLIC_KEY

#### Description

Response to a `CONTINUE_TRANSACTION_GET_PUBLIC_KEY` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC791          |

#### Fields

| Type    | Name         | Description |
|---------|--------------|-------------|
| `bytes` | `public_key` | Transaction's blinding factor's public key |

### CONTINUE_TRANSACTION_GET_PUBLIC_NONCE

#### Description

Requests the session's transaction state's public nonce. Returns a `TRANSACTION_PUBLIC_NONCE` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC712          |

#### Fields

| Type | Name | Description |
|------|------|-------------|
| N/A  |      | |

### TRANSACTION_PUBLIC_NONCE

#### Description

Response to a `CONTINUE_TRANSACTION_GET_PUBLIC_NONCE` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC792          |

#### Fields

| Type    | Name           | Description |
|---------|----------------|-------------|
| `bytes` | `public_nonce` | Public nonce |

### CONTINUE_TRANSACTION_GET_MESSAGE_SIGNATURE

#### Description

Requests the signature for a provided UTF-8 message signed with the session's transaction state's blinding factor. Returns a `TRANSACTION_MESSAGE_SIGNATURE` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC713          |

#### Fields

| Type    | Name      | Description |
|---------|-----------|-------------|
| `bytes` | `message` | UTF-8 message (max size 255 bytes) |

### TRANSACTION_MESSAGE_SIGNATURE

#### Description

Response to a `CONTINUE_TRANSACTION_GET_MESSAGE_SIGNATURE` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC793          |

#### Fields

| Type    | Name                | Description |
|---------|---------------------|-------------|
| `bytes` | `message_signature` | Single-signer signature |

### FINISH_TRANSACTION

#### Description
Requests the signature for the provided kernel information signed with the session's transaction state's blinding factor after obtaining user's approval. Returns a `TRANSACTION_SIGNATURE_AND_PAYMENT_PROOF` message response on success.

A payment proof signature will be returned if receiving a payment, a `kernel_commitment` is provided, and an `address` was provided to the `START_TRANSACTION` message. In this situation, the the `address` provided to `START_TRANSACTION` will be treated as the sender's address and the `address_type` will be treated as the desired receiver's address type.

A payment proof address will be displayed if a `kernel_commitment` is provided, a `payment_proof` is provided if sending a payment, and an `address` was provided to the `START_TRANSACTION` message. In this situation, the the `address` provided to `START_TRANSACTION` will be treated as the receiver's address if sending a payment or the sender's address if receiving a payment. The `address_type` will be treated as the desired sender's address type if sending a payment or the desired receiver's address type if receiving a payment. The payment proof address displayed will be the recipient's payment proof address if sending a payment or the sender's payment proof address if receiving a payment.

If a sent transaction needs to be finalized at a later time, then the session's slate state can be restored by starting a transaction, including the same inputs and outputs, applying the same offset, and using the secret nonce index that was previously obtained with a `CONTINUE_TRANSACTION_APPLY_OFFSET` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC714          |

#### Fields

| Type    | Name                 | Description |
|---------|----------------------|-------------|
| `enum`  | `address_type`       | 0x00 for MQS, 0x01 for Tor, or 0x02 for Slatepack address that will be used if verifying or creating a payment proof |
| `bytes` | `public_nonce`       | Public nonce (size 33 bytes) |
| `bytes` | `public_key`         | Public key (size 33 bytes) |
| `bytes` | `kernel_information` | 0x00 for plain, 0x01 for coinbase, 0x02 and lock height (8 bytes, little endian) for height locked, or 0x03 and relative height (2 bytes, little endian, max 10080) |
| `bytes` | `kernel_commitment`  | Optional kernel commitment that will be used for creating or verifying a payment proof (size 33 bytes) |
| `bytes` | `payment_proof`      | Optional receiver's payment proof signature that will be used when verifying a payment proof (max size 72 bytes) |

### TRANSACTION_SIGNATURE_AND_PAYMENT_PROOF

#### Description

Response to a `FINISH_TRANSACTION` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC794          |

#### Fields

| Type    | Name            | Description |
|---------|-----------------|-------------|
| `bytes` | `signature`     | Single-signer signature for the transaction and kernel information |
| `bytes` | `payment_proof` | Optional receiver's payment proof signature |

### GET_MQS_CHALLENGE_SIGNATURE

#### Description

Requests the signature for a provided timestamp or hardcoded challenge signed with an account's MQS private key at a provided index after obtaining user's approval. The default challenge, `7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc`, will be signed if no timestamp is provided. Returns an `MQS_CHALLENGE_SIGNATURE` message response on success.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC715          |

#### Fields

| Type     | Name               | Description |
|----------|--------------------|-------------|
| `enum`   | `coin_type`        | 0x00 for MimbleWimble Coin, 0x01 for Grin, or 0x02 for Epic Cash |
| `enum`   | `network_type`     | 0x00 for mainnet, 0x01 for testnet/floonet |
| `uint32` | `account`          | Account number (max 0x7FFFFFFF) |
| `uint32` | `index`            | Index number |
| `uint64` | `timestamp`        | Optional timestamp epoch in milliseconds to sign (max 0x36EE7FFFC91567) |
| `sint32` | `time_zone_offset` | Optional time zone offset in minutes used when displaying the timestamp (min -779, max 899) |

### MQS_CHALLENGE_SIGNATURE

#### Description

Response to a `GET_MQS_CHALLENGE_SIGNATURE` message.

#### Identifier

| Wire Identifier |
|-----------------|
| 0xC795          |

#### Fields

| Type    | Name                      | Description |
|---------|---------------------------|-------------|
| `bytes` | `mqs_challenge_signature` | DER signature of the challenge |

## Notes
* The firmware will reset its session's slate and/or transaction state when unrelated messages are requested. For example, requesting a `START_TRANSACTION` message followed by a `GET_COMMITMENT` message will reset the session's transaction state thus requiring another `START_TRANSACTION` message to be requested before a `CONTINUE_TRANSACTION_INCLUDE_OUTPUT` request can be successfully performed.
