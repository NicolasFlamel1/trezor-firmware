# generated from coins.py.mako
# (by running `make templates` in `core`)
# do not edit manually!

# Imports
from typing import TYPE_CHECKING
from trezor.crypto import mimblewimble_coin

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.enums import MimbleWimbleCoinCoinType, MimbleWimbleCoinNetworkType


# Constants

# Address derivation type
AddressDerivationType = mimblewimble_coin.AddressDerivationType

# Payment proof message type
PaymentProofMessageType = mimblewimble_coin.PaymentProofMessageType

# Payment proof address type
PaymentProofAddressType = mimblewimble_coin.PaymentProofAddressType

# Slate encryption type
SlateEncryptionType = mimblewimble_coin.SlateEncryptionType


# Classes

# Coin info class
class CoinInfo:

	# Constructor
	def __init__(
		self,
		name: str,
		slip44: int,
		fractionalDigits: int,
		enableMqsAddress: bool,
		enableTorAddress: bool,
		enableSlatepackAddress: bool,
		enableNoRecentDuplicateKernels: bool,
		mqsVersion: list[int],
		slatepackAddressHumanReadablePart: str,
		maximumFee: int,
		addressDerivationType: AddressDerivationType,
		paymentProofMessageType: PaymentProofMessageType,
		supportedPaymentProofAddressTypes: PaymentProofAddressType,
		supportedSlateEncryptionTypes: SlateEncryptionType,
		mqsName: str,
	) -> None:
	
		self.name = name
		self.slip44 = slip44
		self.fractionalDigits = fractionalDigits
		self.enableMqsAddress = enableMqsAddress
		self.enableTorAddress = enableTorAddress
		self.enableSlatepackAddress = enableSlatepackAddress
		self.enableNoRecentDuplicateKernels = enableNoRecentDuplicateKernels
		self.mqsVersion = mqsVersion
		self.slatepackAddressHumanReadablePart = slatepackAddressHumanReadablePart
		self.maximumFee = maximumFee
		self.addressDerivationType = addressDerivationType
		self.paymentProofMessageType = paymentProofMessageType
		self.supportedPaymentProofAddressTypes = supportedPaymentProofAddressTypes
		self.supportedSlateEncryptionTypes = supportedSlateEncryptionTypes
		self.mqsName = mqsName


# Supporting function implementation

# Get coin info
def getCoinInfo(coinType: MimbleWimbleCoinCoinType, networkType: MimbleWimbleCoinNetworkType) -> CoinInfo:

	# Imports
	from trezor.enums import MimbleWimbleCoinCoinType, MimbleWimbleCoinNetworkType
	from trezor.wire import DataError
	from trezor.utils import MODEL_IS_T2B1
	
	# Check if model is Trezor Model R
	if MODEL_IS_T2B1:

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.EPIC_CASH and networkType == MimbleWimbleCoinNetworkType.MAINNET:
		
			# Return coin info
			return CoinInfo(
				"Epic Cash",
				23000,
				8,
				True,
				True,
				False,
				False,
				[1,0],
				"",
				0xFFFFFFFFFFFFFFFF,
				AddressDerivationType.GRIN_ADDRESS_DERIVATION,
				PaymentProofMessageType.BINARY_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.MQS_SLATE_ENCRYPTION,
				"Epicbox",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.GRIN and networkType == MimbleWimbleCoinNetworkType.MAINNET:
		
			# Return coin info
			return CoinInfo(
				"Grin",
				592,
				9,
				False,
				False,
				True,
				True,
				[0,0],
				"grin",
				1099511627775,
				AddressDerivationType.GRIN_ADDRESS_DERIVATION,
				PaymentProofMessageType.BINARY_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.SLATEPACK_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.SLATEPACK_SLATE_ENCRYPTION,
				"",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.MIMBLEWIMBLE_COIN and networkType == MimbleWimbleCoinNetworkType.MAINNET:
		
			# Return coin info
			return CoinInfo(
				"MimbleWimble Coin",
				593,
				9,
				True,
				True,
				False,
				True,
				[1,69],
				"",
				0xFFFFFFFFFFFFFFFF,
				AddressDerivationType.MWC_ADDRESS_DERIVATION,
				PaymentProofMessageType.ASCII_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.MQS_PAYMENT_PROOF_ADDRESS|PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.MQS_SLATE_ENCRYPTION|SlateEncryptionType.TOR_SLATE_ENCRYPTION,
				"MQS",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.EPIC_CASH and networkType == MimbleWimbleCoinNetworkType.TESTNET:
		
			# Return coin info
			return CoinInfo(
				"Epic Cash Floonet",
				1,
				8,
				True,
				True,
				False,
				False,
				[1,136],
				"",
				0xFFFFFFFFFFFFFFFF,
				AddressDerivationType.GRIN_ADDRESS_DERIVATION,
				PaymentProofMessageType.BINARY_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.MQS_SLATE_ENCRYPTION,
				"Epicbox",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.GRIN and networkType == MimbleWimbleCoinNetworkType.TESTNET:
		
			# Return coin info
			return CoinInfo(
				"Grin Testnet",
				1,
				9,
				False,
				False,
				True,
				True,
				[0,0],
				"tgrin",
				1099511627775,
				AddressDerivationType.GRIN_ADDRESS_DERIVATION,
				PaymentProofMessageType.BINARY_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.SLATEPACK_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.SLATEPACK_SLATE_ENCRYPTION,
				"",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.MIMBLEWIMBLE_COIN and networkType == MimbleWimbleCoinNetworkType.TESTNET:
		
			# Return coin info
			return CoinInfo(
				"MimbleWimble Coin Floonet",
				1,
				9,
				True,
				True,
				False,
				True,
				[1,121],
				"",
				0xFFFFFFFFFFFFFFFF,
				AddressDerivationType.MWC_ADDRESS_DERIVATION,
				PaymentProofMessageType.ASCII_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.MQS_PAYMENT_PROOF_ADDRESS|PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.MQS_SLATE_ENCRYPTION|SlateEncryptionType.TOR_SLATE_ENCRYPTION,
				"MQS",
			)

	# Otherwise
	else:

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.EPIC_CASH and networkType == MimbleWimbleCoinNetworkType.MAINNET:
		
			# Return coin info
			return CoinInfo(
				"Epic Cash",
				23000,
				8,
				True,
				True,
				False,
				False,
				[1,0],
				"",
				0xFFFFFFFFFFFFFFFF,
				AddressDerivationType.GRIN_ADDRESS_DERIVATION,
				PaymentProofMessageType.BINARY_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.MQS_SLATE_ENCRYPTION,
				"Epicbox",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.GRIN and networkType == MimbleWimbleCoinNetworkType.MAINNET:
		
			# Return coin info
			return CoinInfo(
				"Grin",
				592,
				9,
				False,
				False,
				True,
				True,
				[0,0],
				"grin",
				1099511627775,
				AddressDerivationType.GRIN_ADDRESS_DERIVATION,
				PaymentProofMessageType.BINARY_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.SLATEPACK_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.SLATEPACK_SLATE_ENCRYPTION,
				"",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.MIMBLEWIMBLE_COIN and networkType == MimbleWimbleCoinNetworkType.MAINNET:
		
			# Return coin info
			return CoinInfo(
				"MimbleWimble Coin",
				593,
				9,
				True,
				True,
				False,
				True,
				[1,69],
				"",
				0xFFFFFFFFFFFFFFFF,
				AddressDerivationType.MWC_ADDRESS_DERIVATION,
				PaymentProofMessageType.ASCII_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.MQS_PAYMENT_PROOF_ADDRESS|PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.MQS_SLATE_ENCRYPTION|SlateEncryptionType.TOR_SLATE_ENCRYPTION,
				"MQS",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.EPIC_CASH and networkType == MimbleWimbleCoinNetworkType.TESTNET:
		
			# Return coin info
			return CoinInfo(
				"Epic Cash Floonet",
				1,
				8,
				True,
				True,
				False,
				False,
				[1,136],
				"",
				0xFFFFFFFFFFFFFFFF,
				AddressDerivationType.GRIN_ADDRESS_DERIVATION,
				PaymentProofMessageType.BINARY_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.MQS_SLATE_ENCRYPTION,
				"Epicbox",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.GRIN and networkType == MimbleWimbleCoinNetworkType.TESTNET:
		
			# Return coin info
			return CoinInfo(
				"Grin Testnet",
				1,
				9,
				False,
				False,
				True,
				True,
				[0,0],
				"tgrin",
				1099511627775,
				AddressDerivationType.GRIN_ADDRESS_DERIVATION,
				PaymentProofMessageType.BINARY_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.SLATEPACK_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.SLATEPACK_SLATE_ENCRYPTION,
				"",
			)

		# Check if coin info is requested
		if coinType == MimbleWimbleCoinCoinType.MIMBLEWIMBLE_COIN and networkType == MimbleWimbleCoinNetworkType.TESTNET:
		
			# Return coin info
			return CoinInfo(
				"MimbleWimble Coin Floonet",
				1,
				9,
				True,
				True,
				False,
				True,
				[1,121],
				"",
				0xFFFFFFFFFFFFFFFF,
				AddressDerivationType.MWC_ADDRESS_DERIVATION,
				PaymentProofMessageType.ASCII_PAYMENT_PROOF_MESSAGE,
				PaymentProofAddressType.MQS_PAYMENT_PROOF_ADDRESS|PaymentProofAddressType.TOR_PAYMENT_PROOF_ADDRESS,
				SlateEncryptionType.MQS_SLATE_ENCRYPTION|SlateEncryptionType.TOR_SLATE_ENCRYPTION,
				"MQS",
			)

	# Raise data error
	raise DataError("")
