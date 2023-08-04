# generated from coins.py.mako
# (by running `make templates` in `core`)
# do not edit manually!

from typing import TYPE_CHECKING

if TYPE_CHECKING:
	from enum import IntEnum
	from trezor.enums import MimbleWimbleCoinCoinType, MimbleWimbleCoinNetworkType
else:
	IntEnum = object


class AddressDerivationType(IntEnum):
	MWC_ADDRESS_DERIVATION = 0
	GRIN_ADDRESS_DERIVATION = 1

class PaymentProofMessageType(IntEnum):
	ASCII_PAYMENT_PROOF_MESSAGE = 0
	BINARY_PAYMENT_PROOF_MESSAGE = 1

class PaymentProofAddressType(IntEnum):
	MQS_PAYMENT_PROOF_ADDRESS = 1 << 0
	TOR_PAYMENT_PROOF_ADDRESS = 1 << 1
	SLATEPACK_PAYMENT_PROOF_ADDRESS = 1 << 2

class SlateEncryptionType(IntEnum):
	MQS_SLATE_ENCRYPTION = 1 << 0
	TOR_SLATE_ENCRYPTION = 1 << 1
	SLATEPACK_SLATE_ENCRYPTION = 1 << 2

class CoinInfo:
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


def getCoinInfo(coinType: MimbleWimbleCoinCoinType, networkType: MimbleWimbleCoinNetworkType) -> CoinInfo:
	from trezor.enums import MimbleWimbleCoinCoinType, MimbleWimbleCoinNetworkType
	if coinType == MimbleWimbleCoinCoinType.EPIC_CASH and networkType == MimbleWimbleCoinNetworkType.MAINNET:
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
	if coinType == MimbleWimbleCoinCoinType.GRIN and networkType == MimbleWimbleCoinNetworkType.MAINNET:
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
	if coinType == MimbleWimbleCoinCoinType.MIMBLEWIMBLE_COIN and networkType == MimbleWimbleCoinNetworkType.MAINNET:
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
	if coinType == MimbleWimbleCoinCoinType.EPIC_CASH and networkType == MimbleWimbleCoinNetworkType.TESTNET:
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
	if coinType == MimbleWimbleCoinCoinType.GRIN and networkType == MimbleWimbleCoinNetworkType.TESTNET:
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
	if coinType == MimbleWimbleCoinCoinType.MIMBLEWIMBLE_COIN and networkType == MimbleWimbleCoinNetworkType.TESTNET:
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
	raise ValueError
