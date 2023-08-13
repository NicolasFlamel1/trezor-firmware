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
% for c in supported_on("trezor2", mimblewimble_coin):

	# Check if coin info is requested
	if coinType == MimbleWimbleCoinCoinType.${c.coin_type.upper()} and networkType == MimbleWimbleCoinNetworkType.${"TESTNET" if c.is_testnet else "MAINNET"}:
	
		# Return coin info
		return CoinInfo(
			"${c.name}",
			${c.slip44},
			${c.fractional_digits},
			${c.enable_mqs_address},
			${c.enable_tor_address},
			${c.enable_slatepack_address},
			${c.enable_no_recent_duplicate_kernels},
			[${','.join(map(lambda x: str(x), c.mqs_version))}],
			"${c.slatepack_address_human_readable_part}",
			${"0xFFFFFFFFFFFFFFFF" if c.maximum_fee == "UINT64_MAX" else c.maximum_fee},
			AddressDerivationType.${c.address_derivation_type}_ADDRESS_DERIVATION,
			PaymentProofMessageType.${c.payment_proof_message_type}_PAYMENT_PROOF_MESSAGE,
			${'|'.join(map(lambda x: 'PaymentProofAddressType.' + x + '_PAYMENT_PROOF_ADDRESS', c.payment_proof_address_types))},
			${'|'.join(map(lambda x: 'SlateEncryptionType.' + x + '_SLATE_ENCRYPTION', c.slate_encryption_types))},
			"${c.mqs_name}",
		)
% endfor

	# Raise data error
	raise DataError("")
