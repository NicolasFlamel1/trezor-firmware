# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinGetRootPublicKey, MimbleWimbleCoinRootPublicKey


# Supporting function implementation

# Get root public key
async def get_root_public_key(context: Context, message: MimbleWimbleCoinGetRootPublicKey) -> MimbleWimbleCoinRootPublicKey:

	# Imports
	from trezor.messages import MimbleWimbleCoinRootPublicKey
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey
	
	# Get coin info
	coinInfo = getCoinInfo(message.coin_type, message.network_type)
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(context, coinInfo, message.account)
	
	# Get root public key from the extended private key's public key
	rootPublicKey = extendedPrivateKey.public_key()
	
	# Return root public key
	return MimbleWimbleCoinRootPublicKey(root_public_key = rootPublicKey)
