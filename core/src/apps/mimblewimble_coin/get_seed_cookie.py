# Imports
from typing import TYPE_CHECKING

# Check if type checking
if TYPE_CHECKING:

	# Imports
	from trezor.wire import Context
	from trezor.messages import MimbleWimbleCoinGetSeedCookie, MimbleWimbleCoinSeedCookie


# Supporting function implementation

# Get seed cookie
async def get_seed_cookie(context: Context, message: MimbleWimbleCoinGetSeedCookie) -> MimbleWimbleCoinSeedCookie:

	# Imports
	from trezor.messages import MimbleWimbleCoinSeedCookie
	from trezor.crypto.hashlib import sha512
	from .coins import getCoinInfo
	from .common import getExtendedPrivateKey
	
	# Get coin info
	coinInfo = getCoinInfo(message.coin_type, message.network_type)
	
	# Get extended private key
	extendedPrivateKey = await getExtendedPrivateKey(context, coinInfo, message.account)
	
	# Get root public key from the extended private key's public key
	rootPublicKey = extendedPrivateKey.public_key()
	
	# Get seed cookie from the hash of the root public key
	seedCookie = sha512(rootPublicKey).digest()
	
	# Return seed cookie
	return MimbleWimbleCoinSeedCookie(seed_cookie = seedCookie)
