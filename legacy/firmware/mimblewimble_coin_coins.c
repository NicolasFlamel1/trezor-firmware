// Header files
#include "mimblewimble_coin_coins.h"


// Supporting function implementation

// Get MimbleWimble Coin coin info
const MimbleWimbleCoinCoinInfo *getMimbleWimbleCoinCoinInfo(const MimbleWimbleCoinCoinType coinType, const MimbleWimbleCoinNetworkType networkType) {

	// Check if coin type is invalid
	if(coinType > _MimbleWimbleCoinCoinType_MAX) {
	
		// Return nothing
		return NULL;
	}
	
	// Check if network type is invalid
	if(networkType > _MimbleWimbleCoinNetworkType_MAX) {
	
		// Return nothing
		return NULL;
	}
	
	// Go through all MimbleWimble Coin coins
	for(size_t i = 0; i < MIMBLEWIMBLE_COIN_COINS_COUNT; ++i) {
	
		// Check if MimbleWimble Coin coin has the specified coin type and network type
		if(mimbleWimbleCoinCoins[i].coinType == coinType && mimbleWimbleCoinCoins[i].networkType == networkType) {
		
			// Return MimbleWimble Coin coin info
			return &mimbleWimbleCoinCoins[i];
		}
	}
	
	// Return nothing
	return NULL;
}
