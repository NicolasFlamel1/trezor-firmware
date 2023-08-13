// Header guard
#ifndef __MIMBLEWIMBLE_COIN_GENERATORS_H__
#define __MIMBLEWIMBLE_COIN_GENERATORS_H__


// Header files
#include "ecdsa.h"


// Definitions

// Number of generators
#define MIMBLEWIMBLE_COIN_NUMBER_OF_GENERATORS 128

// Generators window size
#define MIMBLEWIMBLE_COIN_GENERATORS_WINDOW_SIZE 3

// Number of odd generator multiples
#define MIMBLEWIMBLE_COIN_NUMBER_OF_ODD_GENERATOR_MULTIPLES (1 << (MIMBLEWIMBLE_COIN_GENERATORS_WINDOW_SIZE - 2))


// Constants

// Generators
extern const curve_point MIMBLEWIMBLE_COIN_GENERATORS[MIMBLEWIMBLE_COIN_NUMBER_OF_GENERATORS * MIMBLEWIMBLE_COIN_NUMBER_OF_ODD_GENERATOR_MULTIPLES];


#endif
