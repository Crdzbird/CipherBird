#pragma once
/* The fips profile surface (assessment r2, C3): every operation here runs */
/* inside the OpenSSL FIPS Provider in approved mode. See provider.hpp for how */
/* the module is loaded and what the profile deliberately does not offer. */
#include "provider.hpp"
#include "primitives.hpp"
#include "envelope.hpp"
#include "hpke_p256.hpp"
