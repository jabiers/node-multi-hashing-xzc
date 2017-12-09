// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LBRY_H
#define LBRY_H


#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_sha2.h"
#include "sha3/sph_ripemd.h"

void lbry_hash(const void* input,void* output);


#ifdef __cplusplus
}
#endif

#endif

