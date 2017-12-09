// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LBRY_H
#define LBRY_H


#ifdef __cplusplus
extern "C" {
#endif

#include "lbry/ripemd160.h"
#include "lbry/sha256.h"
//#include "lbry/uint256.h"
#include "lbry/sha512.h"
#include "lbry/common.h"

//typedef uint256 ChainCode;
void lbry_hash(char* input, char* output);
/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256 {
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[sha.OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, sha.OUTPUT_SIZE).Finalize(hash);
    }

    CHash256& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash256& Reset() {
        sha.Reset();
        return *this;
    }
};


#endif

