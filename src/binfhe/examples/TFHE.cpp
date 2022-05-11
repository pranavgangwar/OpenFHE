//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example for the FHEW scheme small precision arbitrary function evaluation
 */

#include "binfhecontext.h"
#define OFFSET 2

using namespace lbcrypto;

// Initialize Function f(x) = 1 if x >= 0
auto threshold = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
    if (m%p1 > 2*OFFSET)
        return 2*OFFSET + 1;
    else if (m%p1 == 2*OFFSET)
        return 2*OFFSET;
    else 
        return 2*OFFSET - 1;
};

//Homomorphic Comparison
void comparison (int a, int b, int p, BinFHEContext cc, LWEPrivateKey sk, std::vector<NativeInteger> lut);
    

int main() {
    // Sample Program: Step 1: Set CryptoContext
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, true, 12);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Create the to-be-evaluated funciton and obtain its corresponding LUT
    int p = cc.GetMaxPlaintextSpace().ConvertToInt();  // Obtain the maximum plaintext space
    std::cout << "p = " << p << std::endl;
    

    // Generate LUT from function f(x)
    auto lut = cc.GenerateLUTviaFunction(threshold, p);
    std::cout << "Evaluate f(x) = 1, x >= 0" << "." << std::endl;

    // Sample Program: Step 4: evalute f(x) homomorphically and decrypt
    // Note that we check for all the possible plaintexts.
    
    for (int a = -2; a < 2; a++) {
        for (int b = -2; b < 2; b++)
            comparison (a, b, p, cc, sk, lut);
    }
    
    return 0;
}

void comparison (int a, int b, int p, BinFHEContext cc, LWEPrivateKey sk, std::vector<NativeInteger> lut) {

    //Added offset to convert signed numbers into offset binary

    int m = a - b + 2*OFFSET;
    auto ct = cc.Encrypt(sk, m, FRESH, p);
    auto ct_thresh = cc.EvalFunc(ct, lut);
    LWEPlaintext result;
    cc.Decrypt(sk, ct_thresh, &result, p);


            
    std::cout << "a: " << a << std::endl
    << "b: " << b << std::endl
    << "a-b: " << (a-b) % p << std::endl
    << "Expected {(a-b) >= 0}: " << threshold(m, p) - 2*OFFSET << std::endl
    << "Evaluated {(a-b) >= 0}:  " << result - 2*OFFSET << std::endl 
    << std::endl;
}

// void comparison (int a, int b, int p, BinFHEContext cc, LWEPrivateKey sk, std::vector<NativeInteger> lut) {

//     auto bits = 2;

//     //Added offset to convert signed numbers into offset binary
//     a += OFFSET;
//     b += OFFSET; 
//     int diff = a - b;

//     // m = a - b + (2*OFFSET);
//     // auto ct1 = cc.Encrypt(sk, m, FRESH, p);
//     // auto ct_thresh = cc.EvalFunc(ct1, lut);
//     // LWEPlaintext result;
//     // cc.Decrypt(sk, ct_thresh, &result, p);

//     auto ct_a = cc.Encrypt(sk, a % p, FRESH, p);
//     auto ctRounded_a = cc.EvalFloor(ct_a, bits);
//     LWEPlaintext msb_a;

//     auto ct_b = cc.Encrypt(sk, b % p, FRESH, p);
//     auto ctRounded_b = cc.EvalFloor(ct_b, bits);
//     LWEPlaintext msb_b;

//     auto ct_diff = cc.Encrypt(sk, diff % p, FRESH, p);
//     auto ctRounded_diff = cc.EvalFloor(ct_diff, bits);
//     LWEPlaintext msb_diff;

//     cc.Decrypt(sk, ctRounded_a, &msb_a, p / (1 << bits));
//     cc.Decrypt(sk, ctRounded_b, &msb_b, p / (1 << bits));
//     cc.Decrypt(sk, ctRounded_diff, &msb_diff, p / (1 << bits));

//     ///////////////////////////////////// AND is behaving like XOR proobably due to noise after all these operations. But, XOR behaves normally
//     LWEPlaintext ptXOR, ptNotXOR_AND_diff;
//     auto ctXOR = cc.EvalBinGate(XOR, ctRounded_a, ctRounded_b); //Tells if the polarity is same
//     auto ctNotXOR = cc.EvalNOT(ctXOR);  //For same polarity AND with a-b
//     auto ctNotXOR_AND_diff = cc.EvalBinGate(NAND, ctNotXOR, ctRounded_diff);

//     cc.Decrypt(sk, ctXOR, &ptXOR);
//     cc.Decrypt(sk, ctNotXOR_AND_diff, &ptNotXOR_AND_diff);
            
//     std::cout << "a: " << a - OFFSET << std::endl
//     << "b: " << b - OFFSET << std::endl
//     << "a-b: " << (a-b) % p << std::endl
//     << "ptNotXOR_AND_diff = " << ptNotXOR_AND_diff << std::endl << std::endl
//     //<< "Expected {(a-b) >= 0}: " << threshold(m, p) << std::endl
//     << "Expected MSB a = " << (a % p >> bits) << std::endl
//     << "Evaluated MSB a = " << msb_a << std::endl 
//     << "Expected MSB b = " << (b % p >> bits) << std::endl
//     << "Evaluated MSB b = " << msb_b << std::endl
//     << "Evaluated (MSB A) ^ (MSB B) = " << ptXOR << std::endl 
//     << std::endl;
// }