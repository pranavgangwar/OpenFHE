# BinFHE Examples

This folder contains various examples of the ways to use `binfhe`. For further details about these examples,
visit [BinFHE Examples Documentation](). 

At a high level:

- [GINX Bootstrapping](boolean.cpp): - `boolean.cpp`
    - bootstrapping as described
      in [TFHE: Fast Fully Homomorphic Encryption over the Torus](https://eprint.iacr.org/2018/421) and
      in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2020/086.pdf)

- [AP Bootstrapping - boolean.cpp](boolean-ap.cpp): - `boolean-ap.cpp`
    - bootstrapping as described
      in [FHEW: Bootstrapping Homomorphic Encryption in less than a second](https://eprint.iacr.org/2014/816.pdf) and
      in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2020/086.pdf)

- [Boolean Serialization - binary format](boolean-serial-binary.cpp): - `boolean-serial-binary.cpp`

- [Boolean Serialization - json format](boolean-serial-json.cpp): - `boolean-serial-json.cpp`

- [Boolean Truth Tables](boolean-truth-tables.cpp): - `boolean-truth-tables.cpp`
    - prints out the truth tables for all supported binary gates

Examples below are based on the functionalities described
in [Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping](https://eprint.iacr.org/2021/1337)

Note that for these advanced features, only GINX bootstrapping with 128-bit security (and toy security) is supported. To use these features, GenerateBinFHEContext needs to be called with at least two parameters: security parameter and whether arbitrary function evaluation is needed. For homomorphic sign evaluation and homomorphic digit decomposition, the large precision Q also needs to be specified. Please see the examples for details.

- [Eval Decomposition](eval-decomp.cpp): - `eval-decomp.cpp`
    - runs a homomorphic digit decomposition process on the input ciphertext

- [Eval Flooring](eval-flooring.cpp): - `eval-flooring.cpp`
    - rounds down the input ciphertext by certain number of bits

- [Eval Function](eval-function.cpp): - `eval-function.cpp`
    - evaluates a function _f: Z<sub>p</sub> -> Z<sub>p</sub>_ on the input ciphertext

- [Eval Sign](eval-sign.cpp): - `eval-sign.cpp`
    - evaluates the most-significant bit of the input ciphertext
