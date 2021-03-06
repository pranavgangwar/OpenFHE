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

#ifndef LBCRYPTO_CRYPTO_BASE_PARAMETERGENERATION_H
#define LBCRYPTO_CRYPTO_BASE_PARAMETERGENERATION_H

#include <vector>
#include <memory>

#include "constants.h"
#include "schemebase/base-cryptoparameters.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface for parameter generation algorithm
 * @tparam Element a ring element.
 */
template <class Element>
class ParameterGenerationBase {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

public:
  virtual ~ParameterGenerationBase() {}

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters
   *
   * @param *cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch
   * operations are performed.
   * @param evalMultCount number of EvalMults assuming no EvalAdd and
   * KeySwitch operations are performed.
   * @param keySwitchCount number of KeySwitch operations assuming no EvalAdd
   * and EvalMult operations are performed.
   * @param dcrtBits number of bits in each CRT modulus*
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   */
  virtual bool ParamsGenBFVRNS(
      std::shared_ptr<CryptoParametersBase<Element>> cryptoParams,
      int32_t evalAddCount = 0,
      int32_t evalMultCount = 0,
      int32_t keySwitchCount = 0,
      size_t dcrtBits = 0,
      uint32_t n = 0,
      enum KeySwitchTechnique ksTech = BV,
      enum RescalingTechnique rsTech = FIXEDMANUAL,
      enum EncryptionTechnique encTech = STANDARD,
      enum MultiplicationTechnique multTech = HPS) const {
    OPENFHE_THROW(
        config_error,
        "This signature for ParamsGen is not supported for this scheme.");
  }

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters.
   *
   * @param *cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param cyclOrder the cyclotomic order.
   * @param numPrimes number of modulus towers to support.
   * @param scaleExp the bit-width for plaintexts and DCRTPoly's.
   * @param relinWindow the relinearization window
   * @param mode
   * @param ksTech the key switching technique used (e.g., BV or GHS)
   * @param firstModSize the bit-size of the first modulus
   * @param rsTech the rescaling technique used (e.g., FIXEDMANUAL or
   * FLEXIBLEAUTO)
   */
  virtual bool ParamsGenCKKSRNS(
      std::shared_ptr<CryptoParametersBase<Element>> cryptoParams,
      usint cyclOrder,
      usint numPrimes,
      usint scaleExp,
      usint relinWindow,
      enum MODE mode,
      usint firstModSize = 60,
      uint32_t mulPartQ = 4,
      enum KeySwitchTechnique ksTech = BV,
      enum RescalingTechnique rsTech = FIXEDMANUAL,
      enum EncryptionTechnique encTech = STANDARD,
      enum MultiplicationTechnique multTech = HPS) const {
    OPENFHE_THROW(
        config_error,
        "This signature for ParamsGen is not supported for this scheme.");
  }

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters. This is intended for BGVrns
   * @param *cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param cyclOrder the cyclotomic order.
   * @param numPrimes number of modulus towers to support.
   * @param relinWindow the relinearization window
   * @param mode
   * @param ksTech the key switching technique used (e.g., BV or GHS)
   * @param firstModSize the bit-size of the first modulus
   * @param dcrtBits the bit-width of moduli.
   */
  virtual bool ParamsGenBGVRNS(
      std::shared_ptr<CryptoParametersBase<Element>> cryptoParams, usint cyclOrder,
      usint ptm, usint numPrimes, usint relinWindow, MODE mode,
      usint firstModSize = 60,
      usint dcrtBits = 60,
      uint32_t numPartQ = 4,
      usint multihopQBound = 0,
      enum KeySwitchTechnique ksTech = BV,
      enum RescalingTechnique rsTech = FIXEDMANUAL,
      enum EncryptionTechnique encTech = STANDARD,
      enum MultiplicationTechnique multTech = HPS) const {
    OPENFHE_THROW(
        not_implemented_error,
        "This signature for ParamsGen is not supported for this scheme.");
  }


  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {}

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {}

  std::string SerializedObjectName() const { return "ParameterGenerationBase"; }
};

}  // namespace lbcrypto

#endif
