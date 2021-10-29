// @file thresh-utils.h - utilities to be used with
//    ckks-a ckks-b
//    thresh-server
// @authors: David Cousins, Ian Quah
// TPOC: contact@palisade-crypto.org

// @copyright Copyright (c) 2020, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// remove explicit directory

#ifndef THRESH_UTILS_H
#define THRESH_UTILS_H

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/ckks/ckks-ser.h"
#include "utils/serial.h"
#include <iostream>
#include <fstream>
#include <olc_net.h>
#include <boost/interprocess/streams/bufferstream.hpp>  // to convert between Serialize and msg

using namespace lbcrypto;

// shortcuts for PALISADE types to make the code more readable
using CC = CryptoContext<DCRTPoly>;         // crypto context
using CT = Ciphertext<DCRTPoly>;            // ciphertext
using PT = Plaintext;                       // plaintext
using KeyPair = LPKeyPair<DCRTPoly>;        // secret/public key par.
using EvalKey = LPEvalKey<DCRTPoly>;        // evaluation key (reencryption key)
using PrivateKey = LPPrivateKey<DCRTPoly>;  // secret key of par.
using PublicKey = LPPublicKey<DCRTPoly>;    // public key of par.
using vecInt = vector<int64_t>;             // vector of ints

// ThreshMsgTypes are the trigger messages to/from the server to the clients.
// Based on this trigger message, the server responds and clients transition
// through their states (enumerated by ClientAStates and ClientBStates in the
// two party case) based on the trigger message.
enum class ThreshMsgTypes : uint32_t {
  ServerAccept,
  RequestCC,
  SendCC,
  SendRnd1PubKey,
  AckRnd1PubKey,
  NackRnd1PubKey,
  SendRnd1evalMultKey,
  AckRnd1evalMultKey,
  NackRnd1evalMultKey,
  SendRnd1evalSumKeys,
  AckRnd1evalSumKeys,
  NackRnd1evalSumKeys,
  RequestRnd1PubKey,
  RequestRnd1evalMultKey,
  RequestRnd1evalSumKeys,
  SendRnd2SharedKey,
  AckRnd2SharedKey,
  NackRnd2SharedKey,
  SendRnd2EvalMultAB,
  AckRnd2EvalMultAB,
  NackRnd2EvalMultAB,
  SendRnd2EvalMultBAB,
  AckRnd2EvalMultBAB,
  NackRnd2EvalMultBAB,
  SendRnd2EvalSumKeysJoin,
  AckRnd2EvalSumKeysJoin,
  NackRnd2EvalSumKeysJoin,
  RequestRnd2SharedKey,
  RequestRnd2EvalMultAB,
  RequestRnd2EvalMultBAB,
  RequestRnd2EvalSumKeysJoin,
  SendRnd3EvalMultFinal,
  AckRnd3EvalMultFinal,
  RequestRnd3EvalMultFinal,
  NackRnd3evalMultFinal,
  SendCT1,
  AckCT1,
  NackCT1,
  SendCT2,
  AckCT2,
  NackCT2,
  SendCT3,
  AckCT3,
  NackCT3,
  RequestCT1,
  RequestCT2,
  RequestCT3,
  SendDecryptPartialMainAdd,
  SendDecryptPartialMainMult,
  SendDecryptPartialMainSum,
  SendDecryptPartialLeadAdd,
  SendDecryptPartialLeadMult,
  SendDecryptPartialLeadSum,
  AckPartialMainAdd,
  AckPartialMainMult,
  AckPartialMainSum,
  AckPartialLeadAdd,
  AckPartialLeadMult,
  AckPartialLeadSum,
  NackPartialMainAdd,
  NackPartialMainMult,
  NackPartialMainSum,
  NackPartialLeadAdd,
  NackPartialLeadMult,
  NackPartialLeadSum,
  RequestDecryptMainAdd,
  RequestDecryptLeadAdd,
  SendDecryptMainAdd,
  SendDecryptLeadAdd,
  RequestDecryptMainMult,
  RequestDecryptLeadMult,
  SendDecryptMainMult,
  SendDecryptLeadMult,
  RequestDecryptMainSum,
  RequestDecryptLeadSum,
  SendDecryptMainSum,
  SendDecryptLeadSum,
  DisconnectClient,
};

vector<string> ThreshMsgNames{
    "ServerAccept",
    "RequestCC",
    "SendCC",
    "SendRnd1PubKey",
    "AckRnd1PubKey",
    "NackRnd1PubKey",
    "SendRnd1evalMultKey",
    "AckRnd1evalMultKey",
    "NackRnd1evalMultKey",
    "SendRnd1evalSumKeys",
    "AckRnd1evalSumKeys",
    "NackRnd1evalSumKeys",
    "RequestRnd1PubKey",
    "RequestRnd1evalMultKey",
    "RequestRnd1evalSumKeys",
    "SendRnd2SharedKey",
    "AckRnd2SharedKey",
    "NackRnd2SharedKey",
    "SendRnd2EvalMultAB",
    "AckRnd2EvalMultAB",
    "NackRnd2EvalMultAB",
    "SendRnd2EvalMultBAB",
    "AckRnd2EvalMultBAB",
    "NackRnd2EvalMultBAB",
    "SendRnd2EvalSumKeysJoin",
    "AckRnd2EvalSumKeysJoin",
    "NackRnd2EvalSumKeysJoin",
    "RequestRnd2SharedKey",
    "RequestRnd2EvalMultAB",
    "RequestRnd2EvalMultBAB",
    "RequestRnd2EvalSumKeysJoin",
    "SendRnd3EvalMultFinal",
    "AckRnd3EvalMultFinal",
    "RequestRnd3EvalMultFinal",
    "NackRnd3evalMultFinal",
    "SendCT1",
    "AckCT1",
    "NackCT1",
    "SendCT2",
    "AckCT2",
    "NackCT2",
    "SendCT3",
    "AckCT3",
    "NackCT3",
    "RequestCT1",
    "RequestCT2",
    "RequestCT3",
    "SendDecryptPartialMainAdd",
    "SendDecryptPartialMainMult",
    "SendDecryptPartialMainSum",
    "SendDecryptPartialLeadAdd",
    "SendDecryptPartialLeadMult",
    "SendDecryptPartialLeadSum",
    "AckPartialMainAdd",
    "AckPartialMainMult",
    "AckPartialMainSum",
    "AckPartialLeadAdd",
    "AckPartialLeadMult",
    "AckPartialLeadSum",
    "NackPartialMainAdd",
    "NackPartialMainMult",
    "NackPartialMainSum",
    "NackPartialLeadAdd",
    "NackPartialLeadMult",
    "NackPartialLeadSum",
    "RequestDecryptMainAdd",
    "RequestDecryptLeadAdd",
    "SendDecryptMainAdd",
    "SendDecryptLeadAdd",
    "RequestDecryptMainMult",
    "RequestDecryptLeadMult",
    "SendDecryptMainMult",
    "SendDecryptLeadMult",
    "RequestDecryptMainSum",
    "RequestDecryptLeadSum",
    "SendDecryptMainSum",
    "SendDecryptLeadSum",
	"DisconnectClient",
};

// Code to convert from enum class to underlying int for reference.
std::ostream& operator<<(std::ostream& os, const ThreshMsgTypes& obj) {
  os << static_cast<std::underlying_type<ThreshMsgTypes>::type>(obj);
  os << ": "
     << ThreshMsgNames[static_cast<std::underlying_type<ThreshMsgTypes>::type>(
            obj)];
  return os;
}

/**
 * Take a powernap of (DEFAULT) 0.5 seconds
 * @param ms - number of milisec to nap
 */
void nap(const int& ms = 500) {
  std::chrono::duration<int, std::milli> timespan(ms);
  std::this_thread::sleep_for(timespan);
}

#endif  // THRESH_UTILS_H
