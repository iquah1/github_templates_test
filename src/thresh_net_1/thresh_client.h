#ifndef THRESH_CLIENT_H
#define THRESH_CLIENT_H

#include "thresh_utils.h"

// common to both parties (Alice and Bob) in the threshold encryption
// computation
class ThreshCommonClient : public olc::net::client_interface<ThreshMsgTypes> {
 public:
  DEBUG_FLAG(false);  // set to true to turn on DEBUG() statements

  void RequestCC(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting CC");
    msg.header.id = ThreshMsgTypes::RequestCC;
    Send(msg);
  }

  CC RecvCC(olc::net::message<ThreshMsgTypes> &msg) {
    CC cc;
    unsigned int msgSize(msg.body.size());

    DEBUG("Client: read CC of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("Client istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("Client: Deserialize");
    Serial::Deserialize(cc, is, SerType::BINARY);

    DEBUG("Client: Done");
    assert(is.good());
    return cc;
  }

  CT RecvCT(olc::net::message<ThreshMsgTypes> &msg) {
    CT ct;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read CT of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(ct, is, SerType::BINARY);
    return ct;
  }

  void DisconnectClient(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Disconnecting");
    msg.header.id = ThreshMsgTypes::DisconnectClient;
    Send(msg);
  }


};

// Alice client methods
class ClientA : public ThreshCommonClient {
 public:
  DEBUG_FLAG(false);  // set to true to turn on DEBUG() statements
  void RequestRnd2SharedKey(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Round 2 public key");
    msg.header.id = ThreshMsgTypes::RequestRnd2SharedKey;
    Send(msg);
  }

  void RequestRnd2evalMultAB(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Round 2 EvalMultAB");
    msg.header.id = ThreshMsgTypes::RequestRnd2EvalMultAB;
    Send(msg);
  }

  void RequestRnd2evalMultBAB(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Round 2 EvalMultBAB");
    msg.header.id = ThreshMsgTypes::RequestRnd2EvalMultBAB;
    Send(msg);
  }

  void RequestRnd2evalSumKeysJoin(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Round 2 EvalSumKeysJoin");
    msg.header.id = ThreshMsgTypes::RequestRnd2EvalSumKeysJoin;
    Send(msg);
  }

  void RequestDecryptMainAdd(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Partial decrypt main add");
    msg.header.id = ThreshMsgTypes::RequestDecryptMainAdd;
    Send(msg);
  }

  void RequestDecryptMainMult(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Partial decrypt main mult");
    msg.header.id = ThreshMsgTypes::RequestDecryptMainMult;
    Send(msg);
  }

  void RequestDecryptMainSum(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Partial decrypt main sum");
    msg.header.id = ThreshMsgTypes::RequestDecryptMainSum;
    Send(msg);
  }

  void RequestCT1(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting ciphertext1");
    msg.header.id = ThreshMsgTypes::RequestCT1;
    Send(msg);
  }

  void RequestCT2(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting ciphertext2");
    msg.header.id = ThreshMsgTypes::RequestCT2;
    Send(msg);
  }

  void RequestCT3(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting ciphertext3");
    msg.header.id = ThreshMsgTypes::RequestCT3;
    Send(msg);
  }

  void SendRnd1PubKey(KeyPair &kp) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Alice: serializing public key");
    Serial::Serialize(kp.publicKey, os, SerType::BINARY);
    DEBUG("Alice: done");
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendRnd1PubKey;
    msg << os.str();
    DEBUG("Alice: final msg.body.size " << msg.body.size());
    DEBUG("Alice: final msg.size " << msg.size());
    Send(msg);
  }

  void SendRnd1evalMultKey(EvalKey &EvalMultKey) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Alice: serializing EvalMultkey");
    Serial::Serialize(EvalMultKey, os, SerType::BINARY);
    DEBUG("Alice: done");
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendRnd1evalMultKey;
    msg << os.str();
    DEBUG("Alice: final msg.body.size " << msg.body.size());
    DEBUG("Alice: final msg.size " << msg.size());
    Send(msg);
  }

  void SendRnd1evalSumKeys(
      std::shared_ptr<std::map<usint, EvalKey>> &EvalSumKeys) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Alice: serializing EvalSumkeys");
    Serial::Serialize(EvalSumKeys, os, SerType::BINARY);
    DEBUG("Alice: done");
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendRnd1evalSumKeys;
    msg << os.str();
    DEBUG("Alice: final msg.body.size " << msg.body.size());
    DEBUG("Alice: final msg.size " << msg.size());
    Send(msg);
  }

  void SendRnd3EvalMultFinal(EvalKey &EvalMultKey) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Alice: serializing EvalMultFinal");
    Serial::Serialize(EvalMultKey, os, SerType::BINARY);
    DEBUG("Alice: done");
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendRnd3EvalMultFinal;
    msg << os.str();
    DEBUG("Alice: final msg.body.size " << msg.body.size());
    DEBUG("Alice: final msg.size " << msg.size());
    Send(msg);
  }

  PublicKey RecvRnd2SharedKey(olc::net::message<ThreshMsgTypes> &msg) {
    PublicKey Rnd2PubKey;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read public key of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(Rnd2PubKey, is, SerType::BINARY);
    return Rnd2PubKey;
  }

  auto RecvRnd2evalMultAB(olc::net::message<ThreshMsgTypes> &msg) {
    EvalKey evalMultAB;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read evalmultAB key of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(evalMultAB, is, SerType::BINARY);
    return evalMultAB;
  }

  auto RecvRnd2evalMultBAB(olc::net::message<ThreshMsgTypes> &msg) {
    EvalKey evalMultBAB;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read evalmultBAB key of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(evalMultBAB, is, SerType::BINARY);
    return evalMultBAB;
  }

  auto RecvRnd2evalSumKeysJoin(olc::net::message<ThreshMsgTypes> &msg) {
    std::shared_ptr<std::map<usint, EvalKey>> evalSumKeysJoin;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read evalsumkeysjoin of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(evalSumKeysJoin, is, SerType::BINARY);
    return evalSumKeysJoin;
  }

  void SendCTPartialAdd(CT &ct) {
    DEBUG("Client: serializing add lead partial decrypt ct");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendDecryptPartialLeadAdd;
    msg << os.str();
    DEBUG("Client: final msg.body.size " << msg.body.size());
    DEBUG("Client: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCTPartialMult(CT &ct) {
    DEBUG("Client: serializing mult lead partial decrypt ct");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendDecryptPartialLeadMult;
    msg << os.str();
    DEBUG("Client: final msg.body.size " << msg.body.size());
    DEBUG("Client: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCTPartialSum(CT &ct) {
    DEBUG("Client: serializing sum lead partial decrypt ct");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendDecryptPartialLeadSum;
    msg << os.str();
    DEBUG("Client: final msg.body.size " << msg.body.size());
    DEBUG("Client: final msg.size " << msg.size());
    Send(msg);
  }
};

// Bob client methods
class ClientB : public ThreshCommonClient {
 public:
  DEBUG_FLAG(false);  // set to true to turn on DEBUG() statements
  void RequestRnd1PubKey(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Round 1 public key");
    msg.header.id = ThreshMsgTypes::RequestRnd1PubKey;
    Send(msg);
  }

  void RequestRnd1evalMultKey(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Round 1 EvalMultKey");
    msg.header.id = ThreshMsgTypes::RequestRnd1evalMultKey;
    Send(msg);
  }

  void RequestRnd1evalSumKeys(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Round 1 EvalSumKeys");
    msg.header.id = ThreshMsgTypes::RequestRnd1evalSumKeys;
    Send(msg);
  }

  void RequestRnd3evalMultFinal(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Round 3 EvalMultFinal");
    msg.header.id = ThreshMsgTypes::RequestRnd3EvalMultFinal;
    Send(msg);
  }

  void RequestDecryptLeadAdd(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Partial decrypt lead add");
    msg.header.id = ThreshMsgTypes::RequestDecryptLeadAdd;
    Send(msg);
  }

  void RequestDecryptLeadMult(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Partial decrypt lead mult");
    msg.header.id = ThreshMsgTypes::RequestDecryptLeadMult;
    Send(msg);
  }

  void RequestDecryptLeadSum(void) {
    olc::net::message<ThreshMsgTypes> msg;
    DEBUG("Client: Requesting Partial decrypt lead sum");
    msg.header.id = ThreshMsgTypes::RequestDecryptLeadSum;
    Send(msg);
  }

  PublicKey RecvRnd1PubKey(olc::net::message<ThreshMsgTypes> &msg) {
    PublicKey Rnd1PubKey;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read public key of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(Rnd1PubKey, is, SerType::BINARY);
    return Rnd1PubKey;
  }

  auto RecvRnd1evalMultKey(olc::net::message<ThreshMsgTypes> &msg) {
    EvalKey evalMultKey;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read evalmult key of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(evalMultKey, is, SerType::BINARY);
    return evalMultKey;
  }

  auto RecvRnd1evalSumKeys(olc::net::message<ThreshMsgTypes> &msg) {
    std::shared_ptr<std::map<usint, EvalKey>> evalSumKeys;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read evalsumkeys key of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(evalSumKeys, is, SerType::BINARY);
    return evalSumKeys;
  }

  auto RecvRnd3evalMultFinal(olc::net::message<ThreshMsgTypes> &msg) {
    EvalKey evalMultKey;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read evalmultfinal key of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(evalMultKey, is, SerType::BINARY);
    return evalMultKey;
  }

  void SendRnd2SharedKey(KeyPair &kp) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Bob: serializing shared public key");
    Serial::Serialize(kp.publicKey, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendRnd2SharedKey;
    msg << os.str();
    DEBUG("Bob: final msg.body.size " << msg.body.size());
    DEBUG("Bob: final msg.size " << msg.size());
    Send(msg);
  }

  void SendRnd2EvalMultAB(EvalKey &EvalMultAB) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Bob: serializing Round 2 EvalMultAB key");
    Serial::Serialize(EvalMultAB, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendRnd2EvalMultAB;
    msg << os.str();
    DEBUG("Bob: final msg.body.size " << msg.body.size());
    DEBUG("Bob: final msg.size " << msg.size());
    Send(msg);
  }

  void SendRnd2EvalMultBAB(EvalKey &EvalMultBAB) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Bob: serializing Round 2 EvalMultBAB key");
    Serial::Serialize(EvalMultBAB, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendRnd2EvalMultBAB;
    msg << os.str();
    DEBUG("Bob: final msg.body.size " << msg.body.size());
    DEBUG("Bob: final msg.size " << msg.size());
    Send(msg);
  }

  void SendRnd2EvalSumKeysJoin(
      std::shared_ptr<std::map<usint, EvalKey>> &EvalSumKeysJoin) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Bob: serializing Round 2 EvalSumKeysJoin");
    Serial::Serialize(EvalSumKeysJoin, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendRnd2EvalSumKeysJoin;
    msg << os.str();
    DEBUG("Bob: final msg.body.size " << msg.body.size());
    DEBUG("Bob: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCT1(CT &ct, unsigned int num) {
    DEBUG("Client: serializing CT1");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendCT1;
    msg << os.str();
    DEBUG("Client: final msg.body.size " << msg.body.size());
    DEBUG("Client: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCT2(CT &ct, unsigned int num) {
    DEBUG("Client: serializing CT2");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendCT2;
    msg << os.str();
    DEBUG("Client: final msg.body.size " << msg.body.size());
    DEBUG("Client: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCT3(CT &ct, unsigned int num) {
    DEBUG("Client: serializing CT3");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendCT3;
    msg << os.str();
    DEBUG("Client: final msg.body.size " << msg.body.size());
    DEBUG("Client: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCTPartialAdd(CT &ct) {
    DEBUG("Client: serializing add main partial decrypt ct");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendDecryptPartialMainAdd;
    msg << os.str();
    DEBUG("Client: final msg.body.size " << msg.body.size());
    DEBUG("Client: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCTPartialMult(CT &ct) {
    DEBUG("Client: serializing mult main partial decrypt ct");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendDecryptPartialMainMult;
    msg << os.str();
    DEBUG("Client: final msg.body.size " << msg.body.size());
    DEBUG("Client: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCTPartialSum(CT &ct) {
    DEBUG("Client: serializing sum main partial decrypt ct");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendDecryptPartialMainSum;
    msg << os.str();
    DEBUG("Client: final msg.body.size " << msg.body.size());
    DEBUG("Client: final msg.size " << msg.size());
    Send(msg);
  }
};

#endif  // THRESH_CLIENT_H
