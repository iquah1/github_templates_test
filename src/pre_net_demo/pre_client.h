#ifndef PRE_CLIENT_H
#define PRE_CLIENT_H

#include "pre_utils.h"

// common to both Producers and Consumers
class PreCommonClient : public olc::net::client_interface<PreMsgTypes> {
 public:
  DEBUG_FLAG(false);  // set to true to turn on DEBUG() statements

  void RequestCC(void) {
    olc::net::message<PreMsgTypes> msg;
    DEBUG("Client: Requesting CC");
    msg.header.id = PreMsgTypes::RequestCC;
    Send(msg);
  }

  CC RecvCC(olc::net::message<PreMsgTypes> &msg) {
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
};

// producer client methods
class PreProducerClient : public PreCommonClient {
 public:
  DEBUG_FLAG(false);  // set to true to turn on DEBUG() statements

  void SendPrivateKey(KeyPair &kp) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Producer: serializing secret key");
    Serial::Serialize(kp.secretKey, os, SerType::BINARY);
    DEBUG("Producer: done");
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::SendPrivateKey;
    msg << os.str();
    DEBUG("Producer: final msg.body.size " << msg.body.size());
    DEBUG("Producer: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCT(CT &ct) {
    DEBUG("Producer: serializing CT");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::SendCT;
    msg << os.str();
    DEBUG("Producer: final msg.body.size " << msg.body.size());
    DEBUG("Producer: final msg.size " << msg.size());
    Send(msg);
  }

  void RequestVecInt(void) {
    olc::net::message<PreMsgTypes> msg;
    DEBUG("Producer: Requesting VecInt");
    msg.header.id = PreMsgTypes::RequestVecInt;
    Send(msg);
  }
  vecInt RecvVecInt(olc::net::message<PreMsgTypes> &msg) {
    unsigned int msgSize(msg.body.size());

    DEBUG("Producer: read vecInt of " << msgSize << " bytes");
    DEBUG("Producer: msg.size() " << msg.size());
    DEBUG("Producer: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("Producer istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("Producer: Deserialize");
    vecInt vi;  // create the vector
    Serial::Deserialize(vi, is, SerType::BINARY);
    DEBUG("Producer: Done");
    assert(is.good());
    return vi;
  }
};

// consumer client methods
class PreConsumerClient : public PreCommonClient {
 public:
  DEBUG_FLAG(false);  // set to true to turn on DEBUG() statements

  void SendPublicKey(KeyPair &kp) {
    std::string s;
    std::ostringstream os(s);
    DEBUG("Consumer: serializing public key");
    Serial::Serialize(kp.publicKey, os, SerType::BINARY);
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::SendPublicKey;
    msg << os.str();
    DEBUG("Consumer: final msg.body.size " << msg.body.size());
    DEBUG("Consumer: final msg.size " << msg.size());
    Send(msg);
  }

  void RequestReEncryptionKey(unsigned int clientID) {
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::RequestReEncryptionKey;
    msg.header.SubType_ID = clientID;
    Send(msg);
  }

  EvalKey RecvReencryptionKey(olc::net::message<PreMsgTypes> &msg) {
    EvalKey reencKey;
    unsigned int msgSize(msg.body.size());
    DEBUG("CLIENT: read CC of " << msgSize << " bytes");
    DEBUG("Client: msg.size() " << msg.size());
    DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(string(msg.body.begin(), msg.body.end()));
    DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(reencKey, is, SerType::BINARY);
    return reencKey;
  }

  void RequestCT(void) {
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::RequestCT;
    Send(msg);
  }

  CT RecvCT(olc::net::message<PreMsgTypes> &msg) {
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

  void SendVecInt(vecInt &vi) {
    DEBUG("Consumer: serializing vecInt");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(vi, os, SerType::BINARY);
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::SendVecInt;
    msg << os.str();
    DEBUG("Consumer: final msg.body.size " << msg.body.size());
    DEBUG("Consumer: final msg.size " << msg.size());
    DEBUG("Consumer: sending vecInt " << msg.size() << " bytes");
    Send(msg);
  }
};

#endif  // PRE_CLIENT_H
