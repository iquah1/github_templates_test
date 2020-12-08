// @file real-client - code to simulate a client to show an example of encrypted
// server-client processing relationships.
//
//The server serializes contexts, public key and processing keys for
// the client to then load. It then generates and encrypts some data
// to send to the client. The client loads the crypto context and
// keys, then operates on the encrypted data, encrypts additional
// data, and sends the results back to the server.  Finally, the
// server decrypts the result and in this demo verifies that results
// are correct.
// 
// @author: Ian Quah, Dave Cousins
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

#include "utils.h"
#include "palisade.h"

using namespace lbcrypto;

std::tuple<CryptoContext<DCRTPoly>, LPPublicKey<DCRTPoly>>
clientDeserializeContextKeysFromServer(Configs &userConfigs) {
  /////////////////////////////////////////////////////////////////
  // NOTE: ReleaseAllContexts is imperative; it ensures that the environment
  // is cleared before loading anything. The function call ensures we are not
  // keeping any contexts in the process. Use it before creating a new CC
  /////////////////////////////////////////////////////////////////
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

  CryptoContext<DCRTPoly> clientCC;
  if (!Serial::DeserializeFromFile(
          userConfigs.DATAFOLDER + userConfigs.ccLocation, clientCC,
          SerType::BINARY)) {
    std::cerr << "CLIENT: cannot read serialized data from: "
              << userConfigs.DATAFOLDER << "/cryptocontext.txt" << std::endl;
    std::exit(1);
  }
  fRemove(userConfigs.DATAFOLDER + userConfigs.ccLocation);
  
  /////////////////////////////////////////////////////////////////
  // NOTE: the following 2 lines are essential
  // It is possible that the keys are carried over in the cryptocontext
  // serialization so clearing the keys is important
  /////////////////////////////////////////////////////////////////

  clientCC->ClearEvalMultKeys();
  clientCC->ClearEvalAutomorphismKeys();

  LPPublicKey<DCRTPoly> clientPublicKey;
  if (!Serial::DeserializeFromFile(
          userConfigs.DATAFOLDER + userConfigs.pubKeyLocation, clientPublicKey,
          SerType::BINARY)) {
    std::cerr << "CLIENT: cannot read serialized data from: "
              << userConfigs.DATAFOLDER << "/cryptocontext.txt" << std::endl;
    std::exit(1);
  }
  fRemove(userConfigs.DATAFOLDER + userConfigs.pubKeyLocation);
  std::cout << "CLIENT: public key deserialized" << std::endl;

  std::ifstream multKeyIStream(
      userConfigs.DATAFOLDER + userConfigs.multKeyLocation,
      std::ios::in | std::ios::binary);
  if (!multKeyIStream.is_open()) {
    std::cerr << "CLIENT: cannot read serialization from "
              << userConfigs.DATAFOLDER + userConfigs.multKeyLocation
              << std::endl;
    std::exit(1);
  }
  if (!clientCC->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
    std::cerr << "CLIENT: Could not deserialize eval mult key file"
              << std::endl;
    std::exit(1);
  }
  multKeyIStream.close();
  fRemove(userConfigs.DATAFOLDER + userConfigs.multKeyLocation);
  std::cout << "CLIENT: Relinearization keys from server deserialized." << std::endl;

  std::ifstream rotKeyIStream(
      userConfigs.DATAFOLDER + userConfigs.rotKeyLocation,
      std::ios::in | std::ios::binary);
  if (!rotKeyIStream.is_open()) {
    std::cerr << "CLIENT: Cannot read serialization from "
              << userConfigs.DATAFOLDER + userConfigs.multKeyLocation
              << std::endl;
    std::exit(1);
  }

  if (!clientCC->DeserializeEvalAutomorphismKey(rotKeyIStream,
                                                SerType::BINARY)) {
    std::cerr << "CLIENT: Could not deserialize eval rot key file" << std::endl;
    std::exit(1);
  }
  rotKeyIStream.close();
  fRemove(userConfigs.DATAFOLDER + userConfigs.rotKeyLocation);

  return std::make_tuple(clientCC, clientPublicKey);
}

Ciphertext<DCRTPoly> clientReceiveCT(const std::string location){
  Ciphertext<DCRTPoly> c1;
  if (!Serial::DeserializeFromFile(location, c1,
								   SerType::BINARY)) {
    std::cerr << "CLIENT: Cannot read serialization from " << location << std::endl;
	removeLock(GConf.clientLock, GConf.CLIENT_LOCK);
    std::exit(EXIT_FAILURE);
  }
  fRemove(location);
  return c1;
}

void clientComputeAndSendDataToServer(CryptoContext<DCRTPoly> &clientCC,
									  Ciphertext<DCRTPoly> &clientC1,
									  Ciphertext<DCRTPoly> &clientC2,
									  LPPublicKey<DCRTPoly> &clientPublicKey,
									  const Configs &userConfigs) {

  std::cout << "CLIENT: Applying operations on data" << std::endl;
  auto clientCiphertextMult = clientCC->EvalMult(clientC1, clientC2);
  auto clientCiphertextAdd = clientCC->EvalAdd(clientC1, clientC2);
  auto clientCiphertextRot = clientCC->EvalAtIndex(clientC1, 1);
  auto clientCiphertextRotNeg = clientCC->EvalAtIndex(clientC1, -1);

  // Now, we want to simulate a client who is encrypting data for the server to
  // decrypt. E.g weights of a machine learning algorithm

  std::cout << "CLIENT: encrypting a vector" << std::endl;
  complexVector clientVector1 = {1.0, 2.0, 3.0, 4.0};
  if (clientVector1.size() != VECTORSIZE) {
    std::cerr << "clientVector1 size was modified. Must be of length 4"
              << "\n";
    exit(1);
  }
  auto clientPlaintext1 = clientCC->MakeCKKSPackedPlaintext(clientVector1);
  auto clientInitiatedEncryption =
      clientCC->Encrypt(clientPublicKey, clientPlaintext1);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.cipherMultLocation,
      clientCiphertextMult, SerType::BINARY);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.cipherAddLocation,
      clientCiphertextAdd, SerType::BINARY);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.cipherRotLocation,
      clientCiphertextRot, SerType::BINARY);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.cipherRotNegLocation,
      clientCiphertextRotNeg, SerType::BINARY);
  Serial::SerializeToFile(
      userConfigs.DATAFOLDER + userConfigs.clientVectorLocation,
      clientInitiatedEncryption, SerType::BINARY);
}
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

int main() {

  std::cout << "This program requires the subdirectory "
            << GConf.DATAFOLDER << "' to exist, otherwise you will get "
            << "an error writing serializations." << std::endl;
  /////////////////////////////////////////////////////////////////
  // Actual client work
  /////////////////////////////////////////////////////////////////

  // basically we need the server to go first to write out all the serialization
  std::cout << "CLIENT: Open server lock" << std::endl;

  GConf.serverLock = openLock(GConf.SERVER_LOCK);
  std::cout << "CLIENT: create and acquire client lock" << std::endl;
  GConf.clientLock = createAndAcquireLock(GConf.CLIENT_LOCK);

  std::cout << "CLIENT: acquire server lock" << std::endl;
  // the client will sleep until the server is done with the lock
  acquireLock(GConf.serverLock,GConf.SERVER_LOCK);
  std::cout << "CLIENT: Acquired sever lock. Getting serialized crypto context and keys"
			<< std::endl;

  releaseLock(GConf.serverLock,GConf.SERVER_LOCK);

  auto ccAndPubKeyAsTuple = clientDeserializeContextKeysFromServer(GConf);
  auto clientCC = std::get<CRYPTOCONTEXT_INDEX>(ccAndPubKeyAsTuple);
  auto clientPublicKey = std::get<PUBLICKEY_INDEX>(ccAndPubKeyAsTuple);
  
  std::cout << "CLIENT: Getting ciphertexts" << std::endl;
  Ciphertext<DCRTPoly> clientC1 = clientReceiveCT(GConf.DATAFOLDER + GConf.cipherOneLocation);
  Ciphertext<DCRTPoly> clientC2 = clientReceiveCT(GConf.DATAFOLDER + GConf.cipherTwoLocation);

  std::cout << "CLIENT: Computing and Serializing results" << std::endl;
  clientComputeAndSendDataToServer(clientCC, clientC1, clientC2, clientPublicKey,
                               GConf);

  std::cout << "CLIENT: Releasing Client lock" << std::endl;
  releaseLock(GConf.clientLock, GConf.CLIENT_LOCK);
  std::cout << "CLIENT: Acquiring Server lock" << std::endl;
  acquireLock(GConf.serverLock,GConf.SERVER_LOCK);
  std::cout << "CLIENT: Acquired server lock. Server is done" << std::endl;
  releaseLock(GConf.serverLock,GConf.SERVER_LOCK);
  std::cout << "CLIENT: Released server lock. Cleaning up" << std::endl;
  removeLock(GConf.clientLock, GConf.CLIENT_LOCK);
  std::cout << "CLIENT: Exiting" << std::endl;

}
