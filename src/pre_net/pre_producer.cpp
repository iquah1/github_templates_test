// @file pre-producer.cpp - Example of Proxy Re-Encryption producer client
// @author TPOC: contact@palisade-crypto.org
//
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
//
// @section DESCRIPTION
// Example software for multiparty proxy-reencryption of an integer buffer using
// BFV rns scheme. Producer application.
// uses lightweight ASIO connection library Copyright 2018 - 2020 OneLoneCoder.com

// In this example we have two types of clients, producers and consumers.
// producers generate a CT and also send secret keys to the server.
// consumers send a public key to the server and get a recryption key back.
//
// to show correct operation, we allow producers to send a CT to the
// server and consumers to request this CT from the server to verify
// we allow consumers to send decrypted vecInt to server and consumers
// to request that from server for verification.  in a real system
// another service would provide that transfer mechanism.


#define PROFILE

#include <getopt.h>
//#include <chrono>

#include "palisade.h"
#include "pre_utils.h"

#include "pre_client.h"
  

using namespace lbcrypto;
/**
 * main program
 * requires inputs
 */


enum class ProducerStates: uint64_t  {
  GetMessage,
  RequestCC,
  GenKeys,
  GenCT,
  RequestVecInt,
  Verify,
};


int main(int argc, char *argv[]) {
  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////
  int opt;
  string myName("");  // name of client to run
  uint32_t port(0);
  string hostName(""); //name of server host
  
  while ((opt = getopt(argc, argv, "i:n:p:h")) != -1) {
    switch (opt) {
	case 'i':
	  hostName = optarg;
	  std::cout << "host name " << hostName << std::endl;
	  break;
	case 'n':
	  myName = optarg;
	  std::cout << "starting producer client named " << myName << std::endl;
	  break;
	case 'p':
	  port = atoi(optarg);
	  std::cout << "host port " << port << std::endl;
	  break;
	case 'h':
	default: /* '?' */
	  std::cerr << "Usage: " << std::endl
				<< "arguments:" << std::endl
				<< "  -n name of the consumer client" << std::endl
				<< "  -i IP or hostname of the server" << std::endl
				<< "  -p port of the server" << std::endl
				<< "  -h prints this message" << std::endl;
	  std::exit(EXIT_FAILURE);
    }
  }
  PreProducerClient c;
  // connect to the server
  PROFILELOG(myName << ": Connecing to server at " << hostName << ":"
			 << port );  
  c.Connect(hostName, port);
  if (c.IsConnected()) {
	PROFILELOG(myName << ": Connected to server");
	// if (c.Incoming().empty()) {
	//   PROFILELOG(myName << " Incomming empty");
	// }else {
	//   PROFILELOG(myName << " Incomming full");
	// }
  } else {
	PROFILELOG(myName << ": Not Connected to server. Exiting");
	exit (EXIT_FAILURE);
  }
  
  bool done = false;
  bool good = true;
  // producer is a simple state machine, set initial state 
  ProducerStates state(ProducerStates::GetMessage); 

  CC clientCC;
  KeyPair keyPair;
  PT pt;
  CT ct;
  unsigned int ringsize(0U);
  unsigned int nShort(0U);
  unsigned int plaintextModulus(0U);
  vecInt vShorts; // our vector of shorts (must be stored as int64_t)
  vecInt unpackedConsumer(0);
  TimeVar t;  // time benchmarking variable

  DEBUG_FLAG(false); //Turns on and off DEBUG() statements

  while(!done) {
	if (c.IsConnected()) {
	  
	  switch (state) {	// sequence of states that producer executes
	  case ProducerStates::GetMessage:
		// client tests for a response from the server
		if (!c.Incoming().empty()) {
		  auto msg = c.Incoming().pop_front().msg;

		  switch (msg.header.id) {
		  case PreMsgTypes::ServerAccept:
			// Server has responded to the Connect()				
			DEBUG("Server Accepted Connection");
			state = ProducerStates::RequestCC;
			break;		  
			
		  case PreMsgTypes::SendCC:
			PROFILELOG(myName << ": reading crypto context from server");
			TIC(t);
			clientCC = c.RecvCC(msg);
			PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
			state = ProducerStates::GenKeys;
			break;
			
		  case PreMsgTypes::AckPrivateKey:
			// Server has responded to a sendPrivateKey
			DEBUG("Server Accepted PrivateKey");
			state = ProducerStates::GenCT;
			break;		  
			
		  case PreMsgTypes::AckCT:
			// Server has responded to a sendCT
			DEBUG("Server Accepted CT");
			state = ProducerStates::RequestVecInt;
			break;		  
			
		  case PreMsgTypes::SendVecInt:
			
			PROFILELOG(myName << ": reading vecInt from server");
			TIC(t);
			unpackedConsumer = c.RecvVecInt(msg);
			PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
			state = ProducerStates::Verify;
			break;

		  case PreMsgTypes::NackVecInt:
			// Server has responded to a SendVecInt with a NAC, retry
			DEBUG("Server NackVecInt");
			nap(1000); //sleep for a second and retry. 
		  state = ProducerStates::RequestVecInt;
			break;		  

		  default:
			PROFILELOG(myName << ": received unhandled message from Server " << msg.header.id);		  
		  }
		} // end isEmpty -- could sleep here
		break;
		
	  case ProducerStates::RequestCC: //first step
		TIC(t);
		PROFILELOG(myName << ": Requesting CC");
		c.RequestCC(); //request the CC from the server. 
		PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
		state = ProducerStates::GetMessage;
		break;

	  case ProducerStates::GenKeys: //if have received the CC from the server
		// then generate keys and send the private key to server
		PROFILELOG(myName << ": Generating keys");
		TIC(t);
		keyPair = clientCC->KeyGen();
		PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
		
		if (!keyPair.good()) {
		  std::cerr << myName << " Key generation failed!" << std::endl;
		  std::exit(EXIT_FAILURE);
		}
		
		PROFILELOG(myName << ": Serializing and sending private key");
		TIC(t);
		c.SendPrivateKey(keyPair);
		PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
		state = ProducerStates::GetMessage;		
		
		break;
		
	  case ProducerStates::GenCT: //if we have sent the private key to the
		// server generate and send CT
		ringsize = clientCC->GetRingDimension();
		plaintextModulus =
		  clientCC->GetCryptoParameters()->GetPlaintextModulus();
		PROFILELOG(myName << ": plaintext modulus is :" << plaintextModulus);
		
		if (plaintextModulus < 65536) {
		  std::cerr
			<< "error, code is designed for plaintextModulus>65536, modulus is "
			<< plaintextModulus << std::endl;
		  std::exit(EXIT_FAILURE);
		}
		PROFILELOG(myName << ": can encrypt " <<
				   ringsize * 2 << " bytes of data");
		nShort = ringsize;
		PROFILELOG(myName << ": encrypting data, length " << nShort);
		TIC(t);

		// we selected a plaintext modulus for the common
		// cryptocontext so that we could encode source data as a
		// packed vector of shorts ringsize elements long
		for (size_t i = 0; i < nShort; i++){ //generate a random array of shorts
		  vShorts.push_back(std::rand() % 65536);
		}

		//pack them into a packed plaintext (vector encryption)
		pt = clientCC->MakePackedPlaintext(vShorts);
		
		ct = clientCC->Encrypt(keyPair.publicKey, pt); // Encrypt
		PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
		PROFILELOG(myName << ": sending CT to server");
		c.SendCT(ct);
		state = ProducerStates::GetMessage;
		break;

	  case ProducerStates::RequestVecInt: //CT sent, ask for vecInt in return
		TIC(t);
		PROFILELOG(myName << ": Requesting VecInt");
		c.RequestVecInt(); //request the VecInt from the server. 
		PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
		state = ProducerStates::GetMessage;
		break;

	  case ProducerStates::Verify://got vecInt, verify it
		PROFILELOG(myName << ": got verification");

		// producer's final verification.
		PROFILELOG(myName << ": decrypting my data as a check");
		// self Decryption of producer's Ciphertext for testing
		TIC(t);
		PT ptDec;
		clientCC->Decrypt(keyPair.secretKey, ct, &ptDec);
		
		ptDec->SetLength(pt->GetLength()); //need to reset the length
		//unpack the plaintext data into vecInts
		vecInt unpackedOriginalProducer = pt->GetPackedValue();
		vecInt unpackedEncryptedProducer = ptDec->GetPackedValue();
		
		// note PALISADE assumes that plaintext is in the range of -p/2..p/2
		// to recover 0...q simply add q if the unpacked value is negative
		for (unsigned int j = 0; j < pt->GetLength(); j++) {
		  if (unpackedEncryptedProducer[j] < 0)
			unpackedEncryptedProducer[j] += plaintextModulus;
		}
		
		// verify result
		PROFILELOG(myName << ": verifying ");
		// compare all results for correctness and return good=true if correct
		for (unsigned int j = 0; j < unpackedConsumer.size(); j++) {
		  if ((unpackedOriginalProducer[j] != unpackedEncryptedProducer[j]) ||
			  (unpackedOriginalProducer[j] != unpackedConsumer[j])) {
			std::cout << j << ", " << unpackedOriginalProducer[j] << ", "
					  << unpackedEncryptedProducer[j] << ", "
					  << unpackedConsumer[j] << std::endl;
			good = false;
		  }
		}
		// producer is done
		PROFILELOG(myName << ": Execution Completed.");
		c.DisconnectProducer();		
		
		done = true;
		break;
		
	  } //switch state

	} //IsConnected()

	nap(100); //take a 100 msec pause

	
  } // while !done
  if (good) {
	std::cout << myName << ": PRE passes" << std::endl;
  } else {
	std::cout << myName << ": PRE fails" << std::endl;
  }
  
  ////////////////////////////////////////////////////////////
  // Done
  ////////////////////////////////////////////////////////////
  
  PROFILELOG(myName << ": Execution Completed.");

  if (!good) {  // there could be an error
	std::exit(EXIT_FAILURE);
  }
  std::exit(EXIT_SUCCESS);  // successful return
}
