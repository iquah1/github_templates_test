Sample programs for Encrypted Processing between cooperating
processes.  There are several example programs available that show how
to use PALISADE to build systems of multiple cooperating heavyweight
processes, using both IPC with files and Mutexes, and network
sockets. It is tricky to break the single thread examples in the
PALISADE distro into multiple programs without some example code to
document the process. We hope that these examples help users with
building new systems! The examples start with simple outsourced
computation, and then build in complexity to show the capabilities of
PALISADE's Proxy-Re-encryption (allowing a third party to re-encrypt
Alice's encrypted data with Bob's decryption key without involving
Alice), Threshold Encryption (where multiple parties cooperate on a
common computation task and all participate in decryption.

Note several of these examples are written for pedagogical purposes,
and may not represent the best way to distribute the responsibility
of Crypto context generation, and key distribution. As we develop
better examples, we may revise or delete earlier ones. Earlier
examples will always be available in prior repository releases

A short description of the various examples systems now follows:

* Simple Client Server Real Number Serialization example - IPC with Files and Mutex 

Found in the `src/real_server` directory. These files simulate a
server with private data and a client that requests that data
encrypted, performs computation on the data and sends the results back
to the server for decryption. Boost Mutex are used for
synchronization. Data is serialized via files.

* Simple Client Server Real Number Serialization example - IPC with Boost/ASIO Sockets

Found in the `src/real_socket_server` directory. The same
functionality as the above file version, but with boost sockets for
IPC. Significantly faster than files (approx 3.5x faster).


* Threshold Encryption Network Service Example 

Found in the `src\thresh_net_1` and `src\thresh_net_2` directories.

There are two versions in this example to show different
configurations that can be achieved with threshold encryption:

- `thresh_net_1` (where the clients independently compute on the
cipher-texts and compute the final decryption) and

- `thresh_net_2` (where the server computes on the cipher-texts and
the clients independently compute the final decryption).

* Proxy-re-encryption (PRE) Network Service Example -- IPC with Asynchronous Server 

Found in the `src/pre-net` directory. A proxy re-encryption server
starts, waits for a producer client to get the Crypto-context, then
generate a secret key and a sample Ciphertext. A consumer client gets
the Crypto-context, then generates and sends s public key to the
server. the server sends a re-encryption key for the producer's data
to the consumer, sends a sample Ciphertext from the producer, and the
consumer decrypts the cipher-text and passes the resulting data back
through the server to the producer for verification.

* PRE Network Service For AES Key Distribution Demo

Found in the `src/pre_net_demo` directory. This example demonstrates
an application of `pre_net` to distribute sensitive data such as
symmetric keys from producers to consumers. A single trusted server
generates PALISADE Crypto Contexts for a producer and consumer. It
generates an encryption key for the producer, a decryption key for the
consumer and does the actual recryption of a cipher-text generated by
the producer, and relayed to the consumer. It also includes an example
of denying access to unauthorized consumers. Note elaborations of this
are possible that are more secure, such as using a separate broker
process (to perform re-encryption that cannot decrypt).

# Building Instructions

Building the examples. 

## Build instructions for Ubuntu

Please note that we have not tried installing and running these
examples on windows or macOS. If anyone does try this, please update
this file with instructions and generate a merge request.
It's recommended to use at least Ubuntu 19 gnu g++ 7 or greater.

1. Install prerequisites (if not already installed):
   `g++`, `cmake`, `make`, `boost` and `autoconf`. Sample commands using `apt-get` are listed below. It is possible that these are already installed on your system.

	> `sudo apt-get install build-essential #this already includes g++`

	> `sudo apt-get install autoconf`

	> `sudo apt-get install make`

	> `sudo apt-get install cmake`

	> `sudo apt-get install libboost-all-dev`

	Note that `sudo apt-get install g++-<version>` can be used to
	install a specific version of the compiler. You can use `g++
	--version` to check the version of `g++` that is the current system
	default. The version of boost installation required might be 1.71 or
	higher for compatibility.
	
	Also Note theat 

1. Install PALISADE on your system. This code was tested with
   development stable-release 1.11.3

	Full instructions for this are to be found in the `README.md` file in
the PALISADE repo.

	Run `make install` at the end to install the system to the default
location (you can change this location, but then you will have to
change the CMakefile in this repo to reflect the new location).

	Note you may have to execute the following on your system to
automatically find the installed libraries and include files:
	> `sudo ldconfig`
	
1. Clone this repo onto your system.
1. Create the build directory
   > `mkdir build`
   
1. Move to that directory and run `cmake`
   > `cd build`
   > `cmake ..`

	Note if you used a different install directory for Palisade (for
    example if I installed it in `/home/thisuser/opt` then you need to
    run this as 
	
	> `cmake -DCMAKE_INSTALL_PREFIX=/home/thisuser/opt ..`
	
	Note: If you have multiple versions (revisions) of PALISADE on
    your system, `cmake` may find the wrong one and cause build errors
    (`cmake` uses an elaborate set of search rules to find a library,
    and it may not be the version you expect). If you have strange
    build errors, consider using the above `-DCMAKE_INSTALL_PREFIX` to
    point to the correct version.

1. Build the examples using make. Please note that PALISADE serialization uses CEREAL which can result in some long compile times.

   > `make`

	Executables for all the examples will be in the `build/bin` directory.

# Running The Examples

## Simple Client Server Real Number Serialization example - IPC with Files and Mutex 

From the `build` directory, make a `demoData` subdirectory (required
by some examples).

> `mkdir demoData`

Open two windows and cd to the build directory.

In window 1 run the server

> `bin/real_server`


In window 2 run the client

> `bin/real_client`

Note should an error occur (such as not being able to open a mutex),
rerunning the server and client should clear and reinitialize the state. Be sure
to delete and files in demoData that were left after the error. 


## Simple Client Server Real Number Serialization example - IPC with Boost/ASIO Sockets

From the build directory (this code does not need a demoData sub-directory)

Open two windows and cd to the build directory.

In window 1 run the server


> `bin/real_socket_server <port-number>`

where port-number is an unassigned TCP-IP port like 60000. This might need sudo rights.

In window 2 run the client

> `bin/real_socket_client <server-hostname> <port-number>`

Where server-hostname is the resolvable name of the machine the server
is running on, and port-number is the same port used by the
server. For running on the same machine, you can use localhost as the
server-hostname

## Threshold Encryption Network Service Example 

There are two versions in this example to show different
configurations that can be achieved with threshold encrypton:

- `thresh_net_1` (where the clients independently compute on the
cipher-texts and compute the final decryption) and

- `thresh_net_2` (where the server computes on the cipher-texts and
the clients independently compute the final decryption).

The example demos work with a threshold server and two
clients A (Alice) and B (Bob). The steps shown below to run the
example are with the version `thresh_net_1` but they are the same for
running version `thresh_net_2` as well by replacing `thresh1*` with
`thresh2*` in the examples.

From the `build` directory (this code does not need a demoData sub-directory)

Open three windows and cd to the build directory.

In window 1 run the server

> `bin/thresh1_server -p <port-number>`

where port-number is an unassigned TCP-IP port like 60000

In window 2 run client A (Alice)

> `bin/thresh1_a -n <client-name> -i <server-hostname> -p  <port-number>`

Where client-name is an arbitrary string, server-hostname is the
resolvable name of the machine the server is running on, and
port-number is the same port used by the server. For running on the
same machine, you can use localhost as the server-hostname

In window 3 run Client B (Bob)

> `bin/thresh1_b -n <client-name> -i <server-hostname> -p  <port-number>`

Where client-name is an arbitrary string, server-hostname is the
resolvable name of the machine the server is running on, and
port-number is the same port used by the server. For running on the
same machine, you can use localhost as the server-hostname

Note this example is simplified. Once the two clients have completed
their work they shut down and ask the server to shut down. 
You may see error messages such as `Read Header Fail, closing Socket.` in the client
windows. This is expected. 

## Proxy-re-encryption (PRE) Network Service Example -- IPC with Asynchronous Server 

From the build directory (this code does not need a demoData sub-directory)

Open three windows and cd to the build directory.

In window 1 run the server

> `bin/pre_server -p <port-number>`

where port-number is an unassigned TCP-IP port like 60000

In window 2 run the producer client

> `bin/pre_producer -n <client-name> -i <server-hostname> -p  <port-number>`

Where client-name is an arbitrary string, server-hostname is the
resolvable name of the machine the server is running on, and
port-number is the same port used by the server. For running on the
same machine, you can use localhost as the server-hostname

In window 3 run the consumer client

> `bin/pre_consumer -n <client-name> -i <server-hostname> -p  <port-number>`

Where client-name is an arbitrary string, server-hostname is the
resolvable name of the machine the server is running on, and
port-number is the same port used by the server. For running on the
same machine, you can use localhost as the server-hostname


Within the multiple windows you will see the following steps occur:
   1. The Server generates a PALISADE Crypto Context CC. 
   1. The Producer requests the CC and requests a PRE encryption key
      from the server.
   1. The Producer uses the PRE encryption key to encrypt an vector
      (the cipher-text) and sends it to the server. 
   1. The Consumer requests the CC and requests a PRE decryption key
      from the server.
   1. The Server re-encrypts the cipher-text and passes the re-encrypted
      cipher-text to the consumer.
   1. The Consumer decrypts the vector using their private key and sends the 
	  result back to the Server. 
   1. The Consumer requests the vector from the server and compares it against
	  the original vector, reporting success or failure. 
	  
Once the consumer and producer are finished, the server remains running.
The producer and consumer programs can be run again and again. 
You can kill the server with a control-C in that window.


## PRE Network For AES Key Distribution Demo

The `pre_net_demo` example demonstrates an application of `pre_net` to
distribute sensitive data such as symmetric keys from producers to
consumers. A single trusted server generates PALISADE Crypto Contexts
for a producer and consumer. It generates an encryption key for the
producer, a decryption key for the consumer and does the actual
recryption of a cipher-text generated by the producer, and relayed to
the consumer. It also includes an example of denying access to
unauthorized consumers. Note elaborations of this are possible that are
more secure, such as using a separate broker process (to perform
re-encryption that cannot decrypt).

The demo requires additional third party applications to be installed:

* tmux
* mpv
* openssl (should be installed in most linux distros). 
* zenity (should be installed in most linux distros). 

> `sudo apt-get install tmux`

> `sudo apt-get install mpv`

To run the demo, build the example by following instructions under "Building"


1. open a new terminal window, expand it to a large size,  and type
   > `tmux`
   to open the multiple terminal windows that will show the various component 
   printouts.
   
1. In another window cd to the root directory of this repo and type   
   > `./demoscript_pre_tmux.sh`

1. Within the multiple windows you will see the following steps occur:
   1. The Producer generates an AES key and encrypts a video (displayed)
   1. The Server generates a PALISADE Crypto Context CC. 
   1. The Producer requests the CC and requests a PRE encryption key
      from the server.
   1. The Consumer requests the CC and requests a PRE decryption key
      from the server.
   1. The Producer uses the PRE encryption key to encrypt an AES key
      (the cipher-text).
   1. The Server re-encrypts that AES key and passes the re-encrypted
      cipher-text to the consumer.
   1. The Consumer decrypts the AES key using their private key
   then decrypts the media using the AES key (displayed).
   1. An new unauthorized Consumer then requests the recryption key. 
   1. The server, not recognizing the new Consumer, responds with a
      bogus random key.
   1. The unauthorized Consumer then tries to decrypts the encrypted
      AES and fails (error shown). Click on the error window to dismiss it.



If you see errors like `no server running on /tmp/tmux-1000/default`
then you forgot to run `tmux` in another window, and the demo will not
run properly.  The script is timed so events can be seen occurring
sequentially with built in pauses. It can also run interactively by
adding a second parameter after the script command:

> `./demoscript_pre_tmux.sh interactive`
