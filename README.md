# PALISADE Serialization examples

Sample programs for Encrypted Processing between cooperating processes.

# Simple Client Server Real Number Serialization example 

Found in the src/real_server directory. These file simulate a server with private data and a client that requests that data encrypted, performs computation on the data and sends the results back to the server for decryption. 


# Building

Building the system
===================

Build instructions for Ubuntu
---------

Please note that we have not tried installing this on windows or
macOS. If anyone does try this, please update this file with
instructions.  It's recommended to use at least Ubuntu 18.04, and gnu g++ 7 or greater.


1. Install pre-requisites (if not already installed):
`g++`, `cmake`, `make`, and `autoconf`. Sample commands using `apt-get` are listed below. It is possible that these are already installed on your system.

> `sudo apt-get install build-essential #this already includes g++`

> `sudo apt-get install autoconf`

> `sudo apt-get install make`

> `sudo apt-get install cmake`

> Note that `sudo apt-get install g++-<version>` can be used to
install a specific version of the compiler. You can use `g++
--version` to check the version of `g++` that is the current system
default.

2. Install PALISADE on your system. This code was tested with pre-release 1.10.3.

Full instructions for this are to be found in the `README.md` file in the PALISADE repo. 

Run `make install` at the end to install the system to the default
location (you can change this location, but then you will have to
change the Makefile in this repo to reflect the new location).

Note you may have to execute the following on your system to
automatically find the installed libraries and include files:

> `sudo ldconfig`

3. Clone this repo onto your system.

4. Create the build directory

> `mkdir build`

5. Move to that directory and run `cmake`

> `cd build`
> `cmake ..`

6. Build the system using make

> `make`

All the examples will be in the `build/bin` directory.

Running Examples
=======================

From the build directory, make a demoData subdirectory.

> `mkdir demoData`

Open two windows and cd to the build directory.

In window 1 run the server

> `bin/real-server`


In window 2 run the client

> `bin/real-client`



