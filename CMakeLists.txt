cmake_minimum_required(VERSION 3.18)
project(SerialExamples)

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
add_subDirectory(src)
