cmake_minimum_required(VERSION 3.4.1)

set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 11)

add_library(Secp256k1ZkpReact
            SHARED
            ../cpp/secp256k1-zkp-react.cpp
            cpp-adapter.cpp
            ../secp256k1-zkp-master/src/secp256k1.c
)

include_directories(
            ../cpp
            ../secp256k1-zkp-master
            ../secp256k1-zkp-master/src
            ../secp256k1-zkp-master/include
)

add_definitions(-D USE_ENDOMORPHISM -D USE_NUM_NONE -D USE_FIELD_INV_BUILTIN -D USE_SCALAR_INV_BUILTIN -D USE_FIELD_10X26 -D USE_SCALAR_8X32 -D USE_ECMULT_STATIC_PRECOMPUTATION -D ENABLE_MODULE_ECDH -D ENABLE_MODULE_GENERATOR -D ENABLE_MODULE_COMMITMENT -D ENABLE_MODULE_BULLETPROOF -D ENABLE_MODULE_AGGSIG)
