cmake_minimum_required(VERSION 3.14)
project(ghostdmp CXX)

set(CMAKE_CXX_STANDARD  14)

add_library(ghostdmp SHARED Main.cpp NtDirect.cpp NtDirect.h Utils.cpp Utils.h DataPool.cpp DataPool.h)

set ( CMAKE_CXX_FLAGS "-static -w")
TARGET_LINK_LIBRARIES(ghostdmp dbghelp)