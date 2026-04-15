cmake_minimum_required(VERSION 3.20)

project(zdr-triage
  VERSION 0.1.0
  DESCRIPTION "Fast single-binary file triage for incident response and audit."
  LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

include(cmake/CompilerFlags.cmake)

# --- Dependencies -----------------------------------------------------------

find_package(OpenSSL REQUIRED)  # SHA-256 (hardware-accelerated on ARMv8 crypto)

# --- Core library -----------------------------------------------------------

add_library(zdr_triage_core STATIC
  src/entropy.cpp
  src/magic.cpp
  src/hashing.cpp
  src/ioc.cpp
  src/ndjson.cpp
  src/triage.cpp
)
target_include_directories(zdr_triage_core
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(zdr_triage_core PUBLIC OpenSSL::Crypto)
target_compile_features(zdr_triage_core PUBLIC cxx_std_20)
zdr_apply_flags(zdr_triage_core)

# --- CLI binary -------------------------------------------------------------

add_executable(zdr-triage src/main.cpp)
target_link_libraries(zdr-triage PRIVATE zdr_triage_core)
zdr_apply_flags(zdr-triage)

install(TARGETS zdr-triage RUNTIME DESTINATION bin)

# --- Tests ------------------------------------------------------------------

option(ZDR_BUILD_TESTS "Build tests" ON)
if(ZDR_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# --- Benchmarks -------------------------------------------------------------

option(ZDR_BUILD_BENCH "Build microbenchmarks" OFF)
if(ZDR_BUILD_BENCH)
  add_subdirectory(bench)
endif()
