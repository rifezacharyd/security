# Centralized warning + hardening flags for all zdr-triage targets.

include(CheckCXXCompilerFlag)

function(zdr_apply_flags target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive-)
    return()
  endif()

  target_compile_options(${target} PRIVATE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wdouble-promotion
    -Wformat=2 -Wunused -Wnull-dereference
    -Wimplicit-fallthrough
    -fno-omit-frame-pointer
  )

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(${target} PRIVATE -g -O0
      -fsanitize=address,undefined
    )
    target_link_options(${target} PRIVATE
      -fsanitize=address,undefined
    )
  else()
    target_compile_options(${target} PRIVATE -O2)
  endif()

  # Apple Silicon and Linux aarch64 — enable NEON + crypto extensions when
  # available. OpenSSL's SHA-256 picks up ARMv8 crypto at runtime anyway.
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "(aarch64|arm64)")
    check_cxx_compiler_flag("-march=armv8-a+crypto+simd" ZDR_HAS_ARMV8_CRYPTO)
    if(ZDR_HAS_ARMV8_CRYPTO AND NOT APPLE)
      target_compile_options(${target} PRIVATE -march=armv8-a+crypto+simd)
    endif()
    target_compile_definitions(${target} PRIVATE ZDR_TARGET_ARM64=1)
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64)")
    target_compile_definitions(${target} PRIVATE ZDR_TARGET_X86_64=1)
    target_compile_options(${target} PRIVATE -msse4.2)
  endif()
endfunction()
