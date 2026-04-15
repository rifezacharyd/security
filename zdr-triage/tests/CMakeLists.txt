include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
)
FetchContent_MakeAvailable(Catch2)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)

add_executable(zdr_tests
    test_entropy.cpp
    test_magic.cpp
    test_ioc.cpp
    test_hashing.cpp
)

target_link_libraries(zdr_tests
    PRIVATE
        zdr_triage_core
        Catch2::Catch2WithMain
)

include(Catch)
catch_discover_tests(zdr_tests)
