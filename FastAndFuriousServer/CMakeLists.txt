find_package(OpenSSL REQUIRED)
find_package(liboqs CONFIG REQUIRED)
find_package(libuv CONFIG REQUIRED)

add_executable (
    FastAndFuriousServer
    "Source/main.c"
    "Include/FastAndFuriousServer.h"
    "Include/Encription.h"
)

if (CMAKE_VERSION VERSION_GREATER 3.25)
    set_property(TARGET FastAndFuriousServer PROPERTY C_STANDARD 23)
    set_property(TARGET FastAndFuriousServer PROPERTY CXX_STANDARD 26)
endif()

target_link_libraries(FastAndFuriousServer PRIVATE OpenSSL::SSL)
target_link_libraries(FastAndFuriousServer PRIVATE OpenSSL::Crypto)
target_link_libraries(FastAndFuriousServer PRIVATE OQS::oqs)
target_link_libraries(FastAndFuriousServer PRIVATE $<IF:$<TARGET_EXISTS:libuv::uv_a>,libuv::uv_a,libuv::uv>)
