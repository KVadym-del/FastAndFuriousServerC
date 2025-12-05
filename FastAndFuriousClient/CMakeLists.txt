find_package(OpenSSL REQUIRED)
find_package(liboqs CONFIG REQUIRED)
find_package(libuv CONFIG REQUIRED)

add_executable (
    FastAndFuriousClient
    "main.c"
    "Include/faf_client.h"
)

if (CMAKE_VERSION VERSION_GREATER 3.25)
    set_property(TARGET FastAndFuriousClient PROPERTY C_STANDARD 23)
    set_property(TARGET FastAndFuriousClient PROPERTY CXX_STANDARD 26)
endif()

target_link_libraries(FastAndFuriousClient PRIVATE OpenSSL::SSL)
target_link_libraries(FastAndFuriousClient PRIVATE OpenSSL::Crypto)
target_link_libraries(FastAndFuriousClient PRIVATE OQS::oqs)
target_link_libraries(FastAndFuriousClient PRIVATE $<IF:$<TARGET_EXISTS:libuv::uv_a>,libuv::uv_a,libuv::uv>)
