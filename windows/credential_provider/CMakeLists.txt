cmake_minimum_required(VERSION 3.15)
project(KeyLinkProvider CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compile flags for a clean Windows DLL with MinGW
add_compile_options(-Wall -Wextra)

# Define the DLL library target
add_library(KeyLinkProvider SHARED
    Dll.cpp
    CredentialProvider.cpp
    CredentialProviderCredential.cpp
    helpers.cpp
    helpers.h
    guid.h
    CredentialProvider.h
    CredentialProviderCredential.h
    exports.def
)

# Set Windows link libraries for DLL
target_link_libraries(KeyLinkProvider
    PRIVATE
    ole32
    uuid
    kernel32
    secur32
    credui
)

# Output formatting options (ensures clean DLL generation)
set_target_properties(KeyLinkProvider PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
)

# Define the test client executable
add_executable(test_client
    test_client.cpp
    helpers.cpp
    helpers.h
)

# Set Windows link libraries for test client
target_link_libraries(test_client
    PRIVATE
    ole32
    uuid
    kernel32
)
