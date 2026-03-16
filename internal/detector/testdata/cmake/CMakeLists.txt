cmake_minimum_required(VERSION 3.16)
project(MyApp CXX)

# Find dependencies
find_package(OpenSSL 1.1 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Boost 1.74 COMPONENTS filesystem REQUIRED)
find_package(Threads REQUIRED)

add_executable(myapp main.cpp)

target_link_libraries(myapp
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        Boost::filesystem
        Threads::Threads
)
