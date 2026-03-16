cmake_minimum_required(VERSION 3.16)
project(SampleApp CXX)

find_package(OpenSSL 1.1 REQUIRED)
find_package(ZLIB REQUIRED)

add_executable(sample_app src/main.cpp)

target_link_libraries(sample_app
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
)
