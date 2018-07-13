cmake_minimum_required(VERSION 3.5)
project(irods_smb)

add_library(irods_smb SHARED irods_smb.cpp)
target_compile_options(irods_smb -std=c++14 -Wall -Wextra)
target_include_directories(irods_smb PRIVATE ../../source3/include)
target_link_libraries(irods_smb PRIVATE ...)
