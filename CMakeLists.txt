cmake_minimum_required(VERSION 3.10)

project(disasmer VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCES
    src/main.cpp
)

add_executable(disasmer ${SOURCES})

include_directories(include)
