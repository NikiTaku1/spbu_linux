cmake_minimum_required(VERSION 3.12)
project(backup_daemon)

# Установи стандарт языка на C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${PROJECT_NAME} main.cpp)
target_sources(${PROJECT_NAME} PRIVATE INIReader.h)
