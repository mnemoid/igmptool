cmake_minimum_required(VERSION 3.0)

project(igmptool)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED on)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")

add_executable(igmptool igmptool.c log.c)

install(TARGETS igmptool DESTINATION bin)