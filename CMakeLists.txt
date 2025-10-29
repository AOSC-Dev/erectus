# SPDX-FileCopyrightText: Copyright 2025 Anthon Open Source Community
# SPDX-License-Identifier: GPL-2.0-or-later
cmake_minimum_required(VERSION 3.12)
project(erectus LANGUAGES C CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig)
pkg_check_modules(LIBELF libelf)
find_package(Python3)

add_executable(erectus main.cpp patching.hpp)
target_include_directories(erectus PRIVATE ${LIBELF_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(erectus PRIVATE ${LIBELF_LIBRARIES})
