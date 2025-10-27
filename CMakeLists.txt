cmake_minimum_required(VERSION 3.12)
project(erectus LANGUAGES C CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(REGENERATE_SHIMS "Regenerate various shims from C source code" OFF)

find_package(PkgConfig)
pkg_check_modules(LIBELF libelf)
find_package(Python3)

function(FindLoongArchCC)
  # First test if the host system compiler is LoongArch64
  execute_process(
    COMMAND ${CMAKE_C_COMPILER} -dumpmachine
    OUTPUT_VARIABLE HOST_TRIPLE
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(HOST_TRIPLE MATCHES "loongarch64")
    set(LOONGARCH_CC ${CMAKE_C_COMPILER} CACHE PATH "LoongArch C Compiler" FORCE)
    return()
  endif()
  # Next try if the system Clang has the LoongArch64 target
  execute_process(
    COMMAND clang --target=loongarch64-linux-gnu -x c - -c -o /dev/null
    INPUT_FILE /dev/null
    RESULT_VARIABLE CLANG_LOONGARCH_RESULT
  )
  if(CLANG_LOONGARCH_RESULT EQUAL 0)
    set(LOONGARCH_CC "clang --target=loongarch64-linux-gnu" CACHE PATH "LoongArch C Compiler" FORCE)
    return()
  endif()
  message(FATAL_ERROR "Could not find a LoongArch C Compiler")
endfunction()

if (REGENERATE_SHIMS)
  FindLoongArchCC()
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/errno-lut.c
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/assets/generate-errno-lut.py "${CMAKE_CURRENT_BINARY_DIR}/errno-lut.c"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/assets
    DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/assets/generate-errno-lut.py
    ${CMAKE_CURRENT_SOURCE_DIR}/assets/errno-table.csv
  )
  add_custom_target(generate_errno_lut ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/errno-lut.c
  )
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/errno_conversion_code.hpp
    COMMAND "BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}" "LOONGARCH_CC=${LOONGARCH_CC}" bash -e ${CMAKE_CURRENT_SOURCE_DIR}/generate-shim-data.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/generate-shim-data.sh
    ${CMAKE_CURRENT_SOURCE_DIR}/shims.c
    generate_errno_lut
  )
  add_custom_target(regenerate_shims ALL
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/shims.c
  )
else()
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/errno_conversion_code.hpp
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_CURRENT_SOURCE_DIR}/assets/errno_conversion_code.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/errno_conversion_code.hpp
  )
endif()

add_executable(erectus main.cpp patching.hpp
  ${CMAKE_CURRENT_BINARY_DIR}/errno_conversion_code.hpp
)
target_include_directories(erectus PRIVATE ${LIBELF_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(erectus PRIVATE ${LIBELF_LIBRARIES})
