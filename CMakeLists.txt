cmake_minimum_required (VERSION 3.0)
project (MiniDbg)

add_compile_options(--std=c++14)

include_directories(dependencies/libelfin dependencies/linenoise include)
add_executable(minidbg src/minidbg.cpp dependencies/linenoise/linenoise.c)

add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/dependencies/libelfin
)
target_link_libraries(minidbg
                      ${PROJECT_SOURCE_DIR}/dependencies/libelfin/dwarf/libdwarf++.so
                      ${PROJECT_SOURCE_DIR}/dependencies/libelfin/elf/libelf++.so)
add_dependencies(minidbg libelfin)
