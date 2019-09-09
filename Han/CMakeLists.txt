# CMakeList.txt: 顶层 CMake 项目文件，在此处执行全局配置
# 并包含子项目。
#
cmake_minimum_required (VERSION 3.8)

project ("Han" C CXX)

if (CMAKE_HOST_WIN32)
	set (plthook "plthook/plthook_win32.c")
elseif (CMAKE_HOST_UNIX)
	set (plthook "plthook/plthook_elf.c")
elseif (CMAKE_HOST_APPLE)
	set (plthook "plthook/plthook_osx.c")
endif ()

if (IDA_TYPE STREQUAL "64")
	set (Han Han64)
else ()
	set (Han Han)
endif ()

add_library (${Han} SHARED "main.cpp" "RestoreMacroCompression.cpp" "RestoreMacroCompression.h")

target_include_directories (${Han} PUBLIC "${IDA_PATH}/plugins/hexrays_sdk/include" "${IDA_SDK_PATH}/include")

target_link_libraries (${Han} PUBLIC ${IDA_LIB})

add_library (plthook STATIC "plthook/plthook.h" ${plthook})

target_include_directories (${Han} PUBLIC "${PROJECT_SOURCE_DIR}/plthook")

target_link_libraries (${Han} PUBLIC plthook)