# CMakeList.txt: 顶层 CMake 项目文件，在此处执行全局配置
# 并包含子项目。
#
cmake_minimum_required (VERSION 3.8)

project ("Han")

if (IDA_TYPE STREQUAL "64")
	set (Han Han64)
else ()
	set (Han Han)
endif ()

add_library (${Han} SHARED "main.cpp" "RestoreMacroCompression.cpp" "RestoreMacroCompression.h")

target_include_directories (${Han} PUBLIC "${IDA_PATH}/plugins/hexrays_sdk/include" "${IDA_SDK_PATH}/include")

target_link_libraries (${Han} LINK_PUBLIC ${IDA_LIB})
