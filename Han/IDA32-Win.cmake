set (IDA_PATH "C:/IDA Pro 7.3")
set (IDA_SDK_PATH "C:/IDA Pro 7.3 SDK/idasdk73")
set (IDA_TYPE "32")

add_definitions (-D__NT__)
add_definitions (-D__x86_64__)

link_libraries("${IDA_SDK_PATH}/lib/x64_win_vc_32/ida.lib")