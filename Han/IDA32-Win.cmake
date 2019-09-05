set (IDA_PATH "C:/IDA Pro 7.3")
set (IDA_SDK_PATH "C:/IDA Pro 7.3 SDK/idasdk73")
set (IDA_TYPE "32")
set (IDA_LIB "${IDA_SDK_PATH}/lib/x64_win_vc_32/ida.lib")

add_definitions (-D__NT__)
add_definitions (-D__x86_64__)
