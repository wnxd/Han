set (IDA_PATH "C:/IDA Pro 7.3")
set (IDA_SDK_PATH "C:/IDA Pro 7.3 SDK/idasdk73")
set (IDA_TYPE "64")

add_definitions (-D__NT__)
add_definitions (-D__EA64__)
add_definitions (-D__x86_64__)

include_directories ("platform/win")

link_libraries("${IDA_SDK_PATH}/lib/x64_win_vc_64/ida.lib")