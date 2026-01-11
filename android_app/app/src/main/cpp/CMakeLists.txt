cmake_minimum_required(VERSION 3.18.1)

project("ringeventparser_jni")

# Create shared library from our JNI wrapper
add_library(ringeventparser_jni SHARED
    ringeventparser_jni.cpp
)

# Find required Android libraries
find_library(log-lib log)
find_library(android-lib android)

# Link against log (for __android_log_print) and dl (for dlopen/dlsym)
target_link_libraries(ringeventparser_jni
    ${log-lib}
    ${android-lib}
    dl
)

# Set C++ standard
set_target_properties(ringeventparser_jni PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
)
