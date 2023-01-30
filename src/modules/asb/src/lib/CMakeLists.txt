# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(asblib)

add_library(asblib STATIC Asb.c)
set_property(TARGET asblib PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(asblib PRIVATE logging commonutils)
target_include_directories(asblib
    PUBLIC
        ${MODULES_INC_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR})