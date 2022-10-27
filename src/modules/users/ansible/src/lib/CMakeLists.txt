# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(userslib)

add_library(userslib STATIC Users.c)
set_property(TARGET userslib PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(userslib PRIVATE logging commonutils parsonlib)
target_include_directories(userslib
    PUBLIC
        ${MODULES_INC_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR})

configure_file(ansible-exec.py /usr/lib/osconfig/ansible-exec.p COPYONLY)