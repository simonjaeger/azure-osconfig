# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(asblib)

add_library(asblib STATIC Asb.c)
set_property(TARGET asblib PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(asblib PRIVATE logging commonutils parsonlib)
target_include_directories(asblib
    PUBLIC
        ${MODULES_INC_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR})

configure_file(asc_audits.json /etc/osconfig/asb/asc_audits.json COPYONLY)
configure_file(cis_audits.json /etc/osconfig/asb/cis_audits.json COPYONLY)
configure_file(common_audits.json /etc/osconfig/asb/common_audits.json COPYONLY)
configure_file(ssh_audits.json /etc/osconfig/asb/ssh_audits.json COPYONLY)