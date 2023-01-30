# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(asb)

add_library(asb SHARED AsbModule.c)
target_link_libraries(asb
    PRIVATE
        commonutils
        logging
    PUBLIC
        asblib
)
target_include_directories(asb
    PUBLIC
        ${MODULES_INC_DIR}
)
set_target_properties(asb
    PROPERTIES
        PREFIX ""
        POSITION_INDEPENDENT_CODE ON
)
install(TARGETS asb DESTINATION ${MODULES_INSTALL_DIR})