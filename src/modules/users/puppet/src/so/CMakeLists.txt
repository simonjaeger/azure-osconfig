# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(users)

add_library(users SHARED UsersModule.c)
target_link_libraries(users
    PRIVATE
        commonutils
        logging
    PUBLIC
        userslib
)
target_include_directories(users
    PUBLIC
        ${MODULES_INC_DIR}
)
set_target_properties(users
    PROPERTIES
        PREFIX ""
        POSITION_INDEPENDENT_CODE ON
)
install(TARGETS users DESTINATION ${MODULES_INSTALL_DIR})