#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

project (sss_pkcs11)

SET(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/simw_lib)

INCLUDE(${SIMW_LIB_DIR}/simw_lib.cmake)

FILE(
    GLOB
    files
    se_pkcs11/${PROJECT_NAME}.c
    ${SIMW_SE_SOURCES}
)

FILE(
    GLOB
    pkcs11_files
    se_pkcs11/*.c
)

ADD_LIBRARY(${PROJECT_NAME} SHARED ${files} ${pkcs11_files})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    se_pkcs11/
    pkcs11/published/2-40-errata-1
    ${SIMW_INC_DIR}
    )

ADD_DEFINITIONS(-DPKCS11_LIBRARY)
ADD_DEFINITIONS(-DPKCS11_SESSION_OPEN)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)