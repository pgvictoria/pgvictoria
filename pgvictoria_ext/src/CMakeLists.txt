#
# Copyright (C) 2026 The pgvictoria community
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list
#    of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this
#    list of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may
#    be used to endorse or promote products derived from this software without
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# pgvictoria
#
# Add files for pgvictoria_ext
#
FILE(GLOB SOURCE_FILES "pgvictoria_ext/*.c")
FILE(GLOB HEADER_FILES "include/*.h")

set(SOURCES ${SOURCE_FILES} ${HEADER_FILES})

#
# Retrieving PostgreSQL configuration paths
#
execute_process(COMMAND pg_config --includedir
                OUTPUT_STRIP_TRAILING_WHITESPACE
                OUTPUT_VARIABLE EXT_INCLUDE_DIR)


if (EXT_INCLUDE_DIR)
  message(STATUS "Include directory: ${EXT_INCLUDE_DIR}")
else (EXT_INCLUDE_DIR)
  message(FATAL_ERROR "pg_config --includedir failed")
endif (EXT_INCLUDE_DIR)


execute_process(COMMAND pg_config --includedir-server
                OUTPUT_STRIP_TRAILING_WHITESPACE
                OUTPUT_VARIABLE EXT_INCLUDE_SERVER_DIR)

if (EXT_INCLUDE_SERVER_DIR)
  message(STATUS "Include directory: ${EXT_INCLUDE_SERVER_DIR}")
else (EXT_INCLUDE_SERVER_DIR)
  message(FATAL_ERROR "pg_config --includedir-server failed")
endif (EXT_INCLUDE_SERVER_DIR)

execute_process(COMMAND pg_config --pkglibdir
                OUTPUT_STRIP_TRAILING_WHITESPACE
                OUTPUT_VARIABLE EXT_INSTALL_DIR)

if (EXT_INSTALL_DIR)
  message(STATUS "Library directory: ${EXT_INSTALL_DIR}")
else (EXT_INSTALL_DIR)
  message(FATAL_ERROR "pg_config --pkglibdir failed")
endif (EXT_INSTALL_DIR)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${EXT_INCLUDE_DIR}
  ${EXT_INCLUDE_SERVER_DIR}
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(pgvictoria_ext SHARED ${SOURCES})

set_target_properties(pgvictoria_ext PROPERTIES
  LINKER_LANGUAGE C
  PREFIX ""
)

install(TARGETS pgvictoria_ext
        DESTINATION ${EXT_INSTALL_DIR})