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