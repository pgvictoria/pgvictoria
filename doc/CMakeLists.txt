if (RST2MAN_FOUND)
  # man target
  add_custom_target(man ALL)

  # man page definitions
  set(MAN_PAGES pgvictoria-config.1 pgvictoria-cli.1 pgvictoria-admin.1)
  set(MAN_DST_FILES)

  # Generate man pages
  foreach(MAN_PAGE ${MAN_PAGES})
    set(MAN_SRC_FILE "${CMAKE_CURRENT_SOURCE_DIR}/man/${MAN_PAGE}.rst")
    set(MAN_DST_FILE "${CMAKE_CURRENT_BINARY_DIR}/${MAN_PAGE}")

    add_custom_command(
      OUTPUT ${MAN_DST_FILE}
      COMMAND ${RST2MAN_EXECUTABLE} ${MAN_SRC_FILE} ${MAN_DST_FILE}
      DEPENDS ${MAN_SRC_FILE}
      COMMENT "Generating man page: ${MAN_PAGE}"
    )

    list(APPEND MAN_DST_FILES ${MAN_DST_FILE})
  endforeach()

  # Define the target to group all man pages
  add_custom_target(manpages ALL
    DEPENDS ${MAN_DST_FILES}
  )

  # Add the 'man' target as a dependency to 'manpages'
  add_dependencies(man manpages)

  install(DIRECTORY . DESTINATION share/doc/pgvictoria FILES_MATCHING PATTERN "*.md" EXCLUDE PATTERN "man" EXCLUDE PATTERN "manual" EXCLUDE)

  install(FILES ${MAN_DST_FILES} DESTINATION share/man/man1)
endif()

#
# Generate manual
#
if(DOCS)
  if (PANDOC_FOUND)
    # Files
    FILE(GLOB EN "manual/en/??-*.md")

    # Manuals definitions
    set(MANUAL_OUTPUT_DIR "${CMAKE_BINARY_DIR}/doc")

    add_custom_command(
      OUTPUT ${MANUAL_OUTPUT_DIR}/pgvictoria-en.pdf
      COMMAND ${PANDOC_EXECUTABLE} -o ${MANUAL_OUTPUT_DIR}/pgvictoria-en.pdf --resource-path=${CMAKE_BINARY_DIR} --from markdown --pdf-engine=xelatex --template eisvogel --listings -N --toc ${EN}
      DEPENDS ${EN}
      COMMENT "Generating English PDF documentation"
    )

    add_custom_command(
      OUTPUT ${MANUAL_OUTPUT_DIR}/pgvictoria-en.html
      COMMAND ${PANDOC_EXECUTABLE} -o ${MANUAL_OUTPUT_DIR}/pgvictoria-en.html -s -f markdown-smart -N --toc -t html5 ${EN}
      DEPENDS ${EN}
      COMMENT "Generating English Guide HTML documentation"
    )

    add_custom_target(
      all_docs ALL
      DEPENDS ${MANUAL_OUTPUT_DIR}/pgvictoria-en.pdf ${MANUAL_OUTPUT_DIR}/pgvictoria-en.html
    )

    install(FILES ${MANUAL_OUTPUT_DIR}/pgvictoria-en.pdf DESTINATION share/doc/pgvictoria/manual)
    install(FILES ${MANUAL_OUTPUT_DIR}/pgvictoria-en.html DESTINATION share/doc/pgvictoria/manual)
  endif()

  #
  # Generate API docs
  #
  if (DOXYGEN_FOUND)
    add_custom_target(api ALL)
    set(DOXYGEN_GENERATE_HTML YES)
    set(DOXYGEN_GENERATE_MAN NO)
    set(DOXYGEN_WARN_AS_ERROR FAIL_ON_WARNINGS)
    set(DOXYGEN_EXCLUDE_PATTERNS "internal.h")
    set(DOXYFILE_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.doxygen)
    doxygen_add_docs(doxygen
      ${PROJECT_SOURCE_DIR}/src/include/)
    if (${DOXYGEN_VERSION} STREQUAL "1.10.0" OR
        ${DOXYGEN_VERSION} STREQUAL "1.11.0" OR
        ${DOXYGEN_VERSION} STREQUAL "1.12.0" OR
        ${DOXYGEN_VERSION} STREQUAL "1.13.0" OR
        ${DOXYGEN_VERSION} STREQUAL "1.13.1" OR
        ${DOXYGEN_VERSION} STREQUAL "1.13.2" OR
        ${DOXYGEN_VERSION} STREQUAL "1.14.0" OR
        ${DOXYGEN_VERSION} STREQUAL "1.15.0" OR
        ${DOXYGEN_VERSION} STREQUAL "1.16.0" OR
        ${DOXYGEN_VERSION} STREQUAL "1.16.1" OR
        ${DOXYGEN_VERSION} STREQUAL "1.17.0")
      add_custom_command(
        TARGET api
        POST_BUILD
        COMMAND ${DOXYGEN_EXECUTABLE} -q ${DOXYFILE_OUT}
        COMMENT "Generating API documentation"
      )
    else()
      add_custom_command(
        TARGET api
        POST_BUILD
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
        COMMENT "Generating API documentation"
      )
    endif()
  endif()
endif()
