/*
 * Copyright (C) 2026 The pgvictoria community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PGVICTORIA_SUGGEST_H
#define PGVICTORIA_SUGGEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pgvictoria.h>
#include <report.h>
#include <stdint.h>

/**
  * Database Workload Types
  */
enum pgvictoria_db_workload_type {
   PGVICTORIA_DB_WORKLOAD_TYPE_GENERAL,
   PGVICTORIA_DB_WORKLOAD_TYPE_WEB,
   PGVICTORIA_DB_WORKLOAD_TYPE_DW,
   PGVICTORIA_DB_WORKLOAD_TYPE_OLTP,
   PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP,
   PGVICTORIA_DB_WORKLOAD_TYPE_MIXED
};

/**
 * Auto Detect System Parameters used in suggestions
 * @param total_ram The total system memory in bytes
 * @return 0 upon success, otherwise 1
 */
int auto_detect_system_parameter(uint64_t *total_ram);

/**
 * Calculate suggested shared_buffers based on total_ram ans DB workload type
 * @param total_ram The total system memory in bytes
 * @param type The DB workload type
 * @return suggested shared_buffers size in GB/MB bases on the total_ram size
 */
uint64_t suggested_shared_buffers(uint64_t total_ram, enum pgvictoria_db_workload_type type);

/**
 * Suggest
 * @param type The DB workload type
 * @param output_file The path of output_file or NULL and print the suggestions on CLI.
 * @param format The output format (text, HTML, or Markdown)
 * @return suggested shared_buffers size in GB/MB bases on the total_ram size
 */
int pgvictoria_suggest_mode(enum pgvictoria_db_workload_type type, char *output_file, enum pgvictoria_output_format format);

#ifdef __cplusplus
}
#endif

#endif
