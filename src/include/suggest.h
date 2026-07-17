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
#include <stdbool.h>
#include <stdint.h>

/**
 * Workload profiles for configuration suggestions
 */
enum pgvictoria_workload {
   PGVICTORIA_WORKLOAD_OLTP = 0, /**< Web / OLTP (default) */
   PGVICTORIA_WORKLOAD_OLAP,     /**< Data warehouse / analytics */
   PGVICTORIA_WORKLOAD_MIXED,    /**< Mixed workload */
   PGVICTORIA_WORKLOAD_DESKTOP,  /**< Desktop / Development */
};

/**
 * Hardware detection result
 */
struct pgvictoria_hw_info
{
   int cpu_count;      /**< Number of logical CPU cores */
   uint64_t total_ram; /**< Total system memory in bytes */
   bool disk_is_ssd;   /**< True if the disk appears to be an SSD/NVMe */
   char os_name[64];   /**< The operating system name */
};

/**
 * Detect hardware specifications.
 * 
 * @param hw Pointer to the hw_info struct to populate
 * @return 0 upon success, otherwise 1
 */
int pgvictoria_detect_hardware(struct pgvictoria_hw_info* hw);

/**
 * Calculate and output a suggested PostgreSQL configuration.
 * 
 * @param hw The hardware specifications
 * @param workload The expected workload
 * @param pg_version The target PostgreSQL version (e.g. 18)
 * @param max_connections The maximum number of expected connections
 * @param output_file The path to write the suggested config to
 * @param output_format The format to output (text, md, html)
 * @return 0 upon success, otherwise 1
 */
int pgvictoria_suggest(
   struct pgvictoria_hw_info* hw,
   enum pgvictoria_workload workload,
   int pg_version,
   int max_connections,
   char* output_file,
   int output_format);

#ifdef __cplusplus
}
#endif

#endif
