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

#ifndef PGVICTORIA_REPORT_H
#define PGVICTORIA_REPORT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pgvictoria.h>
#include <postgresql.h>
#include <openssl/ssl.h>

/**
 * A single configuration setting compared against its version baseline.
 */
struct pgvictoria_diff_item
{
   char key[128];           /**< The configuration parameter name */
   char baseline_val[1024]; /**< The expected value from the version baseline */
   char current_val[1024];  /**< The value reported by the live server */
   char status[32];         /**< Comparison result: "Default", "Modified" or "Custom" */
};

/**
 * Which GUCs the report should list. Selected with -t/--type in both online and
 * file mode. "changed" (the default) hides settings whose value matches the
 * baseline default; "full" lists every setting.
 */
enum pgvictoria_report_type {
   PGVICTORIA_REPORT_CHANGED = 0,
   PGVICTORIA_REPORT_FULL,
};

/**
 * Generate a configuration report for the specified server online
 * @param server The server index
 * @param format The output format (text, HTML, or Markdown)
 * @param type Which GUCs to list (changed or full)
 * @param output_file Destination path for the report (required)
 * @return 0 upon success, otherwise 1
 */
int pgvictoria_report_online(int server, enum pgvictoria_output_format format, enum pgvictoria_report_type type, char* output_file);

/**
 * Generate a configuration report from a file directly on disk
 * @param filename The configuration file path
 * @param format The output format (text, HTML, or Markdown)
 * @param type Which GUCs to list (changed or full)
 * @param output_file Destination path for the report (required)
 * @param override_version The baseline version to compare against, or 0 to auto-detect
 * @return 0 upon success, otherwise 1
 */
int pgvictoria_report_file(char* filename, enum pgvictoria_output_format format, enum pgvictoria_report_type type, char* output_file, int override_version);

#ifdef __cplusplus
}
#endif

#endif
