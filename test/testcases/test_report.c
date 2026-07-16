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
 *
 */

#include <mctf.h>
#include <tscommon.h>
#include <report.h>
#include <utils.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

MCTF_TEST_SETUP(report)
{
   pgvictoria_test_setup();

   /*
    * Classification compares against the compiled-in baseline. Make sure no
    * earlier test left an external baseline directory configured, so every
    * override_version pins the compiled-in pgNN baseline deterministically.
    */
   unsetenv("PGVICTORIA_BASELINES_DIR");
}

MCTF_TEST_TEARDOWN(report)
{
   pgvictoria_test_teardown();
}

/* Write `contents` to `path`, overwriting. Returns 0 on success. */
static int
write_conf(const char* path, const char* contents)
{
   FILE* f = fopen(path, "w");
   if (f == NULL)
   {
      return 1;
   }
   fputs(contents, f);
   fclose(f);
   return 0;
}

/* Read the whole file at `path` into a malloc'd NUL-terminated buffer that the
 * caller frees, or NULL if the file could not be read. */
static char*
read_whole_file(const char* path)
{
   FILE* f = fopen(path, "r");
   if (f == NULL)
   {
      return NULL;
   }

   if (fseek(f, 0, SEEK_END) != 0)
   {
      fclose(f);
      return NULL;
   }
   long size = ftell(f);
   rewind(f);
   if (size < 0)
   {
      fclose(f);
      return NULL;
   }

   char* buf = malloc((size_t)size + 1);
   if (buf == NULL)
   {
      fclose(f);
      return NULL;
   }

   size_t got = fread(buf, 1, (size_t)size, f);
   buf[got] = '\0';
   fclose(f);
   return buf;
}

/* Return a pointer to the start of the text-report row whose first column is
 * exactly `key`, or NULL when no such row exists. Data rows begin at column 0
 * with the key left-justified, so a match is a line whose start equals `key`
 * followed by the column padding (space/tab) or the '|' separator; the padding
 * check keeps a key from matching a longer key that shares its prefix. */
static const char*
find_row(const char* report, const char* key)
{
   int klen = (int)strlen(key);
   const char* line = report;

   while (line != NULL && *line != '\0')
   {
      if (strncmp(line, key, klen) == 0 &&
          (line[klen] == ' ' || line[klen] == '\t' || line[klen] == '|'))
      {
         return line;
      }
      const char* nl = strchr(line, '\n');
      line = (nl != NULL) ? nl + 1 : NULL;
   }
   return NULL;
}

/* True if the text-report row for `key` exists and contains `needle` (searched
 * within that single row line only). */
static bool
row_contains(const char* report, const char* key, const char* needle)
{
   const char* row = find_row(report, key);
   if (row == NULL)
   {
      return false;
   }

   /* Bound the search to this single row line so a value in a later row cannot
    * satisfy the match, without copying into a fixed-size buffer. */
   const char* nl = strchr(row, '\n');
   int len = (nl != NULL) ? (int)(nl - row) : (int)strlen(row);
   int needle_len = (int)strlen(needle);

   for (int i = 0; i + needle_len <= len; i++)
   {
      if (strncmp(row + i, needle, needle_len) == 0)
      {
         return true;
      }
   }
   return false;
}

/* Write `conf_body` to a temp config file under TEST_BASE_DIR, run
 * pgvictoria_report_file() into a temp output file, read the generated report
 * into *out_report (malloc'd, caller frees; NULL if nothing was produced), and
 * return the report_file() return code. Both temp files are removed. `tag` makes
 * the temp filenames unique per test. */
static int
run_file_report(const char* tag, const char* conf_body,
                enum pgvictoria_output_format format,
                enum pgvictoria_report_type type,
                int override_version, char** out_report)
{
   char conf_path[MAX_PATH];
   char out_path[MAX_PATH];

   *out_report = NULL;

   pgvictoria_snprintf(conf_path, sizeof(conf_path), "%s/report_%s.conf", TEST_BASE_DIR, tag);
   pgvictoria_snprintf(out_path, sizeof(out_path), "%s/report_%s.out", TEST_BASE_DIR, tag);

   if (write_conf(conf_path, conf_body) != 0)
   {
      return -1;
   }

   int rc = pgvictoria_report_file(conf_path, format, type, out_path, override_version);

   *out_report = read_whole_file(out_path);

   unlink(conf_path);
   unlink(out_path);
   return rc;
}

/* Classification: a value that differs from the baseline is reported Modified. */
MCTF_TEST(test_report_modified_value)
{
   char* report = NULL;

   int rc = run_file_report("modified", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "Modified"), cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "200"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Classification: a value equal to the baseline is reported Default (full mode
 * keeps default rows). */
MCTF_TEST(test_report_default_value_full)
{
   char* report = NULL;

   int rc = run_file_report("default", "max_connections = 100\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "Default"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Classification: a key absent from the baseline is reported Custom. */
MCTF_TEST(test_report_custom_key)
{
   char* report = NULL;

   int rc = run_file_report("custom", "my_custom_setting_xyz = 1\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(row_contains(report, "my_custom_setting_xyz", "Custom"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Normalization: the engine compares via pgvictoria_check_guc, so a value that
 * differs only by case from the baseline is Default, not Modified. */
MCTF_TEST(test_report_normalizes_equivalent_value)
{
   char* report = NULL;

   int rc = run_file_report("normalize", "wal_level = REPLICA\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(row_contains(report, "wal_level", "Default"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Type flag: in changed mode a setting equal to the baseline default is dropped. */
MCTF_TEST(test_report_changed_omits_default)
{
   char* report = NULL;

   int rc = run_file_report("changed_default", "wal_level = replica\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_CHANGED, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT_PTR_NULL(find_row(report, "wal_level"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Type flag: in changed mode a modified setting is still listed. */
MCTF_TEST(test_report_changed_keeps_modified)
{
   char* report = NULL;

   int rc = run_file_report("changed_modified", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_CHANGED, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "Modified"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Version resolution: an explicit override_version wins over the file's own
 * version comment. */
MCTF_TEST(test_report_override_version_respected)
{
   char* report = NULL;

   int rc = run_file_report("override", "# PostgreSQL 15\nmax_connections = 100\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "Version  PostgreSQL 18") != NULL, cleanup);
   MCTF_ASSERT(strstr(report, "PostgreSQL 15") == NULL, cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Version resolution: with no override, the version is detected from a file
 * comment. */
MCTF_TEST(test_report_detect_version_from_file_comment)
{
   char* report = NULL;

   int rc = run_file_report("detect", "# PostgreSQL 16\nmax_connections = 100\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 0, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "Version  PostgreSQL 16") != NULL, cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Multiple PG versions: each supported baseline is selected via override_version
 * and applied to the comparison. max_connections defaults to 100 on every
 * supported version, so 200 is Modified against each. */
MCTF_TEST(test_report_baseline_pg14)
{
   char* report = NULL;

   int rc = run_file_report("pg14", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 14, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "Version  PostgreSQL 14") != NULL, cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "Modified"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

MCTF_TEST(test_report_baseline_pg15)
{
   char* report = NULL;

   int rc = run_file_report("pg15", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 15, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "Version  PostgreSQL 15") != NULL, cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "Modified"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

MCTF_TEST(test_report_baseline_pg16)
{
   char* report = NULL;

   int rc = run_file_report("pg16", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 16, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "Version  PostgreSQL 16") != NULL, cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "Modified"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

MCTF_TEST(test_report_baseline_pg17)
{
   char* report = NULL;

   int rc = run_file_report("pg17", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 17, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "Version  PostgreSQL 17") != NULL, cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "Modified"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

MCTF_TEST(test_report_baseline_pg18)
{
   char* report = NULL;

   int rc = run_file_report("pg18", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "Version  PostgreSQL 18") != NULL, cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "Modified"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

MCTF_TEST(test_report_baseline_pg19)
{
   char* report = NULL;

   int rc = run_file_report("pg19", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 19, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "Version  PostgreSQL 19") != NULL, cleanup);
   MCTF_ASSERT(row_contains(report, "max_connections", "Modified"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Format: text output is produced and carries the report title. */
MCTF_TEST(test_report_format_text)
{
   char* report = NULL;

   int rc = run_file_report("fmt_text", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "Configuration Difference Report") != NULL, cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Format: markdown output is produced and carries a markdown table. */
MCTF_TEST(test_report_format_markdown)
{
   char* report = NULL;

   int rc = run_file_report("fmt_md", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_MD, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "| Status |") != NULL, cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Format: HTML output is produced and carries an HTML table. */
MCTF_TEST(test_report_format_html)
{
   char* report = NULL;

   int rc = run_file_report("fmt_html", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_HTML, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "<table") != NULL, cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Scope header: file mode labels the audited source "File" and names the
 * configuration file it read. */
MCTF_TEST(test_report_scope_file_row)
{
   char* report = NULL;
   char expected[MAX_PATH + 16];

   int rc = run_file_report("scope_file", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);

   /* run_file_report() writes the config to this path; the header reports it
    * resolved, which for an already-absolute TEST_BASE_DIR is the same string. */
   pgvictoria_snprintf(expected, sizeof(expected), "File     %s/report_scope_file.conf", TEST_BASE_DIR);
   MCTF_ASSERT(strstr(report, expected) != NULL, cleanup);
   MCTF_ASSERT(strstr(report, "Report Scope:") == NULL, cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Scope header: the system row is emitted with its label column. */
MCTF_TEST(test_report_scope_system_row)
{
   char* report = NULL;

   int rc = run_file_report("scope_system", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "\nSystem   ") != NULL, cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Scope header: markdown renders the scope block as a label/value table. */
MCTF_TEST(test_report_scope_markdown_table)
{
   char* report = NULL;

   int rc = run_file_report("scope_md", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_MD, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "| Item | Value |") != NULL, cleanup);
   MCTF_ASSERT(strstr(report, "| **File** |") != NULL, cleanup);
   MCTF_ASSERT(strstr(report, "| **Version** | PostgreSQL 18 |") != NULL, cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Scope header: HTML renders the scope block as a metadata table. */
MCTF_TEST(test_report_scope_html_table)
{
   char* report = NULL;

   int rc = run_file_report("scope_html", "max_connections = 200\n",
                            PGVICTORIA_OUTPUT_HTML, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(strstr(report, "<table class=\"metadata\">") != NULL, cleanup);
   MCTF_ASSERT(strstr(report, "<td>File</td>") != NULL, cleanup);
   MCTF_ASSERT(strstr(report, "<td>PostgreSQL 18</td>") != NULL, cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Parser: a single-quoted value is unquoted before comparison. */
MCTF_TEST(test_report_quoted_value)
{
   char* report = NULL;

   int rc = run_file_report("quoted", "application_name = 'myapp'\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT(row_contains(report, "application_name", "myapp"), cleanup);
   MCTF_ASSERT(!row_contains(report, "application_name", "'"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Parser: commented-out lines are ignored and produce no row. */
MCTF_TEST(test_report_comment_line_ignored)
{
   char* report = NULL;

   int rc = run_file_report("comment", "# max_connections = 999\nwal_level = replica\n",
                            PGVICTORIA_OUTPUT_TEXT, PGVICTORIA_REPORT_FULL, 18, &report);
   MCTF_ASSERT_INT_EQ(rc, 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(report, cleanup);
   MCTF_ASSERT_PTR_NULL(find_row(report, "max_connections"), cleanup);

cleanup:
   free(report);
   MCTF_FINISH();
}

/* Validation: a nonexistent input file is rejected. */
MCTF_TEST(test_report_nonexistent_file)
{
   char conf_path[MAX_PATH];
   char out_path[MAX_PATH];

   pgvictoria_snprintf(conf_path, sizeof(conf_path), "%s/report_does_not_exist.conf", TEST_BASE_DIR);
   pgvictoria_snprintf(out_path, sizeof(out_path), "%s/report_missing.out", TEST_BASE_DIR);
   unlink(conf_path);

   int rc = pgvictoria_report_file(conf_path, PGVICTORIA_OUTPUT_TEXT,
                                   PGVICTORIA_REPORT_FULL, out_path, 18);
   MCTF_ASSERT_INT_EQ(rc, 1, cleanup);

cleanup:
   unlink(out_path);
   MCTF_FINISH();
}

/* Validation: a directory passed as the input file is rejected. */
MCTF_TEST(test_report_directory_input)
{
   char out_path[MAX_PATH];

   pgvictoria_snprintf(out_path, sizeof(out_path), "%s/report_dir.out", TEST_BASE_DIR);

   int rc = pgvictoria_report_file(TEST_BASE_DIR, PGVICTORIA_OUTPUT_TEXT,
                                   PGVICTORIA_REPORT_FULL, out_path, 18);
   MCTF_ASSERT_INT_EQ(rc, 1, cleanup);

cleanup:
   unlink(out_path);
   MCTF_FINISH();
}

/* Validation: an empty output path is rejected. */
MCTF_TEST(test_report_empty_output_path)
{
   char conf_path[MAX_PATH];
   char empty_out[1] = "";

   pgvictoria_snprintf(conf_path, sizeof(conf_path), "%s/report_empty_out.conf", TEST_BASE_DIR);
   MCTF_ASSERT_INT_EQ(write_conf(conf_path, "max_connections = 200\n"), 0, cleanup);

   int rc = pgvictoria_report_file(conf_path, PGVICTORIA_OUTPUT_TEXT,
                                   PGVICTORIA_REPORT_FULL, empty_out, 18);
   MCTF_ASSERT_INT_EQ(rc, 1, cleanup);

cleanup:
   unlink(conf_path);
   MCTF_FINISH();
}
