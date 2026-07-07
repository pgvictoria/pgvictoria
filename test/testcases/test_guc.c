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
#include <guc.h>
#include <value.h>
#include <stdbool.h>

MCTF_TEST_SETUP(guc)
{
   pgvictoria_test_setup();
}

MCTF_TEST_TEARDOWN(guc)
{
   pgvictoria_test_teardown();
}

/* Locale: en_US.UTF-8 and en_US.utf8 are the same locale (case + hyphen). */
MCTF_TEST(test_guc_locale_equivalent)
{
   bool modified = true;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("lc_messages", ValueString, "en_US.utf8", "en_US.UTF-8", &modified), 0, cleanup);
   MCTF_ASSERT(!modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* Locale: genuinely different locales are still reported as modified. */
MCTF_TEST(test_guc_locale_different)
{
   bool modified = false;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("lc_monetary", ValueString, "en_US.utf8", "de_DE.UTF-8", &modified), 0, cleanup);
   MCTF_ASSERT(modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* String: a trailing space does not count as a change. */
MCTF_TEST(test_guc_string_trailing_whitespace)
{
   bool modified = true;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("log_line_prefix", ValueString, "%m [%p]", "%m [%p] ", &modified), 0, cleanup);
   MCTF_ASSERT(!modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* String: leading and trailing whitespace does not count as a change. */
MCTF_TEST(test_guc_string_leading_and_trailing_whitespace)
{
   bool modified = true;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("search_path", ValueString, "\"$user\", public", "  \"$user\", public  ", &modified), 0, cleanup);
   MCTF_ASSERT(!modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* String: comparison is case-insensitive. */
MCTF_TEST(test_guc_string_case_insensitive)
{
   bool modified = true;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("bytea_output", ValueString, "hex", "HEX", &modified), 0, cleanup);
   MCTF_ASSERT(!modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* String: internal whitespace is significant, so a path that differs only by an
 * inner space is reported as modified rather than silently collapsed. */
MCTF_TEST(test_guc_string_internal_whitespace_significant)
{
   bool modified = false;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("data_directory", ValueString, "/var/lib/my data", "/var/lib/mydata", &modified), 0, cleanup);
   MCTF_ASSERT(modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* String: hyphens are only dropped for locale settings; on the generic path they
 * are kept, so two distinct names are not collapsed into one. */
MCTF_TEST(test_guc_string_hyphen_preserved)
{
   bool modified = false;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("cluster_name", ValueString, "my-cluster", "mycluster", &modified), 0, cleanup);
   MCTF_ASSERT(modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* String: a real difference is reported as modified. */
MCTF_TEST(test_guc_string_different)
{
   bool modified = false;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("listen_addresses", ValueString, "*", "localhost", &modified), 0, cleanup);
   MCTF_ASSERT(modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* String: an empty value differs from a non-empty one. */
MCTF_TEST(test_guc_string_empty_differs_from_value)
{
   bool modified = false;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("application_name", ValueString, "psql", "", &modified), 0, cleanup);
   MCTF_ASSERT(modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* String: a whitespace-only value trims down to empty, matching an empty
 * baseline. */
MCTF_TEST(test_guc_string_whitespace_only_is_empty)
{
   bool modified = true;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("application_name", ValueString, "", "   ", &modified), 0, cleanup);
   MCTF_ASSERT(!modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* Numeric: equal values are not modified. */
MCTF_TEST(test_guc_numeric_equal)
{
   bool modified = true;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("autovacuum_work_mem", ValueInt64, "-1", "-1", &modified), 0, cleanup);
   MCTF_ASSERT(!modified, cleanup);

cleanup:
   MCTF_FINISH();
}

/* Numeric: compared exactly, so a hyphen is never stripped and "-1" stays
 * distinct from "1". */
MCTF_TEST(test_guc_numeric_different)
{
   bool modified = false;

   MCTF_ASSERT_INT_EQ(pgvictoria_check_guc("autovacuum_work_mem", ValueInt64, "-1", "1", &modified), 0, cleanup);
   MCTF_ASSERT(modified, cleanup);

cleanup:
   MCTF_FINISH();
}
