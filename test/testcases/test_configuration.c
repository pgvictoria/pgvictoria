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

#include <pgvictoria.h>
#include <configuration.h>
#include <mctf.h>
#include <tscommon.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

MCTF_TEST(test_configuration_indented_lines)
{
   char* path = "test_configuration_indented.conf";
   struct main_configuration* config = NULL;
   FILE* f = NULL;

   config = (struct main_configuration*)calloc(1, sizeof(struct main_configuration));
   MCTF_ASSERT_PTR_NONNULL(config, cleanup, "could not allocate the configuration");
   pgvictoria_init_main_configuration(config);

   f = fopen(path, "w");
   MCTF_ASSERT_PTR_NONNULL(f, cleanup, "could not create %s", path);
   fprintf(f, "[pgvictoria]\n");
   fprintf(f, "            host = localhost\n");
   fprintf(f, "   unix_socket_dir = /tmp/   # comment\n");
   fclose(f);
   f = NULL;

   MCTF_ASSERT_INT_EQ(pgvictoria_read_main_configuration(config, path), 0, cleanup, "reading the configuration failed");
   MCTF_ASSERT_STR_EQ(config->host, "localhost", cleanup, "host mismatch");
   MCTF_ASSERT_STR_EQ(config->unix_socket_dir, "/tmp/", cleanup, "unix_socket_dir mismatch");

cleanup:
   if (f != NULL)
   {
      fclose(f);
   }
   unlink(path);
   free(config);
   MCTF_FINISH();
}

MCTF_TEST(test_configuration_large_file)
{
   char* path = "test_configuration_large.conf";
   FILE* f = NULL;
   char line_buf[1024];
   int line_count = 0;

   /* Create a configuration file with 8500 lines (> old MAX_LINES of 8192) */
   f = fopen(path, "w");
   MCTF_ASSERT_PTR_NONNULL(f, cleanup, "could not create %s", path);
   fprintf(f, "[general]\n");
   for (int i = 0; i < 8300; i++)
   {
      fprintf(f, "# comment line %d\n", i);
   }
   fprintf(f, "key = value\n");
   fclose(f);
   f = NULL;

   /* Set a new key in the general section */
   MCTF_ASSERT_INT_EQ(pgvictoria_config_set(path, "general", "new_key", "new_value", NULL), 0, cleanup, "config_set failed on large file");

   /* Verify that both original key and new key exist and are correct */
   MCTF_ASSERT_INT_EQ(pgvictoria_config_get(path, "general", "key"), 0, cleanup, "original key missing after set");
   MCTF_ASSERT_INT_EQ(pgvictoria_config_get(path, "general", "new_key"), 0, cleanup, "new_key missing after set");

   /* Verify line count: 1 header + 8300 comments + 1 original key + 1 new key = 8303 lines */
   f = fopen(path, "r");
   MCTF_ASSERT_PTR_NONNULL(f, cleanup, "could not open %s for line count check", path);
   line_count = 0;
   while (fgets(line_buf, sizeof(line_buf), f) != NULL)
   {
      line_count++;
   }
   fclose(f);
   f = NULL;
   MCTF_ASSERT_INT_EQ(line_count, 8303, cleanup, "file was truncated after config_set");

   /* Delete the new key from the general section */
   MCTF_ASSERT_INT_EQ(pgvictoria_config_del(path, "general", "new_key"), 0, cleanup, "config_del failed on large file");

   /* Verify original key is still intact and new_key is gone */
   MCTF_ASSERT_INT_EQ(pgvictoria_config_get(path, "general", "key"), 0, cleanup, "original key missing after del");
   MCTF_ASSERT_INT_NE(pgvictoria_config_get(path, "general", "new_key"), 0, cleanup, "deleted key should not be found");

   /* Verify line count after deletion: 8302 lines */
   f = fopen(path, "r");
   MCTF_ASSERT_PTR_NONNULL(f, cleanup, "could not open %s for line count check", path);
   line_count = 0;
   while (fgets(line_buf, sizeof(line_buf), f) != NULL)
   {
      line_count++;
   }
   fclose(f);
   f = NULL;
   MCTF_ASSERT_INT_EQ(line_count, 8302, cleanup, "file was truncated after config_del");

cleanup:
   if (f != NULL)
   {
      fclose(f);
   }
   unlink(path);
   MCTF_FINISH();
}
