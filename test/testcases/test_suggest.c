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

#include <mctf.h>
#include <tscommon.h>
#include <suggest.h>
#include <string.h>

MCTF_TEST_SETUP(suggest)
{
   pgvictoria_test_setup();
}

MCTF_TEST_TEARDOWN(suggest)
{
   pgvictoria_test_teardown();
}

MCTF_TEST(test_suggest_detect_hardware)
{
   struct pgvictoria_hw_info hw;
   int status;

   status = pgvictoria_detect_hardware(&hw);
   MCTF_ASSERT_INT_EQ(status, 0, cleanup);

   MCTF_ASSERT(hw.cpu_count >= 1, cleanup);
   MCTF_ASSERT(hw.total_ram > 0, cleanup);
   MCTF_ASSERT(strlen(hw.os_name) > 0, cleanup);

cleanup:
   MCTF_FINISH();
}

MCTF_TEST(test_suggest_calculate)
{
   struct pgvictoria_hw_info hw;
   hw.cpu_count = 8;
   hw.total_ram = 16ULL * 1024ULL * 1024ULL * 1024ULL; // 16GB
   hw.disk_is_ssd = true;
   snprintf(hw.os_name, sizeof(hw.os_name), "TestOS");

   char* output_file = "/tmp/pgvictoria-test/suggest.conf";

   int status = pgvictoria_suggest(&hw, PGVICTORIA_WORKLOAD_OLTP, 16, 200, output_file, 0);
   MCTF_ASSERT_INT_EQ(status, 0, cleanup);

   FILE* f = fopen(output_file, "r");
   MCTF_ASSERT(f != NULL, cleanup);

   char line[256];
   bool found_shared_buffers = false;
   bool found_max_connections = false;
   while (fgets(line, sizeof(line), f))
   {
      if (strstr(line, "shared_buffers = 4096MB"))
         found_shared_buffers = true;
      if (strstr(line, "max_connections = 200"))
         found_max_connections = true;
   }
   fclose(f);
   remove(output_file);

   MCTF_ASSERT(found_shared_buffers, cleanup);
   MCTF_ASSERT(found_max_connections, cleanup);

cleanup:
   MCTF_FINISH();
}
