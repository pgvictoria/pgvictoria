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

#include <suggest.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <html_suggest.h>
#include <markdown.h>

#ifdef __linux__
#include <sys/sysinfo.h>
#endif

int
auto_detect_system_parameter(uint64_t *total_ram)
{
/*Total ram*/
#ifdef __linux__
   struct sysinfo info;
   if (sysinfo(&info) != 0)
   {
      return 1;
   }
   *total_ram = (uint64_t)info.totalram * info.mem_unit;

#else
   return 1;
#endif

   return 0;
}

uint64_t
suggested_shared_buffers(uint64_t total_ram, enum pgvictoria_db_workload_type type)
{
   uint64_t shared_buffers;
   if (type == PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP)
   {
      shared_buffers = total_ram / 16;
   }
   else
   {
      shared_buffers = total_ram / 4;
   }

   return shared_buffers;
}

int
pgvictoria_suggest_mode(enum pgvictoria_db_workload_type type, char *output_file, enum pgvictoria_output_format format)
{
   uint64_t total_ram;

   /* Detect System Parameters */
   if (auto_detect_system_parameter(&total_ram) != 0)
   {
      return 1;
   }

   uint64_t mb = 1024ULL * 1024ULL;
   uint64_t gb = 1024ULL * mb;

   uint64_t shared_buffers = suggested_shared_buffers(total_ram, type);
   uint64_t shared_buffers_val;
   const char *shared_buffers_unit;

   if (shared_buffers % gb == 0)
   {
      shared_buffers_val = shared_buffers / gb;
      shared_buffers_unit = "GB";
   }

   else
   {
      shared_buffers_val = shared_buffers / mb;
      shared_buffers_unit = "MB";
   }

   /* No Output file: print only directly to the CLI */
   if (output_file == NULL)
   {
      printf("Suggested PostgreSQL Configuration:\n");
      printf("shared_buffers = %" PRIu64 "%s\n", shared_buffers_val, shared_buffers_unit);
      return 0;
   }

   /** 
     * If Output file specified
     * First print the suggestions for conformation then write to the specified file
    */
   printf("Suggested PostgreSQL Configuration:\n");
   printf("shared_buffers = %" PRIu64 "%s\n", shared_buffers_val, shared_buffers_unit);

   printf("\nWrite these suggestions to '%s'? [y/N]: ", output_file);
   char answer[8];

   if (fgets(answer, sizeof(answer), stdin) == NULL)
   {
      return 1;
   }

   if (answer[0] != 'y' && answer[0] != 'Y')
   {
      printf("Suggestions were not written to the file.\n");
      return 0;
   }

   int ret = 0;
   if (format == PGVICTORIA_OUTPUT_MD)
   {
      ret = pgvictoria_generate_markdown_suggest(output_file, shared_buffers_val, shared_buffers_unit);
   }

   else if (format == PGVICTORIA_OUTPUT_HTML)
   {
      ret = pgvictoria_generate_html_suggest(output_file, shared_buffers_val, shared_buffers_unit);
   }

   else
   {
      FILE *f = fopen(output_file, "w");

      if (f == NULL)
      {
         perror("Could not open output file");
         return 1;
      }
      fprintf(f, "shared_buffers = %" PRIu64 "%s\n", shared_buffers_val, shared_buffers_unit);
      fclose(f);
   }

   if (ret != 0)
   {
      return 1;
   }

   printf("Suggestions written to '%s'.\n", output_file);

   return 0;
}