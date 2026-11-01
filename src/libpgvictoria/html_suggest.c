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

#include <html_suggest.h>

#include <inttypes.h>
#include <stdio.h>

int
pgvictoria_generate_html_suggest(const char* output_html_path, struct pgvictoria_suggest_item* parameters)
{
   FILE* f = fopen(output_html_path, "w");

   if (f == NULL)
   {
      perror("Could not open output file");
      return 1;
   }

   fprintf(f, "<!DOCTYPE html>\n");
   fprintf(f, "<html>\n");
   fprintf(f, "<head>\n");
   fprintf(f, " <title>Suggested PostgreSQL Configurations Parameters</title>\n");
   fprintf(f, "</head>\n");

   fprintf(f, "<body>\n");
   fprintf(f, " <h1>Suggested PostgreSQL Configurations Parameters</h1>\n");
   fprintf(f, " <pre>shared_buffers = %" PRIu64 "%s</pre>\n", parameters->shared_buffers_val, parameters->shared_buffers_unit);
   fprintf(f, " <pre>max_connections = %d</pre>\n", parameters->max_connections);
   fprintf(f, " <pre>effective_cache_size = %" PRIu64 "%s</pre>\n", parameters->effective_cache_size_val, parameters->effective_cache_size_unit);
   fprintf(f, " <pre>maintenance_work_mem = %" PRIu64 "%s</pre>\n", parameters->maintenance_work_mem_val, parameters->maintenance_work_mem_unit);
   fprintf(f, " <pre>min_wal_size = %" PRIu64 "%s</pre>\n", parameters->min_wal_size, parameters->min_wal_size == 100 ? "MB" : "GB");
   fprintf(f, " <pre>max_wal_size = %" PRIu64 "GB</pre>\n", parameters->max_wal_size);
   fprintf(f, " <pre>wal_buffers = %" PRIu64 "%s</pre>\n", parameters->wal_buffers_val, parameters->wal_buffers_unit);
   fprintf(f, " <pre>default_statistics_target = %d</pre>\n", parameters->default_statistics_target);
   fprintf(f, " <pre>huge_pages = %s</pre>\n", parameters->huge_pages == PGVICTORIA_HUGE_PAGES_TRY ? "try" : "off");
   if (parameters->parallel_settings.max_worker_processes > 0)
   {
      fprintf(f, " <pre>max_worker_processes = %d</pre>\n", parameters->parallel_settings.max_worker_processes);
      fprintf(f, " <pre>max_parallel_workers_per_gather = %d</pre>\n", parameters->parallel_settings.max_parallel_workers_per_gather);

      if (parameters->parallel_settings.max_parallel_workers > 0)
      {
         fprintf(f, " <pre>max_parallel_workers = %d</pre>\n", parameters->parallel_settings.max_parallel_workers);
      }
      if (parameters->parallel_settings.max_parallel_maintenance_workers)
      {
         fprintf(f, " <pre>max_parallel_maintenance_workers = %d</pre>\n", parameters->parallel_settings.max_parallel_maintenance_workers);
      }
   }
   if (parameters->wal_settings.wal_level != NULL)
   {
      fprintf(f, " <pre>wal_level = %s</pre>\n", parameters->wal_settings.wal_level);
      fprintf(f, " <pre>max_wal_senders = %d/<pre>\n", parameters->wal_settings.max_wal_senders);
   }
   if (parameters->jit != NULL)
   {
      fprintf(f, " <pre>jit = %s</pre>\n", parameters->jit);
   }
   if (parameters->wal_compression)
   {
      fprintf(f, " <pre>wal_compression = %s</pre>\n", parameters->wal_compression);
   }
   if (parameters->autovacuum_max_workers != 3)
   {
      fprintf(f, " <pre>autovacuum_max_workers = %d</pre>\n", parameters->autovacuum_max_workers);
   }
   if (parameters->autovacuum_work_mem_val > 0)
   {
      fprintf(f, " <pre>autovacuum_work_mem = %" PRIu64 "%s</pre>\n", parameters->autovacuum_work_mem_val, parameters->autovacuum_work_mem_unit);
   }
   if (parameters->io_method != NULL)
   {
      fprintf(f, " <pre>io_method = %s</pre>\n", parameters->io_method);
   }
   if (parameters->io_workers != 0)
   {
      fprintf(f, " <pre>io_workers = %d</pre>\n", parameters->io_workers);
   }
   fprintf(f, " <pre>work_mem = %" PRIu64 "%s</pre>\n", parameters->work_mem_val, parameters->work_mem_unit);
   fprintf(f, " <pre>random_page_cost = %.1f</pre>\n", parameters->random_page_cost);
   if (parameters->effective_io_concurrency != -1)
   {
      fprintf(f, " <pre>effective_io_concurrency = %d </pre>\n", parameters->effective_io_concurrency);
   }
   fprintf(f, "</body>\n");

   fprintf(f, "</html>\n");

   fclose(f);
   return 0;
}