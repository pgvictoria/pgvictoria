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

/* pgvictoria */
#include <deque.h>
#include <markdown.h>
#include <utils.h>

/* system */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
pgvictoria_generate_markdown_report(const char* output_md_path, int version, struct deque* items, const char* scope_label, const char* scope_value)
{
   pgvictoria_mkdir_parent(output_md_path);

   FILE* f = fopen(output_md_path, "w");
   if (!f)
   {
      return 1;
   }

   fprintf(f, "# PostgreSQL %d Configuration Difference Report\n\n", version);

   fprintf(f, "| Item | Value |\n");
   fprintf(f, "| :--- | :--- |\n");

   if (scope_label && scope_value)
   {
      fprintf(f, "| **%s** | `%s` |\n", scope_label, scope_value);
   }
   fprintf(f, "| **Version** | PostgreSQL %d |\n", version);

   char* os_name = NULL;
   int k_major = 0, k_minor = 0, k_patch = 0;
   if (pgvictoria_os_kernel_version(&os_name, &k_major, &k_minor, &k_patch) == 0)
   {
      fprintf(f, "| **System** | %s %d.%d.%d |\n", os_name, k_major, k_minor, k_patch);
      free(os_name);
   }
   fprintf(f, "\n");

   fprintf(f, "| Configuration Key | Baseline Default | Current Value | Status |\n");
   fprintf(f, "| :--- | :--- | :--- | :--- |\n");

   struct deque_iterator* it = NULL;
   pgvictoria_deque_iterator_create(items, &it);
   while (pgvictoria_deque_iterator_next(it))
   {
      struct pgvictoria_diff_item* curr = (struct pgvictoria_diff_item*)it->value->data;

      /* Wrap values in backticks for clean markdown coding format */
      fprintf(f, "| `%s` | `%s` | `%s` | **%s** |\n",
              curr->key,
              curr->baseline_val,
              curr->current_val,
              curr->status);
   }
   pgvictoria_deque_iterator_destroy(it);

   fclose(f);
   printf("Report successfully generated to %s\n", output_md_path);
   return 0;
}

int
pgvictoria_generate_markdown_suggest(const char* output_md_path, struct pgvictoria_suggest_item* parameters)
{
   FILE* f = fopen(output_md_path, "w");

   if (f == NULL)
   {
      perror("Could not open output file");
      return 1;
   }

   fprintf(f, "# Suggested PostgreSQL Configuration Parameters\n");
   fprintf(f, "```conf\n");

   fprintf(f, "shared_buffers = %" PRIu64 "%s\n", parameters->shared_buffers_val, parameters->shared_buffers_unit);
   fprintf(f, "max_connections = %d\n", parameters->max_connections);
   fprintf(f, "effective_cache_size = %" PRIu64 "%s\n", parameters->effective_cache_size_val, parameters->effective_cache_size_unit);
   fprintf(f, "maintenance_work_mem = %" PRIu64 "%s\n", parameters->maintenance_work_mem_val, parameters->maintenance_work_mem_unit);
   fprintf(f, "min_wal_size = %" PRIu64 "%s\n", parameters->min_wal_size, parameters->min_wal_size == 100 ? "MB" : "GB");
   fprintf(f, "max_wal_size = %" PRIu64 "GB\n", parameters->max_wal_size);
   fprintf(f, "wal_buffers = %" PRIu64 "%s\n", parameters->wal_buffers_val, parameters->wal_buffers_unit);
   fprintf(f, "default_statistics_target = %d\n", parameters->default_statistics_target);
   fprintf(f, "huge_pages = %s\n", parameters->huge_pages == PGVICTORIA_HUGE_PAGES_TRY ? "try" : "off");
   if (parameters->parallel_settings.max_worker_processes > 0)
   {
      fprintf(f, "max_worker_processes = %d\n", parameters->parallel_settings.max_worker_processes);
      fprintf(f, "max_parallel_workers_per_gather = %d\n", parameters->parallel_settings.max_parallel_workers_per_gather);

      if (parameters->parallel_settings.max_parallel_workers > 0)
      {
         fprintf(f, "max_parallel_workers = %d\n", parameters->parallel_settings.max_parallel_workers);
      }
      if (parameters->parallel_settings.max_parallel_maintenance_workers)
      {
         fprintf(f, "max_parallel_maintenance_workers = %d\n", parameters->parallel_settings.max_parallel_maintenance_workers);
      }
   }
   if (parameters->wal_settings.wal_level != NULL)
   {
      fprintf(f, "wal_level = %s\n", parameters->wal_settings.wal_level);
      fprintf(f, "max_wal_senders = %d\n", parameters->wal_settings.max_wal_senders);
   }
   if (parameters->jit != NULL)
   {
      fprintf(f, "jit = %s\n", parameters->jit);
   }
   if (parameters->wal_compression)
   {
      fprintf(f, "wal_compression = %s\n", parameters->wal_compression);
   }
   if (parameters->autovacuum_max_workers != 3)
   {
      fprintf(f, "autovacuum_max_workers = %d\n", parameters->autovacuum_max_workers);
   }
   if (parameters->autovacuum_work_mem_val > 0)
   {
      fprintf(f, "autovacuum_work_mem = %" PRIu64 "%s\n", parameters->autovacuum_work_mem_val, parameters->autovacuum_work_mem_unit);
   }
   if (parameters->io_method != NULL)
   {
      fprintf(f, "io_method = %s\n", parameters->io_method);
   }
   if (parameters->io_workers != 0)
   {
      fprintf(f, "io_workers = %d\n", parameters->io_workers);
   }
   fprintf(f, "work_mem = %" PRIu64 "%s\n", parameters->work_mem_val, parameters->work_mem_unit);
   fprintf(f, "random_page_cost = %.1f\n", parameters->random_page_cost);
   if (parameters->effective_io_concurrency != -1)
   {
      fprintf(f, "effective_io_concurrency = %d\n", parameters->effective_io_concurrency);
   }
   fprintf(f, "```\n");

   fclose(f);

   return 0;
}
