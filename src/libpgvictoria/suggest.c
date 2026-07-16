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
#include <pgvictoria.h>
#include <logging.h>
#include <report.h>
#include <suggest.h>
#include <utils.h>

/* system */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(HAVE_DARWIN) || defined(HAVE_OSX) || defined(__APPLE__)
#include <sys/types.h>
#endif

int
pgvictoria_detect_hardware(struct pgvictoria_hw_info* hw)
{
   char* os = NULL;
   int major, minor, patch;

   if (hw == NULL)
   {
      return 1;
   }

   memset(hw, 0, sizeof(struct pgvictoria_hw_info));

   /* Detect OS */
   if (pgvictoria_os_kernel_version(&os, &major, &minor, &patch) == 0)
   {
      if (os != NULL)
      {
         snprintf(hw->os_name, sizeof(hw->os_name), "%s", os);
         free(os);
      }
   }
   else
   {
      snprintf(hw->os_name, sizeof(hw->os_name), "Unknown");
   }

   /* Detect CPU Count */
#if defined(_SC_NPROCESSORS_ONLN)
   hw->cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
#else
   hw->cpu_count = 1;
#endif

   if (hw->cpu_count < 1)
   {
      hw->cpu_count = 1;
   }

   /* Detect Total RAM */
   hw->total_ram = 0;
#if defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
   long pages = sysconf(_SC_PHYS_PAGES);
   long page_size = sysconf(_SC_PAGESIZE);
   if (pages > 0 && page_size > 0)
   {
      hw->total_ram = (uint64_t)pages * (uint64_t)page_size;
   }
#endif

   /* Fallback if detection failed: assume 1GB */
   if (hw->total_ram == 0)
   {
      hw->total_ram = 1024ULL * 1024ULL * 1024ULL;
   }

   /* Detect Disk Type (Assume SSD by default) */
   hw->disk_is_ssd = true;

#if defined(HAVE_LINUX)
   /* On Linux, check if /sys/block/sda/queue/rotational exists and is 1 */
   FILE* f = fopen("/sys/block/sda/queue/rotational", "r");
   if (f != NULL)
   {
      int rotational = 0;
      if (fscanf(f, "%d", &rotational) == 1)
      {
         if (rotational == 1)
         {
            hw->disk_is_ssd = false;
         }
      }
      fclose(f);
   }
#endif

   return 0;
}

int
pgvictoria_suggest(
   struct pgvictoria_hw_info* hw,
   enum pgvictoria_workload workload,
   int pg_version,
   int max_connections,
   char* output_file,
   int output_format)
{
   if (hw == NULL || output_file == NULL)
   {
      return 1;
   }

   FILE* f = fopen(output_file, "w");
   if (!f)
   {
      return 1;
   }

   uint64_t mb = 1024ULL * 1024ULL;
   uint64_t gb = 1024ULL * mb;

   /* max_connections */
   int connections = max_connections > 0 ? max_connections : 100;

   /* shared_buffers */
   uint64_t shared_buffers_bytes;
   if (workload == PGVICTORIA_WORKLOAD_DESKTOP)
   {
      shared_buffers_bytes = hw->total_ram / 16;
   }
   else
   {
      shared_buffers_bytes = hw->total_ram / 4;
   }
   uint64_t shared_buffers_mb = shared_buffers_bytes / mb;

   /* effective_cache_size */
   uint64_t effective_cache_bytes;
   if (workload == PGVICTORIA_WORKLOAD_DESKTOP)
   {
      effective_cache_bytes = hw->total_ram / 4;
   }
   else
   {
      effective_cache_bytes = (hw->total_ram / 4) * 3;
   }
   uint64_t effective_cache_mb = effective_cache_bytes / mb;

   /* maintenance_work_mem */
   uint64_t maintenance_work_mem_bytes;
   if (workload == PGVICTORIA_WORKLOAD_OLAP)
   {
      maintenance_work_mem_bytes = hw->total_ram / 8;
      if (maintenance_work_mem_bytes > 2ULL * gb)
      {
         maintenance_work_mem_bytes = 2ULL * gb;
      }
   }
   else if (workload == PGVICTORIA_WORKLOAD_DESKTOP)
   {
      maintenance_work_mem_bytes = hw->total_ram / 16;
      if (maintenance_work_mem_bytes > 2ULL * gb)
      {
         maintenance_work_mem_bytes = 2ULL * gb;
      }
   }
   else
   {
      maintenance_work_mem_bytes = hw->total_ram / 16;
      if (maintenance_work_mem_bytes > 2ULL * gb)
      {
         maintenance_work_mem_bytes = 2ULL * gb;
      }
   }
   uint64_t maintenance_work_mem_mb = maintenance_work_mem_bytes / mb;

   /* checkpoint_completion_target */
   double checkpoint_target = 0.9;

   /* wal_buffers: 3% of shared_buffers, capped at 64MB, minimum 1MB */
   uint64_t wal_buffers_bytes = shared_buffers_bytes * 3 / 100;
   if (wal_buffers_bytes > 64ULL * mb)
   {
      wal_buffers_bytes = 64ULL * mb;
   }
   uint64_t wal_buffers_mb = wal_buffers_bytes / mb;
   if (wal_buffers_mb < 1)
   {
      wal_buffers_mb = 1;
   }

   /* default_statistics_target */
   int default_stats = (workload == PGVICTORIA_WORKLOAD_OLAP) ? 500 : 100;

   /* random_page_cost */
   double random_page_cost = hw->disk_is_ssd ? 1.1 : 4.0;

   /* effective_io_concurrency */
   int io_concurrency = hw->disk_is_ssd ? 200 : 2;

   /* work_mem */
   uint64_t work_mem_bytes;
   if (workload == PGVICTORIA_WORKLOAD_OLAP)
   {
      work_mem_bytes = (hw->total_ram - shared_buffers_bytes) / ((uint64_t)connections * 3ULL);
   }
   else if (workload == PGVICTORIA_WORKLOAD_MIXED)
   {
      work_mem_bytes = (hw->total_ram - shared_buffers_bytes) / ((uint64_t)connections * 3ULL);
   }
   else if (workload == PGVICTORIA_WORKLOAD_DESKTOP)
   {
      work_mem_bytes = (hw->total_ram - shared_buffers_bytes) / ((uint64_t)connections * 3ULL);
   }
   else
   {
      work_mem_bytes = (hw->total_ram - shared_buffers_bytes) / ((uint64_t)connections * 3ULL);
   }
   uint64_t work_mem_mb = work_mem_bytes / mb;
   if (work_mem_mb < 4)
   {
      work_mem_mb = 4;
   }

   /* min_wal_size and max_wal_size */
   uint64_t min_wal_size_mb;
   uint64_t max_wal_size_mb;
   if (workload == PGVICTORIA_WORKLOAD_OLAP)
   {
      min_wal_size_mb = 2048;
      max_wal_size_mb = 8192;
   }
   else if (workload == PGVICTORIA_WORKLOAD_DESKTOP)
   {
      min_wal_size_mb = 512;
      max_wal_size_mb = 2048;
   }
   else
   {
      min_wal_size_mb = 1024;
      max_wal_size_mb = 4096;
   }

   /* Workers */
   int workers = hw->cpu_count;
   int gather = hw->cpu_count / 2;
   int maintenance_workers = hw->cpu_count / 2;

   if (workload == PGVICTORIA_WORKLOAD_DESKTOP)
   {
      if (gather > 2)
      {
         gather = 2;
      }
      if (maintenance_workers > 2)
      {
         maintenance_workers = 2;
      }
   }
   else
   {
      if (gather > 4)
      {
         gather = 4;
      }
      if (maintenance_workers > 4)
      {
         maintenance_workers = 4;
      }
   }
   if (gather < 2)
   {
      gather = 2;
   }
   if (maintenance_workers < 2)
   {
      maintenance_workers = 2;
   }

   /* Write config */
   if (output_format == PGVICTORIA_OUTPUT_MD)
   {
      fprintf(f, "```ini\n");
   }
   else if (output_format == PGVICTORIA_OUTPUT_HTML)
   {
      fprintf(f, "<pre><code>\n");
   }

   const char* workload_str = "OLTP";
   if (workload == PGVICTORIA_WORKLOAD_OLAP)
   {
      workload_str = "OLAP";
   }
   else if (workload == PGVICTORIA_WORKLOAD_MIXED)
   {
      workload_str = "Mixed";
   }
   else if (workload == PGVICTORIA_WORKLOAD_DESKTOP)
   {
      workload_str = "Desktop";
   }

   fprintf(f, "# pgvictoria suggested postgresql.conf\n");
   fprintf(f, "# Hardware: %d CPUs, %llu MB RAM, %s\n", hw->cpu_count, (unsigned long long)(hw->total_ram / mb), hw->disk_is_ssd ? "SSD" : "HDD");
   fprintf(f, "# Workload: %s\n", workload_str);
   fprintf(f, "# PostgreSQL Version: %d\n\n", pg_version);

   fprintf(f, "max_connections = %d\n", connections);
   fprintf(f, "shared_buffers = %lluMB\n", (unsigned long long)shared_buffers_mb);
   fprintf(f, "effective_cache_size = %lluMB\n", (unsigned long long)effective_cache_mb);
   fprintf(f, "maintenance_work_mem = %lluMB\n", (unsigned long long)maintenance_work_mem_mb);
   fprintf(f, "checkpoint_completion_target = %.1f\n", checkpoint_target);
   fprintf(f, "wal_buffers = %lluMB\n", (unsigned long long)wal_buffers_mb);
   fprintf(f, "default_statistics_target = %d\n", default_stats);
   fprintf(f, "random_page_cost = %.1f\n", random_page_cost);
   fprintf(f, "effective_io_concurrency = %d\n", io_concurrency);
   fprintf(f, "work_mem = %lluMB\n", (unsigned long long)work_mem_mb);
   fprintf(f, "min_wal_size = %lluMB\n", (unsigned long long)min_wal_size_mb);
   fprintf(f, "max_wal_size = %lluMB\n", (unsigned long long)max_wal_size_mb);
   fprintf(f, "max_worker_processes = %d\n", workers);
   fprintf(f, "max_parallel_workers_per_gather = %d\n", gather);
   fprintf(f, "max_parallel_workers = %d\n", workers);
   fprintf(f, "max_parallel_maintenance_workers = %d\n", maintenance_workers);

   if (output_format == PGVICTORIA_OUTPUT_MD)
   {
      fprintf(f, "```\n");
   }
   else if (output_format == PGVICTORIA_OUTPUT_HTML)
   {
      fprintf(f, "</code></pre>\n");
   }

   fclose(f);
   return 0;
}
