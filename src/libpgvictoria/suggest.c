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

#include <postgresql.h>
#include <suggest.h>
#include <html_suggest.h>
#include <markdown.h>
#include <security.h>
#include <network.h>
#include <json.h>
#include <utils.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <err.h>
#include <stdbool.h>

#ifdef __linux__
#include <sys/sysinfo.h>
#endif

/**
 * The suggested maximum number of connections based on workload type
 * @param type The database workload type
 * @return Suggested max_connections
 */
static int suggested_max_connections(enum pgvictoria_db_workload_type type);

/**
 * Helper Function that tells which unit to use GB or MB
 * @param value The passed parameter value to calculate in bytes
 * @param unit The selected unit of passed parameter value
 * @return The converted value in GB or MB.
 */
static uint64_t calculations_gb_or_mb_or_kb_unit(uint64_t value, const char **unit);

int
auto_detect_system_parameters(int server, struct pgvictoria_hardware_system_parameters *hardware)
{
   int ret = 0;
   /* Operating System type */
   char *os_name = NULL;
   int k_major = 0, k_minor = 0, k_patch = 0;

   if (pgvictoria_os_kernel_version(&os_name, &k_major, &k_minor, &k_patch))
   {
      ret = 1;
   }

   if (strcmp(os_name, "Linux") == 0)
   {
      hardware->os_type = PGVICTORIA_OS_TYPE_LINUX;
   }
   else if (strcmp(os_name, "Windows") == 0)
   {
      hardware->os_type = PGVICTORIA_OS_TYPE_WINDOWS;
   }
   else if (strcmp(os_name, "Darwin") == 0)
   {
      hardware->os_type = PGVICTORIA_OS_TYPE_MACOS;
   }
   else
   {
      ret = 1;
   }
   free(os_name);

/* Total RAM */
#ifdef __linux__
   struct sysinfo info;
   if (sysinfo(&info) != 0)
   {
      ret = 1;
   }
   hardware->total_ram = (uint64_t)info.totalram * info.mem_unit;
#endif

   /* CPU count */
   long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
   if (cpu_count < 1)
   {
      hardware->cpu_count = 1;
   }
   else
   {
      hardware->cpu_count = (int)cpu_count;
   }
   /* PostgreSQL version */
   SSL *ssl = NULL;
   int fd = -1;

   if (pgvictoria_connect_server(server, &ssl, &fd))
   {
      ret = 1;
      goto error;
   }

   if (pgvictoria_get_pg_version(ssl, fd, &hardware->pg_version))
   {
      ret = 1;
      goto error;
   }

error:
   if (ssl)
   {
      pgvictoria_close_ssl(ssl);
   }
   if (fd != -1)
   {
      pgvictoria_disconnect(fd);
   }

   return ret;
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

static int
suggested_max_connections(enum pgvictoria_db_workload_type type)
{
   switch (type)
   {
      case PGVICTORIA_DB_WORKLOAD_TYPE_WEB:
         return 200;

      case PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP:
         return 20;

      case PGVICTORIA_DB_WORKLOAD_TYPE_DW:
         return 40;

      case PGVICTORIA_DB_WORKLOAD_TYPE_OLTP:
         return 300;

      default:
         return 100;
   }
}

int
max_connections_number(enum pgvictoria_db_workload_type type, int connection_number, bool user_provided)
{
   int suggested = suggested_max_connections(type);

   if (connection_number <= 0)
   {
      return suggested;
   }

   if (user_provided && connection_number > suggested)
   {
      printf("Warning: connection_number %d exceeds the recommended value %d for this workload\n",
             connection_number, suggested);
      return connection_number;
   }

   return connection_number;
}

uint64_t
suggested_effective_cache_size(uint64_t total_ram, enum pgvictoria_db_workload_type type)
{
   uint64_t effective_cache_size;
   if (type == PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP)
   {
      effective_cache_size = total_ram / 4;
   }
   else
   {
      effective_cache_size = (total_ram / 4) * 3;
   }

   return effective_cache_size;
}

uint64_t
suggested_maintenance_work_mem(uint64_t total_ram, int pg_version, enum pgvictoria_db_workload_type type, enum pgvictoria_os_type os_type)
{
   uint64_t maintenance_work_mem;
   if (type == PGVICTORIA_DB_WORKLOAD_TYPE_DW)
   {
      maintenance_work_mem = total_ram / 8;
   }
   else
   {
      maintenance_work_mem = total_ram / 16;
   }

   uint64_t memory_limit = 8ULL * 1024ULL * 1024ULL * 1024ULL;

   /* Windows 64-bit has a strict 2GB limit up to PostgreSQL 17 */
   if (os_type == PGVICTORIA_OS_TYPE_WINDOWS && pg_version <= 17)
   {
      memory_limit = 2ULL * 1024ULL * 1024ULL * 1024ULL;
   }

   if (maintenance_work_mem >= memory_limit)
   {
      if (os_type == PGVICTORIA_OS_TYPE_WINDOWS && pg_version <= 17)
      {
         maintenance_work_mem = memory_limit - (1024ULL * 1024ULL);
      }
      else
      {
         maintenance_work_mem = memory_limit;
      }
   }

   return maintenance_work_mem;
}

uint64_t
suggested_max_wal_size(enum pgvictoria_db_workload_type type)
{
   uint64_t max_wal_size;
   if (type == PGVICTORIA_DB_WORKLOAD_TYPE_OLTP)
   {
      max_wal_size = 8;
   }
   else if (type == PGVICTORIA_DB_WORKLOAD_TYPE_DW)
   {
      max_wal_size = 16;
   }
   else if (type == PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP)
   {
      max_wal_size = 2;
   }
   else
   {
      max_wal_size = 4;
   }
   return max_wal_size;
}

uint64_t
suggested_min_wal_size(enum pgvictoria_db_workload_type type)
{
   uint64_t min_wal_size;
   if (type == PGVICTORIA_DB_WORKLOAD_TYPE_OLTP)
   {
      min_wal_size = 2;
   }
   else if (type == PGVICTORIA_DB_WORKLOAD_TYPE_DW)
   {
      min_wal_size = 4;
   }
   else if (type == PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP)
   {
      min_wal_size = 100;
   }
   else
   {
      min_wal_size = 1;
   }
   return min_wal_size;
}

uint64_t
suggested_wal_buffers(uint64_t shared_buffers)
{
   uint64_t wal_buffers = shared_buffers * 3 / 100;
   if (wal_buffers > 16 * 1024 * 1024)
   {
      wal_buffers = 16 * 1024 * 1024;
   }
   else if (wal_buffers < 32 * 1024)
   {
      wal_buffers = 32 * 1024;
   }

   return wal_buffers;
}

enum pgvictoria_huge_pages
suggested_huge_pages_settings(uint64_t shared_buffers)
{
   if (shared_buffers >= 2ULL * 1024 * 1024 * 1024)
   {
      return PGVICTORIA_HUGE_PAGES_TRY;
   }

   return PGVICTORIA_HUGE_PAGES_OFF;
}

struct pgvictoria_parallel_settings
suggested_parallel_settings(int cpu_count, enum pgvictoria_db_workload_type type, int pg_version)
{
   struct pgvictoria_parallel_settings parallel_settings = {0};

   if (cpu_count < 4)
   {
      return parallel_settings;
   }

   parallel_settings.max_worker_processes = cpu_count;

   parallel_settings.max_parallel_workers_per_gather = (cpu_count + 1) / 2;

   if (type != PGVICTORIA_DB_WORKLOAD_TYPE_DW && parallel_settings.max_parallel_workers_per_gather > 4)
   {
      parallel_settings.max_parallel_workers_per_gather = 4;
   }

   if (pg_version >= 10)
   {
      parallel_settings.max_parallel_workers = cpu_count;
   }

   if (pg_version >= 11)
   {
      parallel_settings.max_parallel_maintenance_workers = (cpu_count + 1) / 2;
      if (parallel_settings.max_parallel_maintenance_workers > 4)
      {
         parallel_settings.max_parallel_maintenance_workers = 4;
      }
   }

   return parallel_settings;
}

struct pgvictoria_wal_settings
suggested_wal_settings(enum pgvictoria_db_workload_type type)
{
   struct pgvictoria_wal_settings wal_settings = {NULL, 0};

   if (type == PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP)
   {
      wal_settings.wal_level = "minimal";
   }

   return wal_settings;
}

const char *
suggested_jit_setting(int pg_version, enum pgvictoria_db_workload_type type)
{
   if (pg_version >= 12 && (type == PGVICTORIA_DB_WORKLOAD_TYPE_WEB ||
                            type == PGVICTORIA_DB_WORKLOAD_TYPE_OLTP ||
                            type == PGVICTORIA_DB_WORKLOAD_TYPE_MIXED))
   {
      return "off";
   }

   return NULL;
}

const char *
suggested_wal_compression(int pg_version)
{
   if (pg_version >= 15)
   {
      return "lz4";
   }

   if (pg_version >= 10)
   {
      return "on";
   }

   return NULL;
}

int
suggested_autovacuum_max_workers(int cpu_count)
{
   int autovacuum_max_workers = 3;
   if (cpu_count >= 32)
   {
      autovacuum_max_workers = 5;
   }

   else if (cpu_count >= 16)
   {
      autovacuum_max_workers = 4;
   }

   return autovacuum_max_workers;
}

uint64_t
suggested_autovacuum_work_mem(uint64_t maintenance_work_mem, enum pgvictoria_os_type os_type, int pg_version)
{
   uint64_t autovacuum_work_mem = 0;

   if (maintenance_work_mem >= 2ULL * 1024 * 1024 * 1024)
   {
      autovacuum_work_mem = 2ULL * 1024 * 1024 * 1024;
   }

   if (os_type == PGVICTORIA_OS_TYPE_WINDOWS && pg_version <= 17 && autovacuum_work_mem)
   {
      autovacuum_work_mem = 2ULL * 1024 * 1024 * 1024 - 1ULL * 1024 * 1024;
   }

   return autovacuum_work_mem;
}

const char *
suggested_io_method(int pg_version, enum pgvictoria_os_type os_type)
{
   if (pg_version < 18)
   {
      return NULL;
   }

   if (os_type == PGVICTORIA_OS_TYPE_LINUX)
   {
      return "io_uring";
   }

   return "worker";
}

int
suggested_io_workers(int pg_version, int cpu_count, const char *io_method)
{
   if (pg_version < 18 || cpu_count < 1 || (io_method != NULL && strcmp(io_method, "io_uring") == 0))
   {
      return 0;
   }
   int io_workers = MIN(32, MAX(3, cpu_count / 4));

   if (io_workers > 3)
   {
      return io_workers;
   }

   return 0;
}

uint64_t
suggested_work_mem(enum pgvictoria_db_workload_type type, uint64_t total_ram, uint64_t shared_buffers, int max_connections, struct pgvictoria_parallel_settings parallel_settings)
{
   uint64_t work_mem = (total_ram - shared_buffers) / (uint64_t)(max_connections + parallel_settings.max_worker_processes) * 3ULL;

   if (type == PGVICTORIA_DB_WORKLOAD_TYPE_OLTP || type == PGVICTORIA_DB_WORKLOAD_TYPE_MIXED)
   {
      work_mem /= 2;
   }

   else if (type == PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP)
   {
      work_mem /= 6;
   }

   uint64_t min_work_mem = 4ULL * 1024 * 1024;

   if (work_mem < min_work_mem)
   {
      work_mem = min_work_mem;
   }

   return work_mem;
}

static uint64_t
calculations_gb_or_mb_or_kb_unit(uint64_t value, const char **unit)
{
   uint64_t mb = 1024ULL * 1024ULL;
   uint64_t gb = 1024ULL * mb;
   if (value % gb == 0)
   {
      *unit = "GB";
      return value / gb;
   }

   if (value % mb == 0)
   {
      *unit = "MB";
      return value / mb;
   }

   *unit = "KB";
   return value / 1024ULL;
}

static void
print_suggested_configurations(struct pgvictoria_suggest_item *parameters)
{
   printf("Suggested PostgreSQL Configuration:\n");
   printf("shared_buffers = %" PRIu64 "%s\n", parameters->shared_buffers_val, parameters->shared_buffers_unit);
   printf("max_connections = %d\n", parameters->max_connections);
   printf("effective_cache_size = %" PRIu64 "%s\n", parameters->effective_cache_size_val, parameters->effective_cache_size_unit);
   printf("maintenance_work_mem = %" PRIu64 "%s\n", parameters->maintenance_work_mem_val, parameters->maintenance_work_mem_unit);
   printf("min_wal_size = %" PRIu64 "%s\n", parameters->min_wal_size, parameters->min_wal_size == 100 ? "MB" : "GB");
   printf("max_wal_size = %" PRIu64 "GB\n", parameters->max_wal_size);
   printf("wal_buffers = %" PRIu64 "%s\n", parameters->wal_buffers_val, parameters->wal_buffers_unit);
   printf("default_statistics_target = %d\n", parameters->default_statistics_target);
   if (parameters->parallel_settings.max_worker_processes > 0)
   {
      printf("max_worker_processes = %d\n", parameters->parallel_settings.max_worker_processes);
      printf("max_parallel_workers_per_gather = %d\n", parameters->parallel_settings.max_parallel_workers_per_gather);

      if (parameters->parallel_settings.max_parallel_workers > 0)
      {
         printf("max_parallel_workers = %d\n", parameters->parallel_settings.max_parallel_workers);
      }
      if (parameters->parallel_settings.max_parallel_maintenance_workers)
      {
         printf("max_parallel_maintenance_workers = %d\n", parameters->parallel_settings.max_parallel_maintenance_workers);
      }
   }
   if (parameters->wal_settings.wal_level != NULL)
   {
      printf("wal_level = %s\n", parameters->wal_settings.wal_level);
      printf("max_wal_senders = %d\n", parameters->wal_settings.max_wal_senders);
   }
   if (parameters->jit != NULL)
   {
      printf("jit = %s\n", parameters->jit);
   }
   if (parameters->wal_compression != NULL)
   {
      printf("wal_compression = %s\n", parameters->wal_compression);
   }
   if (parameters->autovacuum_max_workers != 3)
   {
      printf("autovacuum_max_workers = %d\n", parameters->autovacuum_max_workers);
   }
   if (parameters->autovacuum_work_mem_val > 0)
   {
      printf("autovacuum_work_mem = %" PRIu64 "%s\n", parameters->autovacuum_work_mem_val, parameters->autovacuum_work_mem_unit);
   }
   if (parameters->io_method != NULL)
   {
      printf("io_method = %s\n", parameters->io_method);
   }
   if (parameters->io_workers != 0)
   {
      printf("io_workers = %d\n", parameters->io_workers);
   }
   printf("work_mem = %" PRIu64 "%s\n", parameters->work_mem_val, parameters->work_mem_unit);
}

int
pgvictoria_suggest_mode(int server, enum pgvictoria_db_workload_type type, int connection_number, bool user_provided, char *output_file, enum pgvictoria_output_format format)
{
   struct pgvictoria_hardware_system_parameters hardware;

   /* Detect System Parameters */
   if (auto_detect_system_parameters(server, &hardware) != 0)
   {
      printf("Failed to auto-detect system parameters\n");
      return 1;
   }

   /* shared_buffers suggestion */
   uint64_t shared_buffers = suggested_shared_buffers(hardware.total_ram, type);
   const char *shared_buffers_unit;
   uint64_t shared_buffers_val = calculations_gb_or_mb_or_kb_unit(shared_buffers, &shared_buffers_unit);

   /* max_connections */
   int max_connections = max_connections_number(type, connection_number, user_provided);

   /* effective cache size */
   uint64_t effective_cache_size = suggested_effective_cache_size(hardware.total_ram, type);
   const char *effective_cache_size_unit;
   uint64_t effective_cache_size_val = calculations_gb_or_mb_or_kb_unit(effective_cache_size, &effective_cache_size_unit);

   /* maintenance_work_mem*/
   uint64_t maintenance_work_mem = suggested_maintenance_work_mem(hardware.total_ram, hardware.pg_version, type, hardware.os_type);
   const char *maintenance_work_mem_unit;
   uint64_t maintenance_work_mem_val = calculations_gb_or_mb_or_kb_unit(maintenance_work_mem, &maintenance_work_mem_unit);

   /* min_wal_size and max_wal_size */
   uint64_t min_wal_size = suggested_min_wal_size(type);
   uint64_t max_wal_size = suggested_max_wal_size(type);

   /* wal buffers */
   uint64_t wal_buffers = suggested_wal_buffers(shared_buffers);
   const char *wal_buffers_unit;
   uint64_t wal_buffers_val = calculations_gb_or_mb_or_kb_unit(wal_buffers, &wal_buffers_unit);

   /* default_statistics_target */
   int default_statistics_target = (type == PGVICTORIA_DB_WORKLOAD_TYPE_DW) ? 500 : 100;

   /* huge_page */
   enum pgvictoria_huge_pages huge_pages = suggested_huge_pages_settings(shared_buffers);

   /* parallel_settings */
   struct pgvictoria_parallel_settings parallel_settings = suggested_parallel_settings(hardware.cpu_count, type, hardware.pg_version);

   /* wal_level and max_wal_senders */
   struct pgvictoria_wal_settings wal_settings = suggested_wal_settings(type);

   /* jit settings */
   const char *jit = suggested_jit_setting(hardware.pg_version, type);

   /* wal_compression */
   const char *wal_compression = suggested_wal_compression(hardware.pg_version);

   /* autovacuum_max_workers */
   int autovacuum_max_workers = suggested_autovacuum_max_workers(hardware.cpu_count);

   /* autovacuum_work_mem */
   uint64_t autovacuum_work_mem = suggested_autovacuum_work_mem(maintenance_work_mem, hardware.os_type, hardware.pg_version);
   const char *autovacuum_work_mem_unit;
   uint64_t autovacuum_work_mem_val = calculations_gb_or_mb_or_kb_unit(autovacuum_work_mem, &autovacuum_work_mem_unit);

   /* io_method */
   const char *io_method = suggested_io_method(hardware.pg_version, hardware.os_type);

   /* io_workers */
   int io_workers = suggested_io_workers(hardware.pg_version, hardware.cpu_count, io_method);

   /* work_mem */
   uint64_t work_mem = suggested_work_mem(type, hardware.total_ram, shared_buffers, max_connections, parallel_settings);
   const char *work_mem_unit;
   uint64_t work_mem_val = calculations_gb_or_mb_or_kb_unit(work_mem, &work_mem_unit);

   struct pgvictoria_suggest_item parameters =
      {
         .shared_buffers_val = shared_buffers_val,
         .shared_buffers_unit = shared_buffers_unit,
         .max_connections = max_connections,
         .effective_cache_size_val = effective_cache_size_val,
         .effective_cache_size_unit = effective_cache_size_unit,
         .maintenance_work_mem_val = maintenance_work_mem_val,
         .maintenance_work_mem_unit = maintenance_work_mem_unit,
         .min_wal_size = min_wal_size,
         .max_wal_size = max_wal_size,
         .wal_buffers_val = wal_buffers_val,
         .wal_buffers_unit = wal_buffers_unit,
         .default_statistics_target = default_statistics_target,
         .huge_pages = huge_pages,
         .parallel_settings.max_worker_processes = parallel_settings.max_worker_processes,
         .parallel_settings.max_parallel_workers_per_gather = parallel_settings.max_parallel_workers_per_gather,
         .parallel_settings.max_parallel_workers = parallel_settings.max_parallel_workers,
         .parallel_settings.max_parallel_maintenance_workers = parallel_settings.max_parallel_maintenance_workers,
         .wal_settings.wal_level = wal_settings.wal_level,
         .wal_settings.max_wal_senders = wal_settings.max_wal_senders,
         .jit = jit,
         .wal_compression = wal_compression,
         .autovacuum_max_workers = autovacuum_max_workers,
         .autovacuum_work_mem_val = autovacuum_work_mem_val,
         .autovacuum_work_mem_unit = autovacuum_work_mem_unit,
         .io_method = io_method,
         .io_workers = io_workers,
         .work_mem_val = work_mem_val,
         .work_mem_unit = work_mem_unit};

   /* No Output file: print only directly to the CLI */
   if (output_file == NULL)
   {
      print_suggested_configurations(&parameters);
      return 0;
   }

   /** 
     * If Output file specified
     * First print the suggestions for conformation then write to the specified file
    */
   print_suggested_configurations(&parameters);

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
      ret = pgvictoria_generate_markdown_suggest(output_file, &parameters);
   }

   else if (format == PGVICTORIA_OUTPUT_HTML)
   {
      ret = pgvictoria_generate_html_suggest(output_file, &parameters);
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
      fprintf(f, "max_connections = %d\n", max_connections);
      fprintf(f, "effective_cache_size = %" PRIu64 "%s\n", effective_cache_size_val, effective_cache_size_unit);
      fprintf(f, "maintenance_work_mem = %" PRIu64 "%s\n", maintenance_work_mem_val, maintenance_work_mem_unit);
      fprintf(f, "min_wal_size = %" PRIu64 "%s\n", min_wal_size, type == PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP ? "MB" : "GB");
      fprintf(f, "max_wal_size = %" PRIu64 "GB\n", max_wal_size);
      fprintf(f, "wal_buffers = %" PRIu64 "%s\n", wal_buffers_val, wal_buffers_unit);
      fprintf(f, "default_statistics_target = %d\n", default_statistics_target);
      fprintf(f, "huge_pages = %s\n", huge_pages == PGVICTORIA_HUGE_PAGES_TRY ? "try" : "off");
      if (parallel_settings.max_worker_processes > 0)
      {
         fprintf(f, "max_worker_processes = %d\n", parallel_settings.max_worker_processes);
         fprintf(f, "max_parallel_workers_per_gather = %d\n", parallel_settings.max_parallel_workers_per_gather);
         if (parallel_settings.max_parallel_workers > 0)
         {
            fprintf(f, "max_parallel_workers = %d\n", parallel_settings.max_parallel_workers);
         }
         if (parallel_settings.max_parallel_maintenance_workers)
         {
            fprintf(f, "max_parallel_maintenance_workers = %d\n", parallel_settings.max_parallel_maintenance_workers);
         }
      }
      if (wal_settings.wal_level != NULL)
      {
         fprintf(f, "wal_level = %s\n", wal_settings.wal_level);
         fprintf(f, "max_wal_senders = %d\n", wal_settings.max_wal_senders);
      }
      if (jit != NULL)
      {
         fprintf(f, "jit = %s\n", jit);
      }
      if (wal_compression != NULL)
      {
         fprintf(f, "wal_compression = %s\n", wal_compression);
      }
      if (autovacuum_max_workers != 3)
      {
         fprintf(f, "autovacuum_max_workers = %d\n", autovacuum_max_workers);
      }
      if (autovacuum_work_mem_val > 0)
      {
         fprintf(f, "autovacuum_work_mem = %" PRIu64 "%s\n", autovacuum_work_mem_val, maintenance_work_mem_unit);
      }
      if (io_method != NULL)
      {
         fprintf(f, "io_method = %s\n", io_method);
      }
      if (io_workers != 0)
      {
         fprintf(f, "io_workers = %d\n", io_workers);
      }
      fprintf(f, "work_mem = %" PRIu64 "%s\n", work_mem_val, work_mem_unit);
      fclose(f);
   }

   if (ret != 0)
   {
      return 1;
   }

   printf("Suggestions written to '%s'.\n", output_file);

   return 0;
}