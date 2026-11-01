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

#ifndef PGVICTORIA_SUGGEST_H
#define PGVICTORIA_SUGGEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <postgresql.h>

#include <stdint.h>
#include <stdbool.h>

/**
  * Database Workload Types
  */
enum pgvictoria_db_workload_type {
   PGVICTORIA_DB_WORKLOAD_TYPE_GENERAL,
   PGVICTORIA_DB_WORKLOAD_TYPE_WEB,
   PGVICTORIA_DB_WORKLOAD_TYPE_DW,
   PGVICTORIA_DB_WORKLOAD_TYPE_OLTP,
   PGVICTORIA_DB_WORKLOAD_TYPE_DESKTOP,
   PGVICTORIA_DB_WORKLOAD_TYPE_MIXED
};

/**
 * Operating System Types
 */
enum pgvictoria_os_type {
   PGVICTORIA_OS_TYPE_LINUX,
   PGVICTORIA_OS_TYPE_WINDOWS,
   PGVICTORIA_OS_TYPE_MACOS
};

/**
 * Disk Type types
 */
enum pgvictoria_disk_type {
   PGVICTORIA_DISK_TYPE_UNKNOWN,
   PGVICTORIA_DISK_TYPE_HDD,
   PGVICTORIA_DISK_TYPE_SSD,
   PGVICTORIA_DISK_TYPE_NVME
};

enum pgvictoria_huge_pages {
   PGVICTORIA_HUGE_PAGES_OFF,
   PGVICTORIA_HUGE_PAGES_TRY
};

/* Hardware collected automatically for suggestion */
struct pgvictoria_hardware_system_parameters
{
   uint64_t total_ram;                  /* The total system memory in bytes */
   enum pgvictoria_os_type os_type;     /* Operating system type */
   int pg_version;                      /* PostgreSQL version */
   int cpu_count;                       /* Number of CPU cores */
   enum pgvictoria_disk_type disk_type; /* Disk Type*/
};

struct pgvictoria_wal_settings
{
   const char *wal_level;
   int max_wal_senders;
};

/**
 * Parallel settings parameters
 */
struct pgvictoria_parallel_settings
{
   int max_worker_processes;
   int max_parallel_workers;
   int max_parallel_workers_per_gather;
   int max_parallel_maintenance_workers;
};

/**
 * PostgreSQL Configuration Parameters
 */
struct pgvictoria_suggest_item
{
   uint64_t shared_buffers_val;
   const char *shared_buffers_unit;
   int max_connections;
   uint64_t effective_cache_size_val;
   const char *effective_cache_size_unit;
   uint64_t maintenance_work_mem_val;
   const char *maintenance_work_mem_unit;
   uint64_t min_wal_size;
   uint64_t max_wal_size;
   uint64_t wal_buffers_val;
   const char *wal_buffers_unit;
   int default_statistics_target;
   enum pgvictoria_huge_pages huge_pages;
   struct pgvictoria_parallel_settings parallel_settings;
   struct pgvictoria_wal_settings wal_settings;
   const char *jit;
   const char *wal_compression;
   int autovacuum_max_workers;
   uint64_t autovacuum_work_mem_val;
   const char *autovacuum_work_mem_unit;
   const char *io_method;
   int io_workers;
   uint64_t work_mem_val;
   const char *work_mem_unit;
   double random_page_cost;
   int effective_io_concurrency;
};

/**
 * Auto Detect System Parameters used in suggestions
 * @param server The server index
 * @param hardware Hardware calcualted data
 * @return 0 upon success, otherwise 1
 */
int
auto_detect_system_parameters(int server, struct pgvictoria_hardware_system_parameters *hardware);

/**
 * Calculate suggested shared_buffers based on total_ram and DB workload type
 * @param total_ram The total system memory in bytes
 * @param type The database workload type
 * @return Suggested shared_buffers size in bytes
 */
uint64_t suggested_shared_buffers(uint64_t total_ram, enum pgvictoria_db_workload_type type);

/**
 * The suggested maximum number of connections
 * @param type The database workload type
 * @param connection_number number of connections user specify, or 0 if not specified
 * @return The user-specified connection number, or a suggested value based on workload type
 */
int max_connections_number(enum pgvictoria_db_workload_type type, int connection_number, bool user_provided);

/**
 * Effective Cache size Suggestion
 * @param total_ram The total system memory in bytes
 * @param type The Database workload type
 * @return Suggested effective_cache_size in bytes
 */
uint64_t suggested_effective_cache_size(uint64_t total_ram, enum pgvictoria_db_workload_type type);

/**
 * Maintenance Work Mem Suggestion
 * @param total_ram The total system memory in bytes
 * @param pg_version PostgreSQL version
 * @param type The database workload type
 * @param os_type Operating system type
 * @return Suggested maintenance_work_mem in bytes
 */
uint64_t suggested_maintenance_work_mem(uint64_t total_ram, int pg_version, enum pgvictoria_db_workload_type type, enum pgvictoria_os_type os_type);

/**
 * Suggested Min Wal Size
 * @param type The database workload type
 * @return Suggested min_wal_size in GB, except for desktop type in MB
 */
uint64_t suggested_min_wal_size(enum pgvictoria_db_workload_type type);

/**
 * Suggested Max Wal Size
 * @param type The database workload type
 * @return Suggested max_wal_size in GB.
 */
uint64_t suggested_max_wal_size(enum pgvictoria_db_workload_type type);

/**
 * Suggested wal buffers based on shared_buffers value
 * @param shared_buffers The shared_buffers value in bytes
 * @return Suggested wal_buffers in bytes
 */
uint64_t suggested_wal_buffers(uint64_t shared_buffers);

/**
 * Huge Pages settings suggestion
 * @param shared_buffers The shared_buffers value in bytes
 * @return The suggested huge_pages setting (try or off)
 */
enum pgvictoria_huge_pages suggested_huge_pages_settings(uint64_t shared_buffers);

/**
 * Suggest parallel settings based on CPU count, workload type, and PostgreSQL version
 * @param cpu_count Number of CPU cores
 * @param type The database workload type
 * @param pg_version PostgreSQL version
 * @return Suggested parallel settings
 */
struct pgvictoria_parallel_settings suggested_parallel_settings(int cpu_count, enum pgvictoria_db_workload_type type, int pg_version);

/**
 * Suggest wal level and max wal level
 * @param type The database workload type
 * @return Suggested wal_level and max_wal_senders
 */
struct pgvictoria_wal_settings suggested_wal_settings(enum pgvictoria_db_workload_type type);

/**
 * Suggest jit settings
 * @param pg_version PostgreSQL version
 * @param type The database workload type
 * @return Suggested jit setting, or NULL for keeping the default value of on
 */
const char *suggested_jit_setting(int pg_version, enum pgvictoria_db_workload_type type);

/**
 * Suggest Wal compression
 * @param pg_version PostgreSQL version
 * @return Suggested wal_compression, or NULL keeping the default value of off
 */
const char *suggested_wal_compression(int pg_version);

/**
 * Suggest Autovacum max workers
 * @param cpu_count Number of CPU cores
 * @return Suggested autovacuum_max_workers
 */
int suggested_autovacuum_max_workers(int cpu_count);

/**
 * Suggest Autovacum work mem
 * @param maintenance_work_mem Maintence woek mem in bytes
 * @param os_type Operating system type
 * @param pg_version PostgreSQL version
 * @return Suggested autovacuum_work_mem
 */
uint64_t suggested_autovacuum_work_mem(uint64_t maintenance_work_mem, enum pgvictoria_os_type os_type, int pg_version);

/**
 * @param pg_version PostgreSQL version
 * @param os_type Operating system type
 * @return Suggested io_method, or NULL to keep the PostgreSQL default
 */
const char *suggested_io_method(int pg_version, enum pgvictoria_os_type os_type);

/**
 * @param pg_version PostgreSQL version
 * @param cpu_count Number of CPU cores
 * @param io_method IO method or NULL if not specified
 * @return suggested io_workers, or 0 if not supported or keeping default value of 3
 */
int suggested_io_workers(int pg_version, int cpu_count, const char *io_method);

/**
 * @param type The database workload type
 * @param total_ram The total system memory in bytes
 * @param shared_buffers The shared_buffers value in bytes
 * @param max_connections The maximum number of database connections
 * @param parallel_settings The PostgreSQL parallel serttings
 * @return Suggested work_mem in bytes
 */
uint64_t suggested_work_mem(enum pgvictoria_db_workload_type type, uint64_t total_ram, uint64_t shared_buffers, int max_connections, struct pgvictoria_parallel_settings parallel_settings);

/**
 * Suggest I/O method based on PostgreSQL version and OS type
 * @param pg_version PostgreSQL version
 * @param os_type OS type
 * @return suggested I/O method, or NULL to keep default
 */
const char *suggested_io_method(int pg_version, enum pgvictoria_os_type os_type);

/**
 * Suggest random_page_cost based on disk type and workload
 * @param disk_type Disk type
 * @param type The database workload type
 * @return suggested random_page_cost value
 */
double suggested_random_page_cost(enum pgvictoria_disk_type disk_type, enum pgvictoria_db_workload_type type);

/**
 * Suggest effective_io_concurrency based on OS and disk_type
 * @param os_type Operating system type
 * @param disk_type Disk type
 * @return suggested value, or -1 to keep default
 */
int suggested_effective_io_concurrency(enum pgvictoria_os_type os_type, enum pgvictoria_disk_type disk_type);

/**
 * Suggested PostgreSQL Configuration
 * @param server The server index
 * @param type The database workload type
 * @param connection_number number of connections to the server
 * @param output_file The path of output_file or NULL and print the suggestions on CLI.
 * @param format The output format (text, HTML, or Markdown)
 * @return 0 upon success, otherwise 1
 */
int pgvictoria_suggest_mode(int server, enum pgvictoria_db_workload_type type, int connection_number, bool user_provided, char *output_file, enum pgvictoria_output_format format);

#ifdef __cplusplus
}
#endif

#endif
