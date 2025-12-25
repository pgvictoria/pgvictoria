/*
 * Copyright (C) 2025 The pgvictoria community
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
#include <configuration.h>
#include <cmd.h>
#include <logging.h>
#include <memory.h>
#include <shmem.h>
#include <utils.h>

/* system */
#include <err.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <openssl/crypto.h>

#define NAME           "main"
#define MAX_FDS        64
#define SIGNALS_NUMBER 6

static int create_pidfile(void);
static void remove_pidfile(void);

struct accept_io
{
   struct ev_io io;
   int socket;
   char** argv;
};

static volatile int stop = 0;
static char** argv_ptr;
static struct ev_loop* main_loop = NULL;

static void
version(void)
{
   printf("pgvictoria %s\n", VERSION);
   exit(1);
}

static void
usage(void)
{
   printf("pgvictoria %s\n", VERSION);
   printf("  Tuning solution for PostgreSQL\n");
   printf("\n");

   printf("Usage:\n");
   printf("  pgvictoria [ -c CONFIG_FILE ] [ -u USERS_FILE ]\n");
   printf("\n");
   printf("Options:\n");
   printf("  -c, --config CONFIG_FILE  Set the path to the pgvictoria.conf file\n");
   printf("  -u, --users USERS_FILE    Set the path to the pgvictoria_users.conf file\n");
   printf("  -D, --directory DIRECTORY Set the directory containing all configuration files\n");
   printf("                            Can also be set via PGVICTORIA_CONFIG_DIR environment variable\n");
   printf("  -V, --version             Display version information\n");
   printf("  -?, --help                Display help\n");
   printf("\n");
   printf("pgvictoria: %s\n", PGVICTORIA_HOMEPAGE);
   printf("Report bugs: %s\n", PGVICTORIA_ISSUES);
}

int
main(int argc, char** argv)
{
   char* configuration_path = NULL;
   char* users_path = NULL;
   char* directory_path = NULL;
   bool pid_file_created = false;
   size_t shmem_size;
   struct main_configuration* config = NULL;
   int ret;
   char* os = NULL;
   int kernel_major, kernel_minor, kernel_patch;
   char* filepath = NULL;
   int optind = 0;
   int num_options = 0;
   int num_results = 0;
   char config_path_buffer[MAX_PATH];
   char users_path_buffer[MAX_PATH];
   struct stat path_stat = {0};
   char* adjusted_dir_path = NULL;

   cli_option options[] = {
      {"c", "config", true},
      {"u", "users", true},
      {"D", "directory", true},
      {"V", "version", false},
      {"?", "help", false},
   };

   argv_ptr = argv;

   num_options = sizeof(options) / sizeof(options[0]);

   cli_result results[num_options];

   num_results = cmd_parse(argc, argv, options, num_options, results, num_options, false, &filepath, &optind);

   if (num_results < 0)
   {
      errx(1, "Error parsing command line\n");
      return 1;
   }

   for (int i = 0; i < num_results; i++)
   {
      char* optname = results[i].option_name;
      char* optarg = results[i].argument;

      if (optname == NULL)
      {
         break;
      }
      else if (!strcmp(optname, "c") || !strcmp(optname, "config"))
      {
         configuration_path = optarg;
      }
      else if (!strcmp(optname, "u") || !strcmp(optname, "users"))
      {
         users_path = optarg;
      }
      else if (!strcmp(optname, "D") || !strcmp(optname, "directory"))
      {
         directory_path = optarg;
      }
      else if (!strcmp(optname, "V") || !strcmp(optname, "version"))
      {
         version();
      }
      else if (!strcmp(optname, "?") || !strcmp(optname, "help"))
      {
         usage();
         exit(0);
      }
   }

   if (getuid() == 0)
   {
      warnx("pgvictoria: Using the root account is not allowed");
      exit(1);
   }

   shmem_size = sizeof(struct main_configuration);
   if (pgvictoria_create_shared_memory(shmem_size, HUGEPAGE_OFF, &shmem))
   {
      warnx("pgvictoria: Error in creating shared memory");
      goto error;
   }

   pgvictoria_init_main_configuration(shmem);
   config = (struct main_configuration*)shmem;

   if (directory_path == NULL)
   {
      // Check for environment variable if no -D flag provided
      directory_path = getenv("PGVICTORIA_CONFIG_DIR");
      if (directory_path != NULL)
      {
         pgvictoria_log_info("Configuration directory set via PGVICTORIA_CONFIG_DIR environment variable: %s", directory_path);
      }
   }

   if (directory_path != NULL)
   {
      if (!strcmp(directory_path, "/etc/pgvictoria"))
      {
         pgvictoria_log_warn("Using the default configuration directory %s, -D can be omitted.", directory_path);
      }

      if (access(directory_path, F_OK) != 0)
      {
         pgvictoria_log_error("Configuration directory not found: %s", directory_path);
         exit(1);
      }

      if (stat(directory_path, &path_stat) == 0)
      {
         if (!S_ISDIR(path_stat.st_mode))
         {
            pgvictoria_log_error("Path is not a directory: %s", directory_path);
            exit(1);
         }
      }

      if (access(directory_path, R_OK | X_OK) != 0)
      {
         pgvictoria_log_error("Insufficient permissions for directory: %s", directory_path);
         exit(1);
      }

      if (directory_path[strlen(directory_path) - 1] != '/')
      {
         adjusted_dir_path = pgvictoria_append(strdup(directory_path), "/");
      }
      else
      {
         adjusted_dir_path = strdup(directory_path);
      }

      if (adjusted_dir_path == NULL)
      {
         pgvictoria_log_error("Memory allocation failed while copying directory path.");
         exit(1);
      }

      if (!configuration_path && pgvictoria_normalize_path(adjusted_dir_path, "pgvictoria.conf", PGVICTORIA_DEFAULT_CONFIG_FILE_PATH, config_path_buffer, sizeof(config_path_buffer)) == 0 && strlen(config_path_buffer) > 0)
      {
         configuration_path = config_path_buffer;
      }

      if (!users_path && pgvictoria_normalize_path(adjusted_dir_path, "pgvictoria_users.conf", PGVICTORIA_DEFAULT_USERS_FILE_PATH, users_path_buffer, sizeof(users_path_buffer)) == 0 && strlen(users_path_buffer) > 0)
      {
         users_path = users_path_buffer;
      }

      free(adjusted_dir_path);
   }

   if (configuration_path != NULL)
   {
      if (pgvictoria_read_main_configuration(shmem, configuration_path))
      {
         warnx("pgvictoria: Configuration not found: %s", configuration_path);
         goto error;
      }
   }
   else
   {
      configuration_path = "/etc/pgvictoria/pgvictoria.conf";
      if (pgvictoria_read_main_configuration(shmem, configuration_path))
      {
         warnx("pgvictoria: Configuration not found: /etc/pgvictoria/pgvictoria.conf");
         goto error;
      }
   }

   memcpy(&config->common.configuration_path[0], configuration_path, MIN(strlen(configuration_path), (size_t)MAX_PATH - 1));

   if (users_path != NULL)
   {
      ret = pgvictoria_read_users_configuration(shmem, users_path);
      if (ret == 1)
      {
         warnx("pgvictoria: USERS configuration not found: %s", users_path);
         goto error;
      }
      else if (ret == 2)
      {
         warnx("pgvictoria: Invalid master key file");
         goto error;
      }
      else if (ret == 3)
      {
         warnx("pgvictoria: USERS: Too many users defined %d (max %d)", config->common.number_of_users, NUMBER_OF_USERS);
         goto error;
      }
   }
   else
   {
      users_path = "/etc/pgvictoria/pgvictoria_users.conf";
      ret = pgvictoria_read_users_configuration(shmem, users_path);
      if (ret == 1)
      {
         warnx("pgvictoria: USERS configuration not found: %s", users_path);
         goto error;
      }
      else if (ret == 2)
      {
         warnx("pgvictoria: Invalid master key file");
         goto error;
      }
      else if (ret == 3)
      {
         warnx("pgvictoria: USERS: Too many users defined %d (max %d)", config->common.number_of_users, NUMBER_OF_USERS);
         goto error;
      }
   }

   memcpy(&config->common.users_path[0], users_path, MIN(strlen(users_path), (size_t)MAX_PATH - 1));

   if (pgvictoria_start_logging())
   {
      goto error;
   }

   if (pgvictoria_validate_main_configuration(shmem))
   {
      goto error;
   }
   if (pgvictoria_validate_users_configuration(shmem))
   {
      goto error;
   }

   config = (struct main_configuration*)shmem;

   if (create_pidfile())
   {
      goto error;
   }
   pid_file_created = true;

   pgvictoria_set_proc_title(argc, argv, "main", NULL);

   /* libev */
   main_loop = ev_default_loop(pgvictoria_libev(config->libev));
   if (!main_loop)
   {
      pgvictoria_log_fatal("No loop implementation (%x) (%x)",
                           pgvictoria_libev(config->libev), ev_supported_backends());
#ifdef HAVE_SYSTEMD
      sd_notifyf(0, "STATUS=No loop implementation (%x) (%x)", pgvictoria_libev(config->libev), ev_supported_backends());
#endif
      goto error;
   }

   pgvictoria_log_info("Started on %s", config->host);
   pgvictoria_libev_engines();
   pgvictoria_log_debug("libev engine: %s", pgvictoria_libev_engine(ev_backend(main_loop)));
   pgvictoria_log_debug("%s", OpenSSL_version(OPENSSL_VERSION));
   pgvictoria_log_debug("Configuration size: %lu", shmem_size);
   pgvictoria_log_debug("Known users: %d", config->common.number_of_users);

   pgvictoria_os_kernel_version(&os, &kernel_major, &kernel_minor, &kernel_patch);

   free(os);

   pgvictoria_log_info("Shutdown");

   ev_loop_destroy(main_loop);

   remove_pidfile();

   pgvictoria_stop_logging();
   pgvictoria_destroy_shared_memory(shmem, shmem_size);

   if (stop)
   {
      kill(0, SIGTERM);
   }

   return 0;

error:

   if (pid_file_created)
   {
      remove_pidfile();
      pid_file_created = false;
   }

   config->running = false;

   pgvictoria_stop_logging();
   pgvictoria_destroy_shared_memory(shmem, shmem_size);

   if (stop)
   {
      kill(0, SIGTERM);
   }

   exit(1);

   return 1;
}

static int
create_pidfile(void)
{
   char buffer[64];
   pid_t pid;
   int r;
   int fd;
   struct main_configuration* config;

   config = (struct main_configuration*)shmem;

   if (strlen(config->pidfile) == 0)
   {
      // no pidfile set, use a default one
      if (!pgvictoria_ends_with(config->unix_socket_dir, "/"))
      {
         snprintf(config->pidfile, sizeof(config->pidfile), "%s/pgvictoria.%s.pid",
                  config->unix_socket_dir,
                  !strncmp(config->host, "*", sizeof(config->host)) ? "all" : config->host);
      }
      else
      {
         snprintf(config->pidfile, sizeof(config->pidfile), "%spgvictoria.%s.pid",
                  config->unix_socket_dir,
                  !strncmp(config->host, "*", sizeof(config->host)) ? "all" : config->host);
      }
      pgvictoria_log_debug("PID file automatically set to: [%s]", config->pidfile);
   }

   if (strlen(config->pidfile) > 0)
   {
      // check pidfile is not there
      if (access(config->pidfile, F_OK) == 0)
      {
         pgvictoria_log_fatal("PID file [%s] exists, is there another instance running ?", config->pidfile);
         goto error;
      }

      pid = getpid();

      fd = open(config->pidfile, O_WRONLY | O_CREAT | O_EXCL, 0644);
      if (fd < 0)
      {
         warn("Could not create PID file '%s'", config->pidfile);
         goto error;
      }

      snprintf(&buffer[0], sizeof(buffer), "%u\n", (unsigned)pid);

      pgvictoria_permission(config->pidfile, 6, 4, 0);

      r = write(fd, &buffer[0], strlen(buffer));
      if (r < 0)
      {
         warn("Could not write pidfile '%s'", config->pidfile);
         goto error;
      }

      close(fd);
   }

   return 0;

error:

   return 1;
}

static void
remove_pidfile(void)
{
   struct main_configuration* config;

   config = (struct main_configuration*)shmem;

   if (strlen(config->pidfile) > 0 && access(config->pidfile, F_OK) == 0)
   {
      unlink(config->pidfile);
   }
}
