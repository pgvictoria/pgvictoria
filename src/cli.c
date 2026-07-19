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

#include <pgvictoria.h>
#include <cmd.h>
#include <configuration.h>
#include <logging.h>
#include <memory.h>
#include <report.h>
#include <postgresql.h>
#include <shmem.h>
#include <utils.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ACTION_UNKNOWN  0
#define ACTION_REPORT   1
#define ACTION_CONF_GET 3
#define ACTION_CONF_SET 4
#define ACTION_CONF_DEL 5
#define ACTION_CONF_LS  6

static bool
load_config(void* shmem, const char* default_path, char* user_path, char** resolved_path, int (*read_func)(void*, char*), const char* label)
{
   char* path = user_path ? user_path : (char*)default_path;
   char* res = NULL;
   if (pgvictoria_resolve_path(path, &res) != 0 || res == NULL)
   {
      res = strdup(path);
   }
   *resolved_path = res;

   if (pgvictoria_exists(res))
   {
      if (pgvictoria_is_directory(res))
      {
         warnx("pgvictoria-cli: %s path %s is a directory, not a file", label, res);
      }
      else if (!pgvictoria_is_file(res))
      {
         warnx("pgvictoria-cli: %s path %s is not a regular file", label, res);
      }
      else
      {
         return (read_func(shmem, res) == 0);
      }
   }
   return false;
}

static void
version(void)
{
   printf("pgvictoria-cli %s\n", VERSION);
   exit(1);
}

static void
usage(void)
{
   printf("pgvictoria-cli %s\n", VERSION);
   printf("  Command line utility for pgvictoria\n");
   printf("\n");
   printf("Usage:\n");
   printf("  pgvictoria-cli [ OPTIONS ] report [ CONFIG_FILE ]\n");
   printf("\n");
   printf("Commands:\n");
   printf("  report                       Generate a configuration report against the version baseline\n");
   printf("                                 no arguments  - scan the live server (online mode)\n");
   printf("                                 CONFIG_FILE   - compare a postgresql.conf file (offline mode)\n");
   printf("  conf get <file> <section> <key>\n");
   printf("                               Get a configuration value\n");
   printf("  conf set <file> <section> <key> <value> [comment]\n");
   printf("                               Set a configuration value (optional inline comment)\n");
   printf("  conf del <file> <section> [key]\n");
   printf("                               Delete a section or key\n");
   printf("  conf ls <file> [section]     List sections or keys in a section\n");
   printf("\n");
   printf("Options:\n");
   printf("  -c, --config CONFIG_FILE      Set the path to the pgvictoria.conf file\n");
   printf("  -u, --users USERS_FILE        Set the path to the pgvictoria_users.conf file\n");
   printf("  -H, --host HOST               Set the PostgreSQL host (default: 127.0.0.1)\n");
   printf("  -P, --port PORT               Set the PostgreSQL port (default: 5432)\n");
   printf("  -U, --user USER               Set the database user (default: postgres)\n");
   printf("  -W, --password PASSWORD       Set the database password\n");
   printf("  -pg, --postgresql VERSION     Override the baseline version to compare against (14-19)\n");
   printf("  -f, --format FORMAT           Report format: text|html|md (default: auto-detected from output file extension, fallback: text)\n");
   printf("  -t, --type TYPE               Report type: full|changed (default: changed)\n");
   printf("  -o, --output OUTPUT_FILE      Write the report to OUTPUT_FILE (required)\n");
   printf("  -i, --init                    Initialize a pgvictoria-cli configuration file interactively\n");
   printf("  -V, --version                 Display version information\n");
   printf("  -?, --help                    Display help\n");
   printf("\n");
   printf("pgvictoria: %s\n", PGVICTORIA_HOMEPAGE);
   printf("Report bugs: %s\n", PGVICTORIA_ISSUES);
}

int
main(int argc, char** argv)
{
   char* configuration_path = NULL;
   char* users_path = NULL;
   char* filepath = NULL;
   int optind = 0;
   int num_results = 0;
   size_t shmem_size;
   struct main_configuration* config = NULL;

   char* host = NULL;
   int port = 5432;
   char* user = NULL;
   char* password = NULL;
   int override_version = 0;
   enum pgvictoria_output_format output_format = PGVICTORIA_OUTPUT_TEXT;
   bool format_specified = false;
   enum pgvictoria_report_type report_type = PGVICTORIA_REPORT_CHANGED;
   char* output_file = NULL;

   cli_option options[] = {
      {"c", "config", true},
      {"u", "users", true},
      {"i", "init", false},
      {"V", "version", false},
      {"?", "help", false},
      {"H", "host", true},
      {"P", "port", true},
      {"U", "user", true},
      {"W", "password", true},
      {"pg", "postgresql", true},
      {"f", "format", true},
      {"t", "type", true},
      {"o", "output", true},
   };

   struct pgvictoria_command command_table[] = {
      {
         .command = "report",
         .subcommand = "",
         .accepted_argument_count = {0, 1},
         .action = ACTION_REPORT,
         .deprecated = false,
         .log_message = "report",
      },
      {
         .command = "conf",
         .subcommand = "get",
         .accepted_argument_count = {3},
         .action = ACTION_CONF_GET,
         .deprecated = false,
         .log_message = "conf get",
      },
      {
         .command = "conf",
         .subcommand = "set",
         .accepted_argument_count = {4, 5},
         .action = ACTION_CONF_SET,
         .deprecated = false,
         .log_message = "conf set",
      },
      {
         .command = "conf",
         .subcommand = "del",
         .accepted_argument_count = {2, 3},
         .action = ACTION_CONF_DEL,
         .deprecated = false,
         .log_message = "conf del",
      },
      {
         .command = "conf",
         .subcommand = "ls",
         .accepted_argument_count = {1, 2},
         .action = ACTION_CONF_LS,
         .deprecated = false,
         .log_message = "conf ls",

      }};

   cli_result results[sizeof(options) / sizeof(options[0])];
   num_results = cmd_parse(argc, argv, options, sizeof(options) / sizeof(options[0]), results, sizeof(options) / sizeof(options[0]), false, &filepath, &optind);

   if (num_results < 0)
   {
      warnx("Error parsing command line\n");
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
      else if (!strcmp(optname, "i") || !strcmp(optname, "init"))
      {
         if (pgvictoria_config_init("pgvictoria-cli.conf", false, false, TARGET_CLI))
         {
            errx(1, "Error generating configuration");
         }
         exit(0);
      }
      else if (!strcmp(optname, "H") || !strcmp(optname, "host"))
      {
         host = optarg;
      }
      else if (!strcmp(optname, "P") || !strcmp(optname, "port"))
      {
         if (!pgvictoria_is_number(optarg, 10))
         {
            warnx("pgvictoria-cli: Invalid port number: %s", optarg);
            exit(1);
         }
         port = pgvictoria_atoi(optarg);
         if (port < 1 || port > 65535)
         {
            warnx("pgvictoria-cli: Invalid port number: %s", optarg);
            exit(1);
         }
      }
      else if (!strcmp(optname, "U") || !strcmp(optname, "user"))
      {
         user = optarg;
      }
      else if (!strcmp(optname, "W") || !strcmp(optname, "password"))
      {
         password = optarg;
      }
      else if (!strcmp(optname, "pg") || !strcmp(optname, "postgresql"))
      {
         if (!pgvictoria_is_number(optarg, 10))
         {
            warnx("pgvictoria-cli: Unsupported PostgreSQL version: %s", optarg);
            exit(1);
         }
         override_version = pgvictoria_atoi(optarg);
         if (!pgvictoria_is_version_supported(override_version))
         {
            warnx("pgvictoria-cli: Unsupported PostgreSQL version: %s", optarg);
            exit(1);
         }
      }
      else if (!strcmp(optname, "f") || !strcmp(optname, "format"))
      {
         format_specified = true;
         /* Select the output format; honored in both online and file mode. */
         if (!strcmp(optarg, "text"))
         {
            output_format = PGVICTORIA_OUTPUT_TEXT;
         }
         else if (!strcmp(optarg, "html"))
         {
            output_format = PGVICTORIA_OUTPUT_HTML;
         }
         else if (!strcmp(optarg, "md") || !strcmp(optarg, "markdown"))
         {
            output_format = PGVICTORIA_OUTPUT_MD;
         }
         else
         {
            warnx("pgvictoria-cli: Unsupported output format: %s (expected text|html|md)", optarg);
            exit(1);
         }
      }
      else if (!strcmp(optname, "t") || !strcmp(optname, "type"))
      {
         /* Select which GUCs to list; honored in both online and file mode. */
         if (!strcmp(optarg, "changed"))
         {
            report_type = PGVICTORIA_REPORT_CHANGED;
         }
         else if (!strcmp(optarg, "full"))
         {
            report_type = PGVICTORIA_REPORT_FULL;
         }
         else
         {
            warnx("pgvictoria-cli: Unsupported report type: %s (expected full|changed)", optarg);
            exit(1);
         }
      }
      else if (!strcmp(optname, "o") || !strcmp(optname, "output"))
      {
         /* Destination path for the report; honored in both online and file mode. */
         if (strlen(optarg) >= MAX_PATH)
         {
            warnx("pgvictoria-cli: Invalid or excessively long output path");
            exit(1);
         }
         output_file = optarg;
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
      warnx("pgvictoria-cli: Using the root account is not allowed");
      exit(1);
   }

   struct pgvictoria_parsed_command parsed;
   memset(&parsed, 0, sizeof(struct pgvictoria_parsed_command));
   if (!parse_command(argc, argv, optind, &parsed, command_table, sizeof(command_table) / sizeof(struct pgvictoria_command)))
   {
      usage();
      exit(1);
   }

   shmem_size = sizeof(struct main_configuration);
   if (pgvictoria_create_shared_memory(shmem_size, HUGEPAGE_OFF, &shmem))
   {
      warnx("pgvictoria-cli: Error in creating shared memory");
      goto error;
   }

   pgvictoria_init_main_configuration(shmem);
   pgvictoria_memory_init();

   char* resolved_config_path = NULL;
   char* resolved_users_path = NULL;

   bool has_config = load_config(shmem, "/etc/pgvictoria/pgvictoria.conf", configuration_path, &resolved_config_path, pgvictoria_read_main_configuration, "Config");
   bool has_users = load_config(shmem, "/etc/pgvictoria/pgvictoria_users.conf", users_path, &resolved_users_path, pgvictoria_read_users_configuration, "Users config");

   // Populate in-memory configuration if CLI arguments are provided or config file is missing
   config = (struct main_configuration*)shmem;
   if (!has_config || host != NULL || port != 5432 || user != NULL)
   {
      if (host && strlen(host) >= MISC_LENGTH)
      {
         warnx("pgvictoria-cli: Host length exceeds maximum limit of %d characters", MISC_LENGTH - 1);
         goto error;
      }
      if (user && strlen(user) >= MAX_USERNAME_LENGTH)
      {
         warnx("pgvictoria-cli: Username length exceeds maximum limit of %d characters", MAX_USERNAME_LENGTH - 1);
         goto error;
      }

      config->common.number_of_servers = 1;

      char* tmp = NULL;

      // Server name
      tmp = pgvictoria_append(tmp, "cli_target");
      if (tmp)
      {
         snprintf(config->common.servers[0].name, sizeof(config->common.servers[0].name), "%s", tmp);
         free(tmp);
         tmp = NULL;
      }

      // Server host
      tmp = pgvictoria_append(tmp, host ? host : "127.0.0.1");
      if (tmp)
      {
         snprintf(config->common.servers[0].host, sizeof(config->common.servers[0].host), "%s", tmp);
         free(tmp);
         tmp = NULL;
      }

      config->common.servers[0].port = port ? port : 5432;

      // Server username
      tmp = pgvictoria_append(tmp, user ? user : "postgres");
      if (tmp)
      {
         snprintf(config->common.servers[0].username, sizeof(config->common.servers[0].username), "%s", tmp);
         free(tmp);
         tmp = NULL;
      }
   }

   char* pgpass = getenv("PGPASSWORD");
   if (!has_users || user != NULL || password != NULL || pgpass != NULL)
   {
      if (user && strlen(user) >= MAX_USERNAME_LENGTH)
      {
         warnx("pgvictoria-cli: Username length exceeds maximum limit of %d characters", MAX_USERNAME_LENGTH - 1);
         goto error;
      }
      if (password && strlen(password) >= MAX_PASSWORD_LENGTH)
      {
         warnx("pgvictoria-cli: Password length exceeds maximum limit of %d characters", MAX_PASSWORD_LENGTH - 1);
         goto error;
      }
      if (pgpass && strlen(pgpass) >= MAX_PASSWORD_LENGTH)
      {
         warnx("pgvictoria-cli: PGPASSWORD length exceeds maximum limit of %d characters", MAX_PASSWORD_LENGTH - 1);
         goto error;
      }

      config->common.number_of_users = 1;

      char* tmp = NULL;

      // User username
      tmp = pgvictoria_append(tmp, user ? user : "postgres");
      if (tmp)
      {
         snprintf(config->common.users[0].username, sizeof(config->common.users[0].username), "%s", tmp);
         free(tmp);
         tmp = NULL;
      }

      // User password
      if (password)
      {
         tmp = pgvictoria_append(tmp, password);
      }
      else if (pgpass)
      {
         tmp = pgvictoria_append(tmp, pgpass);
      }

      if (tmp)
      {
         snprintf(config->common.users[0].password, sizeof(config->common.users[0].password), "%s", tmp);
         free(tmp);
         tmp = NULL;
      }
      else
      {
         config->common.users[0].password[0] = '\0';
      }
   }

   if (parsed.cmd->action == ACTION_REPORT)
   {
      if (output_file == NULL || output_file[0] == '\0')
      {
         warnx("pgvictoria-cli: -o/--output is required");
         goto error;
      }

      if (!format_specified)
      {
         if (pgvictoria_ends_with(output_file, ".html") || pgvictoria_ends_with(output_file, ".HTML"))
         {
            output_format = PGVICTORIA_OUTPUT_HTML;
         }
         else if (pgvictoria_ends_with(output_file, ".md") || pgvictoria_ends_with(output_file, ".MD") ||
                  pgvictoria_ends_with(output_file, ".markdown") || pgvictoria_ends_with(output_file, ".MARKDOWN"))
         {
            output_format = PGVICTORIA_OUTPUT_MD;
         }
         else
         {
            output_format = PGVICTORIA_OUTPUT_TEXT;
         }
      }

      if (parsed.args[0] != NULL)
      {
         if (pgvictoria_report_file(parsed.args[0], output_format, report_type, output_file, override_version))
         {
            warnx("pgvictoria-cli: Failed to generate file report");
            goto error;
         }
      }
      else
      {
         if (pgvictoria_report_online(0, output_format, report_type, output_file))
         {
            warnx("pgvictoria-cli: Failed to generate report");
            goto error;
         }
      }
   }
   else if (parsed.cmd->action == ACTION_CONF_GET)
   {
      if (pgvictoria_config_get(parsed.args[0], parsed.args[1], parsed.args[2]))
      {
         exit(1);
      }
   }
   else if (parsed.cmd->action == ACTION_CONF_SET)
   {
      const char* comment = parsed.args[4] ? parsed.args[4] : NULL;
      if (pgvictoria_config_set(parsed.args[0], parsed.args[1], parsed.args[2], parsed.args[3], comment))
      {
         errx(1, "Error setting configuration value");
      }
   }
   else if (parsed.cmd->action == ACTION_CONF_DEL)
   {
      if (pgvictoria_config_del(parsed.args[0], parsed.args[1], parsed.args[2]))
      {
         errx(1, "Error deleting configuration");
      }
   }
   else if (parsed.cmd->action == ACTION_CONF_LS)
   {
      if (pgvictoria_config_ls(parsed.args[0], parsed.args[1]))
      {
         exit(1);
      }
   }
   else
   {
      warnx("pgvictoria-cli: Unknown action");
      goto error;
   }

   if (config)
   {
      for (int i = 0; i < config->common.number_of_users; i++)
      {
         pgvictoria_cleanse(config->common.users[i].password, sizeof(config->common.users[i].password));
      }
   }

   if (resolved_config_path)
   {
      free(resolved_config_path);
   }
   if (resolved_users_path)
   {
      free(resolved_users_path);
   }

   pgvictoria_memory_destroy();
   pgvictoria_destroy_shared_memory(shmem, shmem_size);
   return 0;

error:
   if (config)
   {
      for (int i = 0; i < config->common.number_of_users; i++)
      {
         pgvictoria_cleanse(config->common.users[i].password, sizeof(config->common.users[i].password));
      }
   }

   if (resolved_config_path)
   {
      free(resolved_config_path);
   }
   if (resolved_users_path)
   {
      free(resolved_users_path);
   }

   pgvictoria_memory_destroy();
   pgvictoria_destroy_shared_memory(shmem, shmem_size);
   return 1;
}
