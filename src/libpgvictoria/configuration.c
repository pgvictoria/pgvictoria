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
#include <aes.h>
#include <configuration.h>
#include <logging.h>
#include <security.h>
#include <shmem.h>
#include <utils.h>
#include <value.h>

/* system */
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define NAME "configuration"
#define LINE_LENGTH 512

static int extract_syskey_value(char* str, char** key, char** value);
static void extract_key_value(char* str, char** key, char** value);
static int as_int(char* str, int* i);
static int as_logging_type(char* str);
static int as_logging_level(char* str);
static int as_logging_mode(char* str);
static int as_hugepage(char* str);
static unsigned int as_update_process_title(char* str, unsigned int default_policy);
static int as_logging_rotation_size(char* str, int* size);
static int as_seconds(char* str, int* age, int default_age);
static int as_bytes(char* str, int* bytes, int default_bytes);

static bool transfer_configuration(struct main_configuration* config, struct main_configuration* reload);
static int copy_server(struct server* dst, struct server* src);
static void copy_user(struct user* dst, struct user* src);
static int restart_int(char* name, int e, int n);
static int restart_string(char* name, char* e, char* n);

static bool is_empty_string(char* s);
static int remove_leading_whitespace_and_comments(char* s, char** trimmed_line);

int
pgvictoria_init_main_configuration(void* shm)
{
   char* home_dir = NULL;
   struct main_configuration* config;

   config = (struct main_configuration*)shm;

   config->running = true;

   config->authentication_timeout = 5;

   home_dir = pgvictoria_get_home_directory();
   memcpy(&config->common.home_dir, home_dir, strlen(home_dir));

   config->backlog = 16;
   config->hugepage = HUGEPAGE_TRY;

   config->update_process_title = UPDATE_PROCESS_TITLE_VERBOSE;

   config->common.log_type = PGVICTORIA_LOGGING_TYPE_CONSOLE;
   config->common.log_level = PGVICTORIA_LOGGING_LEVEL_INFO;
   config->common.log_mode = PGVICTORIA_LOGGING_MODE_APPEND;
   atomic_init(&config->common.log_lock, STATE_FREE);

   free(home_dir);

   return 0;
}

/**
 *
 */
int
pgvictoria_read_main_configuration(void* shm, char* filename)
{
   FILE* file;
   char section[LINE_LENGTH];
   char line[LINE_LENGTH];
   char* trimmed_line = NULL;
   char* key = NULL;
   char* value = NULL;
   char* ptr = NULL;
   size_t max;
   struct main_configuration* config;
   int idx_server = 0;
   struct server srv = {0};

   file = fopen(filename, "r");

   if (!file)
   {
      return 1;
   }

   memset(&section, 0, LINE_LENGTH);
   config = (struct main_configuration*)shm;

   while (fgets(line, sizeof(line), file))
   {
      if (!is_empty_string(line))
      {
         if (!remove_leading_whitespace_and_comments(line, &trimmed_line))
         {
            if (is_empty_string(trimmed_line))
            {
               free(trimmed_line);
               trimmed_line = NULL;
               continue;
            }
         }
         else
         {
            goto error;
         }

         if (trimmed_line[0] == '[')
         {
            ptr = strchr(trimmed_line, ']');
            if (ptr)
            {
               memset(&section, 0, LINE_LENGTH);
               max = ptr - trimmed_line - 1;
               if (max > MISC_LENGTH - 1)
               {
                  max = MISC_LENGTH - 1;
               }
               memcpy(&section, trimmed_line + 1, max);
               if (strcmp(section, "pgvictoria"))
               {
                  if (idx_server > 0 && idx_server <= NUMBER_OF_SERVERS)
                  {
                     memcpy(&(config->common.servers[idx_server - 1]), &srv, sizeof(struct server));
                  }
                  else if (idx_server > NUMBER_OF_SERVERS)
                  {
                     warnx("Maximum number of servers exceeded");
                  }

                  memset(&srv, 0, sizeof(struct server));
                  memcpy(&srv.name, &section, strlen(section));

                  srv.primary = false;

                  idx_server++;
               }
            }
         }
         else
         {
            if (pgvictoria_starts_with(trimmed_line, "unix_socket_dir")
                || pgvictoria_starts_with(trimmed_line, "log_path")
                || pgvictoria_starts_with(trimmed_line, "pidfile"))
            {
               extract_syskey_value(trimmed_line, &key, &value);
            }
            else
            {
               extract_key_value(trimmed_line, &key, &value);
            }

            if (key && value)
            {
               bool unknown = false;

               /* printf("|%s|%s|\n", key, value); */

               if (!strcmp(key, "host"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->host, value, max);
                  }
                  else if (strlen(section) > 0)
                  {
                     max = strlen(section);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.host, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "port"))
               {
                  if (strlen(section) > 0)
                  {
                     if (as_int(value, &srv.port))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "user"))
               {
                  if (strlen(section) > 0)
                  {
                     max = strlen(section);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(&srv.name, section, max);
                     max = strlen(value);
                     if (max > MAX_USERNAME_LENGTH - 1)
                     {
                        max = MAX_USERNAME_LENGTH - 1;
                     }
                     memcpy(&srv.username, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "pidfile"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->pidfile, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "update_process_title"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     config->update_process_title = as_update_process_title(value, UPDATE_PROCESS_TITLE_VERBOSE);
                  }
                  else
                  {
                     unknown = false;
                  }
               }
               else if (!strcmp(key, "log_type"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     config->common.log_type = as_logging_type(value);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_level"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     config->common.log_level = as_logging_level(value);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_path"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->common.log_path, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_rotation_size"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     if (as_logging_rotation_size(value, &config->common.log_rotation_size))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_rotation_age"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     if (as_seconds(value, &config->common.log_rotation_age, PGVICTORIA_LOGGING_ROTATION_DISABLED))
                     {
                        unknown = true;
                     }
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_line_prefix"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->common.log_line_prefix, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "log_mode"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     config->common.log_mode = as_logging_mode(value);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "unix_socket_dir"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->unix_socket_dir, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "libev"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     max = strlen(value);
                     if (max > MISC_LENGTH - 1)
                     {
                        max = MISC_LENGTH - 1;
                     }
                     memcpy(config->libev, value, max);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else if (!strcmp(key, "hugepage"))
               {
                  if (!strcmp(section, "pgvictoria"))
                  {
                     config->hugepage = as_hugepage(value);
                  }
                  else
                  {
                     unknown = true;
                  }
               }
               else
               {
                  unknown = true;
               }

               if (unknown)
               {
                  warnx("Unknown: Section=%s, Key=%s, Value=%s", strlen(section) > 0 ? section : "<unknown>", key, value);
               }

               free(key);
               free(value);
               key = NULL;
               value = NULL;
            }
            else
            {
               warnx("Unknown: Section=%s, Line=%s", strlen(section) > 0 ? section : "<unknown>", line);

               free(key);
               free(value);
               key = NULL;
               value = NULL;
            }
         }
      }
      free(trimmed_line);
      trimmed_line = NULL;
   }

   if (strlen(srv.name) > 0)
   {
      memcpy(&(config->common.servers[idx_server - 1]), &srv, sizeof(struct server));
   }

   config->common.number_of_servers = idx_server;

   fclose(file);

   return 0;

error:

   free(trimmed_line);
   trimmed_line = NULL;
   if (file)
   {
      fclose(file);
   }

   return 1;
}

/**
 *
 */
int
pgvictoria_validate_main_configuration(void* shm)
{
   struct stat st;
   struct main_configuration* config;

   config = (struct main_configuration*)shm;

   if (strlen(config->host) == 0)
   {
      pgvictoria_log_fatal("No host defined");
      return 1;
   }

   if (strlen(config->unix_socket_dir) == 0)
   {
      pgvictoria_log_fatal("No unix_socket_dir defined");
      return 1;
   }

   if (stat(config->unix_socket_dir, &st) == 0 && S_ISDIR(st.st_mode))
   {
      /* Ok */
   }
   else
   {
      pgvictoria_log_fatal("unix_socket_dir is not a directory (%s)", config->unix_socket_dir);
      return 1;
   }

   if (config->backlog < 16)
   {
      config->backlog = 16;
   }

   if (config->common.number_of_servers <= 0)
   {
      pgvictoria_log_fatal("No servers defined");
      return 1;
   }

   for (int i = 0; i < config->common.number_of_servers; i++)
   {
      if (!strcmp(config->common.servers[i].name, "pgvictoria"))
      {
         pgvictoria_log_fatal("pgvictoria is a reserved word for a host");
         return 1;
      }

      if (!strcmp(config->common.servers[i].name, "all"))
      {
         pgvictoria_log_fatal("all is a reserved word for a host");
         return 1;
      }

      if (strlen(config->common.servers[i].host) == 0)
      {
         pgvictoria_log_fatal("No host defined for %s", config->common.servers[i].name);
         return 1;
      }

      if (config->common.servers[i].port == 0)
      {
         pgvictoria_log_fatal("No port defined for %s", config->common.servers[i].name);
         return 1;
      }

      if (strlen(config->common.servers[i].username) == 0)
      {
         pgvictoria_log_fatal("No user defined for %s", config->common.servers[i].name);
         return 1;
      }

   }

   return 0;
}

/**
 *
 */
int
pgvictoria_read_users_configuration(void* shm, char* filename)
{
   FILE* file;
   char line[LINE_LENGTH];
   char* trimmed_line = NULL;
   int index;
   char* master_key = NULL;
   char* username = NULL;
   char* password = NULL;
   char* decoded = NULL;
   size_t decoded_length = 0;
   char* ptr = NULL;
   struct main_configuration* config;

   file = fopen(filename, "r");

   if (!file)
   {
      goto error;
   }
   if (pgvictoria_get_master_key(&master_key))
   {
      goto masterkey;
   }

   index = 0;
   config = (struct main_configuration*)shm;

   while (fgets(line, sizeof(line), file))
   {

      if (!is_empty_string(line))
      {
         if (!remove_leading_whitespace_and_comments(line, &trimmed_line))
         {
            if (is_empty_string(trimmed_line))
            {
               free(trimmed_line);
               trimmed_line = NULL;
               continue;
            }
         }
         else
         {
            goto error;
         }

         ptr = strtok(trimmed_line, ":");

         username = ptr;

         ptr = strtok(NULL, ":");

         if (ptr == NULL)
         {
            goto error;
         }

         if (pgvictoria_base64_decode(ptr, strlen(ptr), (void**)&decoded, &decoded_length))
         {
            goto error;
         }

         if (pgvictoria_decrypt(decoded, decoded_length, master_key, &password, ENCRYPTION_AES_256_CBC))
         {
            goto error;
         }

         if (strlen(username) < MAX_USERNAME_LENGTH &&
             strlen(password) < MAX_PASSWORD_LENGTH)
         {
            memcpy(&config->common.users[index].username, username, strlen(username));
            memcpy(&config->common.users[index].password, password, strlen(password));
         }
         else
         {
            warnx("pgvictoria: Invalid USER entry");
            warnx("%s", line);
         }

         free(password);
         free(decoded);

         password = NULL;
         decoded = NULL;

         index++;

      }
      free(trimmed_line);
      trimmed_line = NULL;
   }

   config->common.number_of_users = index;

   if (config->common.number_of_users > NUMBER_OF_USERS)
   {
      goto above;
   }

   free(master_key);

   fclose(file);

   return 0;

error:

   free(trimmed_line);
   trimmed_line = NULL;
   free(master_key);
   free(password);
   free(decoded);

   if (file)
   {
      fclose(file);
   }

   return 1;

masterkey:

   free(master_key);
   free(password);
   free(decoded);

   if (file)
   {
      fclose(file);
   }

   return 2;

above:

   free(master_key);
   free(password);
   free(decoded);

   if (file)
   {
      fclose(file);
   }

   return 3;
}

/**
 *
 */
int
pgvictoria_validate_users_configuration(void* shm)
{
   struct main_configuration* config;

   config = (struct main_configuration*)shm;

   if (config->common.number_of_users <= 0)
   {
      pgvictoria_log_fatal("No users defined");
      return 1;
   }

   for (int i = 0; i < config->common.number_of_servers; i++)
   {
      bool found = false;

      for (int j = 0; !found && j < config->common.number_of_users; j++)
      {
         if (!strcmp(config->common.servers[i].username, config->common.users[j].username))
         {
            found = true;
         }
      }

      if (!found)
      {
         pgvictoria_log_fatal("Unknown user (\'%s\') defined for %s", config->common.servers[i].username, config->common.servers[i].name);
         return 1;
      }
   }

   return 0;
}

int
pgvictoria_reload_configuration(bool* restart)
{
   size_t reload_size;
   struct main_configuration* reload = NULL;
   struct main_configuration* config;

   config = (struct main_configuration*)shmem;

   *restart = false;

   pgvictoria_log_trace("Configuration: %s", config->common.configuration_path);
   pgvictoria_log_trace("Users: %s", config->common.users_path);

   reload_size = sizeof(struct main_configuration);

   if (pgvictoria_create_shared_memory(reload_size, HUGEPAGE_OFF, (void**)&reload))
   {
      goto error;
   }

   pgvictoria_init_main_configuration((void*)reload);

   if (pgvictoria_read_main_configuration((void*)reload, config->common.configuration_path))
   {
      goto error;
   }

   if (pgvictoria_read_users_configuration((void*)reload, config->common.users_path))
   {
      goto error;
   }

   if (pgvictoria_validate_main_configuration(reload))
   {
      goto error;
   }

   if (pgvictoria_validate_users_configuration(reload))
   {
      goto error;
   }

   *restart = transfer_configuration(config, reload);

   pgvictoria_destroy_shared_memory((void*)reload, reload_size);

   pgvictoria_log_debug("Reload: Success");

   return 0;

error:
   *restart = true;

   if (reload != NULL)
   {
      pgvictoria_destroy_shared_memory((void*)reload, reload_size);
   }

   pgvictoria_log_debug("Reload: Failure");

   return 1;
}

static void
extract_key_value(char* str, char** key, char** value)
{
   char* equal = NULL;
   char* end = NULL;
   char* ptr = NULL;
   char left[MISC_LENGTH];
   char right[MISC_LENGTH];
   bool start_left = false;
   bool start_right = false;
   int idx = 0;
   int i = 0;
   char c = 0;
   char* k = NULL;
   char* v = NULL;

   *key = NULL;
   *value = NULL;

   memset(left, 0, sizeof(left));
   memset(right, 0, sizeof(right));

   equal = strchr(str, '=');

   if (equal != NULL)
   {
      i = 0;
      while (true)
      {
         ptr = str + i;
         if (ptr != equal)
         {
            c = *(str + i);
            if (c == '\t' || c == ' ' || c == '\"' || c == '\'')
            {
               /* Skip */
            }
            else
            {
               start_left = true;
            }

            if (start_left)
            {
               left[idx] = c;
               idx++;
            }
         }
         else
         {
            break;
         }
         i++;
      }

      end = strchr(str, '\n');
      idx = 0;

      for (size_t i = 0; i < strlen(equal); i++)
      {
         ptr = equal + i;
         if (ptr != end)
         {
            c = *(ptr);
            if (c == '=' || c == ' ' || c == '\t' || c == '\"' || c == '\'')
            {
               /* Skip */
            }
            else
            {
               start_right = true;
            }

            if (start_right)
            {
               if (c != '#')
               {
                  right[idx] = c;
                  idx++;
               }
               else
               {
                  break;
               }
            }
         }
         else
         {
            break;
         }
      }

      for (int i = strlen(left); i >= 0; i--)
      {
         if (left[i] == '\t' || left[i] == ' ' || left[i] == '\0' || left[i] == '\"' || left[i] == '\'')
         {
            left[i] = '\0';
         }
         else
         {
            break;
         }
      }

      for (int i = strlen(right); i >= 0; i--)
      {
         if (right[i] == '\t' || right[i] == ' ' || right[i] == '\0' || right[i] == '\r' || right[i] == '\"' || right[i] == '\'')
         {
            right[i] = '\0';
         }
         else
         {
            break;
         }
      }

      k = calloc(1, strlen(left) + 1);

      if (k == NULL)
      {
         goto error;
      }

      v = calloc(1, strlen(right) + 1);

      if (v == NULL)
      {
         goto error;
      }

      memcpy(k, left, strlen(left));
      memcpy(v, right, strlen(right));

      *key = k;
      *value = v;
   }

   return;

error:

   free(k);
   free(v);
}

/**
 * Given a line of text extracts the key part and the value
 * and expands environment variables in the value (like $HOME).
 * Valid lines must have the form <key> = <value>.
 *
 * The key must be unquoted and cannot have any spaces
 * in front of it.
 *
 * The value will be extracted as it is without trailing and leading spaces.
 *
 * Comments on the right side of a value are allowed.
 *
 * Example of valid lines are:
 * <code>
 * foo = bar
 * foo=bar
 * foo=  bar
 * foo = "bar"
 * foo = 'bar'
 * foo = "#bar"
 * foo = '#bar'
 * foo = bar # bar set!
 * foo = bar# bar set!
 * </code>
 *
 * @param str the line of text incoming from the configuration file
 * @param key the pointer to where to store the key extracted from the line
 * @param value the pointer to where to store the value (as it is)
 * @returns 1 if unable to parse the line, 0 if everything is ok
 */
static int
extract_syskey_value(char* str, char** key, char** value)
{
   int c = 0;
   int offset = 0;
   int length = strlen(str);
   int d = length - 1;
   char* k = NULL;
   char* v = NULL;

   // the key does not allow spaces and is whatever is
   // on the left of the '='
   while (str[c] != ' ' && str[c] != '=' && c < length)
   {
      c++;
   }

   if (c >= length)
   {
      goto error;
   }

   for (int i = 0; i < c; i++)
   {
      k = pgvictoria_append_char(k, str[i]);
   }

   while (c < length && (str[c] == ' ' || str[c] == '\t' || str[c] == '=' || str[c] == '\r' || str[c] == '\n'))
   {
      c++;
   }

   // empty value
   if (c == length)
   {
      v = calloc(1, 1); // empty string
      *key = k;
      *value = v;
      return 0;
   }

   offset = c;

   while ((str[d] == ' ' || str[d] == '\t' || str[d] == '\r' || str[d] == '\n') && d > c)
   {
      d--;
   }

   for (int i = offset; i <= d; i++)
   {
      v = pgvictoria_append_char(v, str[i]);
   }

   char* resolved_path = NULL;

   if (pgvictoria_resolve_path(v, &resolved_path))
   {
      free(k);
      free(v);
      free(resolved_path);
      k = NULL;
      v = NULL;
      resolved_path = NULL;
      goto error;
   }

   free(v);
   v = resolved_path;

   *key = k;
   *value = v;
   return 0;

error:
   return 1;
}

static int
as_int(char* str, int* i)
{
   char* endptr;
   long val;

   errno = 0;
   val = strtol(str, &endptr, 10);

   if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0))
   {
      goto error;
   }

   if (str == endptr)
   {
      goto error;
   }

   if (*endptr != '\0')
   {
      goto error;
   }

   *i = (int)val;

   return 0;

error:

   errno = 0;

   return 1;
}

static int
as_logging_type(char* str)
{
   if (!strcasecmp(str, "console"))
   {
      return PGVICTORIA_LOGGING_TYPE_CONSOLE;
   }

   if (!strcasecmp(str, "file"))
   {
      return PGVICTORIA_LOGGING_TYPE_FILE;
   }

   if (!strcasecmp(str, "syslog"))
   {
      return PGVICTORIA_LOGGING_TYPE_SYSLOG;
   }

   return 0;
}

static int
as_logging_level(char* str)
{
   size_t size = 0;
   int debug_level = 1;
   char* debug_value = NULL;

   if (!strncasecmp(str, "debug", strlen("debug")))
   {
      if (strlen(str) > strlen("debug"))
      {
         size = strlen(str) - strlen("debug");
         debug_value = (char*)malloc(size + 1);

         if (debug_value == NULL)
         {
            goto done;
         }

         memset(debug_value, 0, size + 1);
         memcpy(debug_value, str + 5, size);
         if (as_int(debug_value, &debug_level))
         {
            // cannot parse, set it to 1
            debug_level = 1;
         }
         free(debug_value);
      }

      if (debug_level <= 1)
      {
         return PGVICTORIA_LOGGING_LEVEL_DEBUG1;
      }
      else if (debug_level == 2)
      {
         return PGVICTORIA_LOGGING_LEVEL_DEBUG2;
      }
      else if (debug_level == 3)
      {
         return PGVICTORIA_LOGGING_LEVEL_DEBUG3;
      }
      else if (debug_level == 4)
      {
         return PGVICTORIA_LOGGING_LEVEL_DEBUG4;
      }
      else if (debug_level >= 5)
      {
         return PGVICTORIA_LOGGING_LEVEL_DEBUG5;
      }
   }

   if (!strcasecmp(str, "info"))
   {
      return PGVICTORIA_LOGGING_LEVEL_INFO;
   }

   if (!strcasecmp(str, "warn"))
   {
      return PGVICTORIA_LOGGING_LEVEL_WARN;
   }

   if (!strcasecmp(str, "error"))
   {
      return PGVICTORIA_LOGGING_LEVEL_ERROR;
   }

   if (!strcasecmp(str, "fatal"))
   {
      return PGVICTORIA_LOGGING_LEVEL_FATAL;
   }

done:

   return PGVICTORIA_LOGGING_LEVEL_INFO;
}

static int
as_logging_mode(char* str)
{
   if (!strcasecmp(str, "a") || !strcasecmp(str, "append"))
   {
      return PGVICTORIA_LOGGING_MODE_APPEND;
   }

   if (!strcasecmp(str, "c") || !strcasecmp(str, "create"))
   {
      return PGVICTORIA_LOGGING_MODE_CREATE;
   }

   return PGVICTORIA_LOGGING_MODE_APPEND;
}

static int
as_hugepage(char* str)
{
   if (!strcasecmp(str, "off"))
   {
      return HUGEPAGE_OFF;
   }

   if (!strcasecmp(str, "try"))
   {
      return HUGEPAGE_TRY;
   }

   if (!strcasecmp(str, "on"))
   {
      return HUGEPAGE_ON;
   }

   return HUGEPAGE_OFF;
}

/**
 * Utility function to understand the setting for updating
 * the process title.
 *
 * @param str the value obtained by the configuration parsing
 * @param default_policy a value to set when the configuration cannot be
 * understood
 *
 * @return The policy
 */
static unsigned int
as_update_process_title(char* str, unsigned int default_policy)
{
   if (is_empty_string(str))
   {
      return default_policy;
   }

   if (!strncmp(str, "never", MISC_LENGTH) || !strncmp(str, "off", MISC_LENGTH))
   {
      return UPDATE_PROCESS_TITLE_NEVER;
   }
   else if (!strncmp(str, "strict", MISC_LENGTH))
   {
      return UPDATE_PROCESS_TITLE_STRICT;
   }
   else if (!strncmp(str, "minimal", MISC_LENGTH))
   {
      return UPDATE_PROCESS_TITLE_MINIMAL;
   }
   else if (!strncmp(str, "verbose", MISC_LENGTH) || !strncmp(str, "full", MISC_LENGTH))
   {
      return UPDATE_PROCESS_TITLE_VERBOSE;
   }

   // not a valid setting
   return default_policy;
}

/**
 * Parses a string to see if it contains
 * a valid value for log rotation size.
 * Returns 0 if parsing ok, 1 otherwise.
 *
 */
static int
as_logging_rotation_size(char* str, int* size)
{
   return as_bytes(str, size, PGVICTORIA_LOGGING_ROTATION_DISABLED);
}

/**
 * Parses an age string, providing the resulting value as seconds.
 * An age string is expressed by a number and a suffix that indicates
 * the multiplier. Accepted suffixes, case insensitive, are:
 * - s for seconds
 * - m for minutes
 * - h for hours
 * - d for days
 * - w for weeks
 *
 * The default is expressed in seconds.
 *
 * @param str the value to parse as retrieved from the configuration
 * @param age a pointer to the value that is going to store
 *        the resulting number of seconds
 * @param default_age a value to set when the parsing is unsuccesful

 */
static int
as_seconds(char* str, int* age, int default_age)
{
   int multiplier = 1;
   int index;
   char value[MISC_LENGTH];
   bool multiplier_set = false;
   int i_value = default_age;

   if (is_empty_string(str))
   {
      *age = default_age;
      return 0;
   }

   index = 0;
   for (size_t i = 0; i < strlen(str); i++)
   {
      if (isdigit(str[i]))
      {
         value[index++] = str[i];
      }
      else if (isalpha(str[i]) && multiplier_set)
      {
         // another extra char not allowed
         goto error;
      }
      else if (isalpha(str[i]) && !multiplier_set)
      {
         if (str[i] == 's' || str[i] == 'S')
         {
            multiplier = 1;
            multiplier_set = true;
         }
         else if (str[i] == 'm' || str[i] == 'M')
         {
            multiplier = 60;
            multiplier_set = true;
         }
         else if (str[i] == 'h' || str[i] == 'H')
         {
            multiplier = 3600;
            multiplier_set = true;
         }
         else if (str[i] == 'd' || str[i] == 'D')
         {
            multiplier = 24 * 3600;
            multiplier_set = true;
         }
         else if (str[i] == 'w' || str[i] == 'W')
         {
            multiplier = 24 * 3600 * 7;
            multiplier_set = true;
         }
      }
      else
      {
         // do not allow alien chars
         goto error;
      }
   }

   value[index] = '\0';
   if (!as_int(value, &i_value))
   {
      // sanity check: the value
      // must be a positive number!
      if (i_value >= 0)
      {
         *age = i_value * multiplier;
      }
      else
      {
         goto error;
      }

      return 0;
   }
   else
   {
error:
      *age = default_age;
      return 1;
   }
}

/**
 * Converts a "size string" into the number of bytes.
 *
 * Valid strings have one of the suffixes:
 * - b for bytes (default)
 * - k for kilobytes
 * - m for megabytes
 * - g for gigabytes
 *
 * The default is expressed always as bytes.
 * Uppercase letters work too.
 * If no suffix is specified, the value is expressed as bytes.
 *
 * @param str the string to parse (e.g., "2M")
 * @param bytes the value to set as result of the parsing stage
 * @param default_bytes the default value to set when the parsing cannot proceed
 * @return 1 if parsing is unable to understand the string, 0 is parsing is
 *         performed correctly (or almost correctly, e.g., empty string)
 */
static int
as_bytes(char* str, int* bytes, int default_bytes)
{
   int multiplier = 1;
   int index;
   char value[MISC_LENGTH];
   bool multiplier_set = false;
   int i_value = default_bytes;

   if (is_empty_string(str))
   {
      *bytes = default_bytes;
      return 0;
   }

   index = 0;
   for (size_t i = 0; i < strlen(str); i++)
   {
      if (isdigit(str[i]))
      {
         value[index++] = str[i];
      }
      else if (isalpha(str[i]) && multiplier_set)
      {
         // allow a 'B' suffix on a multiplier
         // like for instance 'MB', but don't allow it
         // for bytes themselves ('BB')
         if (multiplier == 1 || (str[i] != 'b' && str[i] != 'B'))
         {
            // another non-digit char not allowed
            goto error;
         }
      }
      else if (isalpha(str[i]) && !multiplier_set)
      {
         if (str[i] == 'M' || str[i] == 'm')
         {
            multiplier = 1024 * 1024;
            multiplier_set = true;
         }
         else if (str[i] == 'G' || str[i] == 'g')
         {
            multiplier = 1024 * 1024 * 1024;
            multiplier_set = true;
         }
         else if (str[i] == 'K' || str[i] == 'k')
         {
            multiplier = 1024;
            multiplier_set = true;
         }
         else if (str[i] == 'B' || str[i] == 'b')
         {
            multiplier = 1;
            multiplier_set = true;
         }
      }
      else
      {
         // do not allow alien chars
         goto error;
      }
   }

   value[index] = '\0';
   if (!as_int(value, &i_value))
   {
      // sanity check: the value
      // must be a positive number!
      if (i_value >= 0)
      {
         *bytes = i_value * multiplier;
      }
      else
      {
         goto error;
      }

      return 0;
   }
   else
   {
error:
      *bytes = default_bytes;
      return 1;
   }
}

static bool
transfer_configuration(struct main_configuration* config, struct main_configuration* reload)
{
   bool changed = false;

#ifdef HAVE_SYSTEMD
   sd_notify(0, "RELOADING=1");
#endif

   if (restart_string("host", config->host, reload->host))
   {
      changed = true;
   }
   if (restart_int("log_type", config->common.log_type, reload->common.log_type))
   {
      changed = true;
   }
   config->common.log_level = reload->common.log_level;

   if (strncmp(config->common.log_path, reload->common.log_path, MISC_LENGTH) ||
       config->common.log_rotation_size != reload->common.log_rotation_size ||
       config->common.log_rotation_age != reload->common.log_rotation_age ||
       config->common.log_mode != reload->common.log_mode)
   {
      pgvictoria_log_debug("Log restart triggered!");
      pgvictoria_stop_logging();
      config->common.log_rotation_size = reload->common.log_rotation_size;
      config->common.log_rotation_age = reload->common.log_rotation_age;
      config->common.log_mode = reload->common.log_mode;
      memcpy(config->common.log_line_prefix, reload->common.log_line_prefix, MISC_LENGTH);
      memcpy(config->common.log_path, reload->common.log_path, MISC_LENGTH);
      pgvictoria_start_logging();
   }

   config->authentication_timeout = reload->authentication_timeout;

   if (strcmp("", reload->pidfile))
   {
      restart_string("pidfile", config->pidfile, reload->pidfile);
   }

   if (restart_string("libev", config->libev, reload->libev))
   {
      changed = true;
   }
   config->backlog = reload->backlog;
   if (restart_int("hugepage", config->hugepage, reload->hugepage))
   {
      changed = true;
   }
   if (restart_int("update_process_title", config->update_process_title, reload->update_process_title))
   {
      changed = true;
   }
   if (restart_string("unix_socket_dir", config->unix_socket_dir, reload->unix_socket_dir))
   {
      changed = true;
   }

   for (int i = 0; i < NUMBER_OF_SERVERS; i++)
   {
      if (copy_server(&config->common.servers[i], &reload->common.servers[i]))
      {
         changed = true;
      }
   }
   if (restart_int("number_of_servers", config->common.number_of_servers, reload->common.number_of_servers))
   {
      changed = true;
   }

   for (int i = 0; i < NUMBER_OF_USERS; i++)
   {
      copy_user(&config->common.users[i], &reload->common.users[i]);
   }
   config->common.number_of_users = reload->common.number_of_users;

   return changed;
}

static int
copy_server(struct server* dst, struct server* src)
{
   bool changed = false;

   if (restart_string("name", &dst->name[0], &src->name[0]))
   {
      changed = true;
   }
   if (restart_string("host", &dst->host[0], &src->host[0]))
   {
      changed = true;
   }
   if (restart_int("port", dst->port, src->port))
   {
      changed = true;
   }
   if (restart_string("username", &dst->username[0], &src->username[0]))
   {
      changed = true;
   }

   if (changed)
   {
      return 1;
   }

   return 0;
}

static void
copy_user(struct user* dst, struct user* src)
{
   memcpy(&dst->username[0], &src->username[0], MAX_USERNAME_LENGTH);
   memcpy(&dst->password[0], &src->password[0], MAX_PASSWORD_LENGTH);
}

static int
restart_int(char* name, int e, int n)
{
   if (e != n)
   {
      pgvictoria_log_info("Restart required for %s - Existing %d New %d", name, e, n);
      return 1;
   }

   return 0;
}

static int
restart_string(char* name, char* e, char* n)
{
   if (strcmp(e, n))
   {
      pgvictoria_log_info("Restart required for %s - Existing %s New %s", name, e, n);
      return 1;
   }

   return 0;
}

static bool
is_empty_string(char* s)
{
   if (s == NULL)
   {
      return true;
   }

   if (!strcmp(s, ""))
   {
      return true;
   }

   for (size_t i = 0; i < strlen(s); i++)
   {
      if (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')
      {
         /* Ok */
      }
      else
      {
         return false;
      }
   }

   return true;
}

static int
remove_leading_whitespace_and_comments(char* s, char** trimmed_line)
{
   // Find the index of the first non-whitespace character
   int i = 0;
   int last_non_whitespace_index = -1;
   char* result = NULL; // Temporary variable to hold the trimmed line

   while (s[i] != '\0' && isspace(s[i]))
   {
      i++;
   }

   // Loop through the string starting from non-whitespace character
   for (; s[i] != '\0'; i++)
   {
      if (s[i] == ';' || s[i] == '#')
      {
         break; // Break loop if a comment character is encountered
      }
      if (!isspace(s[i]))
      {
         last_non_whitespace_index = i; // Update the index of the last non-whitespace character
      }
      result = pgvictoria_append_char(result, s[i]); // Append the current character to result
      if (result == NULL)
      {
         goto error;
      }
   }
   if (last_non_whitespace_index != -1)
   {
      result[last_non_whitespace_index + 1] = '\0'; // Null-terminate the string at the last non-whitespace character
   }

   *trimmed_line = result; // Assign result to trimmed_line

   return 0;

error:
   free(result); // Free memory in case of error
   *trimmed_line = NULL;
   return 1;
}
