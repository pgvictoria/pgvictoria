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

/* system */
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <configuration.h>

#define INPUT_BUFFER_SIZE   1024
#define MAX_LINE_LENGTH     4096
#define MAX_LINES           8192
#define PGVICTORIA_MAX_PATH 1024
#define MISC_LENGTH         128

/**
 * Prompt the user for input
 * @param prompt The prompt
 * @param default_value The default value
 * @param result The result buffer
 * @param result_size The result size
 * @return 0 upon success, 1 otherwise
 */
static int
prompt_input(const char* prompt, const char* default_value, char* result, size_t result_size)
{
   char buf[INPUT_BUFFER_SIZE];

   if (default_value != NULL && strlen(default_value) > 0)
   {
      printf("%s [%s]: ", prompt, default_value);
   }
   else
   {
      printf("%s: ", prompt);
   }

   memset(buf, 0, sizeof(buf));
   if (fgets(buf, sizeof(buf), stdin) == NULL)
   {
      return 1;
   }

   size_t len = strlen(buf);
   if (len > 0 && buf[len - 1] == '\n')
   {
      buf[len - 1] = '\0';
      len--;
   }

   if (len == 0 && default_value != NULL)
   {
      memset(result, 0, result_size);
      memcpy(result, default_value, MIN(result_size - 1, strlen(default_value)));
   }
   else if (len == 0 && default_value == NULL)
   {
      return 1;
   }
   else
   {
      memset(result, 0, result_size);
      memcpy(result, buf, MIN(result_size - 1, len));
   }

   return 0;
}

/**
 * Prompt the user for a yes/no response
 * @param prompt The prompt
 * @param default_yes The default response
 * @return true for yes, false for no
 */
static bool
prompt_yes_no(const char* prompt, bool default_yes)
{
   char buf[INPUT_BUFFER_SIZE];

   if (default_yes)
   {
      printf("%s [Y/n]: ", prompt);
   }
   else
   {
      printf("%s [y/N]: ", prompt);
   }

   memset(buf, 0, sizeof(buf));
   if (fgets(buf, sizeof(buf), stdin) == NULL)
   {
      return default_yes;
   }

   size_t len = strlen(buf);
   if (len > 0 && buf[len - 1] == '\n')
   {
      buf[len - 1] = '\0';
      len--;
   }

   if (len == 0)
   {
      return default_yes;
   }

   if (buf[0] == 'y' || buf[0] == 'Y')
   {
      return true;
   }
   else if (buf[0] == 'n' || buf[0] == 'N')
   {
      return false;
   }

   return default_yes;
}

/**
 * Write a section to the file
 * @param file The file
 * @param section The section
 */
static void
write_section(FILE* file, const char* section)
{
   fprintf(file, "[%s]\n", section);
}

/**
 * Write a key/value pair to the file
 * @param file The file
 * @param key The key
 * @param value The value
 */
static void
write_key_value(FILE* file, const char* key, const char* value)
{
   fprintf(file, "%s = %s\n", key, value);
}

/**
 * Initialize the configuration file
 * @param output_path The output path
 * @param quiet Quiet mode
 * @param force Force mode
 * @return 0 upon success, 1 otherwise
 */
int
pgvictoria_config_init(const char* output_path, bool quiet, bool force, enum config_target target)
{
   FILE* file = NULL;
   char host[MISC_LENGTH];
   char log_type[MISC_LENGTH];
   char log_level[MISC_LENGTH];
   char log_path[PGVICTORIA_MAX_PATH];
   char unix_socket_dir[MISC_LENGTH];
   struct stat st;
   char tmp_path[PGVICTORIA_MAX_PATH];
   time_t t;
   struct tm* tm_info;
   char date_str[64];

   snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", output_path);

   if (!quiet)
   {
      printf("pgvictoria configuration generator\n");
      printf("==================================\n\n");
   }

   if (stat(output_path, &st) == 0)
   {
      if (!force)
      {
         if (quiet)
         {
            warnx("Output file '%s' already exists. Use --force to overwrite.", output_path);
            return 1;
         }

         if (!prompt_yes_no("Output file already exists. Overwrite?", false))
         {
            printf("Aborted.\n");
            return 1;
         }
      }
   }

   if (!quiet)
   {
      if (target == TARGET_CLI)
      {
         printf("--- [pgvictoria-cli] section ---\n\n");
      }
      else
      {
         printf("--- [pgvictoria] section ---\n\n");
      }
   }

   if (target == TARGET_CLI)
   {
      if (quiet)
      {
         strcpy(host, "localhost");
         strcpy(log_type, "console");
         strcpy(log_level, "info");
         strcpy(log_path, "");
      }
      else
      {
         if (prompt_input("Host", "localhost", host, sizeof(host)))
         {
            warnx("Invalid input for host");
            goto error;
         }

         if (prompt_input("Log type (console, file, syslog)", "console", log_type, sizeof(log_type)))
         {
            warnx("Invalid input for log_type");
            goto error;
         }

         if (prompt_input("Log level (fatal, error, warn, info, debug, trace)", "info", log_level, sizeof(log_level)))
         {
            warnx("Invalid input for log_level");
            goto error;
         }

         if (prompt_input("Log path", "", log_path, sizeof(log_path)))
         {
            warnx("Invalid input for log_path");
            goto error;
         }
      }
   }
   else
   {
      if (quiet)
      {
         strcpy(host, "localhost");
         strcpy(log_type, "console");
         strcpy(log_level, "info");
         strcpy(log_path, "");
         strcpy(unix_socket_dir, "/tmp/");
      }
      else
      {
         if (prompt_input("Host (bind address)", "localhost", host, sizeof(host)))
         {
            warnx("Invalid input for host");
            goto error;
         }

         if (prompt_input("Log type (console, file, syslog)", "console", log_type, sizeof(log_type)))
         {
            warnx("Invalid input for log_type");
            goto error;
         }

         if (prompt_input("Log level (fatal, error, warn, info, debug, trace)", "info", log_level, sizeof(log_level)))
         {
            warnx("Invalid input for log_level");
            goto error;
         }

         if (prompt_input("Log path", "", log_path, sizeof(log_path)))
         {
            warnx("Invalid input for log_path");
            goto error;
         }

         if (prompt_input("Unix socket directory", "/tmp/", unix_socket_dir, sizeof(unix_socket_dir)))
         {
            warnx("Invalid input for unix_socket_dir");
            goto error;
         }
      }
   }

   file = fopen(tmp_path, "w");
   if (file == NULL)
   {
      warn("Could not open temp file '%s'", tmp_path);
      goto error;
   }

   t = time(NULL);
   tm_info = localtime(&t);
   strftime(date_str, sizeof(date_str), "%Y-%m-%d", tm_info);

   fprintf(file, "# generated by pgvictoria-config version %s\n", PGVICTORIA_VERSION);
   fprintf(file, "# on date %s\n\n", date_str);

   if (target == TARGET_CLI)
   {
      write_section(file, "pgvictoria-cli");
      write_key_value(file, "host", host);
      fprintf(file, "\n");
      write_key_value(file, "log_type", log_type);
      write_key_value(file, "log_level", log_level);
      if (strlen(log_path) > 0)
      {
         write_key_value(file, "log_path", log_path);
      }
      fprintf(file, "\n");
   }
   else
   {
      write_section(file, "pgvictoria");
      write_key_value(file, "host", host);
      fprintf(file, "\n");
      write_key_value(file, "log_type", log_type);
      write_key_value(file, "log_level", log_level);
      if (strlen(log_path) > 0)
      {
         write_key_value(file, "log_path", log_path);
      }
      fprintf(file, "\n");
      write_key_value(file, "unix_socket_dir", unix_socket_dir);
      fprintf(file, "\n");

      if (quiet)
      {
         write_section(file, "primary");
         write_key_value(file, "host", "localhost");
         write_key_value(file, "port", "5432");
         write_key_value(file, "user", "pgvictoria");
         fprintf(file, "\n");
      }
      else
      {
         while (prompt_yes_no("\nAdd a PostgreSQL server?", true))
         {
            char section_name[MISC_LENGTH];
            char server_host[MISC_LENGTH];
            char server_port[MISC_LENGTH];
            char server_user[MISC_LENGTH];

            printf("\n--- Server section ---\n\n");

            if (prompt_input("Section name", "primary", section_name, sizeof(section_name)))
            {
               warnx("Invalid input for section name");
               continue;
            }

            if (prompt_input("Host", "localhost", server_host, sizeof(server_host)))
            {
               warnx("Invalid input for server host");
               continue;
            }

            if (prompt_input("Port", "5432", server_port, sizeof(server_port)))
            {
               warnx("Invalid input for server port");
               continue;
            }

            if (prompt_input("User", "pgvictoria", server_user, sizeof(server_user)))
            {
               warnx("Invalid input for server user");
               continue;
            }

            write_section(file, section_name);
            write_key_value(file, "host", server_host);
            write_key_value(file, "port", server_port);
            write_key_value(file, "user", server_user);
            fprintf(file, "\n");
         }
      }
   }

   fflush(file);
#ifndef _WIN32
   fsync(fileno(file));
#endif
   fclose(file);
   file = NULL;

   chmod(tmp_path, S_IRUSR | S_IWUSR);

   if (rename(tmp_path, output_path) != 0)
   {
      warn("Could not rename %s to %s", tmp_path, output_path);
      unlink(tmp_path);
      goto error;
   }

   if (!quiet)
   {
      printf("\nConfiguration written to: %s\n", output_path);
   }

   return 0;

error:

   if (file != NULL)
   {
      fclose(file);
      unlink(tmp_path);
   }

   return 1;
}

/**
 * Trim whitespace from a string
 * @param str The string
 * @return The trimmed string
 */
static char*
trim(char* str)
{
   char* end;

   while (isspace((unsigned char)*str))
   {
      str++;
   }

   if (*str == '\0')
   {
      return str;
   }

   end = str + strlen(str) - 1;
   while (end > str && isspace((unsigned char)*end))
   {
      end--;
   }

   *(end + 1) = '\0';
   return str;
}

/**
 * Get a configuration value
 * @param file_path The file path
 * @param section The section
 * @param key The key
 * @return 0 upon success, 1 otherwise
 */
int
pgvictoria_config_get(const char* file_path, const char* section, const char* key)
{
   FILE* file = NULL;
   char line[MAX_LINE_LENGTH];
   bool in_section = false;
   char section_header[MISC_LENGTH];

   file = fopen(file_path, "r");
   if (file == NULL)
   {
      warnx("Could not open file: %s", file_path);
      goto error;
   }

   snprintf(section_header, sizeof(section_header), "[%s]", section);

   while (fgets(line, sizeof(line), file) != NULL)
   {
      char* trimmed = trim(line);

      if (trimmed[0] == '#' || trimmed[0] == ';' || trimmed[0] == '\0')
      {
         continue;
      }

      if (trimmed[0] == '[')
      {
         char* bracket_end = strchr(trimmed, ']');
         if (bracket_end)
         {
            *(bracket_end + 1) = '\0';
         }

         if (!strcmp(trimmed, section_header))
         {
            in_section = true;
         }
         else if (in_section)
         {
            break;
         }
         continue;
      }

      if (in_section)
      {
         char* eq = strchr(trimmed, '=');
         if (eq != NULL)
         {
            *eq = '\0';
            char* found_key = trim(trimmed);
            char* found_value = trim(eq + 1);

            char* nl = strchr(found_value, '\n');
            if (nl)
            {
               *nl = '\0';
            }

            char* comment = strchr(found_value, '#');
            char* semicolon_comment = strchr(found_value, ';');

            if (semicolon_comment != NULL && (comment == NULL || semicolon_comment < comment))
            {
               comment = semicolon_comment;
            }

            if (comment != NULL)
            {
               *comment = '\0';
               found_value = trim(found_value);
            }

            if (!strcmp(found_key, key))
            {
               printf("%s\n", found_value);
               fclose(file);
               return 0;
            }
         }
      }
   }

   warnx("Key '%s' not found in section [%s]", key, section);

error:

   if (file != NULL)
   {
      fclose(file);
   }

   return 1;
}

/**
 * Set a configuration value
 * @param file_path The file path
 * @param section The section
 * @param key The key
 * @param value The value
 * @param comment The optional comment
 * @return 0 upon success, 1 otherwise
 */
int
pgvictoria_config_set(const char* file_path, const char* section, const char* key, const char* value, const char* comment)
{
   FILE* file = NULL;
   char* lines[MAX_LINES];
   int line_count = 0;
   char line_buf[MAX_LINE_LENGTH];
   char section_header[MISC_LENGTH];
   int section_start = -1;
   int section_end = -1;
   int key_line = -1;
   bool key_found = false;
   bool section_found = false;

   memset(lines, 0, sizeof(lines));

   snprintf(section_header, sizeof(section_header), "[%s]", section);

   file = fopen(file_path, "r");
   if (file != NULL)
   {
      while (fgets(line_buf, sizeof(line_buf), file) != NULL && line_count < MAX_LINES)
      {
         lines[line_count++] = strdup(line_buf);
      }
      fclose(file);
      file = NULL;
   }

   for (int i = 0; i < line_count; i++)
   {
      char temp[MAX_LINE_LENGTH];
      strcpy(temp, lines[i]);
      char* trimmed = trim(temp);

      if (trimmed[0] == '#' || trimmed[0] == ';' || trimmed[0] == '\0')
      {
         continue;
      }

      if (trimmed[0] == '[')
      {
         char* bracket_end = strchr(trimmed, ']');
         if (bracket_end)
         {
            *(bracket_end + 1) = '\0';
         }

         if (!strcmp(trimmed, section_header))
         {
            section_found = true;
            section_start = i;
            section_end = line_count;
         }
         else if (section_found && section_end == line_count)
         {
            section_end = i;
         }
      }

      if (section_found && !key_found && i > section_start && (section_end == line_count || i < section_end))
      {
         char key_temp[MAX_LINE_LENGTH];
         strcpy(key_temp, lines[i]);
         char* kt = trim(key_temp);
         if (kt[0] != '#' && kt[0] != ';' && kt[0] != '[' && kt[0] != '\0')
         {
            char* eq = strchr(kt, '=');
            if (eq != NULL)
            {
               *eq = '\0';
               char* found_key = trim(kt);
               if (!strcmp(found_key, key))
               {
                  key_found = true;
                  key_line = i;
               }
            }
         }
      }
   }

   if (key_found)
   {
      free(lines[key_line]);
      char new_line[MAX_LINE_LENGTH];
      if (comment != NULL && strlen(comment) > 0)
      {
         snprintf(new_line, sizeof(new_line), "%s = %s # %s\n", key, value, comment);
      }
      else
      {
         snprintf(new_line, sizeof(new_line), "%s = %s\n", key, value);
      }
      lines[key_line] = strdup(new_line);
   }
   else if (section_found)
   {
      int insert_at = section_end;
      for (int i = section_end - 1; i > section_start; i--)
      {
         char check_temp[MAX_LINE_LENGTH];
         strcpy(check_temp, lines[i]);
         if (trim(check_temp)[0] != '\0')
         {
            insert_at = i + 1;
            break;
         }
      }
      for (int i = line_count; i > insert_at; i--)
      {
         lines[i] = lines[i - 1];
      }
      char new_line[MAX_LINE_LENGTH];
      if (comment != NULL && strlen(comment) > 0)
      {
         snprintf(new_line, sizeof(new_line), "%s = %s # %s\n", key, value, comment);
      }
      else
      {
         snprintf(new_line, sizeof(new_line), "%s = %s\n", key, value);
      }
      lines[insert_at] = strdup(new_line);
      line_count++;
   }
   else
   {
      if (line_count > 0 && strlen(lines[line_count - 1]) > 0 && lines[line_count - 1][strlen(lines[line_count - 1]) - 1] == '\n')
      {
         char last_line[MAX_LINE_LENGTH];
         strcpy(last_line, lines[line_count - 1]);
         if (trim(last_line)[0] != '\0')
         {
            lines[line_count++] = strdup("\n");
         }
      }
      char new_section[MISC_LENGTH];
      snprintf(new_section, sizeof(new_section), "[%s]\n", section);
      lines[line_count++] = strdup(new_section);
      char new_line[MAX_LINE_LENGTH];
      if (comment != NULL && strlen(comment) > 0)
      {
         snprintf(new_line, sizeof(new_line), "%s = %s # %s\n", key, value, comment);
      }
      else
      {
         snprintf(new_line, sizeof(new_line), "%s = %s\n", key, value);
      }
      lines[line_count++] = strdup(new_line);
   }

   char tmp_path[PGVICTORIA_MAX_PATH];
   snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", file_path);
   file = fopen(tmp_path, "w");
   if (file == NULL)
   {
      warn("Could not open temp file");
      goto error;
   }
   for (int i = 0; i < line_count; i++)
   {
      fputs(lines[i], file);
   }
   fflush(file);
#ifndef _WIN32
   fsync(fileno(file));
#endif
   fclose(file);
   file = NULL;

   chmod(tmp_path, S_IRUSR | S_IWUSR);

   if (rename(tmp_path, file_path) != 0)
   {
      warn("Could not rename %s to %s", tmp_path, file_path);
      unlink(tmp_path);
      goto error;
   }

   for (int i = 0; i < line_count; i++)
   {
      free(lines[i]);
   }
   return 0;

error:
   if (file != NULL)
   {
      fclose(file);
      unlink(tmp_path);
   }
   for (int i = 0; i < line_count; i++)
   {
      free(lines[i]);
   }
   return 1;
}

/**
 * Delete a configuration section or key
 * @param file_path The file path
 * @param section The section
 * @param key The key
 * @return 0 upon success, 1 otherwise
 */
int
pgvictoria_config_del(const char* file_path, const char* section, const char* key)
{
   FILE* file = NULL;
   char* lines[MAX_LINES];
   int line_count = 0;
   char line_buf[MAX_LINE_LENGTH];
   char section_header[MISC_LENGTH];
   int section_start = -1;
   int section_end = -1;
   int key_line = -1;
   bool section_found = false;
   bool key_found = false;

   memset(lines, 0, sizeof(lines));
   snprintf(section_header, sizeof(section_header), "[%s]", section);

   file = fopen(file_path, "r");
   if (file == NULL)
   {
      warnx("Could not open file: %s", file_path);
      goto error;
   }
   while (fgets(line_buf, sizeof(line_buf), file) != NULL && line_count < MAX_LINES)
   {
      lines[line_count++] = strdup(line_buf);
   }
   fclose(file);
   file = NULL;

   for (int i = 0; i < line_count; i++)
   {
      char temp[MAX_LINE_LENGTH];
      strcpy(temp, lines[i]);
      char* trimmed = trim(temp);
      if (trimmed[0] == '[')
      {
         char* bracket_end = strchr(trimmed, ']');
         if (bracket_end)
         {
            *(bracket_end + 1) = '\0';
         }
         if (!strcmp(trimmed, section_header))
         {
            section_found = true;
            section_start = i;
            section_end = line_count;
         }
         else if (section_found && section_end == line_count)
         {
            section_end = i;
         }
      }
      if (section_found && key != NULL && !key_found && i > section_start && (section_end == line_count || i < section_end))
      {
         char key_temp[MAX_LINE_LENGTH];
         strcpy(key_temp, lines[i]);
         char* kt = trim(key_temp);
         if (kt[0] != '#' && kt[0] != ';' && kt[0] != '[' && kt[0] != '\0')
         {
            char* eq = strchr(kt, '=');
            if (eq != NULL)
            {
               *eq = '\0';
               char* found_key = trim(kt);
               if (!strcmp(found_key, key))
               {
                  key_found = true;
                  key_line = i;
               }
            }
         }
      }
   }

   if (!section_found)
   {
      warnx("Section [%s] not found", section);
      goto error;
   }
   if (key != NULL && !key_found)
   {
      warnx("Key '%s' not found in section [%s]", key, section);
      goto error;
   }

   char tmp_path[PGVICTORIA_MAX_PATH];
   snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", file_path);
   file = fopen(tmp_path, "w");
   if (file == NULL)
   {
      warn("Could not open temp file");
      goto error;
   }
   for (int i = 0; i < line_count; i++)
   {
      if (key == NULL)
      {
         if (i >= section_start && i < section_end)
         {
            continue;
         }
      }
      else
      {
         if (i == key_line)
         {
            continue;
         }
      }
      fputs(lines[i], file);
   }
   fflush(file);
#ifndef _WIN32
   fsync(fileno(file));
#endif
   fclose(file);
   file = NULL;
   if (rename(tmp_path, file_path) != 0)
   {
      warn("Could not rename %s to %s", tmp_path, file_path);
      unlink(tmp_path);
      goto error;
   }
   for (int i = 0; i < line_count; i++)
   {
      free(lines[i]);
   }
   return 0;

error:
   if (file != NULL)
   {
      fclose(file);
      unlink(tmp_path);
   }
   for (int i = 0; i < line_count; i++)
   {
      free(lines[i]);
   }
   return 1;
}

/**
 * List configuration sections or keys
 * @param file_path The file path
 * @param section The section
 * @return 0 upon success, 1 otherwise
 */
int
pgvictoria_config_ls(const char* file_path, const char* section)
{
   FILE* file = NULL;
   char line[MAX_LINE_LENGTH];
   bool in_section = false;
   char section_header[MISC_LENGTH];

   file = fopen(file_path, "r");
   if (file == NULL)
   {
      warnx("Could not open file: %s", file_path);
      goto error;
   }
   if (section != NULL)
   {
      snprintf(section_header, sizeof(section_header), "[%s]", section);
   }
   while (fgets(line, sizeof(line), file) != NULL)
   {
      char* trimmed = trim(line);
      if (trimmed[0] == '\0')
      {
         continue;
      }
      if (trimmed[0] == '[')
      {
         char temp[MAX_LINE_LENGTH];
         strcpy(temp, trimmed);
         char* bracket_end = strchr(temp, ']');
         if (bracket_end)
         {
            *(bracket_end + 1) = '\0';
         }
         if (section == NULL)
         {
            char* s = temp + 1;
            char* end = strchr(s, ']');
            if (end)
            {
               *end = '\0';
            }
            printf("%s\n", s);
         }
         else
         {
            if (!strcmp(temp, section_header))
            {
               in_section = true;
            }
            else if (in_section)
            {
               break;
            }
         }
         continue;
      }
      if (in_section && section != NULL)
      {
         if (trimmed[0] == '#' || trimmed[0] == ';')
         {
            continue;
         }
         char* eq = strchr(trimmed, '=');
         if (eq != NULL)
         {
            *eq = '\0';
            printf("%s\n", trim(trimmed));
         }
      }
   }
   fclose(file);
   return 0;

error:
   if (file != NULL)
   {
      fclose(file);
   }
   return 1;
}
