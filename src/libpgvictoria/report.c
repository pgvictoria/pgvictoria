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
 * be used to endorse or promote promote products derived from this software without specific
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

#include <report.h>
#include <deque.h>
#include <guc.h>
#include <html_report.h>
#include <markdown.h>
#include <security.h>
#include <message.h>
#include <postgresql.h>
#include <logging.h>
#include <network.h>
#include <json.h>
#include <value.h>
#include <utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <err.h>
#include <ctype.h>

/* libxml2 */
#include <libxml/HTMLtree.h>
#include <libxml/tree.h>

static uintptr_t
pgvictoria_json_get_typed_case_insensitive(struct json* baseline, char* key, enum value_type* type, char** matched_key)
{
   uintptr_t val = pgvictoria_json_get_typed(baseline, key, type);
   if (val)
   {
      if (matched_key)
      {
         *matched_key = key;
      }
      return val;
   }

   /* Try lowercase lookup to avoid iterator scan */
   char lower_key[128];
   size_t key_len = strlen(key);
   if (key_len < sizeof(lower_key))
   {
      for (size_t i = 0; i < key_len; i++)
      {
         lower_key[i] = tolower((unsigned char)key[i]);
      }
      lower_key[key_len] = '\0';

      if (strcmp(lower_key, key) != 0)
      {
         val = pgvictoria_json_get_typed(baseline, lower_key, type);
         if (val)
         {
            if (matched_key)
            {
               *matched_key = NULL;
            }
            return val;
         }
      }
   }
   return 0;
}

static int
detect_pg_version(void)
{
   FILE* fp = popen("pg_config --version", "r");
   int ver = pgvictoria_get_max_supported_version(); /* default fallback to latest */
   if (fp)
   {
      char buf[128];
      bool success = false;
      if (fgets(buf, sizeof(buf), fp))
      {
         if (pgvictoria_starts_with(buf, "PostgreSQL "))
         {
            int parsed_ver = pgvictoria_atoi(buf + 11);
            if (pgvictoria_is_version_supported(parsed_ver))
            {
               ver = parsed_ver;
               success = true;
            }
         }
      }
      int status = pclose(fp);
      if (status != 0 || !success)
      {
         ver = pgvictoria_get_max_supported_version();
      }
   }
   return ver;
}

static int
trim_and_extract_key_value(char* line, char* key, char* value)
{
   char* p = line;
   char* start_key;
   char* start_val;
   char* end_val;
   int key_len;
   int val_len;
   /* Skip leading whitespace */
   while (*p == ' ' || *p == '\t')
   {
      p++;
   }

   /* Skip comments or empty lines */
   if (*p == '#' || *p == '\0' || *p == '\r' || *p == '\n')
   {
      return 1;
   }

   start_key = p;
   /* Find the end of key (delimited by space, tab, or '=') */
   while (*p && *p != ' ' && *p != '\t' && *p != '=' && *p != '\r' && *p != '\n' && *p != '#')
   {
      p++;
   }

   key_len = p - start_key;
   if (key_len == 0)
   {
      return -3;
   }
   if (key_len >= 128)
   {
      return -4;
   }
   memcpy(key, start_key, key_len);
   key[key_len] = '\0';

   /* Skip whitespace to find divider or value */
   while (*p == ' ' || *p == '\t' || *p == '=')
   {
      p++;
   }

   /* If there is a comment at the end of the line, or it's empty, skip */
   if (*p == '\0' || *p == '\r' || *p == '\n' || *p == '#')
   {
      return -1;
   }

   /* Parse value, handling quotes */
   if (*p == '\'' || *p == '\"')
   {
      char quote_char = *p;
      start_val = p + 1;
      p++;
      while (*p && *p != quote_char && *p != '\r' && *p != '\n')
      {
         p++;
      }
      if (*p != quote_char)
      {
         return -2;
      }
      end_val = p;
   }
   else
   {
      start_val = p;
      while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n' && *p != '#')
      {
         p++;
      }
      end_val = p;
   }

   val_len = end_val - start_val;
   if (val_len <= 0)
   {
      return -1;
   }
   if (val_len >= 1024)
   {
      return -5;
   }
   memcpy(value, start_val, val_len);
   value[val_len] = '\0';

   return 0;
}

/*
 * Classify a single key/value against the baseline (Default / Modified / Custom)
 * and append it as a diff item to the report deque. Shared by both the file and
 * online datasources so the report is built identically regardless of source.
 * When skip_defaults is set, rows whose value matches the baseline default are not
 * added, so every renderer simply outputs whatever the deque contains.
 */
static void
report_add_diff_item(struct deque* items, struct json* baseline, char* key, char* val, int skip_defaults)
{
   /*
    * SHOW ALL returns an empty GUC setting as a zero-length column, which the
    * message decoder turns into a NULL data pointer. Coerce it to "" so the
    * comparison and the rendered value are well-defined (an empty string rather
    * than the undefined behaviour of printing a NULL pointer with "%s").
    */
   const char* cur_val = val ? val : "";

   enum value_type type;
   char* matched_key = NULL;
   uintptr_t baseline_val_ptr = pgvictoria_json_get_typed_case_insensitive(baseline, key, &type, &matched_key);

   const char* disp_key = matched_key ? matched_key : key;
   const char* def_val = "-";
   const char* status_text = "Custom";
   char* default_val_str = NULL;

   if (baseline_val_ptr)
   {
      struct value* v = NULL;
      if (!pgvictoria_value_create(type, baseline_val_ptr, &v))
      {
         if (v)
         {
            default_val_str = pgvictoria_value_to_string(v, FORMAT_TEXT, NULL, 0);
            if (default_val_str)
            {
               bool modified = false;

               def_val = default_val_str;
               pgvictoria_check_guc((char*)disp_key, type, default_val_str, (char*)cur_val, &modified);
               status_text = modified ? "Modified" : "Default";
            }
            pgvictoria_value_destroy(v);
         }
      }
   }
   else if (pgvictoria_json_contains_key(baseline, key))
   {
      /*
       * The key is in the baseline but its default is the empty string (e.g.
       * archive_cleanup_command). json_get_typed returns 0 for an empty value,
       * which is indistinguishable from "absent", so fall back to contains_key
       * and classify against an empty default instead of mislabelling it Custom.
       */
      def_val = "";
      status_text = (cur_val[0] == '\0') ? "Default" : "Modified";
   }

   /* In "changed" mode, drop settings whose value matches the baseline default. */
   if (skip_defaults && strcmp(status_text, "Default") == 0)
   {
      free(default_val_str);
      return;
   }

   struct pgvictoria_diff_item* item = malloc(sizeof(struct pgvictoria_diff_item));
   if (item)
   {
      snprintf(item->key, sizeof(item->key), "%s", disp_key);
      snprintf(item->baseline_val, sizeof(item->baseline_val), "%s", def_val);
      snprintf(item->current_val, sizeof(item->current_val), "%s", cur_val);
      snprintf(item->status, sizeof(item->status), "%s", status_text);

      pgvictoria_deque_add(items, NULL, (uintptr_t)item, ValueMem);
   }

   if (default_val_str)
   {
      free(default_val_str);
   }
}

/*
 * Render the diff deque as a plain-text table to the given stream. Shared by both
 * the file and online datasources; scope_label/scope_value name what was audited
 * ("File" plus a path, or "Online" plus a host:port). Every row in the deque is
 * printed; which rows the deque contains (all vs. non-default only) is decided
 * upstream at deque formation.
 */
static void
report_print_text(FILE* out, struct deque* items, int version, const char* scope_label, const char* scope_value)
{
   fprintf(out, "\nPostgreSQL %d Configuration Difference Report\n\n", version);
   if (scope_label && scope_value)
   {
      fprintf(out, "%-9s%s\n", scope_label, scope_value);
   }
   fprintf(out, "%-9sPostgreSQL %d\n", "Version", version);
   char* os_name = NULL;
   int k_major = 0, k_minor = 0, k_patch = 0;
   if (pgvictoria_os_kernel_version(&os_name, &k_major, &k_minor, &k_patch) == 0)
   {
      fprintf(out, "%-9s%s %d.%d.%d\n", "System", os_name, k_major, k_minor, k_patch);
      free(os_name);
   }
   fprintf(out, "===================================================================================================\n");
   fprintf(out, "%-40s | %-20s | %-20s | %-10s\n", "Configuration Key", "Baseline Default", "Current Value", "Status");
   fprintf(out, "---------------------------------------------------------------------------------------------------\n");

   struct deque_iterator* it = NULL;
   pgvictoria_deque_iterator_create(items, &it);
   while (pgvictoria_deque_iterator_next(it))
   {
      struct pgvictoria_diff_item* row = (struct pgvictoria_diff_item*)it->value->data;

      fprintf(out, "%-40s | %-20s | %-20s | %-10s\n", row->key, row->baseline_val, row->current_val, row->status);
   }
   pgvictoria_deque_iterator_destroy(it);
   fprintf(out, "===================================================================================================\n");
}

/*
 * Render the diff deque in the requested format to the requested destination.
 * Shared by both the file and online datasources after they build their (identical)
 * deque. An output path (-o) is required for every format; scope_label/scope_value
 * fill the report header/metadata. Returns 0 on success, otherwise 1.
 */
static int
report_render(struct deque* items, int version, enum pgvictoria_output_format format, char* output_file, const char* scope_label, const char* scope_value)
{
   if (output_file == NULL || output_file[0] == '\0')
   {
      /* cli.c enforces this up front; guard the library entry points too. */
      warnx("pgvictoria-cli: -o/--output is required");
      return 1;
   }

   char* resolved_output = NULL;
   if (pgvictoria_resolve_path(output_file, &resolved_output) != 0 || resolved_output == NULL)
   {
      resolved_output = strdup(output_file);
   }

   int ret = 0;

   if (format == PGVICTORIA_OUTPUT_MD)
   {
      ret = pgvictoria_generate_markdown_report(resolved_output, version, items, scope_label, scope_value);
   }
   else if (format == PGVICTORIA_OUTPUT_HTML)
   {
      ret = pgvictoria_generate_html_report(resolved_output, version, items, scope_label, scope_value);
   }
   else
   {
      /* Text to a file: create the parent directory like the renderers do. */
      pgvictoria_mkdir_parent(resolved_output);

      FILE* out = fopen(resolved_output, "w");
      if (!out)
      {
         warn("pgvictoria-cli: Cannot open output file %s", resolved_output);
         ret = 1;
      }
      else
      {
         report_print_text(out, items, version, scope_label, scope_value);
         fclose(out);
         printf("Report successfully generated to %s\n", resolved_output);
      }
   }

   if (resolved_output)
   {
      free(resolved_output);
   }

   return ret;
}

int
pgvictoria_report_online(int server, enum pgvictoria_output_format format, enum pgvictoria_report_type type, char* output_file)
{
   struct main_configuration* config = (struct main_configuration*)shmem;
   struct server* srv;
   SSL* ssl = NULL;
   int fd = -1;
   struct message* msg = NULL;
   struct query_response* version_response = NULL;
   struct query_response* all_response = NULL;
   int version = 0;
   struct json* baseline = NULL;
   int ret = 1;

   if (server < 0 || server >= config->common.number_of_servers)
   {
      warnx("Invalid server index");
      return 1;
   }

   srv = &config->common.servers[server];

   char* password_str = "";
   for (int i = 0; i < config->common.number_of_users; i++)
   {
      if (strcmp(config->common.users[i].username, srv->username) == 0)
      {
         password_str = config->common.users[i].password;
         break;
      }
   }
   if (password_str == NULL || *password_str == '\0')
   {
      if (config->common.number_of_users > 0)
      {
         password_str = config->common.users[0].password;
      }
   }

   if (pgvictoria_server_authenticate(server, "postgres", srv->username, password_str, false, &ssl, &fd) != AUTH_SUCCESS)
   {
      warnx("Failed to authenticate to server");
      goto error;
   }

   if (pgvictoria_create_query_message("SHOW server_version_num;", &msg) != MESSAGE_STATUS_OK)
   {
      goto error;
   }

   if (pgvictoria_query_execute(ssl, fd, msg, &version_response))
   {
      goto error;
   }

   pgvictoria_free_message(msg);
   msg = NULL;

   if (version_response && version_response->tuples && version_response->tuples->data[0])
   {
      char* ver_str = version_response->tuples->data[0];
      if (pgvictoria_is_number(ver_str, 10))
      {
         version = pgvictoria_atoi(ver_str) / 10000;
      }
   }

   baseline = pgvictoria_get_baseline(version);
   if (!baseline)
   {
      warnx("No baseline available for PostgreSQL version %d", version);
      goto error;
   }

   if (pgvictoria_create_query_message("SHOW ALL;", &msg) != MESSAGE_STATUS_OK)
   {
      goto error;
   }

   if (pgvictoria_query_execute(ssl, fd, msg, &all_response))
   {
      goto error;
   }

   /* Build the source-agnostic diff deque from the live configuration */
   struct deque* items = NULL;
   pgvictoria_deque_create(false, &items);

   int skip_defaults = (type == PGVICTORIA_REPORT_CHANGED);

   struct tuple* curr = all_response->tuples;
   while (curr)
   {
      report_add_diff_item(items, baseline, curr->data[0], curr->data[1], skip_defaults);
      curr = curr->next;
   }

   /* Render the deque in the requested format */
   char endpoint[MISC_LENGTH + 8];
   pgvictoria_snprintf(endpoint, sizeof(endpoint), "%s:%d", srv->host, srv->port);

   ret = report_render(items, version, format, output_file, "Online", endpoint);

   pgvictoria_deque_destroy(items);

error:
   if (msg)
   {
      pgvictoria_free_message(msg);
      msg = NULL;
   }
   if (version_response)
   {
      pgvictoria_free_query_response(version_response);
   }
   if (all_response)
   {
      pgvictoria_free_query_response(all_response);
   }
   if (baseline)
   {
      pgvictoria_json_destroy(baseline);
      baseline = NULL;
   }
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

static int
detect_pg_version_from_file(const char* filename)
{
   FILE* file = fopen(filename, "r");
   if (!file)
   {
      return 0;
   }
   char line[256];
   int version = 0;
   while (fgets(line, sizeof(line), file))
   {
      if (line[0] == '#')
      {
         char* p = strstr(line, "PostgreSQL ");
         if (p)
         {
            int v = pgvictoria_atoi(p + 11);
            if (pgvictoria_is_version_supported(v))
            {
               version = v;
               break;
            }
         }
         p = strstr(line, "version ");
         if (p)
         {
            int v = pgvictoria_atoi(p + 8);
            if (pgvictoria_is_version_supported(v))
            {
               version = v;
               break;
            }
         }
      }
   }
   fclose(file);
   return version;
}

int
pgvictoria_report_file(char* filename, enum pgvictoria_output_format format, enum pgvictoria_report_type type, char* output_file, int override_version)
{
   int version = 0;
   struct json* baseline = NULL;
   FILE* file = NULL;
   char* resolved_filename = NULL;
   int ret = 0;

   if (filename == NULL || strlen(filename) == 0 || strlen(filename) >= MAX_PATH)
   {
      warnx("pgvictoria-cli: Invalid or excessively long configuration filename");
      return 1;
   }

   if (pgvictoria_resolve_path(filename, &resolved_filename) != 0 || resolved_filename == NULL)
   {
      resolved_filename = strdup(filename);
   }

   if (pgvictoria_is_directory(resolved_filename))
   {
      warnx("pgvictoria-cli: %s is a directory, not a file", resolved_filename);
      free(resolved_filename);
      return 1;
   }

   if (!pgvictoria_is_file(resolved_filename))
   {
      warnx("pgvictoria-cli: %s is not a regular file", resolved_filename);
      free(resolved_filename);
      return 1;
   }

   if (pgvictoria_is_binary_file(resolved_filename))
   {
      warnx("pgvictoria-cli: Configuration file %s appears to be a binary file, rejecting", resolved_filename);
      free(resolved_filename);
      return 1;
   }

   if (pgvictoria_is_version_supported(override_version))
   {
      version = override_version;
   }
   else
   {
      /* Fallback to file comment detection */
      version = detect_pg_version_from_file(resolved_filename);

      /* Fallback to local system check if file comment check failed */
      if (!pgvictoria_is_version_supported(version))
      {
         version = detect_pg_version();
      }
   }

   baseline = pgvictoria_get_baseline(version);
   if (!baseline)
   {
      warnx("No baseline available for PostgreSQL version %d", version);
      free(resolved_filename);
      return 1;
   }

   file = fopen(resolved_filename, "r");
   if (!file)
   {
      warn("pgvictoria-cli: Cannot open configuration file %s", resolved_filename);
      pgvictoria_json_destroy(baseline);
      free(resolved_filename);
      return 1;
   }

   /* Parse file and build comparison list */
   struct deque* items = NULL;
   pgvictoria_deque_create(false, &items);

   int skip_defaults = (type == PGVICTORIA_REPORT_CHANGED);

   char line[1024];
   char key[128];
   char value[1024];

   int line_number = 0;
   while (fgets(line, sizeof(line), file))
   {
      line_number++;
      memset(key, 0, sizeof(key));
      memset(value, 0, sizeof(value));
      int status = trim_and_extract_key_value(line, key, value);

      if (status == 0)
      {
         report_add_diff_item(items, baseline, key, value, skip_defaults);
      }
      else if (status < 0)
      {
         if (status == -1)
         {
            warnx("Warning: Line %d: configuration parameter '%s' has no value, skipping", line_number, key);
         }
         else if (status == -2)
         {
            warnx("Warning: Line %d: configuration parameter '%s' has an unclosed quote, skipping", line_number, key);
         }
         else if (status == -3)
         {
            warnx("Warning: Line %d: invalid syntax, skipping line", line_number);
         }
         else if (status == -4)
         {
            warnx("Warning: Line %d: configuration parameter key name is too long, skipping", line_number);
         }
         else if (status == -5)
         {
            warnx("Warning: Line %d: configuration parameter value is too long, skipping", line_number);
         }
      }
   }

   fclose(file);
   pgvictoria_json_destroy(baseline);

   ret = report_render(items, version, format, output_file, "File", resolved_filename);

   /* Cleanup comparison list */
   pgvictoria_deque_destroy(items);

   free(resolved_filename);

   return ret;
}
