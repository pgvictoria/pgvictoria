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
#include <postgresql.h>
#include <json.h>
#include <utils.h>

/* baselines */
#include <pg14.h>
#include <pg15.h>
#include <pg16.h>
#include <pg17.h>
#include <pg18.h>
#include <pg19.h>

/* system */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct pg_version_baseline
{
   int version;
   const char* json_str;
};

static const char* search_dirs[] = {
   "/etc/pgvictoria/baselines",
   "./baselines"
};

/**
 * Helper function to retrieve supported PostgreSQL versions and baseline JSON strings
 * dynamically from a single central source of truth.
 *
 * @param index The index of the supported version (0-based)
 * @param json_str [out] Pointer to retrieve the JSON baseline string (can be NULL)
 * @return The version number (e.g. 14), or 0 if index is out of bounds.
 */
static int
pgvictoria_get_supported_version_info(int index, const char** json_str)
{
   const struct pg_version_baseline baselines[] = {
      {14, pg14_json},
      {15, pg15_json},
      {16, pg16_json},
      {17, pg17_json},
      {18, pg18_json},
      {19, pg19_json}};

   if (index >= 0 && index < (int)(sizeof(baselines) / sizeof(baselines[0])))
   {
      if (json_str)
      {
         *json_str = baselines[index].json_str;
      }
      return baselines[index].version;
   }
   return 0;
}

static char*
read_file_to_string(const char* filepath)
{
   FILE* f = fopen(filepath, "rb");
   if (!f)
   {
      return NULL;
   }

   if (fseek(f, 0, SEEK_END) != 0)
   {
      fclose(f);
      return NULL;
   }
   long size = ftell(f);
   if (size < 0)
   {
      fclose(f);
      return NULL;
   }
   if (fseek(f, 0, SEEK_SET) != 0)
   {
      fclose(f);
      return NULL;
   }

   char* content = malloc(size + 1);
   if (!content)
   {
      fclose(f);
      return NULL;
   }

   size_t read_bytes = fread(content, 1, size, f);
   content[read_bytes] = '\0';
   fclose(f);
   return content;
}

static char*
search_baseline_in_directory(const char* dirpath, int version)
{
   DIR* dir = opendir(dirpath);
   if (!dir)
   {
      return NULL;
   }

   struct dirent* entry;
   char* found_content = NULL;

   while ((entry = readdir(dir)) != NULL)
   {
      char* name = entry->d_name;
      if (pgvictoria_starts_with(name, "pg") && pgvictoria_ends_with(name, ".json"))
      {
         size_t len = strlen(name);
         if (len > 7) /* "pg" (2) + version (1+) + ".json" (5) */
         {
            char ver_str[32];
            size_t ver_len = len - 7;
            if (ver_len < sizeof(ver_str))
            {
               memcpy(ver_str, name + 2, ver_len);
               ver_str[ver_len] = '\0';
               int file_version = pgvictoria_atoi(ver_str);
               if (file_version == version)
               {
                  char filepath[1024];
                  snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, name);
                  found_content = read_file_to_string(filepath);
                  if (found_content)
                  {
                     break;
                  }
               }
            }
         }
      }
   }

   closedir(dir);
   return found_content;
}

static bool
is_baseline_in_directory(const char* dirpath, int version)
{
   DIR* dir = opendir(dirpath);
   if (!dir)
   {
      return false;
   }

   struct dirent* entry;
   bool found = false;

   while ((entry = readdir(dir)) != NULL)
   {
      char* name = entry->d_name;
      if (pgvictoria_starts_with(name, "pg") && pgvictoria_ends_with(name, ".json"))
      {
         size_t len = strlen(name);
         if (len > 7)
         {
            char ver_str[32];
            size_t ver_len = len - 7;
            if (ver_len < sizeof(ver_str))
            {
               memcpy(ver_str, name + 2, ver_len);
               ver_str[ver_len] = '\0';
               int file_version = pgvictoria_atoi(ver_str);
               if (file_version == version)
               {
                  found = true;
                  break;
               }
            }
         }
      }
   }

   closedir(dir);
   return found;
}

static char*
load_baseline_from_dirs(int version)
{
   char* content = NULL;
   char* env_dir = getenv("PGVICTORIA_BASELINES_DIR");
   if (env_dir)
   {
      content = search_baseline_in_directory(env_dir, version);
      if (content)
      {
         return content;
      }
   }

   for (size_t i = 0; i < sizeof(search_dirs) / sizeof(search_dirs[0]); i++)
   {
      content = search_baseline_in_directory(search_dirs[i], version);
      if (content)
      {
         return content;
      }
   }

   return NULL;
}

static bool
check_baseline_in_dirs(int version)
{
   char* env_dir = getenv("PGVICTORIA_BASELINES_DIR");
   if (env_dir)
   {
      if (is_baseline_in_directory(env_dir, version))
      {
         return true;
      }
   }

   for (size_t i = 0; i < sizeof(search_dirs) / sizeof(search_dirs[0]); i++)
   {
      if (is_baseline_in_directory(search_dirs[i], version))
      {
         return true;
      }
   }

   return false;
}

/**
 * Get the PostgreSQL baseline configuration for a specific version.
 * 
 * @param version The PostgreSQL version (e.g. 14, 15, 16, 17, 18, 19)
 * @return The JSON baseline object, or NULL if the version is not supported or parsing fails.
 */
struct json*
pgvictoria_get_baseline(int version)
{
   /* 1. Try loading dynamically from external JSON files */
   char* json_str = load_baseline_from_dirs(version);
   if (json_str)
   {
      struct json* baseline = NULL;
      if (pgvictoria_json_parse_string(json_str, &baseline) == 0)
      {
         free(json_str);
         return baseline;
      }
      free(json_str);
   }

   /* 2. Fallback to static compiled-in baselines */
   const char* static_json_str = NULL;
   for (int i = 0;; i++)
   {
      int v = pgvictoria_get_supported_version_info(i, &static_json_str);
      if (v == 0)
      {
         break;
      }
      if (v == version)
      {
         struct json* baseline = NULL;
         if (pgvictoria_json_parse_string((char*)static_json_str, &baseline) == 0)
         {
            return baseline;
         }
         break;
      }
   }
   return NULL;
}

bool
pgvictoria_is_version_supported(int version)
{
   /* 1. Check dynamic directory baselines */
   if (check_baseline_in_dirs(version))
   {
      return true;
   }

   /* 2. Check static compiled-in baselines */
   for (int i = 0;; i++)
   {
      int v = pgvictoria_get_supported_version_info(i, NULL);
      if (v == 0)
      {
         break;
      }
      if (v == version)
      {
         return true;
      }
   }
   return false;
}

int
pgvictoria_get_min_supported_version(void)
{
   return pgvictoria_get_supported_version_info(0, NULL);
}

int
pgvictoria_get_max_supported_version(void)
{
   int max_ver = 0;

   /* 1. Check static baselines */
   for (int i = 0;; i++)
   {
      int v = pgvictoria_get_supported_version_info(i, NULL);
      if (v == 0)
      {
         break;
      }
      if (v > max_ver)
      {
         max_ver = v;
      }
   }

   /* 2. Scan directories for larger versions */
   char* env_dir = getenv("PGVICTORIA_BASELINES_DIR");
   if (env_dir)
   {
      DIR* dir = opendir(env_dir);
      if (dir)
      {
         struct dirent* entry;
         while ((entry = readdir(dir)) != NULL)
         {
            char* name = entry->d_name;
            if (pgvictoria_starts_with(name, "pg") && pgvictoria_ends_with(name, ".json"))
            {
               size_t len = strlen(name);
               if (len > 7)
               {
                  char ver_str[32];
                  size_t ver_len = len - 7;
                  if (ver_len < sizeof(ver_str))
                  {
                     memcpy(ver_str, name + 2, ver_len);
                     ver_str[ver_len] = '\0';
                     int file_version = pgvictoria_atoi(ver_str);
                     if (file_version > max_ver)
                     {
                        max_ver = file_version;
                     }
                  }
               }
            }
         }
         closedir(dir);
      }
   }

   for (size_t i = 0; i < sizeof(search_dirs) / sizeof(search_dirs[0]); i++)
   {
      DIR* dir = opendir(search_dirs[i]);
      if (dir)
      {
         struct dirent* entry;
         while ((entry = readdir(dir)) != NULL)
         {
            char* name = entry->d_name;
            if (pgvictoria_starts_with(name, "pg") && pgvictoria_ends_with(name, ".json"))
            {
               size_t len = strlen(name);
               if (len > 7)
               {
                  char ver_str[32];
                  size_t ver_len = len - 7;
                  if (ver_len < sizeof(ver_str))
                  {
                     memcpy(ver_str, name + 2, ver_len);
                     ver_str[ver_len] = '\0';
                     int file_version = pgvictoria_atoi(ver_str);
                     if (file_version > max_ver)
                     {
                        max_ver = file_version;
                     }
                  }
               }
            }
         }
         closedir(dir);
      }
   }

   return max_ver > 0 ? max_ver : 18; /* default fallback if none found */
}
