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
#include <aes.h>
#include <cmd.h>
#include <json.h>
#include <logging.h>
#include <security.h>
#include <utils.h>
#include <utf8.h>
#include <value.h>

/* system */
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <openssl/rand.h>

#define NAME                          "admin"
#define DEFAULT_PASSWORD_LENGTH       64
#define PBKDF2_SALT_LENGTH            16

#define MIN_MASTER_KEY_CHARS          8
#define MAX_PASSWORD_CHARS            256

#define MANAGEMENT_OUTPUT_FORMAT_TEXT 1
#define MANAGEMENT_OUTPUT_FORMAT_JSON 2

#define MANAGEMENT_MASTER_KEY         100
#define MANAGEMENT_ADD_USER           101
#define MANAGEMENT_UPDATE_USER        102
#define MANAGEMENT_REMOVE_USER        103
#define MANAGEMENT_LIST_USERS         104

static char CHARS[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                       'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                       '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                       '!', '@', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', '{', ']', '}', '\\', '|', ':',
                       '\'', '\"', ',', '<', '.', '>', '/', '?'};

static int master_key(char* password, bool generate_pwd, int pwd_length, int output_format);
static bool is_valid_key(char* key);
static int add_user(char* users_path, char* username, char* password, bool generate_pwd, int pwd_length, int32_t output_format);
static int update_user(char* users_path, char* username, char* password, bool generate_pwd, int pwd_length, int32_t output_format);
static int remove_user(char* users_path, char* username, int32_t output_format);
static int list_users(char* users_path, int32_t output_format);
static char* generate_password(int pwd_length);
static int create_response(char* users_path, struct json* json, struct json** response);

/* Local JSON management helpers */
static int management_create_header(int32_t action, int32_t output_format, struct json** json);
static int management_create_outcome_success(struct json* json, struct timespec start_t, struct timespec end_t, struct json** outcome);
static int management_create_outcome_failure(struct json* json, int32_t error, char* workflow, struct json** outcome);

// clang-format off
struct pgvictoria_command command_table[] =
{
   {
      .command = "master-key",
      .subcommand = "",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_MASTER_KEY,
      .log_message = "<master-key>",
   },
   {
      .command = "user",
      .subcommand = "add",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_ADD_USER,
      .log_message = "<user add> [%s]",
   },
   {
      .command = "user",
      .subcommand = "edit",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_UPDATE_USER,
      .log_message = "<user edit> [%s]",
   },
   {
      .command = "user",
      .subcommand = "del",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_REMOVE_USER,
      .log_message = "<user del> [%s]",
   },
   {
      .command = "user",
      .subcommand = "ls",
      .accepted_argument_count = {0},
      .deprecated = false,
      .action = MANAGEMENT_LIST_USERS,
      .log_message = "<user ls>",
   },
};
// clang-format on

static void
version(void)
{
   printf("pgvictoria-admin %s\n", VERSION);
   exit(EXIT_SUCCESS);
}

static void
usage(void)
{
   printf("pgvictoria-admin %s\n", VERSION);
   printf("  Administration utility for pgvictoria\n");
   printf("\n");

   printf("Usage:\n");
   printf("  pgvictoria-admin [ -f FILE ] [ COMMAND ] \n");
   printf("\n");
   printf("Options:\n");
   printf("  -f, --file FILE          Set the path to a user file\n");
   printf("  -U, --user USER          Set the user name\n");
   printf("  -P, --password PASSWORD  Set the password for the user\n");
   printf("  -g, --generate           Generate a password\n");
   printf("  -l, --length             Password length\n");
   printf("  -V, --version            Display version information\n");
   printf("  -F, --format text|json   Set the output format\n");
   printf("  -?, --help               Display help\n");
   printf("\n");
   printf("Commands:\n");
   printf("  master-key               Create or update the master key\n");
   printf("  user <subcommand>        Manage a specific user, where <subcommand> can be\n");
   printf("                           - add  to add a new user\n");
   printf("                           - del  to remove an existing user\n");
   printf("                           - edit to change the password for an existing user\n");
   printf("                           - ls   to list all available users\n");
   printf("\n");
   printf("pgvictoria: %s\n", PGVICTORIA_HOMEPAGE);
   printf("Report bugs: %s\n", PGVICTORIA_ISSUES);
}

int
main(int argc, char** argv)
{
   char* username = NULL;
   char* password = NULL;
   char* file_path = NULL;
   bool generate_pwd = false;
   int pwd_length = DEFAULT_PASSWORD_LENGTH;
   size_t command_count = sizeof(command_table) / sizeof(struct pgvictoria_command);
   struct pgvictoria_parsed_command parsed = {.cmd = NULL, .args = {0}};
   int32_t output_format = MANAGEMENT_OUTPUT_FORMAT_TEXT;
   int num_results = 0;
   char* filepath = NULL;
   int optind = 0;
   int num_options = 0;

   cli_option options[] = {
      {"U", "user", true},
      {"P", "password", true},
      {"f", "file", true},
      {"g", "generate", false},
      {"l", "length", true},
      {"V", "version", false},
      {"F", "format", true},
      {"?", "help", false},
   };

   // Disable stdout buffering (i.e. write to stdout immediately).
   setbuf(stdout, NULL);

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
      else if (pgvictoria_compare_string(optname, "U") || pgvictoria_compare_string(optname, "user"))
      {
         username = optarg;
      }
      else if (pgvictoria_compare_string(optname, "P") || pgvictoria_compare_string(optname, "password"))
      {
         password = optarg;
      }
      else if (pgvictoria_compare_string(optname, "f") || pgvictoria_compare_string(optname, "file"))
      {
         file_path = optarg;
      }
      else if (pgvictoria_compare_string(optname, "g") || pgvictoria_compare_string(optname, "generate"))
      {
         generate_pwd = true;
      }
      else if (pgvictoria_compare_string(optname, "l") || pgvictoria_compare_string(optname, "length"))
      {
         char* endptr = NULL;
         long val;
         errno = 0;
         val = strtol(optarg, &endptr, 10);
         if (errno != 0 || endptr == optarg || *endptr != '\0' || val <= 0 || val > 1024)
         {
            warnx("pgvictoria-admin: Invalid password length: %s", optarg);
            exit(1);
         }
         pwd_length = (int)val;
      }
      else if (pgvictoria_compare_string(optname, "V") || pgvictoria_compare_string(optname, "version"))
      {
         version();
      }
      else if (pgvictoria_compare_string(optname, "F") || pgvictoria_compare_string(optname, "format"))
      {
         if (!strncmp(optarg, "json", MISC_LENGTH))
         {
            output_format = MANAGEMENT_OUTPUT_FORMAT_JSON;
         }
         else if (!strncmp(optarg, "text", MISC_LENGTH))
         {
            output_format = MANAGEMENT_OUTPUT_FORMAT_TEXT;
         }
         else
         {
            warnx("pgvictoria-admin: Invalid output format");
            exit(1);
         }
      }
      else if (pgvictoria_compare_string(optname, "?") || pgvictoria_compare_string(optname, "help"))
      {
         usage();
         exit(0);
      }
   }

   if (getuid() == 0)
   {
      errx(1, "pgvictoria: Using the root account is not allowed");
   }

   if (!parse_command(argc, argv, optind, &parsed, command_table, command_count))
   {
      usage();
      goto error;
   }

   if (parsed.cmd->action == MANAGEMENT_MASTER_KEY)
   {
      if (master_key(password, generate_pwd, pwd_length, output_format))
      {
         errx(1, "Cannot generate master key");
      }
   }
   else
   {
      if (file_path == NULL)
      {
         errx(1, "Missing file argument");
      }

      if (parsed.cmd->action == MANAGEMENT_ADD_USER)
      {
         if (add_user(file_path, username, password, generate_pwd, pwd_length, output_format))
         {
            errx(1, "Error for <user add>");
         }
      }
      else if (parsed.cmd->action == MANAGEMENT_UPDATE_USER)
      {
         if (update_user(file_path, username, password, generate_pwd, pwd_length, output_format))
         {
            errx(1, "Error for <user edit>");
         }
      }
      else if (parsed.cmd->action == MANAGEMENT_REMOVE_USER)
      {
         if (remove_user(file_path, username, output_format))
         {
            errx(1, "Error for <user del>");
         }
      }
      else if (parsed.cmd->action == MANAGEMENT_LIST_USERS)
      {
         if (list_users(file_path, output_format))
         {
            errx(1, "Error for <user ls>");
         }
      }
   }

   exit(0);

error:

   exit(1);
}

static int
master_key(char* password, bool generate_pwd, int pwd_length, int32_t output_format)
{
   FILE* file = NULL;
   char buf[MISC_LENGTH];
   char* home_dir = NULL;
   char* encoded = NULL;
   size_t encoded_length;
   char* encoded_salt = NULL;
   size_t encoded_salt_length = 0;
   struct stat st = {0};
   bool do_free = true;
   struct json* j = NULL;
   struct json* outcome = NULL;
   struct timespec start_t;
   struct timespec end_t;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &start_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &start_t);
#endif

   if (management_create_header(MANAGEMENT_MASTER_KEY, output_format, &j))
   {
      goto error;
   }

   if (password != NULL)
   {
      do_free = false;
   }

   home_dir = pgvictoria_get_home_directory();
   if (home_dir == NULL)
   {
      char* username = pgvictoria_get_user_name();

      if (username != NULL)
      {
         warnx("No home directory for user \'%s\'", username);
      }
      else
      {
         warnx("No home directory for user running pgvictoria");
      }

      goto error;
   }

   memset(&buf, 0, sizeof(buf));
   pgvictoria_snprintf(&buf[0], sizeof(buf), "%s/.pgvictoria", home_dir);

   if (stat(&buf[0], &st) == -1)
   {
      if (mkdir(&buf[0], S_IRWXU) != 0)
      {
         warn("Could not create directory '%s'", &buf[0]);
         goto error;
      }
   }
   else
   {
      if (S_ISDIR(st.st_mode) && st.st_mode & S_IRWXU && !(st.st_mode & S_IRWXG) && !(st.st_mode & S_IRWXO))
      {
         /* Ok */
      }
      else
      {
         warnx("Wrong permissions for ~/.pgvictoria (must be 0700)");
         goto error;
      }
   }

   memset(&buf, 0, sizeof(buf));
   pgvictoria_snprintf(&buf[0], sizeof(buf), "%s/.pgvictoria/master.key", home_dir);

   if (pgvictoria_exists(&buf[0]))
   {
      warnx("The file ~/.pgvictoria/master.key already exists");
      goto error;
   }

   if (stat(&buf[0], &st) == -1)
   {
      /* Ok */
   }
   else
   {
      if (S_ISREG(st.st_mode) && st.st_mode & (S_IRUSR | S_IWUSR) && !(st.st_mode & S_IRWXG) && !(st.st_mode & S_IRWXO))
      {
         /* Ok */
      }
      else
      {
         warnx("Wrong permissions for ~/.pgvictoria/master.key (must be 0600)");
         goto error;
      }
   }

   file = fopen(&buf[0], "w+");
   if (file == NULL)
   {
      warn("Could not write to master key file '%s'", &buf[0]);
      goto error;
   }

#if defined(HAVE_DARWIN) || defined(HAVE_OSX)
#define GET_ENV(name) getenv(name)
#else
#define GET_ENV(name) secure_getenv(name)
#endif

   if (password == NULL)
   {
      if (generate_pwd)
      {
         password = generate_password(pwd_length);
         do_free = true;
      }
      else
      {
         password = GET_ENV("PGVICTORIA_PASSWORD");

         if (password == NULL)
         {
            while (!is_valid_key(password))
            {
               if (password != NULL)
               {
                  pgvictoria_cleanse(password, strlen(password));
                  free(password);
                  password = NULL;
               }

               printf("Master key: ");
               password = pgvictoria_get_password();
               printf("\n");
            }
         }
         else
         {
            do_free = false;
         }
      }
   }
   else
   {
      do_free = false;

      if (!is_valid_key(password))
      {
         goto error;
      }
   }

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &end_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &end_t);
#endif

   if (management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   unsigned char salt[PBKDF2_SALT_LENGTH];

   if (!RAND_bytes(salt, PBKDF2_SALT_LENGTH))
   {
      goto error;
   }

   if (pgvictoria_base64_encode(password, strlen(password), &encoded, &encoded_length))
   {
      goto error;
   }
   if (pgvictoria_base64_encode((char*)salt, PBKDF2_SALT_LENGTH, &encoded_salt, &encoded_salt_length))
   {
      goto error;
   }

   fputs(encoded, file);
   fputs("\n", file);
   fputs(encoded_salt, file);
   fputs("\n", file);

   free(encoded);
   free(encoded_salt);

   free(home_dir);

   pgvictoria_json_destroy(j);

   if (do_free && password != NULL)
   {
      pgvictoria_cleanse(password, strlen(password));
      free(password);
   }

   fflush(file);
   fclose(file);
   file = NULL;

   if (chmod(&buf[0], S_IRUSR | S_IWUSR) != 0)
   {
      warn("Could not set permissions on '%s'", &buf[0]);
      goto error;
   }

   return 0;

error:

   free(home_dir);
   free(encoded);
   free(encoded_salt);

   if (do_free && password != NULL)
   {
      pgvictoria_cleanse(password, strlen(password));
      free(password);
   }

   if (file)
   {
      fflush(file);
      fclose(file);
      file = NULL;
   }

   management_create_outcome_failure(j, 1, NAME, &outcome);

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   pgvictoria_json_destroy(j);

   return 1;
}

static bool
is_valid_key(char* key)
{
   if (!key)
   {
      return false;
   }

   // Validate key is valid UTF-8
   if (!pgvictoria_utf8_valid((const unsigned char*)key, strlen(key)))
   {
      warnx("Master key contains invalid UTF-8 sequence");
      return false;
   }

   // Check character length
   size_t char_count = pgvictoria_utf8_char_length((const unsigned char*)key, strlen(key));
   if (char_count == (size_t)-1)
   {
      warnx("Error counting UTF-8 characters in master key");
      return false;
   }

   if (char_count < MIN_MASTER_KEY_CHARS)
   {
      warnx("Master key must be at least %d characters long", MIN_MASTER_KEY_CHARS);
      return false;
   }

   if (char_count > MAX_PASSWORD_CHARS)
   {
      warnx("Master key too long (%zu characters). Maximum allowed: %d characters.", char_count, MAX_PASSWORD_CHARS);
      return false;
   }

   return true;
}

static int
add_user(char* users_path, char* username, char* password, bool generate_pwd, int pwd_length, int output_format)
{
   FILE* users_file = NULL;
   char line[MISC_LENGTH];
   char* entry = NULL;
   char* master_key = NULL;
   char* ptr = NULL;
   char* encrypted = NULL;
   int encrypted_length = 0;
   char* encoded = NULL;
   size_t encoded_length;
   char un[MAX_USERNAME_LENGTH];
   int number_of_users = 0;
   bool do_verify = true;
   char* verify = NULL;
   bool do_free = true;
   struct json* j = NULL;
   struct json* outcome = NULL;
   struct json* response = NULL;
   struct timespec start_t;
   struct timespec end_t;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &start_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &start_t);
#endif

   if (management_create_header(MANAGEMENT_ADD_USER, output_format, &j))
   {
      goto error;
   }

   if (pgvictoria_get_master_key(&master_key))
   {
      warnx("Invalid master key");
      goto error;
   }

   if (password != NULL)
   {
      do_verify = false;
      do_free = false;
   }

   if (pgvictoria_exists(users_path))
   {
      users_file = fopen(users_path, "r");
      if (users_file == NULL)
      {
         warn("Could not read user file '%s'", users_path);
         goto error;
      }

      /* User name check */
      if (username != NULL)
      {
         while (fgets(line, sizeof(line), users_file))
         {
            number_of_users++;
            ptr = strtok(line, ":");
            if (ptr == NULL)
            {
               warnx("invalid users file line while adding user");
               goto error;
            }
            if (pgvictoria_compare_string(username, ptr))
            {
               warnx("User '%s' already exists", username);
               goto error;
            }
         }
      }
      else
      {
         while (fgets(line, sizeof(line), users_file))
         {
            number_of_users++;
         }
      }

      fclose(users_file);
      users_file = NULL;

      if (number_of_users >= NUMBER_OF_USERS)
      {
         warnx("Maximum number of users reached (%d)", NUMBER_OF_USERS);
         goto error;
      }
   }

   users_file = fopen(users_path, "a+");
   if (users_file == NULL)
   {
      warn("Could not write to user file '%s'", users_path);
      goto error;
   }

   /* User */
   if (username == NULL)
   {
username:
      printf("User name: ");

      memset(&un, 0, sizeof(un));
      if (fgets(&un[0], sizeof(un), stdin) == NULL)
      {
         goto error;
      }
      un[strlen(un) - 1] = 0;
      username = &un[0];
   }

   if (username == NULL || strlen(username) == 0)
   {
      goto username;
   }

   /* Password */
   if (password == NULL)
   {
password:
      if (generate_pwd)
      {
         password = generate_password(pwd_length);
         do_verify = false;
         printf("Password : %s", password);
         do_free = true;
      }
      else
      {
         password = GET_ENV("PGVICTORIA_PASSWORD");

         if (password == NULL)
         {
            printf("Password : ");

            password = pgvictoria_get_password();
            do_free = true;
            do_verify = true;
         }
         else
         {
            do_free = false;
            do_verify = false;
         }
      }
      printf("\n");
   }

   // Validate password is valid UTF-8
   if (!pgvictoria_utf8_valid((const unsigned char*)password, strlen(password)))
   {
      warnx("Invalid UTF-8 sequence in password");
      if (do_free)
      {
         free(password);
      }
      password = NULL;
      goto password;
   }
   // Check character length
   size_t char_count = pgvictoria_utf8_char_length((const unsigned char*)password, strlen(password));
   if (char_count == (size_t)-1)
   {
      warnx("Error counting UTF-8 characters in password");
      if (do_free)
      {
         free(password);
      }
      password = NULL;
      goto password;
   }
   if (char_count > MAX_PASSWORD_CHARS)
   {
      warnx("Password too long (%zu characters). Maximum allowed: %d characters.", char_count, MAX_PASSWORD_CHARS);
      if (do_free)
      {
         free(password);
      }
      password = NULL;
      goto password;
   }

   if (do_verify)
   {
      printf("Verify   : ");

      if (verify != NULL)
      {
         free(verify);
         verify = NULL;
      }

      verify = pgvictoria_get_password();
      printf("\n");

      // Validate verification password is valid UTF-8
      if (!pgvictoria_utf8_valid((const unsigned char*)verify, strlen(verify)))
      {
         warnx("Invalid UTF-8 sequence in verification password. Please use valid UTF-8 encoding.");
         free(verify);
         verify = NULL;
         if (do_free)
         {
            free(password);
         }
         password = NULL;
         goto password;
      }
      // Check character count on verification password
      size_t verify_char_count = pgvictoria_utf8_char_length((const unsigned char*)verify, strlen(verify));
      if (verify_char_count == (size_t)-1)
      {
         warnx("Error counting UTF-8 characters in verification password");
         free(verify);
         verify = NULL;
         if (do_free)
         {
            free(password);
         }
         password = NULL;
         goto password;
      }
      if (verify_char_count > MAX_PASSWORD_CHARS)
      {
         warnx("Verification password too long (%zu characters). Maximum allowed: %d characters.", verify_char_count, MAX_PASSWORD_CHARS);
         free(verify);
         verify = NULL;
         if (do_free)
         {
            free(password);
         }
         password = NULL;
         goto password;
      }
      if (strlen(password) != strlen(verify) || memcmp(password, verify, strlen(password)) != 0)
      {
         warnx("Passwords do not match");
         if (do_free)
         {
            free(password);
         }
         password = NULL;
         free(verify);
         verify = NULL;
         goto password;
      }
   }

   if (pgvictoria_encrypt(password, master_key, &encrypted, &encrypted_length, ENCRYPTION_AES_256_CBC))
   {
      goto error;
   }
   if (pgvictoria_base64_encode(encrypted, encrypted_length, &encoded, &encoded_length))
   {
      goto error;
   }

   entry = pgvictoria_append(entry, username);
   entry = pgvictoria_append(entry, ":");
   entry = pgvictoria_append(entry, encoded);
   entry = pgvictoria_append(entry, "\n");

   fputs(entry, users_file);

   free(entry);
   if (master_key != NULL)
   {
      pgvictoria_cleanse(master_key, strlen(master_key));
      free(master_key);
   }
   free(encrypted);
   free(encoded);
   if (do_free && password != NULL)
   {
      pgvictoria_cleanse(password, strlen(password));
      free(password);
   }
   if (verify != NULL)
   {
      pgvictoria_cleanse(verify, strlen(verify));
      free(verify);
   }

   fflush(users_file);
   fclose(users_file);
   users_file = NULL;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &end_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &end_t);
#endif

   if (management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (create_response(users_path, j, &response))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   pgvictoria_json_destroy(j);

   return 0;

error:

   free(entry);
   if (master_key != NULL)
   {
      pgvictoria_cleanse(master_key, strlen(master_key));
      free(master_key);
   }
   free(encrypted);
   free(encoded);
   if (do_free && password != NULL)
   {
      pgvictoria_cleanse(password, strlen(password));
      free(password);
   }
   if (verify != NULL)
   {
      pgvictoria_cleanse(verify, strlen(verify));
      free(verify);
   }

   if (users_file)
   {
      fflush(users_file);
      fclose(users_file);
      users_file = NULL;
   }

   management_create_outcome_failure(j, 1, NAME, &outcome);

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   pgvictoria_json_destroy(j);

   return 1;
}

static int
update_user(char* users_path, char* username, char* password, bool generate_pwd, int pwd_length, int32_t output_format)
{
   FILE* users_file = NULL;
   FILE* users_file_tmp = NULL;
   char tmpfilename[MISC_LENGTH];
   char line[MISC_LENGTH];
   char line_copy[MISC_LENGTH];
   char* entry = NULL;
   char* master_key = NULL;
   char* ptr = NULL;
   char* encrypted = NULL;
   int encrypted_length = 0;
   char* encoded = NULL;
   size_t encoded_length;
   char un[MAX_USERNAME_LENGTH];
   bool found = false;
   bool do_verify = true;
   char* verify = NULL;
   bool do_free = true;
   struct json* j = NULL;
   struct json* outcome = NULL;
   struct json* response = NULL;
   struct timespec start_t;
   struct timespec end_t;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &start_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &start_t);
#endif

   if (management_create_header(MANAGEMENT_UPDATE_USER, output_format, &j))
   {
      goto error;
   }

   memset(&tmpfilename, 0, sizeof(tmpfilename));

   if (pgvictoria_get_master_key(&master_key))
   {
      warnx("Invalid master key");
      goto error;
   }

   if (password != NULL)
   {
      do_verify = false;
      do_free = false;
   }

   users_file = fopen(users_path, "r");
   if (!users_file)
   {
      warnx("%s not found\n", users_path);
      goto error;
   }

   pgvictoria_snprintf(tmpfilename, sizeof(tmpfilename), "%s.tmp", users_path);
   users_file_tmp = fopen(tmpfilename, "w+");
   if (users_file_tmp == NULL)
   {
      warn("Could not write to temporary user file '%s'", tmpfilename);
      goto error;
   }

   /* User */
   if (username == NULL)
   {
username:
      printf("User name: ");

      memset(&un, 0, sizeof(un));
      if (fgets(&un[0], sizeof(un), stdin) == NULL)
      {
         goto error;
      }
      un[strlen(un) - 1] = 0;
      username = &un[0];
   }

   if (username == NULL || strlen(username) == 0)
   {
      goto username;
   }

   /* Update */
   while (fgets(line, sizeof(line), users_file))
   {
      memset(&line_copy, 0, sizeof(line_copy));
      memcpy(&line_copy, &line, strlen(line));

      ptr = strtok(line, ":");
      if (ptr == NULL)
      {
         warnx("invalid users file line while updating user");
         goto error;
      }
      if (pgvictoria_compare_string(username, ptr))
      {
         /* Password */
         if (password == NULL)
         {
password:
            if (generate_pwd)
            {
               password = generate_password(pwd_length);
               do_verify = false;
               printf("Password : %s", password);
               do_free = true;
            }
            else
            {
               password = GET_ENV("PGVICTORIA_PASSWORD");

               if (password == NULL)
               {
                  printf("Password : ");

                  password = pgvictoria_get_password();
                  do_free = true;
                  do_verify = true;
               }
               else
               {
                  do_free = false;
                  do_verify = false;
               }
            }
            printf("\n");
         }

         // Validate password is valid UTF-8
         if (!pgvictoria_utf8_valid((const unsigned char*)password, strlen(password)))
         {
            warnx("Invalid UTF-8 sequence in password");
            if (do_free)
            {
               free(password);
            }
            password = NULL;
            goto password;
         }
         // Check character length
         size_t char_count = pgvictoria_utf8_char_length((const unsigned char*)password, strlen(password));
         if (char_count == (size_t)-1)
         {
            warnx("Error counting UTF-8 characters in password");
            if (do_free)
            {
               free(password);
            }
            password = NULL;
            goto password;
         }
         if (char_count > MAX_PASSWORD_CHARS)
         {
            warnx("Password too long (%zu characters). Maximum allowed: %d characters.", char_count, MAX_PASSWORD_CHARS);
            if (do_free)
            {
               free(password);
            }
            password = NULL;
            goto password;
         }

         if (do_verify)
         {
            printf("Verify   : ");

            if (verify != NULL)
            {
               free(verify);
               verify = NULL;
            }

            verify = pgvictoria_get_password();
            printf("\n");

            // Validate verification password is valid UTF-8
            if (!pgvictoria_utf8_valid((const unsigned char*)verify, strlen(verify)))
            {
               warnx("Invalid UTF-8 sequence in verification password. Please use valid UTF-8 encoding.");
               free(verify);
               verify = NULL;
               if (do_free)
               {
                  free(password);
               }
               password = NULL;
               goto password;
            }
            // Check character count on verification password
            size_t verify_char_count = pgvictoria_utf8_char_length((const unsigned char*)verify, strlen(verify));
            if (verify_char_count == (size_t)-1)
            {
               warnx("Error counting UTF-8 characters in verification password");
               free(verify);
               verify = NULL;
               if (do_free)
               {
                  free(password);
               }
               password = NULL;
               goto password;
            }
            if (verify_char_count > MAX_PASSWORD_CHARS)
            {
               warnx("Verification password too long (%zu characters). Maximum allowed: %d characters.", verify_char_count, MAX_PASSWORD_CHARS);
               free(verify);
               verify = NULL;
               if (do_free)
               {
                  free(password);
               }
               password = NULL;
               goto password;
            }
            if (strlen(password) != strlen(verify) || memcmp(password, verify, strlen(password)) != 0)
            {
               warnx("Passwords do not match");
               if (do_free)
               {
                  free(password);
               }
               password = NULL;
               free(verify);
               verify = NULL;
               goto password;
            }
         }

         if (pgvictoria_encrypt(password, master_key, &encrypted, &encrypted_length, ENCRYPTION_AES_256_CBC))
         {
            goto error;
         }
         if (pgvictoria_base64_encode(encrypted, encrypted_length, &encoded, &encoded_length))
         {
            goto error;
         }

         memset(&line, 0, sizeof(line));
         entry = NULL;
         entry = pgvictoria_append(entry, username);
         entry = pgvictoria_append(entry, ":");
         entry = pgvictoria_append(entry, encoded);
         entry = pgvictoria_append(entry, "\n");

         fputs(entry, users_file_tmp);
         free(entry);

         found = true;
      }
      else
      {
         fputs(line_copy, users_file_tmp);
      }
   }

   if (!found)
   {
      warnx("User '%s' not found", username);
      goto error;
   }

   if (master_key != NULL)
   {
      pgvictoria_cleanse(master_key, strlen(master_key));
      free(master_key);
   }
   free(encrypted);
   free(encoded);
   if (do_free && password != NULL)
   {
      pgvictoria_cleanse(password, strlen(password));
      free(password);
   }
   if (verify != NULL)
   {
      pgvictoria_cleanse(verify, strlen(verify));
      free(verify);
   }

   fclose(users_file);
   users_file = NULL;
   fflush(users_file_tmp);
   fclose(users_file_tmp);
   users_file_tmp = NULL;

   if (rename(tmpfilename, users_path) != 0)
   {
      warn("Could not rename temporary user file to '%s'", users_path);
      goto error;
   }

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &end_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &end_t);
#endif

   if (management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (create_response(users_path, j, &response))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   pgvictoria_json_destroy(j);

   return 0;

error:

   if (master_key != NULL)
   {
      pgvictoria_cleanse(master_key, strlen(master_key));
      free(master_key);
   }
   free(encrypted);
   free(encoded);
   if (do_free && password != NULL)
   {
      pgvictoria_cleanse(password, strlen(password));
      free(password);
   }
   if (verify != NULL)
   {
      pgvictoria_cleanse(verify, strlen(verify));
      free(verify);
   }

   if (users_file)
   {
      fclose(users_file);
      users_file = NULL;
   }

   if (users_file_tmp)
   {
      fflush(users_file_tmp);
      fclose(users_file_tmp);
      users_file_tmp = NULL;
   }

   if (strlen(tmpfilename) > 0)
   {
      remove(tmpfilename);
   }

   management_create_outcome_failure(j, 1, NAME, &outcome);

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   pgvictoria_json_destroy(j);

   return 1;
}

static int
remove_user(char* users_path, char* username, int32_t output_format)
{
   FILE* users_file = NULL;
   FILE* users_file_tmp = NULL;
   char tmpfilename[MISC_LENGTH];
   char line[MISC_LENGTH];
   char line_copy[MISC_LENGTH];
   char* ptr = NULL;
   char un[MAX_USERNAME_LENGTH];
   bool found = false;
   struct json* j = NULL;
   struct json* outcome = NULL;
   struct json* response = NULL;
   struct timespec start_t;
   struct timespec end_t;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &start_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &start_t);
#endif

   if (management_create_header(MANAGEMENT_REMOVE_USER, output_format, &j))
   {
      goto error;
   }

   users_file = fopen(users_path, "r");
   if (!users_file)
   {
      warnx("%s not found", users_path);
      goto error;
   }

   memset(&tmpfilename, 0, sizeof(tmpfilename));
   pgvictoria_snprintf(tmpfilename, sizeof(tmpfilename), "%s.tmp", users_path);
   users_file_tmp = fopen(tmpfilename, "w+");
   if (users_file_tmp == NULL)
   {
      warn("Could not write to temporary user file '%s'", tmpfilename);
      goto error;
   }

   /* User */
   if (username == NULL)
   {
username:
      printf("User name: ");

      memset(&un, 0, sizeof(un));
      if (fgets(&un[0], sizeof(un), stdin) == NULL)
      {
         goto error;
      }
      un[strlen(un) - 1] = 0;
      username = &un[0];
   }

   if (username == NULL || strlen(username) == 0)
   {
      goto username;
   }

   /* Remove */
   while (fgets(line, sizeof(line), users_file))
   {
      memset(&line_copy, 0, sizeof(line_copy));
      memcpy(&line_copy, &line, strlen(line));

      ptr = strtok(line, ":");
      if (ptr == NULL)
      {
         warnx("invalid users file line while removing user");
         goto error;
      }
      if (pgvictoria_compare_string(username, ptr))
      {
         found = true;
      }
      else
      {
         fputs(line_copy, users_file_tmp);
      }
   }

   if (!found)
   {
      warnx("User '%s' not found", username);
      goto error;
   }

   fclose(users_file);
   users_file = NULL;
   fflush(users_file_tmp);
   fclose(users_file_tmp);
   users_file_tmp = NULL;

   if (rename(tmpfilename, users_path) != 0)
   {
      warn("Could not rename temporary user file to '%s'", users_path);
      goto error;
   }

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &end_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &end_t);
#endif

   if (management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (create_response(users_path, j, &response))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   pgvictoria_json_destroy(j);

   return 0;

error:

   if (users_file)
   {
      fclose(users_file);
      users_file = NULL;
   }

   if (users_file_tmp)
   {
      fflush(users_file_tmp);
      fclose(users_file_tmp);
      users_file_tmp = NULL;
   }

   if (strlen(tmpfilename) > 0)
   {
      remove(tmpfilename);
   }

   management_create_outcome_failure(j, 1, NAME, &outcome);

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   pgvictoria_json_destroy(j);

   return 1;
}

static int
list_users(char* users_path, int32_t output_format)
{
   FILE* users_file = NULL;
   char line[MISC_LENGTH];
   char* ptr = NULL;
   struct json* j = NULL;
   struct json* outcome = NULL;
   struct json* response = NULL;
   struct timespec start_t;
   struct timespec end_t;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &start_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &start_t);
#endif

   if (management_create_header(MANAGEMENT_LIST_USERS, output_format, &j))
   {
      goto error;
   }

   users_file = fopen(users_path, "r");
   if (!users_file)
   {
      goto error;
   }

   /* List */
   while (fgets(line, sizeof(line), users_file))
   {
      ptr = strtok(line, ":");
      if (ptr == NULL)
      {
         warnx("skipping malformed users file line while listing users");
         continue;
      }
      if (strchr(ptr, '\n'))
      {
         continue;
      }
      printf("%s\n", ptr);
   }

   fclose(users_file);
   users_file = NULL;

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &end_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &end_t);
#endif

   if (management_create_outcome_success(j, start_t, end_t, &outcome))
   {
      goto error;
   }

   if (create_response(users_path, j, &response))
   {
      goto error;
   }

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   pgvictoria_json_destroy(j);

   return 0;

error:

   if (users_file)
   {
      fclose(users_file);
      users_file = NULL;
   }

   management_create_outcome_failure(j, 1, NAME, &outcome);

   if (output_format == MANAGEMENT_OUTPUT_FORMAT_JSON)
   {
      pgvictoria_json_print(j, FORMAT_JSON);
   }
   else
   {
      pgvictoria_json_print(j, FORMAT_TEXT);
   }

   pgvictoria_json_destroy(j);

   return 1;
}

static char*
generate_password(int pwd_length)
{
   char* pwd = NULL;
   unsigned char* random_bytes = NULL;

   pwd = malloc(pwd_length + 1);
   if (pwd == NULL)
   {
      return NULL;
   }
   memset(pwd, 0, pwd_length + 1);

   random_bytes = malloc(pwd_length);
   if (random_bytes == NULL)
   {
      free(pwd);
      return NULL;
   }

   if (RAND_bytes(random_bytes, pwd_length) != 1)
   {
      free(pwd);
      free(random_bytes);
      return NULL;
   }

   for (int i = 0; i < pwd_length; i++)
   {
      pwd[i] = CHARS[random_bytes[i] % sizeof(CHARS)];
   }
   pwd[pwd_length] = '\0';

   memset(random_bytes, 0, pwd_length);
   free(random_bytes);

   return pwd;
}

static int
create_response(char* users_path, struct json* json, struct json** response)
{
   struct json* r = NULL;
   struct json* users = NULL;
   FILE* users_file = NULL;
   char line[MISC_LENGTH];
   char* ptr = NULL;

   *response = NULL;

   if (pgvictoria_json_create(&r))
   {
      goto error;
   }

   pgvictoria_json_put(json, "Response", (uintptr_t)r, ValueJSON);

   if (pgvictoria_json_create(&users))
   {
      goto error;
   }

   users_file = fopen(users_path, "r");
   if (!users_file)
   {
      goto error;
   }

   while (fgets(line, sizeof(line), users_file))
   {
      ptr = strtok(line, ":");
      if (ptr == NULL)
      {
         warnx("skipping malformed users file line while creating response");
         continue;
      }
      if (strchr(ptr, '\n'))
      {
         continue;
      }
      pgvictoria_json_append(users, (uintptr_t)ptr, ValueString);
   }

   pgvictoria_json_put(r, "Users", (uintptr_t)users, ValueJSON);

   *response = r;

   return 0;

error:

   pgvictoria_json_destroy(r);

   return 1;
}

static int
management_create_header(int32_t action, int32_t output_format, struct json** json)
{
   time_t t;
   char timestamp[128];
   struct tm* time_info;
   struct json* j = NULL;
   struct json* header = NULL;

   *json = NULL;

   if (pgvictoria_json_create(&j))
   {
      goto error;
   }

   if (pgvictoria_json_create(&header))
   {
      goto error;
   }

   time(&t);
   time_info = localtime(&t);
   strftime(&timestamp[0], sizeof(timestamp), "%Y%m%d%H%M%S", time_info);

   pgvictoria_json_put(header, "Command", (uintptr_t)action, ValueInt32);
   pgvictoria_json_put(header, "ClientVersion", (uintptr_t)VERSION, ValueString);
   pgvictoria_json_put(header, "Output", (uintptr_t)output_format, ValueUInt8);
   pgvictoria_json_put(header, "Timestamp", (uintptr_t)timestamp, ValueString);

   pgvictoria_json_put(j, "Header", (uintptr_t)header, ValueJSON);

   *json = j;

   return 0;

error:

   pgvictoria_json_destroy(header);
   pgvictoria_json_destroy(j);

   *json = NULL;

   return 1;
}

static int
management_create_outcome_success(struct json* json, struct timespec start_t, struct timespec end_t, struct json** outcome)
{
   double total_seconds = 0;
   char* elapsed = NULL;
   struct json* r = NULL;

   *outcome = NULL;

   if (pgvictoria_json_create(&r))
   {
      goto error;
   }

   elapsed = pgvictoria_get_timestamp_string(start_t, end_t, &total_seconds);

   pgvictoria_json_put(r, "Status", (uintptr_t)true, ValueBool);
   pgvictoria_json_put(r, "Time", (uintptr_t)elapsed, ValueString);

   pgvictoria_json_put(json, "Outcome", (uintptr_t)r, ValueJSON);

   *outcome = r;

   free(elapsed);

   return 0;

error:

   free(elapsed);
   pgvictoria_json_destroy(r);

   return 1;
}

static int
management_create_outcome_failure(struct json* json, int32_t error, char* workflow, struct json** outcome)
{
   struct json* r = NULL;

   *outcome = NULL;

   if (pgvictoria_json_create(&r))
   {
      goto error;
   }

   pgvictoria_json_put(r, "Status", (uintptr_t)false, ValueBool);
   pgvictoria_json_put(r, "Error", (uintptr_t)error, ValueInt32);
   pgvictoria_json_put(r, "Workflow", (uintptr_t)workflow, ValueString);

   pgvictoria_json_put(json, "Outcome", (uintptr_t)r, ValueJSON);

   *outcome = r;

   return 0;

error:

   pgvictoria_json_destroy(r);

   return 1;
}
