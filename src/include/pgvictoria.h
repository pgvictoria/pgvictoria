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

#ifndef PGVICTORIA_H
#define PGVICTORIA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ev.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#if HAVE_OPENBSD
#include <sys/limits.h>
#endif
#include <sys/types.h>
#include <openssl/ssl.h>

#define VERSION                      "0.1.0"

#define PGVICTORIA_HOMEPAGE          "https://pgvictoria.github.io/"
#define PGVICTORIA_ISSUES            "https://github.com/pgvictoria/pgvictoria/issues"

#define POSTGRESQL_MIN_VERSION       13

#define MAIN_UDS                     ".s.pgvictoria"

#define MAX_PROCESS_TITLE_LENGTH     256

#define ALIGNMENT_SIZE               512
#define DEFAULT_BUFFER_SIZE          131072

#define MAX_USERNAME_LENGTH          128
#define MAX_PASSWORD_LENGTH          1024

#define MAX_PATH                     1024
#define MISC_LENGTH                  128
#define MAX_COMMENT                  2048
#define MAX_EXTRA_PATH               8192

#define MAX_EXTRA                    64
#define NUMBER_OF_SERVERS            64
#define NUMBER_OF_USERS              64

#define STATE_FREE                   0
#define STATE_IN_USE                 1

#define MAX_NUMBER_OF_COLUMNS        8

#define ENCRYPTION_NONE              0
#define ENCRYPTION_AES_256_CBC       1
#define ENCRYPTION_AES_192_CBC       2
#define ENCRYPTION_AES_128_CBC       3
#define ENCRYPTION_AES_256_CTR       4
#define ENCRYPTION_AES_192_CTR       5
#define ENCRYPTION_AES_128_CTR       6

#define AUTH_SUCCESS                 0
#define AUTH_BAD_PASSWORD            1
#define AUTH_ERROR                   2
#define AUTH_TIMEOUT                 3

#define HUGEPAGE_OFF                 0
#define HUGEPAGE_TRY                 1
#define HUGEPAGE_ON                  2

#define UPDATE_PROCESS_TITLE_NEVER   0
#define UPDATE_PROCESS_TITLE_STRICT  1
#define UPDATE_PROCESS_TITLE_MINIMAL 2
#define UPDATE_PROCESS_TITLE_VERBOSE 3

#define INDENT_PER_LEVEL             2
#define FORMAT_JSON                  0
#define FORMAT_TEXT                  1
#define FORMAT_JSON_COMPACT          2
#define BULLET_POINT                 "- "

#define likely(x)                    __builtin_expect(!!(x), 1)
#define unlikely(x)                  __builtin_expect(!!(x), 0)

#define EMPTY_STR(_s)                (_s[0] == 0)

#define MAX(a, b) \
   ({ __typeof__ (a) _a = (a);  \
           __typeof__ (b) _b = (b);  \
           _a > _b ? _a : _b; })

#define MIN(a, b) \
   ({ __typeof__ (a) _a = (a);  \
           __typeof__ (b) _b = (b);  \
           _a < _b ? _a : _b; })

/*
 * Common piece of code to perform a sleeping.
 *
 * @param zzz the amount of time to
 * sleep, expressed as nanoseconds.
 *
 * Example
   SLEEP(5000000L)
 *
 */
#define SLEEP(zzz)                  \
   do                               \
   {                                \
      struct timespec ts_private;   \
      ts_private.tv_sec = 0;        \
      ts_private.tv_nsec = zzz;     \
      nanosleep(&ts_private, NULL); \
   }                                \
   while (0);

/*
 * Commonly used block of code to sleep
 * for a specified amount of time and
 * then jump back to a specified label.
 *
 * @param zzz how much time to sleep (as long nanoseconds)
 * @param goto_to the label to which jump to
 *
 * Example:
 *
     ...
     else
       SLEEP_AND_GOTO(100000L, retry)
 */
#define SLEEP_AND_GOTO(zzz, goto_to) \
   do                                \
   {                                 \
      struct timespec ts_private;    \
      ts_private.tv_sec = 0;         \
      ts_private.tv_nsec = zzz;      \
      nanosleep(&ts_private, NULL);  \
      goto goto_to;                  \
   }                                 \
   while (0);

/**
 * The shared memory segment
 */
extern void* shmem;

/**
 * @struct version
 * Semantic version structure for extensions (major.minor.patch format)
 */
struct version
{
   int major; /**< Major version number */
   int minor; /**< Minor version number (-1 if not specified) */
   int patch; /**< Patch version number (-1 if not specified) */
} __attribute__((aligned(64)));

/** @struct server
 * Defines a server
 */
struct server
{
   char name[MISC_LENGTH];             /**< The name of the server */
   char host[MISC_LENGTH];             /**< The host name of the server */
   int port;                           /**< The port of the server */
   bool primary;                       /**< Is the server a primary ? */
   char username[MAX_USERNAME_LENGTH]; /**< The user name */
   int version;                        /**< The major version of the server*/
   int minor_version;                  /**< The minor version of the server*/
} __attribute__((aligned(64)));

/** @struct user
 * Defines a user
 */
struct user
{
   char username[MAX_USERNAME_LENGTH]; /**< The user name */
   char password[MAX_PASSWORD_LENGTH]; /**< The password */
} __attribute__((aligned(64)));

/** @struct common_configuration
 * Defines configurations that are common between all tools
 */
struct common_configuration
{
   char home_dir[MAX_PATH]; /**< The home directory */

   int log_type;                      /**< The logging type */
   int log_level;                     /**< The logging level */
   char log_path[MISC_LENGTH];        /**< The logging path */
   int log_mode;                      /**< The logging mode */
   int log_rotation_size;             /**< bytes to force log rotation */
   int log_rotation_age;              /**< minutes for log rotation */
   char log_line_prefix[MISC_LENGTH]; /**< The logging prefix */
   atomic_schar log_lock;             /**< The logging lock */

   struct server servers[NUMBER_OF_SERVERS]; /**< The servers */
   struct user users[NUMBER_OF_USERS];       /**< The users */

   int number_of_servers; /**< The number of servers */
   int number_of_users;   /**< The number of users */

   char configuration_path[MAX_PATH]; /**< The configuration path */
   char users_path[MAX_PATH];         /**< The users path */
} __attribute__((aligned(64)));

/** @struct main_configuration
 * Defines the main configuration list
 */
struct main_configuration
{
   struct common_configuration common; /**< Common configurations that are shared across multiple tools */

   bool running; /**< Is pgvictoria running */

   char host[MISC_LENGTH]; /**< The host */

   int authentication_timeout; /**< The authentication timeout in seconds */
   char pidfile[MAX_PATH];     /**< File containing the PID */

   unsigned int update_process_title; /**< Behaviour for updating the process title */

   char libev[MISC_LENGTH]; /**< Name of libev mode */
   int backlog;             /**< The backlog for listen */
   unsigned char hugepage;  /**< Huge page support */

   char unix_socket_dir[MISC_LENGTH]; /**< The directory for the Unix Domain Socket */
} __attribute__((aligned(64)));

#ifdef __cplusplus
}
#endif

#endif
