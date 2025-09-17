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

#ifndef PGVICTORIA_CONFIGURATION_H
#define PGVICTORIA_CONFIGURATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pgvictoria.h>
#include <json.h>

#include <stdlib.h>

#define PGVICTORIA_MAIN_INI_SECTION                  "pgvictoria"
#define PGVICTORIA_DEFAULT_CONFIG_FILE_PATH          "/etc/pgvictoria/pgvictoria.conf"
#define PGVICTORIA_DEFAULT_USERS_FILE_PATH           "/etc/pgvictoria/pgvictoria_users.conf"

/* Main configuration fields */
#define CONFIGURATION_ARGUMENT_ENCRYPTION             "encryption"
#define CONFIGURATION_ARGUMENT_HOST                   "host"
#define CONFIGURATION_ARGUMENT_HUGEPAGE               "hugepage"
#define CONFIGURATION_ARGUMENT_LIBEV                  "libev"
#define CONFIGURATION_ARGUMENT_LOG_LEVEL              "log_level"
#define CONFIGURATION_ARGUMENT_LOG_LINE_PREFIX        "log_line_prefix"
#define CONFIGURATION_ARGUMENT_LOG_MODE               "log_mode"
#define CONFIGURATION_ARGUMENT_LOG_PATH               "log_path"
#define CONFIGURATION_ARGUMENT_LOG_ROTATION_AGE       "log_rotation_age"
#define CONFIGURATION_ARGUMENT_LOG_ROTATION_SIZE      "log_rotation_size"
#define CONFIGURATION_ARGUMENT_LOG_TYPE               "log_type"
#define CONFIGURATION_ARGUMENT_MAIN_CONF_PATH         "main_configuration_path"
#define CONFIGURATION_ARGUMENT_PIDFILE                "pidfile"
#define CONFIGURATION_ARGUMENT_PORT                   "port"
#define CONFIGURATION_ARGUMENT_UNIX_SOCKET_DIR        "unix_socket_dir"
#define CONFIGURATION_ARGUMENT_UPDATE_PROCESS_TITLE   "update_process_title"
#define CONFIGURATION_ARGUMENT_USER                   "user"
#define CONFIGURATION_ARGUMENT_USER_CONF_PATH         "users_configuration_path"
#define CONFIGURATION_ARGUMENT_SERVER                 "server"

#define CONFIGURATION_TYPE_MAIN 0
#define CONFIGURATION_TYPE_WALINFO 1

// Set configuration argument constants
#define CONFIGURATION_RESPONSE_STATUS                           "status"
#define CONFIGURATION_RESPONSE_MESSAGE                          "message"
#define CONFIGURATION_RESPONSE_CONFIG_KEY                       "config_key"
#define CONFIGURATION_RESPONSE_REQUESTED_VALUE                  "requested_value"
#define CONFIGURATION_RESPONSE_CURRENT_VALUE                    "current_value"
#define CONFIGURATION_RESPONSE_OLD_VALUE                        "old_value"
#define CONFIGURATION_RESPONSE_NEW_VALUE                        "new_value"
#define CONFIGURATION_RESPONSE_RESTART_REQUIRED                 "restart_required"
#define CONFIGURATION_STATUS_SUCCESS                            "success"
#define CONFIGURATION_STATUS_RESTART_REQUIRED                   "success_restart_required"
#define CONFIGURATION_MESSAGE_SUCCESS                           "Configuration change applied successfully"
#define CONFIGURATION_MESSAGE_RESTART_REQUIRED                  "Configuration change requires restart. Current values preserved."

/**
 * @struct config_key_info
 * @brief Parsed representation of a configuration key for runtime configuration changes.
 *
 * This structure is used internally to represent a configuration key as parsed from
 * user input (e.g., from the CLI or management API). It supports both main/global
 * configuration parameters and server-specific parameters.
 *
 * Example key formats:
 *   - "log_level"                  (main/global parameter)
 *   - "pgvictoria.log_level"         (main/global parameter, explicit section)
 *   - "server.primary.port"        (server-specific parameter)
 *
 * Fields:
 *   section      The top-level section ("pgvictoria" for main config, "server" for server config)
 *   context      The context identifier (e.g., server name for server configs, empty for main)
 *   key          The actual configuration parameter name (e.g., "port", "log_level")
 *   is_main_section True if this refers to the main/global configuration section
 *   section_type  Section type: 0=main, 1=server
 */
struct config_key_info
{
   char section[MISC_LENGTH];   /**< Section name: "pgvictoria" for main config, "server" for server config */
   char context[MISC_LENGTH];   /**< Context identifier: server name for server configs, empty for main config */
   char key[MISC_LENGTH];       /**< Configuration parameter name (e.g., "port", "log_level") */
   bool is_main_section;        /**< True if this is a main/global configuration parameter */
   int section_type;            /**< Section type: 0=main, 1=server */
};

/**
 * Initialize the configuration structure
 * @param shmem The shared memory segment
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_init_main_configuration(void* shmem);

/**
 * Read the configuration from a file
 * @param shmem The shared memory segment
 * @param filename The file name
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_read_main_configuration(void* shmem, char* filename);

/**
 * Validate the configuration
 * @param shmem The shared memory segment
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_validate_main_configuration(void* shmem);

/**
 * Initialize the WALINFO configuration structure
 * @param shmem The shared memory segment
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_init_walinfo_configuration(void* shmem);

/**
 * Read the WALINFO configuration from a file
 * @param shmem The shared memory segment
 * @param filename The file name
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_read_walinfo_configuration(void* shmem, char* filename);

/**
 * Validate the WALINFO configuration
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_validate_walinfo_configuration(void);

/**
 * Initialize the WALFILTER configuration structure
 * @param shmem The shared memory segment
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_init_walfilter_configuration(void* shmem);

/**
 * Read the WALFILTER configuration from a file
 * @param shmem The shared memory segment
 * @param filename The file name
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_read_walfilter_configuration(void* shmem, char* filename);

/**
 * Validate the WALFILTER configuration
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_validate_walfilter_configuration(void);

/**
 * Read the USERS configuration from a file
 * @param shmem The shared memory segment
 * @param filename The file name
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_read_users_configuration(void* shmem, char* filename);

/**
 * Validate the USERS configuration from a file
 * @param shmem The shared memory segment
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_validate_users_configuration(void* shmem);

/**
 * Read the ADMINS configuration from a file
 * @param shmem The shared memory segment
 * @param filename The file name
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_read_admins_configuration(void* shmem, char* filename);

/**
 * Validate the ADMINS configuration from a file
 * @param shmem The shared memory segment
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_validate_admins_configuration(void* shmem);

/**
 * Reload the configuration
 * @param restart Should the server be restarted
 * @return 0 upon success, otherwise 1
 */
int
pgvictoria_reload_configuration(bool* restart);

/**
 * Get a configuration parameter value
 * @param ssl The SSL connection
 * @param client_fd The client
 * @param compression The compress method for wire protocol
 * @param encryption The encrypt method for wire protocol
 * @param payload The payload
 */
void
pgvictoria_conf_get(SSL* ssl, int client_fd, uint8_t compression, uint8_t encryption, struct json* payload);

/**
 * Set a configuration parameter value
 * @param ssl The SSL connection
 * @param client_fd The client
 * @param compression The compress method for wire protocol
 * @param encryption The encrypt method for wire protocol
 * @param payload The payload
 */
int
pgvictoria_conf_set(SSL* ssl, int client_fd, uint8_t compression, uint8_t encryption,
                    struct json* payload, bool* restart_required);

#ifdef __cplusplus
}
#endif

#endif
