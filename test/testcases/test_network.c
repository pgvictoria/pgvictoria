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
 *
 */

#include <pgvictoria.h>
#include <configuration.h>
#include <mctf.h>
#include <network.h>
#include <utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/**
 * Test: pgvictoria_bind_unix_socket creates a socket with 0600 permissions.
 */
MCTF_TEST(test_network_bind_unix_socket_permissions)
{
   int fd = -1;
   int client_fd = -1;
   int ret;
   char tmp_dir[] = "/tmp/pgvictoria_sock_test_XXXXXX";
   char sock_path[107];
   struct stat st;
   struct sockaddr_un addr;
   struct main_configuration test_config;
   void* old_shmem = shmem;

   memset(&test_config, 0, sizeof(struct main_configuration));
   test_config.backlog = 5;
   shmem = &test_config;

   MCTF_ASSERT_PTR_NONNULL(mkdtemp(tmp_dir), cleanup, "mkdtemp should succeed");

   memset(sock_path, 0, sizeof(sock_path));
   snprintf(sock_path, sizeof(sock_path), "%s/%s", tmp_dir, ".s.pgvictoria");

   ret = pgvictoria_bind_unix_socket(tmp_dir, ".s.pgvictoria", &fd);
   MCTF_ASSERT_INT_EQ(ret, 0, cleanup, "pgvictoria_bind_unix_socket should succeed");
   MCTF_ASSERT(fd >= 0, cleanup, "Bound fd should be valid");

   /* Verify socket file exists and has 0600 permissions */
   ret = stat(sock_path, &st);
   MCTF_ASSERT_INT_EQ(ret, 0, cleanup, "stat on socket path should succeed");
   MCTF_ASSERT(S_ISSOCK(st.st_mode), cleanup, "Path should be a socket");
   MCTF_ASSERT_INT_EQ(st.st_mode & 0777, S_IRUSR | S_IWUSR, cleanup, "Socket permissions must be 0600");

   /* Verify client connection succeeds */
   client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
   MCTF_ASSERT(client_fd >= 0, cleanup, "Client socket creation should succeed");

   memset(&addr, 0, sizeof(addr));
   addr.sun_family = AF_UNIX;
   strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

   ret = connect(client_fd, (struct sockaddr*)&addr, sizeof(addr));
   MCTF_ASSERT_INT_EQ(ret, 0, cleanup, "Connecting to socket should succeed");

cleanup:
   if (client_fd >= 0)
   {
      close(client_fd);
   }
   if (fd >= 0)
   {
      close(fd);
   }
   unlink(sock_path);
   rmdir(tmp_dir);
   shmem = old_shmem;
   MCTF_FINISH();
}

/**
 * Test: pgvictoria_bind_unix_socket error cleanup on invalid directory.
 */
MCTF_TEST(test_network_bind_unix_socket_error_cleanup)
{
   int fd = -1;
   int ret;
   struct main_configuration test_config;
   void* old_shmem = shmem;

   memset(&test_config, 0, sizeof(struct main_configuration));
   test_config.backlog = 5;
   shmem = &test_config;

   /* Binding to an uncreatable directory should fail and reset fd to -1 */
   ret = pgvictoria_bind_unix_socket("/dev/null/invalid_dir", "test.sock", &fd);
   MCTF_ASSERT(ret != 0, cleanup, "Binding with invalid directory should fail");
   MCTF_ASSERT_INT_EQ(fd, -1, cleanup, "fd should be -1 on failure");

cleanup:
   if (fd >= 0)
   {
      close(fd);
   }
   shmem = old_shmem;
   MCTF_FINISH();
}
