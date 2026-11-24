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
#include <mctf.h>

#include <tscommon.h>
#include <message.h>
#include <utils.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

MCTF_TEST_SETUP(message)
{
   pgvictoria_test_setup();
}

MCTF_TEST_TEARDOWN(message)
{
   pgvictoria_test_teardown();
}

/* Append a RowDescription column (name plus the 18 fixed bytes) to buf. */
static size_t
add_column(unsigned char* buf, size_t off, const char* name)
{
   size_t n = strlen(name) + 1;

   memcpy(buf + off, name, n);
   memset(buf + off + n, 0, 18);
   return off + n + 18;
}

/* Wrap a body into a 'T' message followed by ReadyForQuery, as one buffer. */
static size_t
finish_T(unsigned char* buf, size_t body_end, uint16_t cols)
{
   uint32_t len = htonl((uint32_t)(body_end - 1));
   uint16_t c = htons(cols);

   buf[0] = 'T';
   memcpy(buf + 1, &len, 4);
   memcpy(buf + 5, &c, 2);

   len = htonl(5);
   buf[body_end] = 'Z';
   memcpy(buf + body_end + 1, &len, 4);
   buf[body_end + 5] = 'I';
   return body_end + 6;
}

static int
run_query(unsigned char* reply, size_t reply_size, struct query_response** response)
{
   int fds[2];
   int ret;
   struct message* q = NULL;

   *response = NULL;
   if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
   {
      return -1;
   }

   pgvictoria_create_query_message("SELECT 1", &q);
   if (write(fds[1], reply, reply_size) != (ssize_t)reply_size)
   {
      ret = -1;
      goto done;
   }
   ret = pgvictoria_query_execute(NULL, fds[0], q, response);

done:
   pgvictoria_free_message(q);
   close(fds[0]);
   close(fds[1]);
   return ret;
}

/* A RowDescription announcing more columns than query_response can hold must be rejected. */
MCTF_TEST(test_query_execute_too_many_columns)
{
   unsigned char buf[2048];
   size_t off = 7;
   struct query_response* r = NULL;

   for (int i = 0; i < MAX_NUMBER_OF_COLUMNS + 4; i++)
   {
      off = add_column(buf, off, "c");
   }

   MCTF_ASSERT_INT_EQ(run_query(buf, finish_T(buf, off, MAX_NUMBER_OF_COLUMNS + 4), &r), 1, cleanup);
   MCTF_ASSERT_PTR_NULL(r, cleanup);

cleanup:
   MCTF_FINISH();
}

/* A column name longer than the name slot must be rejected or truncated, never overflow. */
MCTF_TEST(test_query_execute_long_column_name)
{
   unsigned char buf[2048];
   char name[MISC_LENGTH * 3];
   struct query_response* r = NULL;

   memset(name, 'x', sizeof(name) - 1);
   name[sizeof(name) - 1] = '\0';

   MCTF_ASSERT_INT_EQ(run_query(buf, finish_T(buf, add_column(buf, 7, name), 1), &r), 0, cleanup);
   MCTF_ASSERT_INT_EQ(r->number_of_columns, 1, cleanup);
   MCTF_ASSERT(strlen(r->names[0]) < MISC_LENGTH, cleanup);
   MCTF_ASSERT_INT_EQ(r->names[1][0], 0, cleanup);

cleanup:
   pgvictoria_free_query_response(r);
   MCTF_FINISH();
}
