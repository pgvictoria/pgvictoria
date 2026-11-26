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

MCTF_TEST_SETUP(message_tuple)
{
   pgvictoria_test_setup();
}

MCTF_TEST_TEARDOWN(message_tuple)
{
   pgvictoria_test_teardown();
}

static size_t
put_msg(unsigned char* buf, size_t off, char kind, const void* body, uint32_t body_len)
{
   uint32_t len = htonl(body_len + 4);

   buf[off] = kind;
   memcpy(buf + off + 1, &len, 4);
   memcpy(buf + off + 5, body, body_len);
   return off + 5 + body_len;
}

/* T(1 column "c"), D(body), Z; run through pgvictoria_query_execute over a socketpair. */
static int
run_query(const unsigned char* d_body, uint32_t d_len, struct query_response** response)
{
   unsigned char buf[512];
   unsigned char t[2 + 2 + 18] = {0};
   unsigned char z = 'I';
   size_t off = 0;
   int fds[2];
   int ret = -1;
   struct message* q = NULL;

   t[1] = 1; /* one column */
   t[2] = 'c';

   off = put_msg(buf, off, 'T', t, sizeof(t));
   off = put_msg(buf, off, 'D', d_body, d_len);
   off = put_msg(buf, off, 'Z', &z, 1);

   *response = NULL;
   if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
   {
      return -1;
   }
   pgvictoria_create_query_message("SELECT 1", &q);
   if (write(fds[1], buf, off) == (ssize_t)off)
   {
      ret = pgvictoria_query_execute(NULL, fds[0], q, response);
   }
   pgvictoria_free_message(q);
   close(fds[0]);
   close(fds[1]);
   return ret;
}

/* A DataRow field whose length runs past the end of the message must be rejected. */
MCTF_TEST(test_query_execute_datarow_field_too_long)
{
   /* 1 field announcing 100000 bytes, but only 3 bytes follow */
   unsigned char d[] = {0, 1, 0x00, 0x01, 0x86, 0xA0, 'a', 'b', 'c'};
   struct query_response* r = NULL;

   MCTF_ASSERT_INT_EQ(run_query(d, sizeof(d), &r), 1, cleanup);
   MCTF_ASSERT_PTR_NULL(r, cleanup);

cleanup:
   pgvictoria_free_query_response(r);
   MCTF_FINISH();
}

/* A DataRow with fewer fields than the RowDescription announced must be rejected. */
MCTF_TEST(test_query_execute_datarow_too_few_fields)
{
   unsigned char d[] = {0, 0};
   struct query_response* r = NULL;

   MCTF_ASSERT_INT_EQ(run_query(d, sizeof(d), &r), 1, cleanup);
   MCTF_ASSERT_PTR_NULL(r, cleanup);

cleanup:
   pgvictoria_free_query_response(r);
   MCTF_FINISH();
}

/* A well-formed DataRow still parses. */
MCTF_TEST(test_query_execute_datarow_ok)
{
   unsigned char d[] = {0, 1, 0, 0, 0, 2, 'h', 'i'};
   struct query_response* r = NULL;

   MCTF_ASSERT_INT_EQ(run_query(d, sizeof(d), &r), 0, cleanup);
   MCTF_ASSERT_PTR_NONNULL(r, cleanup);
   MCTF_ASSERT_STR_EQ(r->tuples->data[0], "hi", cleanup);

cleanup:
   pgvictoria_free_query_response(r);
   MCTF_FINISH();
}
