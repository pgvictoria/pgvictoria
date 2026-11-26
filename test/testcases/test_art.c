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
#include <art.h>
#include <mctf.h>
#include <utils.h>

#include <stdlib.h>
#include <string.h>

MCTF_TEST(test_art_iterator_remove_collapse)
{
   struct art* t = NULL;
   struct art_iterator* iter = NULL;
   int cnt = 0;

   pgvictoria_art_create(&t);
   MCTF_ASSERT_PTR_NONNULL(t, cleanup, "ART creation failed");

   MCTF_ASSERT(!pgvictoria_art_insert(t, "aa", 1, ValueInt32), cleanup, "Insert aa failed");
   MCTF_ASSERT(!pgvictoria_art_insert(t, "ab", 2, ValueInt32), cleanup, "Insert ab failed");
   MCTF_ASSERT(!pgvictoria_art_insert(t, "ba", 3, ValueInt32), cleanup, "Insert ba failed");
   MCTF_ASSERT(!pgvictoria_art_insert(t, "bb", 4, ValueInt32), cleanup, "Insert bb failed");

   MCTF_ASSERT(!pgvictoria_art_iterator_create(t, &iter), cleanup, "Iterator creation failed");

   while (pgvictoria_art_iterator_next(iter))
   {
      cnt++;
      if (pgvictoria_compare_string(iter->key, "aa") || pgvictoria_compare_string(iter->key, "ab"))
      {
         pgvictoria_art_iterator_remove(iter);
      }
   }

   MCTF_ASSERT_INT_EQ(cnt, 4, cleanup, "visited count mismatch");
   MCTF_ASSERT_INT_EQ(t->size, 2, cleanup, "size should be 2");
   MCTF_ASSERT(!pgvictoria_art_contains_key(t, "aa"), cleanup, "aa should be removed");
   MCTF_ASSERT(!pgvictoria_art_contains_key(t, "ab"), cleanup, "ab should be removed");
   MCTF_ASSERT(pgvictoria_art_contains_key(t, "ba"), cleanup, "ba should remain");
   MCTF_ASSERT(pgvictoria_art_contains_key(t, "bb"), cleanup, "bb should remain");

cleanup:
   pgvictoria_art_iterator_destroy(iter);
   pgvictoria_art_destroy(t);
   MCTF_FINISH();
}
