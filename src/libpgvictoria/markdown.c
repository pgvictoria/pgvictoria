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
#include <deque.h>
#include <markdown.h>
#include <utils.h>

/* system */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
pgvictoria_generate_markdown_report(const char* output_md_path, int version, struct deque* items, const char* scope_label, const char* scope_value)
{
   pgvictoria_mkdir_parent(output_md_path);

   FILE* f = fopen(output_md_path, "w");
   if (!f)
   {
      return 1;
   }

   fprintf(f, "# PostgreSQL %d Configuration Difference Report\n\n", version);

   fprintf(f, "| Item | Value |\n");
   fprintf(f, "| :--- | :--- |\n");

   if (scope_label && scope_value)
   {
      fprintf(f, "| **%s** | `%s` |\n", scope_label, scope_value);
   }
   fprintf(f, "| **Version** | PostgreSQL %d |\n", version);

   char* os_name = NULL;
   int k_major = 0, k_minor = 0, k_patch = 0;
   if (pgvictoria_os_kernel_version(&os_name, &k_major, &k_minor, &k_patch) == 0)
   {
      fprintf(f, "| **System** | %s %d.%d.%d |\n", os_name, k_major, k_minor, k_patch);
      free(os_name);
   }
   fprintf(f, "\n");

   fprintf(f, "| Configuration Key | Baseline Default | Current Value | Status |\n");
   fprintf(f, "| :--- | :--- | :--- | :--- |\n");

   struct deque_iterator* it = NULL;
   pgvictoria_deque_iterator_create(items, &it);
   while (pgvictoria_deque_iterator_next(it))
   {
      struct pgvictoria_diff_item* curr = (struct pgvictoria_diff_item*)it->value->data;

      /* Wrap values in backticks for clean markdown coding format */
      fprintf(f, "| `%s` | `%s` | `%s` | **%s** |\n",
              curr->key,
              curr->baseline_val,
              curr->current_val,
              curr->status);
   }
   pgvictoria_deque_iterator_destroy(it);

   fclose(f);
   printf("Report successfully generated to %s\n", output_md_path);
   return 0;
}
