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

#include <html_suggest.h>

#include <inttypes.h>
#include <stdio.h>

int
pgvictoria_generate_html_suggest(const char* output_html_path, uint64_t shared_buffers_val, const char* shared_buffers_unit)
{
   FILE* f = fopen(output_html_path, "w");

   if (f == NULL)
   {
      perror("Could not open output file");
      return 1;
   }

   fprintf(f, "<!DOCTYPE html>\n");
   fprintf(f, "<html>\n");
   fprintf(f, "<head>\n");
   fprintf(f, " <title>Suggested PostgreSQL Configurations Parameters</title>\n");
   fprintf(f, "</head>\n");

   fprintf(f, "<body>\n");
   fprintf(f, " <h1>Suggested PostgreSQL Configurations Parameters</h1>\n");
   fprintf(f, " <pre>shared_buffers = %" PRIu64 "%s</pre>\n", shared_buffers_val, shared_buffers_unit);
   fprintf(f, "</body>\n");

   fprintf(f, "</html>\n");

   fclose(f);
   return 0;
}