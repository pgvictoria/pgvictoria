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

/* baselines */
#include <pg14.h>
#include <pg15.h>
#include <pg16.h>
#include <pg17.h>
#include <pg18.h>

/* system */
#include <stdlib.h>
#include <string.h>

/**
 * Get the PostgreSQL baseline configuration for a specific version.
 * 
 * @param version The PostgreSQL version (e.g. 14, 15, 16, 17, 18)
 * @return The JSON baseline object, or NULL if the version is not supported or parsing fails.
 */
struct json*
pgvictoria_get_baseline(int version)
{
   const char* json_str = NULL;
   struct json* baseline = NULL;

   switch (version)
   {
      case 14:
         json_str = pg14_json;
         break;
      case 15:
         json_str = pg15_json;
         break;
      case 16:
         json_str = pg16_json;
         break;
      case 17:
         json_str = pg17_json;
         break;
      case 18:
         json_str = pg18_json;
         break;
      default:
         return NULL;
   }

   if (json_str != NULL)
   {
      if (pgvictoria_json_parse_string((char*)json_str, &baseline) == 0)
      {
         return baseline;
      }
   }

   return NULL;
}
