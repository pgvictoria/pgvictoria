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
#include <logging.h>
#include <utf8.h>

/* system */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

bool
pgvictoria_utf8_sequence_valid(const unsigned char* source, size_t length)
{
   unsigned char a;

   switch (length)
   {
      default:
         return false;

      case 4:
         a = source[3];
         if (a < 0x80 || a > 0xBF)
         {
            return false;
         }
         /* fallthrough */

      case 3:
         a = source[2];
         if (a < 0x80 || a > 0xBF)
         {
            return false;
         }
         /* fallthrough */

      case 2:
         a = source[1];
         switch (source[0])
         {
            case 0xE0:
               if (a < 0xA0 || a > 0xBF)
               {
                  return false;
               }
               break;

            case 0xED:
               if (a < 0x80 || a > 0x9F)
               {
                  return false;
               }
               break;

            case 0xF0:
               if (a < 0x90 || a > 0xBF)
               {
                  return false;
               }
               break;

            case 0xF4:
               if (a < 0x80 || a > 0x8F)
               {
                  return false;
               }
               break;

            default:
               if (a < 0x80 || a > 0xBF)
               {
                  return false;
               }
               break;
         }
         /* fallthrough */

      case 1:
         a = source[0];

         if (a >= 0x80 && a < 0xC2)
         {
            return false;
         }

         if (a > 0xF4)
         {
            return false;
         }
         break;
   }

   return true;
}

int
pgvictoria_utf8_sequence_length(unsigned char first_byte)
{
   if (first_byte < 0x80)
   {
      return 1;
   }
   else if ((first_byte & 0xE0) == 0xC0)
   {
      return 2;
   }
   else if ((first_byte & 0xF0) == 0xE0)
   {
      return 3;
   }
   else if ((first_byte & 0xF8) == 0xF0)
   {
      return 4;
   }
   else
   {
      return -1;
   }
}

bool
pgvictoria_utf8_valid(const unsigned char* buf, size_t length)
{
   size_t i = 0;

   while (i < length)
   {
      int seq_length = pgvictoria_utf8_sequence_length(buf[i]);

      if (seq_length < 0)
      {
         return false;
      }

      if (i + seq_length > length)
      {
         return false;
      }

      if (!pgvictoria_utf8_sequence_valid(&buf[i], seq_length))
      {
         return false;
      }

      i += seq_length;
   }

   return true;
}

size_t
pgvictoria_utf8_char_length(const unsigned char* buf, size_t length)
{
   size_t count = 0;
   size_t i = 0;

   while (i < length)
   {
      int seq_length = pgvictoria_utf8_sequence_length(buf[i]);

      if (seq_length < 0)
      {
         return (size_t)-1;
      }

      if (i + seq_length > length)
      {
         return (size_t)-1;
      }

      if (!pgvictoria_utf8_sequence_valid(&buf[i], seq_length))
      {
         return (size_t)-1;
      }

      i += seq_length;
      count++;
   }

   return count;
}

bool
pgvictoria_is_ascii(const char* str, size_t length)
{
   for (size_t i = 0; i < length; i++)
   {
      if ((unsigned char)str[i] > 127)
      {
         return false;
      }
   }
   return true;
}
