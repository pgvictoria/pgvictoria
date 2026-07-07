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
#include <guc.h>
#include <utils.h>
#include <value.h>

/* system */
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Leading/trailing whitespace is always trimmed before comparing. These list the
 * characters removed everywhere else: nothing for the generic path (so a path or
 * format string keeps its internal spaces), and the hyphen for locale/encoding
 * names so that "UTF-8" and "utf8" collapse together. */
#define GUC_STRIP_NONE   NULL
#define GUC_STRIP_LOCALE "-"

/* One comparator per troublesome GUC: given the baseline default and the live
 * value it decides whether they differ. */
typedef int (*guc_compare_fn)(char* baseline, char* current, bool* modified);

struct guc_comparator
{
   const char* name;       /**< GUC name           */
   guc_compare_fn compare; /**< Its comparator     */
};

/* One function per troublesome GUC. They are the per-GUC seams: when a single
 * setting needs to diverge from the shared behaviour, edit only its function. */
static int compare_lc_messages(char* baseline, char* current, bool* modified);
static int compare_lc_monetary(char* baseline, char* current, bool* modified);
static int compare_lc_numeric(char* baseline, char* current, bool* modified);
static int compare_lc_time(char* baseline, char* current, bool* modified);

/* Reusable building blocks shared by the comparators above. */
static int compare_locale(char* baseline, char* current, bool* modified);
static bool guc_equal(char* baseline, char* current, const char* strip, bool fold_case);
static char* guc_normalize(const char* value, const char* strip, bool fold_case);

/* The list of GUCs that need special comparison, and the function for each.
 * pgvictoria_check_guc consults this list; anything not here uses the default. */
static struct guc_comparator special_gucs[] = {
   {"lc_messages", compare_lc_messages},
   {"lc_monetary", compare_lc_monetary},
   {"lc_numeric", compare_lc_numeric},
   {"lc_time", compare_lc_time},
   {NULL, NULL}};

int
pgvictoria_check_guc(char* guc_name, enum value_type type, char* baseline_val, char* current_val, bool* modified)
{
   char* baseline = baseline_val ? baseline_val : "";
   char* current = current_val ? current_val : "";

   if (modified == NULL)
   {
      return 1;
   }

   /* Does this GUC need special comparison? If it is in the list, hand it to
    * its own function. */
   if (guc_name != NULL)
   {
      for (int i = 0; special_gucs[i].name != NULL; i++)
      {
         if (strcasecmp(guc_name, special_gucs[i].name) == 0)
         {
            return special_gucs[i].compare(baseline, current, modified);
         }
      }
   }

   /*
    * Default handling. String values are compared ignoring case and surrounding
    * whitespace; numeric and boolean values are compared exactly so that a value
    * such as "-1" is never rewritten.
    */
   if (type == ValueString || type == ValueStringRef)
   {
      *modified = !guc_equal(baseline, current, GUC_STRIP_NONE, true);
   }
   else
   {
      *modified = (strcmp(baseline, current) != 0);
   }

   return 0;
}

/*
 * The lc_* settings share the same locale/encoding rules today, so each defers
 * to compare_locale. They stay separate functions so any one of them can grow
 * its own handling later without touching the others.
 */
static int
compare_lc_messages(char* baseline, char* current, bool* modified)
{
   return compare_locale(baseline, current, modified);
}

static int
compare_lc_monetary(char* baseline, char* current, bool* modified)
{
   return compare_locale(baseline, current, modified);
}

static int
compare_lc_numeric(char* baseline, char* current, bool* modified)
{
   return compare_locale(baseline, current, modified);
}

static int
compare_lc_time(char* baseline, char* current, bool* modified)
{
   return compare_locale(baseline, current, modified);
}

/*
 * Shared locale/encoding comparison: case-fold, trim surrounding whitespace, and
 * drop hyphens so that "en_US.UTF-8" and "en_US.utf8" are treated as the same
 * locale. Dropping the hyphen is safe here because these GUCs are always locale
 * strings, never numeric values.
 */
static int
compare_locale(char* baseline, char* current, bool* modified)
{
   *modified = !guc_equal(baseline, current, GUC_STRIP_LOCALE, true);
   return 0;
}

/*
 * Equivalence primitive shared by every normalizing comparator: normalize both
 * sides with the same rules, then compare. Comparators differ only in the rules
 * they pass (which characters to strip, whether to fold case).
 */
static bool
guc_equal(char* baseline, char* current, const char* strip, bool fold_case)
{
   char* nb = guc_normalize(baseline, strip, fold_case);
   char* nc = guc_normalize(current, strip, fold_case);
   bool equal = strcmp(nb ? nb : "", nc ? nc : "") == 0;

   free(nb);
   free(nc);

   return equal;
}

/*
 * Return a newly allocated copy of value with leading and trailing whitespace
 * trimmed, every character in strip removed, and (when fold_case is set)
 * lowercased. Internal whitespace is preserved, so paths and format strings are
 * compared faithfully. Returns NULL for a NULL input or when nothing remains;
 * callers treat NULL as the empty string. Uses the same pgvictoria_append_char
 * building block as pgvictoria_remove_whitespace.
 */
static char*
guc_normalize(const char* value, const char* strip, bool fold_case)
{
   char* result = NULL;
   size_t start;
   size_t end;

   if (value == NULL)
   {
      return NULL;
   }

   /* Trim leading and trailing whitespace; internal whitespace is kept. */
   start = 0;
   while (value[start] != '\0' && isspace((unsigned char)value[start]))
   {
      start++;
   }
   end = strlen(value);
   while (end > start && isspace((unsigned char)value[end - 1]))
   {
      end--;
   }

   for (size_t i = start; i < end; i++)
   {
      char c = value[i];

      if (strip != NULL && strchr(strip, c) != NULL)
      {
         continue;
      }

      if (fold_case)
      {
         c = (char)tolower((unsigned char)c);
      }

      result = pgvictoria_append_char(result, c);
   }

   return result;
}
