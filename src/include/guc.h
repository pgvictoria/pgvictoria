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

#ifndef PGVICTORIA_GUC_H
#define PGVICTORIA_GUC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pgvictoria.h>
#include <value.h>

#include <stdbool.h>

/**
 * Decide whether a live GUC value differs from its baseline default.
 *
 * The baseline default and the live value are compared after normalization so
 * that values which mean the same thing but are spelled differently are not
 * reported as changed. A GUC that needs bespoke handling (e.g. locale/encoding
 * names) is routed to a dedicated comparator; every other GUC uses the generic
 * path.
 *
 * Normalization is gated on @p type: only string-valued GUCs are normalized
 * (case-insensitive, whitespace-insensitive). Numeric and boolean values are
 * compared exactly so a value such as "-1" is never rewritten.
 *
 * @param guc_name The GUC name (used to select a per-GUC comparator)
 * @param type The baseline value type (as stored in the JSON baseline)
 * @param baseline_val The baseline default, rendered as text
 * @param current_val The live value from the server
 * @param modified Set to true when the values differ, false when equivalent
 * @return 0 on success, otherwise 1
 */
int
pgvictoria_check_guc(char* guc_name, enum value_type type, char* baseline_val, char* current_val, bool* modified);

#ifdef __cplusplus
}
#endif

#endif
