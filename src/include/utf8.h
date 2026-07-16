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

#ifndef PGVICTORIA_UTF8_H
#define PGVICTORIA_UTF8_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>

/**
 * Validate if a sequence of bytes is a valid UTF-8 sequence
 * @param source The bytes sequence
 * @param length The length of the sequence
 * @return True if valid, otherwise false
 */
bool
pgvictoria_utf8_sequence_valid(const unsigned char* source, size_t length);

/**
 * Get the expected length of a UTF-8 character based on its first byte
 * @param first_byte The first byte of the UTF-8 character
 * @return The length of the character sequence in bytes (1 to 4), or -1 if invalid
 */
int
pgvictoria_utf8_sequence_length(unsigned char first_byte);

/**
 * Validate if a buffer contains valid UTF-8 content
 * @param buf The buffer
 * @param length The length of the buffer
 * @return True if valid, otherwise false
 */
bool
pgvictoria_utf8_valid(const unsigned char* buf, size_t length);

/**
 * Calculate the number of UTF-8 characters (code points) in a buffer
 * @param buf The buffer
 * @param length The length of the buffer in bytes
 * @return The number of UTF-8 characters, or (size_t)-1 if the buffer contains invalid UTF-8
 */
size_t
pgvictoria_utf8_char_length(const unsigned char* buf, size_t length);

/**
 * Validate if a string contains only ASCII characters
 * @param str The string
 * @param length The length of the string
 * @return True if only ASCII, otherwise false
 */
bool
pgvictoria_is_ascii(const char* str, size_t length);

#ifdef __cplusplus
}
#endif

#endif
