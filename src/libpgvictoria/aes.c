/*
 * Copyright (C) 2025 The pgvictoria community
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

#include <pgvictoria.h>
#include <aes.h>
#include <logging.h>
#include <security.h>
#include <utils.h>

/* System */
#include <dirent.h>

#define NAME "aes"
#define ENC_BUF_SIZE (1024 * 1024)

static int encrypt_file(char* from, char* to, int enc);
static int derive_key_iv(char* password, unsigned char* key, unsigned char* iv, int mode);
static int aes_encrypt(char* plaintext, unsigned char* key, unsigned char* iv, char** ciphertext, int* ciphertext_length, int mode);
static int aes_decrypt(char* ciphertext, int ciphertext_length, unsigned char* key, unsigned char* iv, char** plaintext, int mode);
static const EVP_CIPHER* (*get_cipher(int mode))(void);
static const EVP_CIPHER* (*get_cipher_buffer(int mode))(void);

static int encrypt_decrypt_buffer(unsigned char* origin_buffer, size_t origin_size, unsigned char** res_buffer, size_t* res_size, int enc, int mode);

int
pgvictoria_encrypt_file(char* from, char* to)
{
   int flag = 0;
   if (!pgvictoria_exists(from))
   {
      pgvictoria_log_error("pgvictoria_encrypt_file: file not exist: %s", from);
      return 1;
   }

   if (!to)
   {
      to = pgvictoria_append(to, from);
      to = pgvictoria_append(to, ".aes");
      flag = 1;
   }

   encrypt_file(from, to, 1);

   if (pgvictoria_exists(from))
   {
      pgvictoria_delete_file(from);
   }
   else
   {
      pgvictoria_log_debug("%s doesn't exists", from);
   }

   if (flag)
   {
      free(to);
   }
   return 0;
}

int
pgvictoria_decrypt_file(char* from, char* to)
{
   int flag = 0;

   if (!pgvictoria_exists(from))
   {
      pgvictoria_log_error("pgvictoria_decrypt_file: file not exist: %s", from);
      return 1;
   }

   if (!to)
   {
      if (pgvictoria_strip_extension(from, &to))
      {
         return 1;
      }
      flag = 1;
   }

   encrypt_file(from, to, 0);
   if (pgvictoria_exists(from))
   {
      pgvictoria_delete_file(from);
   }
   else
   {
      pgvictoria_log_debug("%s doesn't exists", from);
   }

   if (flag)
   {
      free(to);
   }
   return 0;
}

int
pgvictoria_encrypt(char* plaintext, char* password, char** ciphertext, int* ciphertext_length, int mode)
{
   unsigned char key[EVP_MAX_KEY_LENGTH];
   unsigned char iv[EVP_MAX_IV_LENGTH];

   memset(&key, 0, sizeof(key));
   memset(&iv, 0, sizeof(iv));

   if (derive_key_iv(password, key, iv, mode) != 0)
   {
      return 1;
   }

   return aes_encrypt(plaintext, key, iv, ciphertext, ciphertext_length, mode);
}

int
pgvictoria_decrypt(char* ciphertext, int ciphertext_length, char* password, char** plaintext, int mode)
{
   unsigned char key[EVP_MAX_KEY_LENGTH];
   unsigned char iv[EVP_MAX_IV_LENGTH];

   memset(&key, 0, sizeof(key));
   memset(&iv, 0, sizeof(iv));

   if (derive_key_iv(password, key, iv, mode) != 0)
   {
      return 1;
   }

   return aes_decrypt(ciphertext, ciphertext_length, key, iv, plaintext, mode);
}

// [private]
static int
derive_key_iv(char* password, unsigned char* key, unsigned char* iv, int mode)
{
   if (!EVP_BytesToKey(get_cipher(mode)(), EVP_sha1(), NULL,
                       (unsigned char*) password, strlen(password), 1,
                       key, iv))
   {
      return 1;
   }

   return 0;
}

// [private]
static int
aes_encrypt(char* plaintext, unsigned char* key, unsigned char* iv, char** ciphertext, int* ciphertext_length, int mode)
{
   EVP_CIPHER_CTX* ctx = NULL;
   int length;
   size_t size;
   unsigned char* ct = NULL;
   int ct_length;
   const EVP_CIPHER* (* cipher_fp)(void) = get_cipher(mode);
   if (!(ctx = EVP_CIPHER_CTX_new()))
   {
      goto error;
   }

   if (EVP_EncryptInit_ex(ctx, cipher_fp(), NULL, key, iv) != 1)
   {
      goto error;
   }

   size = strlen(plaintext) + EVP_CIPHER_block_size(cipher_fp());
   ct = malloc(size);

   if (ct == NULL)
   {
      goto error;
   }

   memset(ct, 0, size);

   if (EVP_EncryptUpdate(ctx,
                         ct, &length,
                         (unsigned char*)plaintext, strlen((char*)plaintext)) != 1)
   {
      goto error;
   }

   ct_length = length;

   if (EVP_EncryptFinal_ex(ctx, ct + length, &length) != 1)
   {
      goto error;
   }

   ct_length += length;

   EVP_CIPHER_CTX_free(ctx);

   *ciphertext = (char*)ct;
   *ciphertext_length = ct_length;

   return 0;

error:
   if (ctx)
   {
      EVP_CIPHER_CTX_free(ctx);
   }

   free(ct);

   return 1;
}

// [private]
static int
aes_decrypt(char* ciphertext, int ciphertext_length, unsigned char* key, unsigned char* iv, char** plaintext, int mode)
{
   EVP_CIPHER_CTX* ctx = NULL;
   int plaintext_length;
   int length;
   size_t size;
   char* pt = NULL;
   const EVP_CIPHER* (* cipher_fp)(void) = get_cipher(mode);

   if (!(ctx = EVP_CIPHER_CTX_new()))
   {
      goto error;
   }

   if (EVP_DecryptInit_ex(ctx, cipher_fp(), NULL, key, iv) != 1)
   {
      goto error;
   }

   size = ciphertext_length + EVP_CIPHER_block_size(cipher_fp());
   pt = malloc(size);

   if (pt == NULL)
   {
      goto error;
   }

   memset(pt, 0, size);

   if (EVP_DecryptUpdate(ctx,
                         (unsigned char*)pt, &length,
                         (unsigned char*)ciphertext, ciphertext_length) != 1)
   {
      goto error;
   }

   plaintext_length = length;

   if (EVP_DecryptFinal_ex(ctx, (unsigned char*)pt + length, &length) != 1)
   {
      goto error;
   }

   plaintext_length += length;

   EVP_CIPHER_CTX_free(ctx);

   pt[plaintext_length] = 0;
   *plaintext = pt;

   return 0;

error:
   if (ctx)
   {
      EVP_CIPHER_CTX_free(ctx);
   }

   free(pt);

   return 1;
}

static const EVP_CIPHER* (*get_cipher(int mode))(void)
{
   if (mode == ENCRYPTION_AES_256_CBC)
   {
      return &EVP_aes_256_cbc;
   }
   if (mode == ENCRYPTION_AES_192_CBC)
   {
      return &EVP_aes_192_cbc;
   }
   if (mode == ENCRYPTION_AES_128_CBC)
   {
      return &EVP_aes_128_cbc;
   }
   if (mode == ENCRYPTION_AES_256_CTR)
   {
      return &EVP_aes_256_ctr;
   }
   if (mode == ENCRYPTION_AES_192_CTR)
   {
      return &EVP_aes_192_ctr;
   }
   if (mode == ENCRYPTION_AES_128_CTR)
   {
      return &EVP_aes_128_ctr;
   }
   return &EVP_aes_256_cbc;
}

// enc: 1 for encrypt, 0 for decrypt
static int
encrypt_file(char* from, char* to, int enc)
{
   unsigned char key[EVP_MAX_KEY_LENGTH];
   unsigned char iv[EVP_MAX_IV_LENGTH];
   char* master_key = NULL;
   EVP_CIPHER_CTX* ctx = NULL;
   const EVP_CIPHER* (* cipher_fp)(void) = NULL;
   int cipher_block_size = 0;
   int inbuf_size = 0;
   int outbuf_size = 0;
   FILE* in = NULL;
   FILE* out = NULL;
   int inl = 0;
   int outl = 0;
   int f_len = 0;

   cipher_fp = get_cipher(ENCRYPTION_AES_256_CBC);
   cipher_block_size = EVP_CIPHER_block_size(cipher_fp());
   inbuf_size = ENC_BUF_SIZE;
   outbuf_size = inbuf_size + cipher_block_size - 1;
   unsigned char inbuf[inbuf_size];
   unsigned char outbuf[outbuf_size];

   if (pgvictoria_get_master_key(&master_key))
   {
      pgvictoria_log_error("pgvictoria_get_master_key: Invalid master key");
      goto error;
   }
   memset(&key, 0, sizeof(key));
   memset(&iv, 0, sizeof(iv));
   if (derive_key_iv(master_key, key, iv, ENCRYPTION_AES_256_CBC) != 0) {
      pgvictoria_log_error("derive_key_iv: Failed to derive key and iv");
      goto error;
   }

   if (!(ctx = EVP_CIPHER_CTX_new()))
   {
      pgvictoria_log_error("EVP_CIPHER_CTX_new: Failed to get context");
      goto error;
   }

   in = fopen(from, "rb");
   if (in == NULL)
   {
      pgvictoria_log_error("fopen: Could not open %s", from);
      goto error;
   }

   out = fopen(to, "w");
   if (out == NULL)
   {
      pgvictoria_log_error("fopen: Could not open %s", to);
      goto error;
   }

   if (EVP_CipherInit_ex(ctx, cipher_fp(), NULL, key, iv, enc) == 0)
   {
      pgvictoria_log_error("EVP_CipherInit_ex: ailed to initialize context");
      goto error;
   }

   while ((inl = fread(inbuf, sizeof(char), inbuf_size, in)) > 0)
   {
      if (EVP_CipherUpdate(ctx, outbuf, &outl, inbuf, inl) == 0)
      {
         pgvictoria_log_error("EVP_CipherUpdate: failed to process block");
         goto error;
      }
      if (fwrite(outbuf, sizeof(char), outl, out) != (size_t)outl)
      {
         pgvictoria_log_error("fwrite: failed to write cipher");
         goto error;
      }
   }

   if (ferror(in))
   {
      pgvictoria_log_error("fread: error reading from file: %s", from);
      goto error;
   }

   if (EVP_CipherFinal_ex(ctx, outbuf, &f_len) == 0)
   {
      pgvictoria_log_error("EVP_CipherFinal_ex: failed to process final cipher block");
      goto error;
   }

   if (f_len)
   {
      if (fwrite(outbuf, sizeof(char), f_len, out) != (size_t)f_len)
      {
         pgvictoria_log_error("fwrite: failed to write final block");
         goto error;
      }
   }

   if (ctx)
   {
      EVP_CIPHER_CTX_free(ctx);
   }
   free(master_key);
   fclose(in);
   fclose(out);
   return 0;

error:
   if (ctx)
   {
      EVP_CIPHER_CTX_free(ctx);
   }

   free(master_key);

   if (in != NULL)
   {
      fclose(in);
   }

   if (out != NULL)
   {
      fclose(out);
   }

   return 1;
}

int
pgvictoria_encrypt_buffer(unsigned char* origin_buffer, size_t origin_size, unsigned char** enc_buffer, size_t* enc_size, int mode)
{
   return encrypt_decrypt_buffer(origin_buffer, origin_size, enc_buffer, enc_size, 1, mode);
}

int
pgvictoria_decrypt_buffer(unsigned char* origin_buffer, size_t origin_size, unsigned char** dec_buffer, size_t* dec_size, int mode)
{
   return encrypt_decrypt_buffer(origin_buffer, origin_size, dec_buffer, dec_size, 0, mode);
}

static int
encrypt_decrypt_buffer(unsigned char* origin_buffer, size_t origin_size, unsigned char** res_buffer, size_t* res_size, int enc, int mode)
{
   unsigned char key[EVP_MAX_KEY_LENGTH];
   unsigned char iv[EVP_MAX_IV_LENGTH];
   char* master_key = NULL;
   EVP_CIPHER_CTX* ctx = NULL;
   const EVP_CIPHER* (*cipher_fp)(void) = NULL;
   size_t cipher_block_size = 0;
   size_t outbuf_size = 0;
   size_t outl = 0;
   size_t f_len = 0;

   cipher_fp = get_cipher_buffer(mode);
   if (cipher_fp == NULL)
   {
      pgvictoria_log_error("Invalid encryption method specified");
      goto error;
   }

   cipher_block_size = EVP_CIPHER_block_size(cipher_fp());

   if (enc == 1)
   {
      outbuf_size = origin_size + cipher_block_size;
   }
   else
   {
      outbuf_size = origin_size;
   }

   *res_buffer = (unsigned char*)malloc(outbuf_size + 1);
   if (*res_buffer == NULL)
   {
      pgvictoria_log_error("pgvictoria_encrypt_decrypt_buffer: Allocation failure");
      goto error;
   }

   if (pgvictoria_get_master_key(&master_key))
   {
      pgvictoria_log_error("pgvictoria_get_master_key: Invalid master key");
      goto error;
   }

   memset(&key, 0, sizeof(key));
   memset(&iv, 0, sizeof(iv));

   if (derive_key_iv(master_key, key, iv, mode) != 0)
   {
      pgvictoria_log_error("derive_key_iv: Failed to derive key and iv");
      goto error;
   }

   if (!(ctx = EVP_CIPHER_CTX_new()))
   {
      pgvictoria_log_error("EVP_CIPHER_CTX_new: Failed to create context");
      goto error;
   }

   if (EVP_CipherInit_ex(ctx, cipher_fp(), NULL, key, iv, enc) == 0)
   {
      pgvictoria_log_error("EVP_CipherInit_ex: Failed to initialize cipher context");
      goto error;
   }

   if (EVP_CipherUpdate(ctx, *res_buffer, (int*)&outl, origin_buffer, origin_size) == 0)
   {
      pgvictoria_log_error("EVP_CipherUpdate: Failed to process data");
      goto error;
   }

   *res_size = outl;

   if (EVP_CipherFinal_ex(ctx, *res_buffer + outl, (int*)&f_len) == 0)
   {
      pgvictoria_log_error("EVP_CipherFinal_ex: Failed to finalize operation");
      goto error;
   }

   *res_size += f_len;

   if (enc == 0)
   {
      (*res_buffer)[*res_size] = '\0';
   }

   EVP_CIPHER_CTX_free(ctx);
   free(master_key);

   return 0;

error:
   if (ctx)
   {
      EVP_CIPHER_CTX_free(ctx);
   }

   free(master_key);

   return 1;
}

static const EVP_CIPHER* (*get_cipher_buffer(int mode))(void)
{
   if (mode == ENCRYPTION_AES_256_CBC)
   {
      return &EVP_aes_256_cbc;
   }
   if (mode == ENCRYPTION_AES_192_CBC)
   {
      return &EVP_aes_192_cbc;
   }
   if (mode == ENCRYPTION_AES_128_CBC)
   {
      return &EVP_aes_128_cbc;
   }
   return &EVP_aes_256_cbc;
}
