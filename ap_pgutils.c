#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <inttypes.h>

#include "postgres.h"
#include "catalog/pg_type.h"
#include "fmgr.h"
#include "utils/builtins.h"

#include "openssl/hmac.h"

#include "ap_pgutils.h"
#include "argon2.h"
#include "argon2/src/core.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1(pg_gethostname);
extern Datum pg_gethostname(PG_FUNCTION_ARGS)
{
  char host_buf[256];
  text *result;
  int status;
  status = gethostname(host_buf, 256);
  if (status == 0) {
    int hlen = strlen(host_buf);
    result = palloc(VARHDRSZ + hlen + 1);
    strcpy(VARDATA(result), host_buf);
    SET_VARSIZE(result, VARHDRSZ + hlen + 1);
    return (Datum) result;
  } else {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("gethostname() failed")));
    return (Datum) NULL;
  }
}

PG_FUNCTION_INFO_V1(pg_argon2);
extern Datum pg_argon2(PG_FUNCTION_ARGS)
{
  text *password = PG_GETARG_TEXT_P(0);
  int pwdlen = VARSIZE(password) - VARHDRSZ;
  text *salt = PG_GETARG_TEXT_P(1);
  int saltlen = VARSIZE(salt) - VARHDRSZ;
  int t_cost = PG_GETARG_INT32(2);
  int log2_mem = PG_GETARG_INT32(3);
  int outlen = PG_GETARG_INT32(4);
  text *variant_text = PG_GETARG_TEXT_P(5);
  char variant = *VARDATA(variant_text);
  int parallelism = PG_GETARG_INT32(6);
  text *result;
  int encodedlen, m_cost, status;

  /* check cost parameters */
  if (t_cost <= 0) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("iterations must be a positive integer, not %d", t_cost)));
    return (Datum) NULL;
  }
  if (log2_mem <= 0 || log2_mem > 32) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("log2_mem must be between 1 and 32, not %d", log2_mem)));
    return (Datum) NULL;
  }
  m_cost = 1 << log2_mem;
  if (outlen <= 0) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("hash length must be a positive integer, not %d",
                    outlen)));
    return (Datum) NULL;
  }
  if (variant != 'd' && variant != 'i') {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("hash variant must be 'i' or 'd', got '%c'", variant)));
    return (Datum) NULL;
  }
  if (parallelism <= 0) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("parallelism must be a positive integer, not %d",
                    parallelism)));
    return (Datum) NULL;
  }

  encodedlen = argon2_encodedlen(t_cost, m_cost, 1, saltlen, outlen);
  result = palloc(VARHDRSZ + encodedlen);
  SET_VARSIZE(result, VARHDRSZ + encodedlen);
  status = argon2_hash(t_cost, m_cost, parallelism,
                       VARDATA(password), pwdlen,
                       VARDATA(salt), saltlen, NULL, outlen,
                       VARDATA(result), encodedlen,
                       variant == 'i' ? Argon2_i : Argon2_d,
                       ARGON2_VERSION_NUMBER);
  if (status != 0) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("argon2 hash failed, err=%s",
                    argon2_error_message(status))));
    return (Datum) NULL;
  }
  return (Datum) result;
}

PG_FUNCTION_INFO_V1(pg_argon2_verify);
extern Datum pg_argon2_verify(PG_FUNCTION_ARGS)
{
  char *encoded = text_to_cstring(PG_GETARG_TEXT_P(0));
  text *password = PG_GETARG_TEXT_P(1);
  int pwdlen = VARSIZE(password) - VARHDRSZ;
  int status;
  char variant;
  
  /* check parameters */
  if (strncmp(encoded, "$argon2", 7) != 0 || strlen(encoded) < 8) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("Not a valid Argon2 hash: \"%s\"", encoded)));
    return (Datum) NULL;
  }
  variant = encoded[7];
  if (variant != 'i' && variant != 'd') {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("Argon2 variant must be 'i' or 'd', not '%c'", variant)));
    return (Datum) NULL;
  }

  status= argon2_verify(encoded, VARDATA(password), pwdlen,
                        variant == 'i' ? Argon2_i : Argon2_d);
  switch (status) {
  case 0:
    PG_RETURN_BOOL(1);
  case ARGON2_VERIFY_MISMATCH:
    PG_RETURN_BOOL(0);
  default:
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("argon2 verification failed, err=%s",
                    argon2_error_message(status))));
    return (Datum) NULL;
  }
}

#define MAXBUFLEN 64
#define TOTP_TIME_STEP 30

PG_FUNCTION_INFO_V1(pg_totp_verify);
extern Datum pg_totp_verify(PG_FUNCTION_ARGS)
{
  text *b32_secret = PG_GETARG_TEXT_P(0);
  int slen = VARSIZE(b32_secret) - VARHDRSZ;
  int otp = PG_GETARG_INT32(1);
  int tolerance = PG_GETARG_INT32(2);
  
  unsigned char buf[MAXBUFLEN]; /* 16 characters * 5 bits/char Base-32 */
  char c;
  int i, j, k, buflen;
  unsigned long long accum;
  long long ctr;
  
  /* check parameters */
  if (!slen) {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("empty TOTP secret")));
    return (Datum) NULL;
  }
  if (slen * 5 > MAXBUFLEN * 8) {
    secure_wipe_memory(VARDATA(b32_secret), slen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("TOTP secret is too large (%d chars)", slen)));
    return (Datum) NULL;
  }
  if (tolerance < 0) {
    secure_wipe_memory(VARDATA(b32_secret), slen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("Tolerance must be >= 0, not  %d", tolerance)));
    return (Datum) NULL;
  }

  /* decode Base-32 encoded secret in chunks of 8 characters (40 bits) */
  accum = 0;
  k = 0;
  for (i=0; i<slen; i++) {
    accum <<= 5;
    c = VARDATA(b32_secret)[i];
    /* XXX would a lookup table be faster? */
    if (c >= 'A' && c <= 'Z') {
      accum |= c - 'A';
    } else if (c >= '2' && c <= '7') {
      accum |= c - '2' + 26;
    } else if (c == '=') {
      break;
    } else {
      secure_wipe_memory(VARDATA(b32_secret), slen);
      secure_wipe_memory(buf, MAXBUFLEN);
      ereport(ERROR,
              (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
               errmsg("Invalid char %c in TOTP secret", c)));
      return (Datum) NULL;
    }
    if (i % 8 == 7) {
      /* unroll the loop */
      buf[k + 4] = accum & 0xFF;
      accum >>= 8;
      buf[k + 3] = accum & 0xFF;
      accum >>= 8;
      buf[k + 2] = accum & 0xFF;
      accum >>= 8;
      buf[k + 1] = accum & 0xFF;
      accum >>= 8;
      buf[k] = accum & 0xFF;
      accum >>= 8;
      k += 5;
    }
  }
  if (i % 8) {
    accum <<= (8 - (i % 8)) * 5;
    for (j=((i % 8)*5)/8; j >= 0; j--) {
      buf[k + j] = accum & 0xFF;
      accum >>= 8;
    }
  }
  buflen = k;
  /* TOTP */
  ctr = time(NULL) / TOTP_TIME_STEP;
  for (i=-tolerance; i <= +tolerance; i += 1) {
    unsigned long long ctr_be;
    unsigned char hashbuf[EVP_MAX_MD_SIZE];
    int offset;
    unsigned int truncated;
    unsigned char *md;
    unsigned int md_len;

#ifdef linux
    #if __BYTE_ORDER == __LITTLE_ENDIAN
    ctr_be =__bswap_constant_64(ctr + i);  // Compiler builtin
    #else
    ctr_be = ctr + i
      #endif
#else
    ctr_be = htonll(ctr + i);
#endif

    md = HMAC(EVP_sha1(), buf, buflen,
              (unsigned char *)&ctr_be, sizeof(ctr_be), hashbuf, &md_len);
    if (!md || md != hashbuf || md_len != 20) { /* SHA-1 = 160 bits */
      secure_wipe_memory(VARDATA(b32_secret), slen);
      secure_wipe_memory(buf, MAXBUFLEN);
      ereport(ERROR,
              (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
               errmsg("Could not hash using OpenSSL HMAC")));
      return (Datum) NULL;
    }
    offset = hashbuf[md_len - 1] & 0xF;
    truncated = ((
                  (hashbuf[offset] << 24)
                  + (hashbuf[offset+1] << 16)
                  + (hashbuf[offset+2] << 8)
                  + (hashbuf[offset+3])
                 ) & 0x7FFFFFFF
                 ) % 1000000;
    if (otp == truncated) {
      PG_RETURN_BOOL(1);
    }
  }
  
  PG_RETURN_BOOL(0);
}

PG_FUNCTION_INFO_V1(pg_b32_encode);
static unsigned char b32_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

extern Datum pg_b32_encode(PG_FUNCTION_ARGS)
{
  bytea *raw = PG_GETARG_BYTEA_P(0);
  int rawlen = VARSIZE(raw) - VARHDRSZ;
  text *out;
  int i, j, outlen, bits;
  unsigned int accum;
  unsigned char *rawdata = (unsigned char *) VARDATA(raw);

  outlen = (8 * rawlen) / 5 + (((8 * rawlen) % 5) ? 1 : 0);
  out = palloc(VARHDRSZ + outlen);
  SET_VARSIZE(out, VARHDRSZ + outlen);
  
  /* encode in chunks of up to 8 bytes */
  accum = 0;
  j = 0;
  for (i=0; i<rawlen; i++) {
    accum = (accum << 8) | rawdata[i];
    bits += 8;
    while (bits >= 5) {
      unsigned int b = accum & (0x1f << (bits - 5));
      accum ^= b;
      b >>= bits - 5;
      VARDATA(out)[j++] = b32_table[b];
      bits -= 5;
    }
  }
  if (bits) {
    accum <<= 5 - bits;
    VARDATA(out)[j++] = b32_table[accum & 0x20];
  }
  
  return (Datum) out;
}
