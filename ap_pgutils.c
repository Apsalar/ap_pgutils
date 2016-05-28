#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "postgres.h"
#include "catalog/pg_type.h"
#include "fmgr.h"
#include "utils/builtins.h"

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
    result = palloc(VARHDRSZ + strlen(host_buf) + 1);
    strcpy(VARDATA(result), host_buf);
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
             errmsg("argon2 hash failed, err=%d", status)));
    return (Datum) NULL;
  }
  return (Datum) result;
}
