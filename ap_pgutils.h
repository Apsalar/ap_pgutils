#ifndef AP_PGUTILS_H
#define AP_PGUTILS_H

#include "fmgr.h"

extern Datum pg_gethostname(PG_FUNCTION_ARGS);
extern Datum pg_argon2(PG_FUNCTION_ARGS);
extern Datum pg_totp_verify(PG_FUNCTION_ARGS);
extern Datum pg_b32_encode(PG_FUNCTION_ARGS);

#endif   /* AP_PGUTILS_H */
