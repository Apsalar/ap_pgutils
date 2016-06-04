CREATE OR REPLACE FUNCTION
gethostname() RETURNS TEXT
LANGUAGE C STABLE
AS '$libdir/ap_pgutils.so', 'pg_gethostname';

CREATE OR REPLACE FUNCTION
argon2(
  IN password TEXT,
  IN salt TEXT,
  IN iterations INT DEFAULT 3,
  IN log2_mem INT DEFAULT 12,
  IN outlen INT DEFAULT 32,
  IN variant TEXT DEFAULT 'i',
  IN parallelism INT DEFAULT 1
) RETURNS TEXT
LANGUAGE C STABLE
AS '$libdir/ap_pgutils.so', 'pg_argon2';

CREATE OR REPLACE FUNCTION
totp_verify(
  IN b32_secret TEXT,
  IN otp INTEGER,
  IN tolerance INTEGER
) RETURNS BOOLEAN
LANGUAGE C VOLATILE
AS '$libdir/ap_pgutils.so', 'pg_totp_verify';

CREATE OR REPLACE FUNCTION
b32_encode(
  IN data BYTEA
) RETURNS TEXT
LANGUAGE C STABLE
AS '$libdir/ap_pgutils.so', 'pg_b32_encode';
