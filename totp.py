import sys, time, math, hashlib, hmac, struct, base64

def totp_gen(secret, time_range=30, i=0):
  tm = int(time.time() / time_range)
  b = struct.pack(">q", tm + i)
  hm = hmac.HMAC(secret, b, hashlib.sha1).digest()
  offset = ord(hm[-1]) & 0x0F
  truncatedHash = hm[offset:offset + 4]
  code = struct.unpack(">L", truncatedHash)[0]
  code &= 0x7FFFFFFF
  code %= 1000000
  return "%06d" % code

if __name__ == '__main__':
  b32 = 'ABCDEFGHIJKLMNOPQRSTUVWX'
  secret = base64.b32decode(b32)
  print "select totp_verify('ABCDEFGHIJKLMNOPQRSTUVWX', '%s', 0);" \
    % totp_gen(secret)
