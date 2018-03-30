#ifndef BASE64_H
#define BASE64_H 1
unsigned char *base64_encode(const char *, size_t, int *);
unsigned char *base64_decode_ex(const char *, size_t, int *, int);
unsigned char *base64_decode(const char *, size_t, int *);
#endif /* BASE64_H */

