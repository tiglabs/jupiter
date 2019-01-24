#ifndef __CRYPTOHASH_H__
#define __CRYPTOHASH_H__

#define MD5_DIGEST_WORDS 4
#define MD5_MESSAGE_BYTES 64

void md5_transform(uint32_t *hash, uint32_t const *in);

#define SHA_DIGEST_WORDS 5
#define SHA_MESSAGE_BYTES (512 /*bits*/ / 8)
#define SHA_WORKSPACE_WORDS 16

void sha_init(uint32_t *buf);
void sha_transform(uint32_t *digest, const char *data, uint32_t *W);

#endif
