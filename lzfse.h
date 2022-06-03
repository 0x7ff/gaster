#ifndef LZFSE_H
#	define LZFSE_H
#	include <inttypes.h>
#	include <stdio.h>
size_t
lzfse_decode_scratch_size(void);
size_t
lzfse_decode_buffer(uint8_t *, size_t, const uint8_t *, size_t, void *);
#endif
