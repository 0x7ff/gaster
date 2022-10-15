/* Copyright 2022 0x7ff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "lzfse.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define LZFSE_ENCODE_L_STATES (64)
#define LZFSE_ENCODE_M_STATES (64)
#define LZFSE_ENCODE_D_STATES (256)
#define LZFSE_ENCODE_L_SYMBOLS (20)
#define LZFSE_ENCODE_M_SYMBOLS (20)
#define LZFSE_ENCODE_D_SYMBOLS (64)
#define LZFSE_MATCHES_PER_BLOCK (10000)
#define LZFSE_NO_BLOCK_MAGIC (0x00000000U)
#define LZFSE_ENCODE_LITERAL_STATES (1024)
#define LZFSE_ENCODE_LITERAL_SYMBOLS (256)
#define LZFSE_ENDOFSTREAM_BLOCK_MAGIC (0x24787662U)
#define LZFSE_UNCOMPRESSED_BLOCK_MAGIC (0x2D787662U)
#define LZFSE_COMPRESSEDV1_BLOCK_MAGIC (0x31787662U)
#define LZFSE_COMPRESSEDV2_BLOCK_MAGIC (0x32787662U)
#define LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC (0x6E787662U)
#define LZFSE_LITERALS_PER_BLOCK (4 * LZFSE_MATCHES_PER_BLOCK)

typedef uint16_t fse_state;
typedef struct {
	uint8_t k, symbol;
	uint16_t delta;
} fse_decoder_entry;
typedef struct {
	uint32_t magic, n_raw_bytes;
} uncompressed_block_header;
typedef struct {
	uint32_t n_raw_bytes;
} uncompressed_block_decoder_state;
typedef struct {
	uint64_t accum;
	uint32_t accum_nbits, pad;
} fse_in_stream;
typedef struct {
	uint8_t total_bits, value_bits;
	uint16_t delta;
	uint32_t vbase;
} fse_value_decoder_entry;
typedef struct {
	uint32_t n_matches, n_lmd_payload_bytes;
	const uint8_t *current_literal;
	int32_t l_value, m_value, d_value, pad_0;
	fse_in_stream lmd_in_stream;
	uint32_t lmd_in_buf;
	uint16_t l_state, m_state, d_state, pad_1;
	fse_value_decoder_entry l_decoder[LZFSE_ENCODE_L_STATES], m_decoder[LZFSE_ENCODE_M_STATES], d_decoder[LZFSE_ENCODE_D_STATES];
	uint32_t literal_decoder[LZFSE_ENCODE_LITERAL_STATES];
	uint8_t literals[LZFSE_LITERALS_PER_BLOCK + 64];
	uint32_t pad_2;
} lzfse_compressed_block_decoder_state;
typedef struct {
	const uint8_t *src, *src_begin, *src_end;
	uint8_t *dst, *dst_begin, *dst_end;
	uint32_t end_of_stream, block_magic;
	lzfse_compressed_block_decoder_state compressed_lzfse_block_state;
	uncompressed_block_decoder_state uncompressed_block_state;
	uint32_t pad;
} lzfse_decoder_state;
typedef struct {
	uint32_t magic, n_raw_bytes;
	uint64_t packed_fields[3];
	uint8_t freq[2 * (LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS)];
} lzfse_compressed_block_header_v2;
typedef struct {
	uint32_t magic, n_raw_bytes, n_payload_bytes, n_literals, n_matches, n_literal_payload_bytes, n_lmd_payload_bytes;
	int32_t literal_bits;
	uint16_t literal_state[4];
	int32_t lmd_bits;
	uint16_t l_state, m_state, d_state, l_freq[LZFSE_ENCODE_L_SYMBOLS], m_freq[LZFSE_ENCODE_M_SYMBOLS], d_freq[LZFSE_ENCODE_D_SYMBOLS], literal_freq[LZFSE_ENCODE_LITERAL_SYMBOLS];
} __attribute__((__packed__, __aligned__(2))) lzfse_compressed_block_header_v1;

static const uint8_t l_extra_bits[LZFSE_ENCODE_L_SYMBOLS] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8
}, m_extra_bits[LZFSE_ENCODE_M_SYMBOLS] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11
}, d_extra_bits[LZFSE_ENCODE_D_SYMBOLS] = {
	0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15
};
static const uint32_t l_base_value[LZFSE_ENCODE_L_SYMBOLS] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60
}, m_base_value[LZFSE_ENCODE_M_SYMBOLS] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312
}, d_base_value[LZFSE_ENCODE_D_SYMBOLS] = {
	0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372
};

static uint64_t
fse_mask_lsb(uint64_t x, uint32_t nbits) {
	return x & ((1ULL << nbits) - 1U);
}

static uint64_t
fse_extract_bits(uint64_t x, uint32_t start, uint32_t nbits) {
	return fse_mask_lsb(x >> start, nbits);
}

static bool
fse_in_init(fse_in_stream *s, int32_t n, const uint8_t **pbuf, const uint8_t *buf_start) {
	if(n != 0) {
		if(*pbuf < buf_start + sizeof(s->accum)) {
			return false;
		}
		*pbuf -= sizeof(s->accum);
		memcpy(&s->accum, *pbuf, sizeof(s->accum));
		s->accum_nbits = (uint32_t)(n + 64);
	} else {
		if(*pbuf < buf_start + sizeof(s->accum) - 1) {
			return false;
		}
		*pbuf -= sizeof(s->accum) - 1;
		memcpy(&s->accum, *pbuf, sizeof(s->accum) - 1);
		s->accum &= (1ULL << 56U) - 1U;
		s->accum_nbits = (uint32_t)(n + 56);
	}
	if(s->accum_nbits < 56 || s->accum_nbits >= 64 || (s->accum >> s->accum_nbits) != 0) {
		return false;
	}
	return true;
}

static bool
fse_in_flush(fse_in_stream *s, const uint8_t **pbuf, const uint8_t *buf_start) {
	uint32_t nbits = (63U - s->accum_nbits) & -sizeof(s->accum);
	const uint8_t *buf = *pbuf - (nbits >> 3U);
	uint64_t incoming;

	if(buf < buf_start) {
		return false;
	}
	*pbuf = buf;
	memcpy(&incoming, buf, sizeof(incoming));
	s->accum = (s->accum << nbits) | fse_mask_lsb(incoming, nbits);
	s->accum_nbits += nbits;
	if(s->accum_nbits < 56 || s->accum_nbits >= 64 || (s->accum >> s->accum_nbits) != 0) {
		return false;
	}
	return true;
}

static uint64_t
fse_in_pull(fse_in_stream *s, uint32_t n) {
	uint64_t result;

	s->accum_nbits -= n;
	result = s->accum >> s->accum_nbits;
	s->accum = fse_mask_lsb(s->accum, s->accum_nbits);
	return result;
}

static uint8_t
fse_decode(fse_state *pstate, const uint32_t *decoder_table, fse_in_stream *in) {
	uint32_t e = decoder_table[*pstate];

	*pstate = (fse_state)((e >> 16U) + fse_in_pull(in, e & 0xFFU));
	return (uint8_t)fse_extract_bits((uint64_t)e, 8, 8);
}

static int32_t
fse_value_decode(fse_state *pstate, const fse_value_decoder_entry *value_decoder_table, fse_in_stream *in) {
	fse_value_decoder_entry entry = value_decoder_table[*pstate];
	uint32_t state_and_value_bits = (uint32_t)fse_in_pull(in, entry.total_bits);

	*pstate = (fse_state)((uint32_t)entry.delta + (state_and_value_bits >> entry.value_bits));
	return (int32_t)((uint64_t)entry.vbase + fse_mask_lsb(state_and_value_bits, entry.value_bits));
}

static bool
fse_init_decoder_table(uint32_t nstates, uint32_t nsymbols, const uint16_t *freq, uint32_t *t) {
	uint32_t f, i, j, k, j0, n_clz = (uint32_t)__builtin_clz(nstates), sum_of_freq = 0;
	fse_decoder_entry e;

	for(i = 0; i < nsymbols; ++i) {
		if((f = freq[i]) == 0) {
			continue;
		}
		sum_of_freq += f;
		if(sum_of_freq > nstates) {
			return false;
		}
		k = (uint32_t)__builtin_clz(f) - n_clz;
		j0 = ((2 * nstates) >> k) - f;
		for(j = 0; j < f; ++j) {
			e.symbol = (uint8_t)i;
			if(j < j0) {
				e.k = (uint8_t)k;
				e.delta = (uint16_t)(((f + j) << k) - nstates);
			} else {
				e.k = (uint8_t)(k - 1);
				e.delta = (uint16_t)((j - j0) << (k - 1));
			}
			memcpy(t, &e, sizeof(e));
			++t;
		}
	}
	return true;
}

static void
fse_init_value_decoder_table(uint32_t nstates, uint32_t nsymbols, const uint16_t *freq, const uint8_t *symbol_vbits, const uint32_t *symbol_vbase, fse_value_decoder_entry *t) {
	uint32_t f, i, j, k, j0, n_clz = (uint32_t)__builtin_clz(nstates);
	fse_value_decoder_entry e, ei;

	for(i = 0; i < nsymbols; ++i) {
		if((f = freq[i]) == 0) {
			continue;
		}
		k = (uint32_t)__builtin_clz(f) - n_clz;
		j0 = ((2 * nstates) >> k) - f;
		ei.value_bits = symbol_vbits[i];
		ei.vbase = symbol_vbase[i];
		for(j = 0; j < f; ++j) {
			e = ei;
			if(j < j0) {
				e.total_bits = (uint8_t)k + e.value_bits;
				e.delta = (uint16_t)(((f + j) << k) - nstates);
			} else {
				e.total_bits = (uint8_t)(k - 1) + e.value_bits;
				e.delta = (uint16_t)((j - j0) << (k - 1));
			}
			memcpy(t, &e, sizeof(e));
			++t;
		}
	}
}

static uint32_t
lzfse_decode_v1_freq_value(uint32_t bits, uint32_t *nbits) {
	const uint8_t lzfse_freq_nbits_table[] = {
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14
	}, lzfse_freq_value_table[] = {
		0, 2, 1, 4, 0, 3, 1, 8, 0, 2, 1, 5, 0, 3, 1, 8, 0, 2, 1, 6, 0, 3, 1, 8, 0, 2, 1, 7, 0, 3, 1, 8
	};
	uint32_t b = bits & 31U, n = lzfse_freq_nbits_table[b];

	*nbits = n;
	if(n == 8) {
		return 8 + ((bits >> 4U) & 0xFU);
	}
	if(n == 14) {
		return 24 + ((bits >> 4U) & 0x3FFU);
	}
	return lzfse_freq_value_table[b];
}

static uint32_t
get_field(uint64_t v, uint32_t offset, uint32_t nbits) {
	if(nbits == 32) {
		return (uint32_t)(v >> offset);
	}
	return (uint32_t)((v >> offset) & ((1U << nbits) - 1U));
}

static uint32_t
lzfse_decode_v2_header_size(lzfse_compressed_block_header_v2 in) {
	return get_field(in.packed_fields[2], 0, 32);
}

static bool
lzfse_decode_v1(lzfse_compressed_block_header_v1 *out, const uint8_t *in, lzfse_compressed_block_header_v2 header_v2) {
	uint32_t i, accum, nbits, accum_nbits;
	const uint8_t *src, *src_end;
	uint16_t *dst;

	memset(out, '\0', sizeof(*out));
	out->magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
	out->n_raw_bytes = header_v2.n_raw_bytes;
	out->n_literals = get_field(header_v2.packed_fields[0], 0, 20);
	out->n_literal_payload_bytes = get_field(header_v2.packed_fields[0], 20, 20);
	out->literal_bits = (int32_t)get_field(header_v2.packed_fields[0], 60, 3) - 7;
	out->literal_state[0] = (uint16_t)get_field(header_v2.packed_fields[1], 0, 10);
	out->literal_state[1] = (uint16_t)get_field(header_v2.packed_fields[1], 10, 10);
	out->literal_state[2] = (uint16_t)get_field(header_v2.packed_fields[1], 20, 10);
	out->literal_state[3] = (uint16_t)get_field(header_v2.packed_fields[1], 30, 10);
	out->n_matches = get_field(header_v2.packed_fields[0], 40, 20);
	out->n_lmd_payload_bytes = get_field(header_v2.packed_fields[1], 40, 20);
	out->lmd_bits = (int32_t)get_field(header_v2.packed_fields[1], 60, 3) - 7;
	out->l_state = (uint16_t)get_field(header_v2.packed_fields[2], 32, 10);
	out->m_state = (uint16_t)get_field(header_v2.packed_fields[2], 42, 10);
	out->d_state = (uint16_t)get_field(header_v2.packed_fields[2], 52, 10);
	out->n_payload_bytes = out->n_literal_payload_bytes + out->n_lmd_payload_bytes;
	src = in + offsetof(lzfse_compressed_block_header_v2, freq);
	src_end = in + lzfse_decode_v2_header_size(header_v2);
	if(src_end == src) {
		return true;
	}
	dst = out->l_freq;
	accum = 0;
	accum_nbits = 0;
	for(i = 0; i < LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS; ++i) {
		while(src < src_end && accum_nbits + 8 <= 32) {
			accum |= (uint32_t)*src << accum_nbits;
			accum_nbits += 8;
			++src;
		}
		dst[i] = (uint16_t)lzfse_decode_v1_freq_value(accum, &nbits);
		if(nbits > accum_nbits) {
			return false;
		}
		accum >>= nbits;
		accum_nbits -= nbits;
	}
	if(accum_nbits >= 8 || src != src_end) {
		return false;
	}
	return true;
}

static bool
lzfse_decode_lmd(lzfse_decoder_state *s) {
	int32_t i, new_d, L = s->compressed_lzfse_block_state.l_value, M = s->compressed_lzfse_block_state.m_value, D = s->compressed_lzfse_block_state.d_value, remaining_bytes = (int32_t)(s->dst_end - s->dst) - 32;
	fse_state l_state = s->compressed_lzfse_block_state.l_state, m_state = s->compressed_lzfse_block_state.m_state, d_state = s->compressed_lzfse_block_state.d_state;
	const uint8_t *src_start = s->src_begin, *src = s->src + s->compressed_lzfse_block_state.lmd_in_buf, *lit = s->compressed_lzfse_block_state.current_literal;
	fse_in_stream in = s->compressed_lzfse_block_state.lmd_in_stream;
	uint32_t symbols = s->compressed_lzfse_block_state.n_matches;
	uint8_t *dst = s->dst;

	if(L != 0 || M != 0) {
		goto ExecuteMatch;
	}
	while(symbols != 0) {
		if(!fse_in_flush(&in, &src, src_start)) {
			return false;
		}
		L = fse_value_decode(&l_state, s->compressed_lzfse_block_state.l_decoder, &in);
		if(lit + L >= s->compressed_lzfse_block_state.literals + LZFSE_LITERALS_PER_BLOCK + 64) {
			return false;
		}
		M = fse_value_decode(&m_state, s->compressed_lzfse_block_state.m_decoder, &in);
		new_d = fse_value_decode(&d_state, s->compressed_lzfse_block_state.d_decoder, &in);
		if(new_d != 0) {
			D = new_d;
		}
		--symbols;
	ExecuteMatch:
		if((uint32_t)D > (uint32_t)(dst + L - s->dst_begin)) {
			return false;
		}
		if(L + M <= remaining_bytes) {
			remaining_bytes -= L + M;
			memcpy(dst, lit, (size_t)L);
			dst += L;
			lit += L;
			for(i = 0; i < M; ++i) {
				dst[i] = dst[i - D];
			}
			dst += M;
		} else {
			remaining_bytes += 32;
			if(L <= remaining_bytes) {
				memcpy(dst, lit, (size_t)L);
				dst += L;
				lit += L;
				remaining_bytes -= L;
			} else {
				return false;
			}
			if(M <= remaining_bytes) {
				for(i = 0; i < M; ++i) {
					dst[i] = dst[i - D];
				}
				dst += M;
				remaining_bytes -= M;
			} else {
				return false;
			}
			remaining_bytes -= 32;
		}
	}
	s->dst = dst;
	return true;
}

static bool
lzfse_decode(lzfse_decoder_state *s) {
	uint32_t i, magic, copy_size, src_space, dst_space;
	lzfse_compressed_block_header_v2 header_v2;
	lzfse_compressed_block_header_v1 header_v1;
	const uint8_t *buf, *buf_start;
	fse_state state[4];
	size_t header_size;
	fse_in_stream in;

	for(;;) {
		switch(s->block_magic) {
			case LZFSE_NO_BLOCK_MAGIC:
				if(s->src + sizeof(magic) > s->src_end) {
					return false;
				}
				memcpy(&magic, s->src, sizeof(magic));
				if(magic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC) {
					s->src += sizeof(magic);
					s->end_of_stream = 1;
					return true;
				}
				if(magic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC) {
					if(s->src + sizeof(uncompressed_block_header) > s->src_end) {
						return false;
					}
					memcpy(&s->uncompressed_block_state.n_raw_bytes, s->src + offsetof(uncompressed_block_header, n_raw_bytes), sizeof(s->uncompressed_block_state.n_raw_bytes));
					s->src += sizeof(uncompressed_block_header);
					s->block_magic = magic;
					break;
				}
				if(magic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC) {
					return false;
				}
				if(magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC || magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC) {
					if(magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC) {
						if(s->src + offsetof(lzfse_compressed_block_header_v2, freq) > s->src_end) {
							return false;
						}
						memcpy(&header_v2, s->src, sizeof(header_v2));
						header_size = lzfse_decode_v2_header_size(header_v2);
						if(s->src + header_size > s->src_end || !lzfse_decode_v1(&header_v1, s->src, header_v2)) {
							return false;
						}
					} else {
						if(s->src + sizeof(header_v1) > s->src_end) {
							return false;
						}
						memcpy(&header_v1, s->src, sizeof(header_v1));
						header_size = sizeof(header_v1);
					}
					if(s->src + header_size + header_v1.n_literal_payload_bytes + header_v1.n_lmd_payload_bytes > s->src_end) {
						return false;
					}
					s->src += header_size;
					s->compressed_lzfse_block_state.n_lmd_payload_bytes = header_v1.n_lmd_payload_bytes;
					s->compressed_lzfse_block_state.n_matches = header_v1.n_matches;
					fse_init_decoder_table(LZFSE_ENCODE_LITERAL_STATES, LZFSE_ENCODE_LITERAL_SYMBOLS, header_v1.literal_freq, s->compressed_lzfse_block_state.literal_decoder);
					fse_init_value_decoder_table(LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, header_v1.l_freq, l_extra_bits, l_base_value, s->compressed_lzfse_block_state.l_decoder);
					fse_init_value_decoder_table(LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, header_v1.m_freq, m_extra_bits, m_base_value, s->compressed_lzfse_block_state.m_decoder);
					fse_init_value_decoder_table(LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, header_v1.d_freq, d_extra_bits, d_base_value, s->compressed_lzfse_block_state.d_decoder);
					buf_start = s->src_begin;
					s->src += header_v1.n_literal_payload_bytes;
					buf = s->src;
					if(!fse_in_init(&in, header_v1.literal_bits, &buf, buf_start)) {
						return false;
					}
					state[0] = header_v1.literal_state[0];
					state[1] = header_v1.literal_state[1];
					state[2] = header_v1.literal_state[2];
					state[3] = header_v1.literal_state[3];
					for(i = 0; i < header_v1.n_literals; i += 4) {
						if(!fse_in_flush(&in, &buf, buf_start)) {
							return false;
						}
						s->compressed_lzfse_block_state.literals[i] = fse_decode(&state[0], s->compressed_lzfse_block_state.literal_decoder, &in);
						s->compressed_lzfse_block_state.literals[i + 1] = fse_decode(&state[1], s->compressed_lzfse_block_state.literal_decoder, &in);
						s->compressed_lzfse_block_state.literals[i + 2] = fse_decode(&state[2], s->compressed_lzfse_block_state.literal_decoder, &in);
						s->compressed_lzfse_block_state.literals[i + 3] = fse_decode(&state[3], s->compressed_lzfse_block_state.literal_decoder, &in);
					}
					s->compressed_lzfse_block_state.current_literal = s->compressed_lzfse_block_state.literals;
					buf = s->src + header_v1.n_lmd_payload_bytes;
					if(!fse_in_init(&in, header_v1.lmd_bits, &buf, s->src)) {
						return false;
					}
					s->compressed_lzfse_block_state.l_state = header_v1.l_state;
					s->compressed_lzfse_block_state.m_state = header_v1.m_state;
					s->compressed_lzfse_block_state.d_state = header_v1.d_state;
					s->compressed_lzfse_block_state.lmd_in_buf = (uint32_t)(buf - s->src);
					s->compressed_lzfse_block_state.l_value = s->compressed_lzfse_block_state.m_value = 0;
					s->compressed_lzfse_block_state.d_value = -1;
					s->compressed_lzfse_block_state.lmd_in_stream = in;
					s->block_magic = magic;
					break;
				}
				return false;
			case LZFSE_UNCOMPRESSED_BLOCK_MAGIC:
				copy_size = s->uncompressed_block_state.n_raw_bytes;
				if(copy_size == 0) {
					s->block_magic = 0;
					break;
				}
				if(s->src_end <= s->src) {
					return false;
				}
				src_space = (uint32_t)(s->src_end - s->src);
				if(copy_size > src_space) {
					copy_size = src_space;
				}
				if(s->dst_end <= s->dst) {
					return false;
				}
				dst_space = (uint32_t)(s->dst_end - s->dst);
				if(copy_size > dst_space) {
					copy_size = dst_space;
				}
				memcpy(s->dst, s->src, copy_size);
				s->src += copy_size;
				s->dst += copy_size;
				s->uncompressed_block_state.n_raw_bytes -= copy_size;
				break;
			case LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
			case LZFSE_COMPRESSEDV2_BLOCK_MAGIC:
				if(s->src_end <= s->src || s->compressed_lzfse_block_state.n_lmd_payload_bytes > (size_t)(s->src_end - s->src) || !lzfse_decode_lmd(s)) {
					return false;
				}
				s->block_magic = LZFSE_NO_BLOCK_MAGIC;
				s->src += s->compressed_lzfse_block_state.n_lmd_payload_bytes;
				break;
			default:
				return false;
		}
	}
	return true;
}

size_t
lzfse_decode_scratch_size(void) {
	return sizeof(lzfse_decoder_state);
}

static size_t
lzfse_decode_buffer_with_scratch(uint8_t *dst_buffer, size_t dst_size, const uint8_t *src_buffer, size_t src_size, void *scratch_buffer) {
	lzfse_decoder_state *s = scratch_buffer;

	memset(s, '\0', sizeof(*s));
	s->src = src_buffer;
	s->src_begin = src_buffer;
	s->src_end = s->src + src_size;
	s->dst = dst_buffer;
	s->dst_begin = dst_buffer;
	s->dst_end = dst_buffer + dst_size;
	return lzfse_decode(s) ? (size_t)(s->dst - dst_buffer) : 0;
}

size_t
lzfse_decode_buffer(uint8_t *dst_buffer, size_t dst_size, const uint8_t *src_buffer, size_t src_size, void *scratch_buffer) {
	bool has_malloc = false;
	size_t ret;

	if(scratch_buffer == NULL) {
		if((scratch_buffer = malloc(lzfse_decode_scratch_size())) == NULL) {
			return 0;
		}
		has_malloc = true;
	}
	ret = lzfse_decode_buffer_with_scratch(dst_buffer, dst_size, src_buffer, src_size, scratch_buffer);
	if(has_malloc) {
		free(scratch_buffer);
	}
	return ret;
}
