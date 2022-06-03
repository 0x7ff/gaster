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
#ifndef LZFSE_H
#	define LZFSE_H
#	include <inttypes.h>
#	include <stdio.h>
size_t
lzfse_decode_scratch_size(void);
size_t
lzfse_decode_buffer(uint8_t *, size_t, const uint8_t *, size_t, void *);
#endif
