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
.text
.align 2

.pool
.set handle_interface_request, 0x7FFFFFF0
.set insecure_memory_base,     0x7FFFFFF1
.set exec_magic,               0x7FFFFFF2
.set done_magic,               0x7FFFFFF3
.set memc_magic,               0x7FFFFFF4
.set memcpy_addr,              0x7FFFFFF5
.set usb_core_do_transfer,     0x7FFFFFF6

.global _main
_main:
	ldr x7, =handle_interface_request
	br x7
	b _main
	ldrh w2, [x0]
	cmp w2, #0x2A1
	bne _main
	stp x29, x30, [sp, #-0x10]!
	stp x19, x20, [sp, #-0x10]!
	mov x19, x0
	ldr x20, =insecure_memory_base
	mov w1, #0xFFFF
	ldrh w2, [x19, #0x2]
	cmp w1, w2
	bne _request_done
	ldr x0, [x20]
	ldr x1, =exec_magic
	cmp x0, x1
	bne _not_exec
	str xzr, [x20]
	ldp x0, x1, [x20, #0x10]
	ldp x2, x3, [x20, #0x20]
	ldp x4, x5, [x20, #0x30]
	ldp x6, x7, [x20, #0x40]
	ldr x8, [x20, #0x8]
	blr x8
	ldr x8, =done_magic
	stp x8, x0, [x20]
	b _request_done
_not_exec:
	ldr x1, =memc_magic
	cmp x0, x1
	bne _request_done
	str xzr, [x20]
	ldp x0, x1, [x20, #0x10]
	ldr x2, [x20, #0x20]
	ldr x3, =memcpy_addr
	blr x3
	ldr x8, =done_magic
	stp x8, x0, [x20]
_request_done:
	mov w0, #0x80
	mov x1, x20
	ldrh w2, [x19, #0x6]
	mov x3, xzr
	ldr x4, =usb_core_do_transfer
	blr x4
	mov w0, #0
	ldp x19, x20, [sp], #0x10
	ldp x29, x30, [sp], #0x10
	ret
