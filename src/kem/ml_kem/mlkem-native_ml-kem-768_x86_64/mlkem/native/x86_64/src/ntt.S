/*
 * Copyright (c) 2024-2025 The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */

// Implementation from Kyber reference repository
// https://github.com/pq-crystals/kyber/blob/main/avx2

#include "../../../common.h"
#if defined(MLK_ARITH_BACKEND_X86_64_DEFAULT) && \
    !defined(MLK_MULTILEVEL_BUILD_NO_SHARED)

/*
 * WARNING: This file is auto-derived from the mlkem-native source file
 *   dev/x86_64/src/ntt.S using scripts/simpasm. Do not modify it directly.
 */


.text
.balign 4
.global MLK_ASM_NAMESPACE(ntt_avx2)
MLK_ASM_FN_SYMBOL(ntt_avx2)

        vmovdqa	(%rsi), %ymm0
        vpbroadcastq	0x140(%rsi), %ymm15
        vmovdqa	0x100(%rdi), %ymm8
        vmovdqa	0x120(%rdi), %ymm9
        vmovdqa	0x140(%rdi), %ymm10
        vmovdqa	0x160(%rdi), %ymm11
        vpbroadcastq	0x148(%rsi), %ymm2
        vpmullw	%ymm15, %ymm8, %ymm12
        vpmullw	%ymm15, %ymm9, %ymm13
        vpmullw	%ymm15, %ymm10, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm8, %ymm8
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm10, %ymm10
        vpmulhw	%ymm2, %ymm11, %ymm11
        vmovdqa	(%rdi), %ymm4
        vmovdqa	0x20(%rdi), %ymm5
        vmovdqa	0x40(%rdi), %ymm6
        vmovdqa	0x60(%rdi), %ymm7
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm8, %ymm4, %ymm3
        vpsubw	%ymm8, %ymm4, %ymm8
        vpaddw	%ymm9, %ymm5, %ymm4
        vpsubw	%ymm9, %ymm5, %ymm9
        vpaddw	%ymm10, %ymm6, %ymm5
        vpsubw	%ymm10, %ymm6, %ymm10
        vpaddw	%ymm11, %ymm7, %ymm6
        vpsubw	%ymm11, %ymm7, %ymm11
        vpsubw	%ymm12, %ymm3, %ymm3
        vpaddw	%ymm12, %ymm8, %ymm8
        vpsubw	%ymm13, %ymm4, %ymm4
        vpaddw	%ymm13, %ymm9, %ymm9
        vpsubw	%ymm14, %ymm5, %ymm5
        vpaddw	%ymm14, %ymm10, %ymm10
        vpsubw	%ymm15, %ymm6, %ymm6
        vpaddw	%ymm15, %ymm11, %ymm11
        vmovdqa	%ymm3, (%rdi)
        vmovdqa	%ymm4, 0x20(%rdi)
        vmovdqa	%ymm5, 0x40(%rdi)
        vmovdqa	%ymm6, 0x60(%rdi)
        vmovdqa	%ymm8, 0x100(%rdi)
        vmovdqa	%ymm9, 0x120(%rdi)
        vmovdqa	%ymm10, 0x140(%rdi)
        vmovdqa	%ymm11, 0x160(%rdi)
        vpbroadcastq	0x140(%rsi), %ymm15
        vmovdqa	0x180(%rdi), %ymm8
        vmovdqa	0x1a0(%rdi), %ymm9
        vmovdqa	0x1c0(%rdi), %ymm10
        vmovdqa	0x1e0(%rdi), %ymm11
        vpbroadcastq	0x148(%rsi), %ymm2
        vpmullw	%ymm15, %ymm8, %ymm12
        vpmullw	%ymm15, %ymm9, %ymm13
        vpmullw	%ymm15, %ymm10, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm8, %ymm8
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm10, %ymm10
        vpmulhw	%ymm2, %ymm11, %ymm11
        vmovdqa	0x80(%rdi), %ymm4
        vmovdqa	0xa0(%rdi), %ymm5
        vmovdqa	0xc0(%rdi), %ymm6
        vmovdqa	0xe0(%rdi), %ymm7
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm8, %ymm4, %ymm3
        vpsubw	%ymm8, %ymm4, %ymm8
        vpaddw	%ymm9, %ymm5, %ymm4
        vpsubw	%ymm9, %ymm5, %ymm9
        vpaddw	%ymm10, %ymm6, %ymm5
        vpsubw	%ymm10, %ymm6, %ymm10
        vpaddw	%ymm11, %ymm7, %ymm6
        vpsubw	%ymm11, %ymm7, %ymm11
        vpsubw	%ymm12, %ymm3, %ymm3
        vpaddw	%ymm12, %ymm8, %ymm8
        vpsubw	%ymm13, %ymm4, %ymm4
        vpaddw	%ymm13, %ymm9, %ymm9
        vpsubw	%ymm14, %ymm5, %ymm5
        vpaddw	%ymm14, %ymm10, %ymm10
        vpsubw	%ymm15, %ymm6, %ymm6
        vpaddw	%ymm15, %ymm11, %ymm11
        vmovdqa	%ymm3, 0x80(%rdi)
        vmovdqa	%ymm4, 0xa0(%rdi)
        vmovdqa	%ymm5, 0xc0(%rdi)
        vmovdqa	%ymm6, 0xe0(%rdi)
        vmovdqa	%ymm8, 0x180(%rdi)
        vmovdqa	%ymm9, 0x1a0(%rdi)
        vmovdqa	%ymm10, 0x1c0(%rdi)
        vmovdqa	%ymm11, 0x1e0(%rdi)
        vmovdqa	0x160(%rsi), %ymm15
        vmovdqa	0x80(%rdi), %ymm8
        vmovdqa	0xa0(%rdi), %ymm9
        vmovdqa	0xc0(%rdi), %ymm10
        vmovdqa	0xe0(%rdi), %ymm11
        vmovdqa	0x180(%rsi), %ymm2
        vpmullw	%ymm15, %ymm8, %ymm12
        vpmullw	%ymm15, %ymm9, %ymm13
        vpmullw	%ymm15, %ymm10, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm8, %ymm8
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm10, %ymm10
        vpmulhw	%ymm2, %ymm11, %ymm11
        vmovdqa	(%rdi), %ymm4
        vmovdqa	0x20(%rdi), %ymm5
        vmovdqa	0x40(%rdi), %ymm6
        vmovdqa	0x60(%rdi), %ymm7
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm8, %ymm4, %ymm3
        vpsubw	%ymm8, %ymm4, %ymm8
        vpaddw	%ymm9, %ymm5, %ymm4
        vpsubw	%ymm9, %ymm5, %ymm9
        vpaddw	%ymm10, %ymm6, %ymm5
        vpsubw	%ymm10, %ymm6, %ymm10
        vpaddw	%ymm11, %ymm7, %ymm6
        vpsubw	%ymm11, %ymm7, %ymm11
        vpsubw	%ymm12, %ymm3, %ymm3
        vpaddw	%ymm12, %ymm8, %ymm8
        vpsubw	%ymm13, %ymm4, %ymm4
        vpaddw	%ymm13, %ymm9, %ymm9
        vpsubw	%ymm14, %ymm5, %ymm5
        vpaddw	%ymm14, %ymm10, %ymm10
        vpsubw	%ymm15, %ymm6, %ymm6
        vpaddw	%ymm15, %ymm11, %ymm11
        vperm2i128	$0x20, %ymm10, %ymm5, %ymm7 # ymm7 = ymm5[0,1],ymm10[0,1]
        vperm2i128	$0x31, %ymm10, %ymm5, %ymm10 # ymm10 = ymm5[2,3],ymm10[2,3]
        vperm2i128	$0x20, %ymm11, %ymm6, %ymm5 # ymm5 = ymm6[0,1],ymm11[0,1]
        vperm2i128	$0x31, %ymm11, %ymm6, %ymm11 # ymm11 = ymm6[2,3],ymm11[2,3]
        vmovdqa	0x1a0(%rsi), %ymm15
        vmovdqa	0x1c0(%rsi), %ymm2
        vpmullw	%ymm15, %ymm7, %ymm12
        vpmullw	%ymm15, %ymm10, %ymm13
        vpmullw	%ymm15, %ymm5, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm7, %ymm7
        vpmulhw	%ymm2, %ymm10, %ymm10
        vpmulhw	%ymm2, %ymm5, %ymm5
        vpmulhw	%ymm2, %ymm11, %ymm11
        vperm2i128	$0x20, %ymm8, %ymm3, %ymm6 # ymm6 = ymm3[0,1],ymm8[0,1]
        vperm2i128	$0x31, %ymm8, %ymm3, %ymm8 # ymm8 = ymm3[2,3],ymm8[2,3]
        vperm2i128	$0x20, %ymm9, %ymm4, %ymm3 # ymm3 = ymm4[0,1],ymm9[0,1]
        vperm2i128	$0x31, %ymm9, %ymm4, %ymm9 # ymm9 = ymm4[2,3],ymm9[2,3]
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm7, %ymm6, %ymm4
        vpsubw	%ymm7, %ymm6, %ymm7
        vpaddw	%ymm10, %ymm8, %ymm6
        vpsubw	%ymm10, %ymm8, %ymm10
        vpaddw	%ymm5, %ymm3, %ymm8
        vpsubw	%ymm5, %ymm3, %ymm5
        vpaddw	%ymm11, %ymm9, %ymm3
        vpsubw	%ymm11, %ymm9, %ymm11
        vpsubw	%ymm12, %ymm4, %ymm4
        vpaddw	%ymm12, %ymm7, %ymm7
        vpsubw	%ymm13, %ymm6, %ymm6
        vpaddw	%ymm13, %ymm10, %ymm10
        vpsubw	%ymm14, %ymm8, %ymm8
        vpaddw	%ymm14, %ymm5, %ymm5
        vpsubw	%ymm15, %ymm3, %ymm3
        vpaddw	%ymm15, %ymm11, %ymm11
        vpunpcklqdq	%ymm5, %ymm8, %ymm9 # ymm9 = ymm8[0],ymm5[0],ymm8[2],ymm5[2]
        vpunpckhqdq	%ymm5, %ymm8, %ymm5 # ymm5 = ymm8[1],ymm5[1],ymm8[3],ymm5[3]
        vpunpcklqdq	%ymm11, %ymm3, %ymm8 # ymm8 = ymm3[0],ymm11[0],ymm3[2],ymm11[2]
        vpunpckhqdq	%ymm11, %ymm3, %ymm11 # ymm11 = ymm3[1],ymm11[1],ymm3[3],ymm11[3]
        vmovdqa	0x1e0(%rsi), %ymm15
        vmovdqa	0x200(%rsi), %ymm2
        vpmullw	%ymm15, %ymm9, %ymm12
        vpmullw	%ymm15, %ymm5, %ymm13
        vpmullw	%ymm15, %ymm8, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm5, %ymm5
        vpmulhw	%ymm2, %ymm8, %ymm8
        vpmulhw	%ymm2, %ymm11, %ymm11
        vpunpcklqdq	%ymm7, %ymm4, %ymm3 # ymm3 = ymm4[0],ymm7[0],ymm4[2],ymm7[2]
        vpunpckhqdq	%ymm7, %ymm4, %ymm7 # ymm7 = ymm4[1],ymm7[1],ymm4[3],ymm7[3]
        vpunpcklqdq	%ymm10, %ymm6, %ymm4 # ymm4 = ymm6[0],ymm10[0],ymm6[2],ymm10[2]
        vpunpckhqdq	%ymm10, %ymm6, %ymm10 # ymm10 = ymm6[1],ymm10[1],ymm6[3],ymm10[3]
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm9, %ymm3, %ymm6
        vpsubw	%ymm9, %ymm3, %ymm9
        vpaddw	%ymm5, %ymm7, %ymm3
        vpsubw	%ymm5, %ymm7, %ymm5
        vpaddw	%ymm8, %ymm4, %ymm7
        vpsubw	%ymm8, %ymm4, %ymm8
        vpaddw	%ymm11, %ymm10, %ymm4
        vpsubw	%ymm11, %ymm10, %ymm11
        vpsubw	%ymm12, %ymm6, %ymm6
        vpaddw	%ymm12, %ymm9, %ymm9
        vpsubw	%ymm13, %ymm3, %ymm3
        vpaddw	%ymm13, %ymm5, %ymm5
        vpsubw	%ymm14, %ymm7, %ymm7
        vpaddw	%ymm14, %ymm8, %ymm8
        vpsubw	%ymm15, %ymm4, %ymm4
        vpaddw	%ymm15, %ymm11, %ymm11
        vmovsldup	%ymm8, %ymm10   # ymm10 = ymm8[0,0,2,2,4,4,6,6]
        vpblendd	$0xaa, %ymm10, %ymm7, %ymm10 # ymm10 = ymm7[0],ymm10[1],ymm7[2],ymm10[3],ymm7[4],ymm10[5],ymm7[6],ymm10[7]
        vpsrlq	$0x20, %ymm7, %ymm7
        vpblendd	$0xaa, %ymm8, %ymm7, %ymm8 # ymm8 = ymm7[0],ymm8[1],ymm7[2],ymm8[3],ymm7[4],ymm8[5],ymm7[6],ymm8[7]
        vmovsldup	%ymm11, %ymm7   # ymm7 = ymm11[0,0,2,2,4,4,6,6]
        vpblendd	$0xaa, %ymm7, %ymm4, %ymm7 # ymm7 = ymm4[0],ymm7[1],ymm4[2],ymm7[3],ymm4[4],ymm7[5],ymm4[6],ymm7[7]
        vpsrlq	$0x20, %ymm4, %ymm4
        vpblendd	$0xaa, %ymm11, %ymm4, %ymm11 # ymm11 = ymm4[0],ymm11[1],ymm4[2],ymm11[3],ymm4[4],ymm11[5],ymm4[6],ymm11[7]
        vmovdqa	0x220(%rsi), %ymm15
        vmovdqa	0x240(%rsi), %ymm2
        vpmullw	%ymm15, %ymm10, %ymm12
        vpmullw	%ymm15, %ymm8, %ymm13
        vpmullw	%ymm15, %ymm7, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm10, %ymm10
        vpmulhw	%ymm2, %ymm8, %ymm8
        vpmulhw	%ymm2, %ymm7, %ymm7
        vpmulhw	%ymm2, %ymm11, %ymm11
        vmovsldup	%ymm9, %ymm4    # ymm4 = ymm9[0,0,2,2,4,4,6,6]
        vpblendd	$0xaa, %ymm4, %ymm6, %ymm4 # ymm4 = ymm6[0],ymm4[1],ymm6[2],ymm4[3],ymm6[4],ymm4[5],ymm6[6],ymm4[7]
        vpsrlq	$0x20, %ymm6, %ymm6
        vpblendd	$0xaa, %ymm9, %ymm6, %ymm9 # ymm9 = ymm6[0],ymm9[1],ymm6[2],ymm9[3],ymm6[4],ymm9[5],ymm6[6],ymm9[7]
        vmovsldup	%ymm5, %ymm6    # ymm6 = ymm5[0,0,2,2,4,4,6,6]
        vpblendd	$0xaa, %ymm6, %ymm3, %ymm6 # ymm6 = ymm3[0],ymm6[1],ymm3[2],ymm6[3],ymm3[4],ymm6[5],ymm3[6],ymm6[7]
        vpsrlq	$0x20, %ymm3, %ymm3
        vpblendd	$0xaa, %ymm5, %ymm3, %ymm5 # ymm5 = ymm3[0],ymm5[1],ymm3[2],ymm5[3],ymm3[4],ymm5[5],ymm3[6],ymm5[7]
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm10, %ymm4, %ymm3
        vpsubw	%ymm10, %ymm4, %ymm10
        vpaddw	%ymm8, %ymm9, %ymm4
        vpsubw	%ymm8, %ymm9, %ymm8
        vpaddw	%ymm7, %ymm6, %ymm9
        vpsubw	%ymm7, %ymm6, %ymm7
        vpaddw	%ymm11, %ymm5, %ymm6
        vpsubw	%ymm11, %ymm5, %ymm11
        vpsubw	%ymm12, %ymm3, %ymm3
        vpaddw	%ymm12, %ymm10, %ymm10
        vpsubw	%ymm13, %ymm4, %ymm4
        vpaddw	%ymm13, %ymm8, %ymm8
        vpsubw	%ymm14, %ymm9, %ymm9
        vpaddw	%ymm14, %ymm7, %ymm7
        vpsubw	%ymm15, %ymm6, %ymm6
        vpaddw	%ymm15, %ymm11, %ymm11
        vpslld	$0x10, %ymm7, %ymm5
        vpblendw	$0xaa, %ymm5, %ymm9, %ymm5 # ymm5 = ymm9[0],ymm5[1],ymm9[2],ymm5[3],ymm9[4],ymm5[5],ymm9[6],ymm5[7],ymm9[8],ymm5[9],ymm9[10],ymm5[11],ymm9[12],ymm5[13],ymm9[14],ymm5[15]
        vpsrld	$0x10, %ymm9, %ymm9
        vpblendw	$0xaa, %ymm7, %ymm9, %ymm7 # ymm7 = ymm9[0],ymm7[1],ymm9[2],ymm7[3],ymm9[4],ymm7[5],ymm9[6],ymm7[7],ymm9[8],ymm7[9],ymm9[10],ymm7[11],ymm9[12],ymm7[13],ymm9[14],ymm7[15]
        vpslld	$0x10, %ymm11, %ymm9
        vpblendw	$0xaa, %ymm9, %ymm6, %ymm9 # ymm9 = ymm6[0],ymm9[1],ymm6[2],ymm9[3],ymm6[4],ymm9[5],ymm6[6],ymm9[7],ymm6[8],ymm9[9],ymm6[10],ymm9[11],ymm6[12],ymm9[13],ymm6[14],ymm9[15]
        vpsrld	$0x10, %ymm6, %ymm6
        vpblendw	$0xaa, %ymm11, %ymm6, %ymm11 # ymm11 = ymm6[0],ymm11[1],ymm6[2],ymm11[3],ymm6[4],ymm11[5],ymm6[6],ymm11[7],ymm6[8],ymm11[9],ymm6[10],ymm11[11],ymm6[12],ymm11[13],ymm6[14],ymm11[15]
        vmovdqa	0x260(%rsi), %ymm15
        vmovdqa	0x280(%rsi), %ymm2
        vpmullw	%ymm15, %ymm5, %ymm12
        vpmullw	%ymm15, %ymm7, %ymm13
        vpmullw	%ymm15, %ymm9, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm5, %ymm5
        vpmulhw	%ymm2, %ymm7, %ymm7
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm11, %ymm11
        vpslld	$0x10, %ymm10, %ymm6
        vpblendw	$0xaa, %ymm6, %ymm3, %ymm6 # ymm6 = ymm3[0],ymm6[1],ymm3[2],ymm6[3],ymm3[4],ymm6[5],ymm3[6],ymm6[7],ymm3[8],ymm6[9],ymm3[10],ymm6[11],ymm3[12],ymm6[13],ymm3[14],ymm6[15]
        vpsrld	$0x10, %ymm3, %ymm3
        vpblendw	$0xaa, %ymm10, %ymm3, %ymm10 # ymm10 = ymm3[0],ymm10[1],ymm3[2],ymm10[3],ymm3[4],ymm10[5],ymm3[6],ymm10[7],ymm3[8],ymm10[9],ymm3[10],ymm10[11],ymm3[12],ymm10[13],ymm3[14],ymm10[15]
        vpslld	$0x10, %ymm8, %ymm3
        vpblendw	$0xaa, %ymm3, %ymm4, %ymm3 # ymm3 = ymm4[0],ymm3[1],ymm4[2],ymm3[3],ymm4[4],ymm3[5],ymm4[6],ymm3[7],ymm4[8],ymm3[9],ymm4[10],ymm3[11],ymm4[12],ymm3[13],ymm4[14],ymm3[15]
        vpsrld	$0x10, %ymm4, %ymm4
        vpblendw	$0xaa, %ymm8, %ymm4, %ymm8 # ymm8 = ymm4[0],ymm8[1],ymm4[2],ymm8[3],ymm4[4],ymm8[5],ymm4[6],ymm8[7],ymm4[8],ymm8[9],ymm4[10],ymm8[11],ymm4[12],ymm8[13],ymm4[14],ymm8[15]
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm5, %ymm6, %ymm4
        vpsubw	%ymm5, %ymm6, %ymm5
        vpaddw	%ymm7, %ymm10, %ymm6
        vpsubw	%ymm7, %ymm10, %ymm7
        vpaddw	%ymm9, %ymm3, %ymm10
        vpsubw	%ymm9, %ymm3, %ymm9
        vpaddw	%ymm11, %ymm8, %ymm3
        vpsubw	%ymm11, %ymm8, %ymm11
        vpsubw	%ymm12, %ymm4, %ymm4
        vpaddw	%ymm12, %ymm5, %ymm5
        vpsubw	%ymm13, %ymm6, %ymm6
        vpaddw	%ymm13, %ymm7, %ymm7
        vpsubw	%ymm14, %ymm10, %ymm10
        vpaddw	%ymm14, %ymm9, %ymm9
        vpsubw	%ymm15, %ymm3, %ymm3
        vpaddw	%ymm15, %ymm11, %ymm11
        vmovdqa	0x2a0(%rsi), %ymm14
        vmovdqa	0x2e0(%rsi), %ymm15
        vmovdqa	0x2c0(%rsi), %ymm8
        vmovdqa	0x300(%rsi), %ymm2
        vpmullw	%ymm14, %ymm10, %ymm12
        vpmullw	%ymm14, %ymm3, %ymm13
        vpmullw	%ymm15, %ymm9, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm8, %ymm10, %ymm10
        vpmulhw	%ymm8, %ymm3, %ymm3
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm11, %ymm11
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm10, %ymm4, %ymm8
        vpsubw	%ymm10, %ymm4, %ymm10
        vpaddw	%ymm3, %ymm6, %ymm4
        vpsubw	%ymm3, %ymm6, %ymm3
        vpaddw	%ymm9, %ymm5, %ymm6
        vpsubw	%ymm9, %ymm5, %ymm9
        vpaddw	%ymm11, %ymm7, %ymm5
        vpsubw	%ymm11, %ymm7, %ymm11
        vpsubw	%ymm12, %ymm8, %ymm8
        vpaddw	%ymm12, %ymm10, %ymm10
        vpsubw	%ymm13, %ymm4, %ymm4
        vpaddw	%ymm13, %ymm3, %ymm3
        vpsubw	%ymm14, %ymm6, %ymm6
        vpaddw	%ymm14, %ymm9, %ymm9
        vpsubw	%ymm15, %ymm5, %ymm5
        vpaddw	%ymm15, %ymm11, %ymm11
        vmovdqa	%ymm8, (%rdi)
        vmovdqa	%ymm4, 0x20(%rdi)
        vmovdqa	%ymm10, 0x40(%rdi)
        vmovdqa	%ymm3, 0x60(%rdi)
        vmovdqa	%ymm6, 0x80(%rdi)
        vmovdqa	%ymm5, 0xa0(%rdi)
        vmovdqa	%ymm9, 0xc0(%rdi)
        vmovdqa	%ymm11, 0xe0(%rdi)
        vmovdqa	0x320(%rsi), %ymm15
        vmovdqa	0x180(%rdi), %ymm8
        vmovdqa	0x1a0(%rdi), %ymm9
        vmovdqa	0x1c0(%rdi), %ymm10
        vmovdqa	0x1e0(%rdi), %ymm11
        vmovdqa	0x340(%rsi), %ymm2
        vpmullw	%ymm15, %ymm8, %ymm12
        vpmullw	%ymm15, %ymm9, %ymm13
        vpmullw	%ymm15, %ymm10, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm8, %ymm8
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm10, %ymm10
        vpmulhw	%ymm2, %ymm11, %ymm11
        vmovdqa	0x100(%rdi), %ymm4
        vmovdqa	0x120(%rdi), %ymm5
        vmovdqa	0x140(%rdi), %ymm6
        vmovdqa	0x160(%rdi), %ymm7
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm8, %ymm4, %ymm3
        vpsubw	%ymm8, %ymm4, %ymm8
        vpaddw	%ymm9, %ymm5, %ymm4
        vpsubw	%ymm9, %ymm5, %ymm9
        vpaddw	%ymm10, %ymm6, %ymm5
        vpsubw	%ymm10, %ymm6, %ymm10
        vpaddw	%ymm11, %ymm7, %ymm6
        vpsubw	%ymm11, %ymm7, %ymm11
        vpsubw	%ymm12, %ymm3, %ymm3
        vpaddw	%ymm12, %ymm8, %ymm8
        vpsubw	%ymm13, %ymm4, %ymm4
        vpaddw	%ymm13, %ymm9, %ymm9
        vpsubw	%ymm14, %ymm5, %ymm5
        vpaddw	%ymm14, %ymm10, %ymm10
        vpsubw	%ymm15, %ymm6, %ymm6
        vpaddw	%ymm15, %ymm11, %ymm11
        vperm2i128	$0x20, %ymm10, %ymm5, %ymm7 # ymm7 = ymm5[0,1],ymm10[0,1]
        vperm2i128	$0x31, %ymm10, %ymm5, %ymm10 # ymm10 = ymm5[2,3],ymm10[2,3]
        vperm2i128	$0x20, %ymm11, %ymm6, %ymm5 # ymm5 = ymm6[0,1],ymm11[0,1]
        vperm2i128	$0x31, %ymm11, %ymm6, %ymm11 # ymm11 = ymm6[2,3],ymm11[2,3]
        vmovdqa	0x360(%rsi), %ymm15
        vmovdqa	0x380(%rsi), %ymm2
        vpmullw	%ymm15, %ymm7, %ymm12
        vpmullw	%ymm15, %ymm10, %ymm13
        vpmullw	%ymm15, %ymm5, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm7, %ymm7
        vpmulhw	%ymm2, %ymm10, %ymm10
        vpmulhw	%ymm2, %ymm5, %ymm5
        vpmulhw	%ymm2, %ymm11, %ymm11
        vperm2i128	$0x20, %ymm8, %ymm3, %ymm6 # ymm6 = ymm3[0,1],ymm8[0,1]
        vperm2i128	$0x31, %ymm8, %ymm3, %ymm8 # ymm8 = ymm3[2,3],ymm8[2,3]
        vperm2i128	$0x20, %ymm9, %ymm4, %ymm3 # ymm3 = ymm4[0,1],ymm9[0,1]
        vperm2i128	$0x31, %ymm9, %ymm4, %ymm9 # ymm9 = ymm4[2,3],ymm9[2,3]
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm7, %ymm6, %ymm4
        vpsubw	%ymm7, %ymm6, %ymm7
        vpaddw	%ymm10, %ymm8, %ymm6
        vpsubw	%ymm10, %ymm8, %ymm10
        vpaddw	%ymm5, %ymm3, %ymm8
        vpsubw	%ymm5, %ymm3, %ymm5
        vpaddw	%ymm11, %ymm9, %ymm3
        vpsubw	%ymm11, %ymm9, %ymm11
        vpsubw	%ymm12, %ymm4, %ymm4
        vpaddw	%ymm12, %ymm7, %ymm7
        vpsubw	%ymm13, %ymm6, %ymm6
        vpaddw	%ymm13, %ymm10, %ymm10
        vpsubw	%ymm14, %ymm8, %ymm8
        vpaddw	%ymm14, %ymm5, %ymm5
        vpsubw	%ymm15, %ymm3, %ymm3
        vpaddw	%ymm15, %ymm11, %ymm11
        vpunpcklqdq	%ymm5, %ymm8, %ymm9 # ymm9 = ymm8[0],ymm5[0],ymm8[2],ymm5[2]
        vpunpckhqdq	%ymm5, %ymm8, %ymm5 # ymm5 = ymm8[1],ymm5[1],ymm8[3],ymm5[3]
        vpunpcklqdq	%ymm11, %ymm3, %ymm8 # ymm8 = ymm3[0],ymm11[0],ymm3[2],ymm11[2]
        vpunpckhqdq	%ymm11, %ymm3, %ymm11 # ymm11 = ymm3[1],ymm11[1],ymm3[3],ymm11[3]
        vmovdqa	0x3a0(%rsi), %ymm15
        vmovdqa	0x3c0(%rsi), %ymm2
        vpmullw	%ymm15, %ymm9, %ymm12
        vpmullw	%ymm15, %ymm5, %ymm13
        vpmullw	%ymm15, %ymm8, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm5, %ymm5
        vpmulhw	%ymm2, %ymm8, %ymm8
        vpmulhw	%ymm2, %ymm11, %ymm11
        vpunpcklqdq	%ymm7, %ymm4, %ymm3 # ymm3 = ymm4[0],ymm7[0],ymm4[2],ymm7[2]
        vpunpckhqdq	%ymm7, %ymm4, %ymm7 # ymm7 = ymm4[1],ymm7[1],ymm4[3],ymm7[3]
        vpunpcklqdq	%ymm10, %ymm6, %ymm4 # ymm4 = ymm6[0],ymm10[0],ymm6[2],ymm10[2]
        vpunpckhqdq	%ymm10, %ymm6, %ymm10 # ymm10 = ymm6[1],ymm10[1],ymm6[3],ymm10[3]
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm9, %ymm3, %ymm6
        vpsubw	%ymm9, %ymm3, %ymm9
        vpaddw	%ymm5, %ymm7, %ymm3
        vpsubw	%ymm5, %ymm7, %ymm5
        vpaddw	%ymm8, %ymm4, %ymm7
        vpsubw	%ymm8, %ymm4, %ymm8
        vpaddw	%ymm11, %ymm10, %ymm4
        vpsubw	%ymm11, %ymm10, %ymm11
        vpsubw	%ymm12, %ymm6, %ymm6
        vpaddw	%ymm12, %ymm9, %ymm9
        vpsubw	%ymm13, %ymm3, %ymm3
        vpaddw	%ymm13, %ymm5, %ymm5
        vpsubw	%ymm14, %ymm7, %ymm7
        vpaddw	%ymm14, %ymm8, %ymm8
        vpsubw	%ymm15, %ymm4, %ymm4
        vpaddw	%ymm15, %ymm11, %ymm11
        vmovsldup	%ymm8, %ymm10   # ymm10 = ymm8[0,0,2,2,4,4,6,6]
        vpblendd	$0xaa, %ymm10, %ymm7, %ymm10 # ymm10 = ymm7[0],ymm10[1],ymm7[2],ymm10[3],ymm7[4],ymm10[5],ymm7[6],ymm10[7]
        vpsrlq	$0x20, %ymm7, %ymm7
        vpblendd	$0xaa, %ymm8, %ymm7, %ymm8 # ymm8 = ymm7[0],ymm8[1],ymm7[2],ymm8[3],ymm7[4],ymm8[5],ymm7[6],ymm8[7]
        vmovsldup	%ymm11, %ymm7   # ymm7 = ymm11[0,0,2,2,4,4,6,6]
        vpblendd	$0xaa, %ymm7, %ymm4, %ymm7 # ymm7 = ymm4[0],ymm7[1],ymm4[2],ymm7[3],ymm4[4],ymm7[5],ymm4[6],ymm7[7]
        vpsrlq	$0x20, %ymm4, %ymm4
        vpblendd	$0xaa, %ymm11, %ymm4, %ymm11 # ymm11 = ymm4[0],ymm11[1],ymm4[2],ymm11[3],ymm4[4],ymm11[5],ymm4[6],ymm11[7]
        vmovdqa	0x3e0(%rsi), %ymm15
        vmovdqa	0x400(%rsi), %ymm2
        vpmullw	%ymm15, %ymm10, %ymm12
        vpmullw	%ymm15, %ymm8, %ymm13
        vpmullw	%ymm15, %ymm7, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm10, %ymm10
        vpmulhw	%ymm2, %ymm8, %ymm8
        vpmulhw	%ymm2, %ymm7, %ymm7
        vpmulhw	%ymm2, %ymm11, %ymm11
        vmovsldup	%ymm9, %ymm4    # ymm4 = ymm9[0,0,2,2,4,4,6,6]
        vpblendd	$0xaa, %ymm4, %ymm6, %ymm4 # ymm4 = ymm6[0],ymm4[1],ymm6[2],ymm4[3],ymm6[4],ymm4[5],ymm6[6],ymm4[7]
        vpsrlq	$0x20, %ymm6, %ymm6
        vpblendd	$0xaa, %ymm9, %ymm6, %ymm9 # ymm9 = ymm6[0],ymm9[1],ymm6[2],ymm9[3],ymm6[4],ymm9[5],ymm6[6],ymm9[7]
        vmovsldup	%ymm5, %ymm6    # ymm6 = ymm5[0,0,2,2,4,4,6,6]
        vpblendd	$0xaa, %ymm6, %ymm3, %ymm6 # ymm6 = ymm3[0],ymm6[1],ymm3[2],ymm6[3],ymm3[4],ymm6[5],ymm3[6],ymm6[7]
        vpsrlq	$0x20, %ymm3, %ymm3
        vpblendd	$0xaa, %ymm5, %ymm3, %ymm5 # ymm5 = ymm3[0],ymm5[1],ymm3[2],ymm5[3],ymm3[4],ymm5[5],ymm3[6],ymm5[7]
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm10, %ymm4, %ymm3
        vpsubw	%ymm10, %ymm4, %ymm10
        vpaddw	%ymm8, %ymm9, %ymm4
        vpsubw	%ymm8, %ymm9, %ymm8
        vpaddw	%ymm7, %ymm6, %ymm9
        vpsubw	%ymm7, %ymm6, %ymm7
        vpaddw	%ymm11, %ymm5, %ymm6
        vpsubw	%ymm11, %ymm5, %ymm11
        vpsubw	%ymm12, %ymm3, %ymm3
        vpaddw	%ymm12, %ymm10, %ymm10
        vpsubw	%ymm13, %ymm4, %ymm4
        vpaddw	%ymm13, %ymm8, %ymm8
        vpsubw	%ymm14, %ymm9, %ymm9
        vpaddw	%ymm14, %ymm7, %ymm7
        vpsubw	%ymm15, %ymm6, %ymm6
        vpaddw	%ymm15, %ymm11, %ymm11
        vpslld	$0x10, %ymm7, %ymm5
        vpblendw	$0xaa, %ymm5, %ymm9, %ymm5 # ymm5 = ymm9[0],ymm5[1],ymm9[2],ymm5[3],ymm9[4],ymm5[5],ymm9[6],ymm5[7],ymm9[8],ymm5[9],ymm9[10],ymm5[11],ymm9[12],ymm5[13],ymm9[14],ymm5[15]
        vpsrld	$0x10, %ymm9, %ymm9
        vpblendw	$0xaa, %ymm7, %ymm9, %ymm7 # ymm7 = ymm9[0],ymm7[1],ymm9[2],ymm7[3],ymm9[4],ymm7[5],ymm9[6],ymm7[7],ymm9[8],ymm7[9],ymm9[10],ymm7[11],ymm9[12],ymm7[13],ymm9[14],ymm7[15]
        vpslld	$0x10, %ymm11, %ymm9
        vpblendw	$0xaa, %ymm9, %ymm6, %ymm9 # ymm9 = ymm6[0],ymm9[1],ymm6[2],ymm9[3],ymm6[4],ymm9[5],ymm6[6],ymm9[7],ymm6[8],ymm9[9],ymm6[10],ymm9[11],ymm6[12],ymm9[13],ymm6[14],ymm9[15]
        vpsrld	$0x10, %ymm6, %ymm6
        vpblendw	$0xaa, %ymm11, %ymm6, %ymm11 # ymm11 = ymm6[0],ymm11[1],ymm6[2],ymm11[3],ymm6[4],ymm11[5],ymm6[6],ymm11[7],ymm6[8],ymm11[9],ymm6[10],ymm11[11],ymm6[12],ymm11[13],ymm6[14],ymm11[15]
        vmovdqa	0x420(%rsi), %ymm15
        vmovdqa	0x440(%rsi), %ymm2
        vpmullw	%ymm15, %ymm5, %ymm12
        vpmullw	%ymm15, %ymm7, %ymm13
        vpmullw	%ymm15, %ymm9, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm2, %ymm5, %ymm5
        vpmulhw	%ymm2, %ymm7, %ymm7
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm11, %ymm11
        vpslld	$0x10, %ymm10, %ymm6
        vpblendw	$0xaa, %ymm6, %ymm3, %ymm6 # ymm6 = ymm3[0],ymm6[1],ymm3[2],ymm6[3],ymm3[4],ymm6[5],ymm3[6],ymm6[7],ymm3[8],ymm6[9],ymm3[10],ymm6[11],ymm3[12],ymm6[13],ymm3[14],ymm6[15]
        vpsrld	$0x10, %ymm3, %ymm3
        vpblendw	$0xaa, %ymm10, %ymm3, %ymm10 # ymm10 = ymm3[0],ymm10[1],ymm3[2],ymm10[3],ymm3[4],ymm10[5],ymm3[6],ymm10[7],ymm3[8],ymm10[9],ymm3[10],ymm10[11],ymm3[12],ymm10[13],ymm3[14],ymm10[15]
        vpslld	$0x10, %ymm8, %ymm3
        vpblendw	$0xaa, %ymm3, %ymm4, %ymm3 # ymm3 = ymm4[0],ymm3[1],ymm4[2],ymm3[3],ymm4[4],ymm3[5],ymm4[6],ymm3[7],ymm4[8],ymm3[9],ymm4[10],ymm3[11],ymm4[12],ymm3[13],ymm4[14],ymm3[15]
        vpsrld	$0x10, %ymm4, %ymm4
        vpblendw	$0xaa, %ymm8, %ymm4, %ymm8 # ymm8 = ymm4[0],ymm8[1],ymm4[2],ymm8[3],ymm4[4],ymm8[5],ymm4[6],ymm8[7],ymm4[8],ymm8[9],ymm4[10],ymm8[11],ymm4[12],ymm8[13],ymm4[14],ymm8[15]
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm5, %ymm6, %ymm4
        vpsubw	%ymm5, %ymm6, %ymm5
        vpaddw	%ymm7, %ymm10, %ymm6
        vpsubw	%ymm7, %ymm10, %ymm7
        vpaddw	%ymm9, %ymm3, %ymm10
        vpsubw	%ymm9, %ymm3, %ymm9
        vpaddw	%ymm11, %ymm8, %ymm3
        vpsubw	%ymm11, %ymm8, %ymm11
        vpsubw	%ymm12, %ymm4, %ymm4
        vpaddw	%ymm12, %ymm5, %ymm5
        vpsubw	%ymm13, %ymm6, %ymm6
        vpaddw	%ymm13, %ymm7, %ymm7
        vpsubw	%ymm14, %ymm10, %ymm10
        vpaddw	%ymm14, %ymm9, %ymm9
        vpsubw	%ymm15, %ymm3, %ymm3
        vpaddw	%ymm15, %ymm11, %ymm11
        vmovdqa	0x460(%rsi), %ymm14
        vmovdqa	0x4a0(%rsi), %ymm15
        vmovdqa	0x480(%rsi), %ymm8
        vmovdqa	0x4c0(%rsi), %ymm2
        vpmullw	%ymm14, %ymm10, %ymm12
        vpmullw	%ymm14, %ymm3, %ymm13
        vpmullw	%ymm15, %ymm9, %ymm14
        vpmullw	%ymm15, %ymm11, %ymm15
        vpmulhw	%ymm8, %ymm10, %ymm10
        vpmulhw	%ymm8, %ymm3, %ymm3
        vpmulhw	%ymm2, %ymm9, %ymm9
        vpmulhw	%ymm2, %ymm11, %ymm11
        vpmulhw	%ymm0, %ymm12, %ymm12
        vpmulhw	%ymm0, %ymm13, %ymm13
        vpmulhw	%ymm0, %ymm14, %ymm14
        vpmulhw	%ymm0, %ymm15, %ymm15
        vpaddw	%ymm10, %ymm4, %ymm8
        vpsubw	%ymm10, %ymm4, %ymm10
        vpaddw	%ymm3, %ymm6, %ymm4
        vpsubw	%ymm3, %ymm6, %ymm3
        vpaddw	%ymm9, %ymm5, %ymm6
        vpsubw	%ymm9, %ymm5, %ymm9
        vpaddw	%ymm11, %ymm7, %ymm5
        vpsubw	%ymm11, %ymm7, %ymm11
        vpsubw	%ymm12, %ymm8, %ymm8
        vpaddw	%ymm12, %ymm10, %ymm10
        vpsubw	%ymm13, %ymm4, %ymm4
        vpaddw	%ymm13, %ymm3, %ymm3
        vpsubw	%ymm14, %ymm6, %ymm6
        vpaddw	%ymm14, %ymm9, %ymm9
        vpsubw	%ymm15, %ymm5, %ymm5
        vpaddw	%ymm15, %ymm11, %ymm11
        vmovdqa	%ymm8, 0x100(%rdi)
        vmovdqa	%ymm4, 0x120(%rdi)
        vmovdqa	%ymm10, 0x140(%rdi)
        vmovdqa	%ymm3, 0x160(%rdi)
        vmovdqa	%ymm6, 0x180(%rdi)
        vmovdqa	%ymm5, 0x1a0(%rdi)
        vmovdqa	%ymm9, 0x1c0(%rdi)
        vmovdqa	%ymm11, 0x1e0(%rdi)
        retq

#endif /* defined(MLK_ARITH_BACKEND_X86_64_DEFAULT) && \
          !defined(MLK_MULTILEVEL_BUILD_NO_SHARED) */
