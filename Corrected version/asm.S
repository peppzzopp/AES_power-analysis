	.syntax unified
	.cpu cortex-m4
    // constant
	.global LogTable_q3
	.global ExpTable_q3
	.set q_1, 256  // 2^8
	.set q_2, 256  // 2^8            
	.set q_3, 512  // 2^9
	.set d, 1
	.set q3_to_q2, 255 // q3 - q2
	.set int_size, 4   // 1 int = 4 byte
	.set dim_int, 2    // dimension of int
	.set block_size, (d+1)*int_size          
	.set column_size, 4*(d+1)*int_size
	.set R_num, d*d
	.set s_num, d
	
	// function
	.global AES_one_round_pre
	.global AES_one_round_online
	
	.global AddRoundKey_pre
	.global AddRoundKey_online
	.global SubBytes_pre
	.global SubBytes_online
	.global MixColumns_pre
	.global MixColumns_online
    .global ShiftRows_share_adapted
    .global MixColumns_share_adapted
		
	.global MaskedTable_pre
	.global MaskedTable_online
	
	// variable
    .global S
	.global A
    .global X_address	
    .global X_k		
    .global Y_address
	.global random_1
    .global random_2
    .global random_3
	.global random_address_2
	.global random_address_3	
    .global R
    .global R_T
	.global temp

	// For PackedShiftRefresh	
	.global W
	.global u
		
    // For ToAdditiveShares
	.global s_address
	.global s_address_1
	.global s_address_2
	.global s_address_3
	.global s_address_4
	.global s_address_5
	.global s_address_6
	.global s_address_7
	.global s_address_8
	.global s_address_9
	.global s_address_10
	.global s_address_11
	.global s_address_12
	.global s_address_13
	.global s_address_14
	.global s_address_15
	.global s_address_16
	.global s_1
	.global t_address
	.global t_address_1
	.global t_address_2
	.global t_address_3
	.global t_address_4
	.global t_address_5
	.global t_address_6
	.global t_address_7
	.global t_address_8
	.global t_address_9 
	.global t_address_10
	.global t_address_11
	.global t_address_12
	.global t_address_13
	.global t_address_14
	.global t_address_15
	.global t_address_16
	.global t_1
	.global t_
		
	.global w_address
	.global w_address_1
	.global w_address_2
	.global w_address_3
	.global w_address_4
	.global w_address_5
	.global w_address_6
	.global w_address_7
	.global w_address_8
	.global w_address_9
	.global w_address_10
	.global w_address_11
	.global w_address_12
	.global w_address_13
	.global w_address_14
	.global w_address_15
	.global w_address_16
	.global w_1
    .global y
	
	// AES one round
	.global plain
	.global cipher
	.global round_key
	.global	MixColumns_table_2
	.global	MixColumns_table_3

	.global plain_masked_1
	.global plain_masked_2
    .global plain_masked_3
    .global plain_masked_4
    .global plain_masked_5
    .global plain_masked_6
    .global plain_masked_7
    .global plain_masked_8
    .global plain_masked_9
    .global plain_masked_10
    .global plain_masked_11
    .global plain_masked_12
    .global plain_masked_13
    .global plain_masked_14
    .global plain_masked_15
    .global plain_masked_16
    		
	
////////////////////////////////////////////////////////////
	.macro mult_exp_q2 opA , opB , res , pttab , tmp
	// init phase
	LDR \pttab , = LogTable_q2
	// log ( opA ) + log ( opB )
	LDR \tmp , [ \pttab , \opA ]
	LDR \res , [ \pttab , \opB ]
	ADD \tmp , \res
	// res <- alog ( tmp )
	//ADD $pttab , #(2^ n )
	LDR \pttab , = ExpTable_q2
	LDR \res , [ \pttab , \tmp ]
	// check if opA or opB is 0
	RSB \tmp , \opA , #0
	AND \tmp , \opB , \tmp , ASR #32
	RSB \tmp , #0
	AND \res , \tmp , ASR #32
	.endm
////////////////////////////////////////////////////////////
	.macro mult_exp_q3_old opA , opB , res , pttab , tmp
	// init phase
	LDR \pttab , = LogTable_q3
	// log ( opA ) + log ( opB )
	LSL \opA, dim_int
	//LSL \opB, dim_int
	LDR \tmp , [ \pttab , \opA ]
	LDR \res , [ \pttab , \opB ]
	ADD \tmp , \opA , \res
	// res <- alog ( tmp )
	//ADD $pttab , #(2^ n )
	LDR \pttab , = ExpTable_q3
	LSL \tmp, dim_int
	LDR \res , [ \pttab , \tmp ]
	// check if opA or opB is 0
	RSB \tmp , \opA , #0
	AND \tmp , \opB , \tmp , ASR #32
	RSB \tmp , #0
	AND \res , \tmp , ASR #32
	.endm
////////////////////////////////////////////////////////////
	.macro mult_exp_q3 opA, opB, res, table_address
    // If either operand is zero, result is zero
    CMP \opA, #0
    BEQ zero_result_\@
    CMP \opB, #0
    BEQ zero_result_\@

    // Compute log(opA) + log(opB)
    LDR \res, =LogTable_q3
    LSL \opA, dim_int
    LDR \opA, [\res, \opA]
    LSL \opB, dim_int
    LDR \opB, [\res, \opB]
    ADD \opA, \opB

    // FIXED: Construct 511 using multiple instructions
    MOV \res, #256                  // Load 256
    ADD \res, #255                  // Add 255 to get 511
    CMP \opA, \res
    IT GT                           // IT block for conditional execution
    SUBGT \opA, \res

    // Compute alog(sum)
    LDR \res, =ExpTable_q3
    LSL \opA, dim_int
    LDR \res, [\res, \opA]
    B end_mult_\@

    zero_result_\@:
    MOV \res, #0

    end_mult_\@:
    .endm
////////////////////////////////////////////////////////////
	.macro Do_LogTable_q3 opA, size, tmp1, tmp2
	// let element of opA be Log_address, opA is a address of an array
	LDR \tmp1 , =LogTable_q3
B jmp_across_ltorg\@
	.ltorg
jmp_across_ltorg\@:
	.set i, 0
	.rept \size
        LDR \tmp2, [\opA, #i]
		LSL \tmp2, dim_int
		LDR \tmp2, [\tmp1, \tmp2]
		LSL \tmp2, dim_int
		STR \tmp2, [\opA, #i]
        .set i, i+int_size
    .endr
	.endm
////////////////////////////////////////////////////////////
	.macro Small_Field opA, res
    // Proper field mapping GF(512) -> GF(256) with IT block
    AND \res, \opA, #0xFF
    LSR \opA, #8
    AND \opA, #1
    CMP \opA, #0
    IT NE
    EORNE \res, #0x1B
    .endm
////////////////////////////////////////////////////////////
    .macro Matrix_Add op1, op2, op3, op9, op10, opA, res
	// b = sum(A), b at res(add), A at opA
	// A is a d*d size matrix, and opA will be changed
//------------------------------------------------------
    MOV \op2, #0
	MA_condition1_\@:
	SUB \op1, \op2, d*int_size
	CBNZ \op1, MA_loop1_\@
	B MA_exit1_\@
	MA_loop1_\@:              //
//------------------------------------------------
    MOV \op9, #0
    MOV \op3, #0
    MA_condition2_\@:
	SUB \op1, \op3, d*int_size
	CBNZ \op1, MA_loop2_\@
	B MA_exit2_\@
	MA_loop2_\@:              //

    LDR \op10, [\opA, \op3]
	EOR \op9, \op9, \op10

	ADD \op3, \op3, int_size
	B MA_condition2_\@
	MA_exit2_\@:
//------------------------------------------------
    STR \op9, [\res, \op2]
	
	ADD \opA, \opA, d*int_size
	ADD \op2, \op2, int_size
	B MA_condition1_\@
	MA_exit1_\@:
//------------------------------------------------------
	.endm
////////////////////////////////////////////////////////////	
	.macro Vector_Add op1, op2, op10, opA, res
	// b = sum(a), b at res(num), a at opA
	// a is a d size vector
//------------------------------------------------------
    MOV \res, #0
	MOV \op2, #0
    VA_condition1_\@:
	SUB \op1, \op2, d*int_size
	CBNZ \op1, VA_loop1_\@
	B VA_exit1_\@
	VA_loop1_\@:              //

    LDR \op10, [\opA, \op2]
	EOR \res, \res, \op10
	
	ADD \op2, \op2, int_size
	B VA_condition1_\@
	VA_exit1_\@:
//------------------------------------------------------
	.endm
////////////////////////////////////////////////////////////
	.macro Matrix_Transpose op1, op2, op3, op4, op10, opR, opRT
	// R_T, R_T at opRT, R at opR
//------------------------------------------------------
    MOV \op2, #0
    MT_condition1_\@:
	SUB \op1, \op2, d*int_size
	CBNZ \op1, MT_loop1_\@
	B MT_exit1_\@
	MT_loop1_\@:              //
//------------------------------------------------
    MOV \op4, \opRT
    MOV \op3, #0
    MT_condition2_\@:
	SUB \op1, \op3, d*int_size
	CBNZ \op1, MT_loop2_\@
	B MT_exit2_\@
	MT_loop2_\@:              //

    LDR \op10, [\opR, \op3]
	STR \op10, [\op4, \op2]

    ADD \op4, \op4, d*int_size
	ADD \op3, \op3, int_size
	B MT_condition2_\@
	MT_exit2_\@:
//------------------------------------------------
    ADD \opR, \opR, d*int_size
	ADD \op2, \op2, int_size
	B MT_condition1_\@
	MT_exit1_\@:
//------------------------------------------------------
	.endm
////////////////////////////////////////////////////////////
	.macro LastShare_CandS op12, op11, op10, op9, op8, op5, op4, tmp1, tmp2, tmp3, table_address
	// op12=w, op11=A's i th row, op10=y, op9=s, op8=X's last(num), op5=cul=0, op4=2^dim_d_int
	
    .set i, 0
        .rept d

		LDR \tmp1, [\op11, #i]
		LDR \tmp2, [\op9, #i]
		mult_exp_q3 \tmp1 ,\tmp2 ,\tmp3 ,\table_address   
		Small_Field \tmp3, \tmp3                           
		
		MOV \tmp2, #0
		LDR \tmp2, [\op12,#i]
		EOR \tmp3, \tmp3, \tmp2
		MOV \tmp2, #0
		EOR \op5, \tmp3

		.set i, i+int_size
	.endr
	
    LSL \op8, dim_int
	LDR \op12, =t_address
	LDR \op12, [\op12]
	LDR \op12, [\op12, \op8]   
	EOR \op5, \op12

	LDR \op10, =Y_address
	LDR \op10, [\op10]
	STR \op5, [\op10, \op4]       
	.endm
////////////////////////////////////////////////////////////--------------

////////////////////////////////////////////////////////////--------------
	SubBytes_SetParameters:
// r12 = s, r11 = t, r10 = w, use r9 as temp
	LDR r9, =s_address_1
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_2
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_3
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_4
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_5
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_6
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_7
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_8
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_9
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_10
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_11
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_12
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_13
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_14
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_15
	STR r12, [r9]
	ADD r12, d*int_size
	LDR r9, =s_address_16
	STR r12, [r9]
	ADD r12, d*int_size
	
	LDR r9, =t_address_1
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_2
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_3
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_4
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_5
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_6
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_7
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_8
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_9
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_10
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_11
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_12
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_13
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_14
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_15
	STR r11, [r9]
	ADD r11, q_1*int_size
	LDR r9, =t_address_16
	STR r11, [r9]
	ADD r11, q_1*int_size
	
	LDR r9, =w_address_1
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_2
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_3
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_4
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_5
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_6
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_7
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_8
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_9
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_10
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_11
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_12
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_13
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_14
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_15
	STR r10, [r9]
	ADD r10, d*int_size
	LDR r9, =w_address_16
	STR r10, [r9]
	ADD r10, d*int_size
	
	BX lr
////////////////////////////////////////////////////////////
	Gennerate_plain_masked:
	// r12 = plain_masked, r10 = plain
	LDR r9, [r10]
//------------------------------------------------	
	MOV r1, #0
    AORP_condition1:
	SUB r0, r1, d*int_size
	CBNZ r0, AORP_loop1
	B AORP_exit1
	AORP_loop1:              // Gennerate plain_masked[16][d+1] in q1

	LDR r11, [r6], 4
	EOR r9, r11
	STR r11, [r12, r1]
	
	ADD r1, r1, int_size
	B AORP_condition1
	AORP_exit1:
//------------------------------------------------	
    STR r9, [r12, r1]
    ADD r10, int_size
	
	BX lr
////////////////////////////////////////////////////////////
    AES_one_round_pre:
	PUSH {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	
	LDR r6, =random_1
	LDR r10, =plain	
    // Gennerate plain_masked[16][d+1] in q1
    LDR r12, =plain_masked_1
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_2
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_3
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_4
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_5
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_6
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_7
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_8
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_9
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_10
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_11
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_12
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_13
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_14
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_15
	BL Gennerate_plain_masked
	LDR r12, =plain_masked_16
	BL Gennerate_plain_masked	

	BL AddRoundKey_pre

	LDR r12, =s_1
    LDR r11, =t_1
	LDR r10, =w_1

	BL SubBytes_SetParameters

	BL SubBytes_pre
    
	POP {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
	AES_one_round_online:
	PUSH {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	
	BL AddRoundKey_online
	LDR r12, =s_1
	LDR r11, =t_1
	LDR r10, =w_1

	BL SubBytes_SetParameters

	BL SubBytes_online
    
    BL ShiftRows_share_adapted
    
	BL MixColumns_share_adapted
	
	POP {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
	AddRoundKey_block:
	// block at r12, roundkey at r11
//------------------------------------------------------
	MOV r1, #0
    ARKB_condition1:
	SUB r0, r1, d*int_size
	CBNZ r0, ARKB_loop1
	B ARKB_exit1
	ARKB_loop1:              // Update one block 
	
	LDR r10, [r12, r1]
	LDR r9, [r11, r1]
	EOR r10, r10, r9
	STR r10, [r12, r1]
	
	ADD r1, r1, int_size
	B ARKB_condition1
	ARKB_exit1:
//------------------------------------------------------
	ADD r11, block_size      // next block of round_key
	
	BX lr
////////////////////////////////////////////////////////////
	AddRoundKey_pre:
	PUSH {lr}
	
	LDR r11, =round_key
	LDR r12, =plain_masked_1
	BL AddRoundKey_block
	LDR r12, =plain_masked_2
	BL AddRoundKey_block
	LDR r12, =plain_masked_3
	BL AddRoundKey_block
	LDR r12, =plain_masked_4
	BL AddRoundKey_block
	LDR r12, =plain_masked_5
	BL AddRoundKey_block
	LDR r12, =plain_masked_6
	BL AddRoundKey_block
	LDR r12, =plain_masked_7
	BL AddRoundKey_block
	LDR r12, =plain_masked_8
	BL AddRoundKey_block
	LDR r12, =plain_masked_9
	BL AddRoundKey_block
	LDR r12, =plain_masked_10
	BL AddRoundKey_block
	LDR r12, =plain_masked_11
	BL AddRoundKey_block
	LDR r12, =plain_masked_12
	BL AddRoundKey_block	 
	LDR r12, =plain_masked_13
	BL AddRoundKey_block
	LDR r12, =plain_masked_14
	BL AddRoundKey_block
	LDR r12, =plain_masked_15
	BL AddRoundKey_block
	LDR r12, =plain_masked_16
	BL AddRoundKey_block

    POP {lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
	SBox_SetParameters:
	// r12 = plain_masked, r11 = s, r10 = t, r9 = w
	//LDR r12, [r12]
	LDR r11, [r11]
	LDR r10, [r10]
	LDR r9, [r9]
	LDR r8, =X_address
	LDR r7, =Y_address
	LDR r6, =s_address
	LDR r5, =t_address
	LDR r4, =w_address
	STR r12, [r8]
	STR r12, [r7]
	STR r11, [r6]
	STR r10, [r5]
	STR r9, [r4]
	
	BX lr
////////////////////////////////////////////////////////////
	SubBytes_pre:
	PUSH {lr}

    LDR r6, =random_2
	LDR r7, =random_address_2
	STR r6, [r7]
    LDR r6, =random_3
	LDR r7, =random_address_3
	STR r6, [r7]

	LDR r12, =plain_masked_1
	LDR r11, =s_address_1
	LDR r10, =t_address_1
	LDR r9, =w_address_1
	BL SBox_SetParameters
	BL MaskedTable_pre

	LDR r12, =plain_masked_2
	LDR r11, =s_address_2
	LDR r10, =t_address_2
	LDR r9, =w_address_2
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_3
	LDR r11, =s_address_3
	LDR r10, =t_address_3
	LDR r9, =w_address_3
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_4
	LDR r11, =s_address_4
	LDR r10, =t_address_4
	LDR r9, =w_address_4
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_5
	LDR r11, =s_address_5
	LDR r10, =t_address_5
	LDR r9, =w_address_5
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_6
	LDR r11, =s_address_6
	LDR r10, =t_address_6
	LDR r9, =w_address_6
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_7
	LDR r11, =s_address_7
	LDR r10, =t_address_7
	LDR r9, =w_address_7
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_8
	LDR r11, =s_address_8
	LDR r10, =t_address_8
	LDR r9, =w_address_8
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_9
	LDR r11, =s_address_9
	LDR r10, =t_address_9
	LDR r9, =w_address_9
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_10
	LDR r11, =s_address_10
	LDR r10, =t_address_10
	LDR r9, =w_address_10
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_11
	LDR r11, =s_address_11
	LDR r10, =t_address_11
	LDR r9, =w_address_11
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_12
	LDR r11, =s_address_12
	LDR r10, =t_address_12
	LDR r9, =w_address_12
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_13
	LDR r11, =s_address_13
	LDR r10, =t_address_13
	LDR r9, =w_address_13
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_14
	LDR r11, =s_address_14
	LDR r10, =t_address_14
	LDR r9, =w_address_14
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_15
	LDR r11, =s_address_15
	LDR r10, =t_address_15
	LDR r9, =w_address_15
	BL SBox_SetParameters
	BL MaskedTable_pre
	
	LDR r12, =plain_masked_16
	LDR r11, =s_address_16
	LDR r10, =t_address_16
	LDR r9, =w_address_16
	BL SBox_SetParameters
	BL MaskedTable_pre

    POP {lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
	MixColumns_column:
	// r12 = col_1, r11 = col_2, r10 = col_3, r9 = col_4, r1 = offset, r2 = MixColumns_table_2, r3 = MixColumns_table_3
	MOV r4, #0
	MOV r5, #0
	MOV r6, #0
	MOV r7, #0
//------------------------------------------	
	LDR r8, [r12, r1]
	LSL r8, dim_int
	LDR r8, [r2, r8]
	EOR r7, r7, r8

	LDR r8, [r11, r1]
	LSL r8, dim_int
	LDR r8, [r3, r8]
	EOR r7, r7, r8
	
	LDR r8, [r10, r1]
	EOR r7, r7, r8
	
	LDR r8, [r9, r1]
	EOR r7, r7, r8
//------------------------------------------	
	LDR r8, [r12, r1]
	EOR r6, r6, r8

	LDR r8, [r11, r1]
	LSL r8, dim_int
	LDR r8, [r2, r8]
	EOR r6, r6, r8
	
	LDR r8, [r10, r1]
	LSL r8, dim_int
	LDR r8, [r3, r8]
	EOR r6, r6, r8
	
	LDR r8, [r9, r1]
	EOR r6, r6, r8
//------------------------------------------	
	LDR r8, [r12, r1]
	EOR r5, r5, r8

	LDR r8, [r11, r1]
	EOR r5, r5, r8
	
	LDR r8, [r10, r1]
	LSL r8, dim_int
	LDR r8, [r2, r8]
	EOR r5, r5, r8
	
	LDR r8, [r9, r1]
	LSL r8, dim_int
	LDR r8, [r3, r8]
	EOR r5, r5, r8
//------------------------------------------
	LDR r8, [r12, r1]
	LSL r8, dim_int
	LDR r8, [r3, r8]
	EOR r4, r4, r8

	LDR r8, [r11, r1]
	EOR r4, r4, r8
	
	LDR r8, [r10, r1]
	EOR r4, r4, r8
	
	LDR r8, [r9, r1]
	LSL r8, dim_int
	LDR r8, [r2, r8]
	EOR r4, r4, r8
//------------------------------------------	
    STR r7, [r12, r1]
	STR r6, [r11, r1]
	STR r5, [r10, r1]
	STR r4, [r9, r1]
	
	BX lr
////////////////////////////////////////////////////////////
	MixColumns_pre:
	PUSH {lr}
	
	LDR r2 ,=MixColumns_table_2
	LDR r3 ,=MixColumns_table_3
//------------------------------------------------
	MOV r1, #0
    MCP_condition1:
	SUB r0, r1, d*int_size
	CBNZ r0, MCP_loop1
	B MCP_exit1
	MCP_loop1:              // Update plain_masked[16][d+1]

    LDR r12, =plain_masked_1
	LDR r11, =plain_masked_5
	LDR r10, =plain_masked_9
	LDR r9, =plain_masked_13
	BL MixColumns_column
	
    LDR r12, =plain_masked_2
	LDR r11, =plain_masked_6
	LDR r10, =plain_masked_10
	LDR r9, =plain_masked_14
	BL MixColumns_column
	
    LDR r12, =plain_masked_3
	LDR r11, =plain_masked_7
	LDR r10, =plain_masked_11
	LDR r9, =plain_masked_15
	BL MixColumns_column
	
    LDR r12, =plain_masked_4
	LDR r11, =plain_masked_8
	LDR r10, =plain_masked_12
	LDR r9, =plain_masked_16
	BL MixColumns_column

	ADD r1, r1, int_size
	B MCP_condition1
	MCP_exit1:
//------------------------------------------------	
    POP {lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
	AddRoundKey_last:
	// r11 = round_key_last, r12 = plain_masked_last
	ADD r12, d*int_size
	
	LDR r9, [r11]
	LDR r10, [r12]
	EOR r10, r9
	STR r10, [r12]
	
	ADD r11, block_size      // next block of round_key
	
	BX lr
////////////////////////////////////////////////////////////
	AddRoundKey_online:
	PUSH {lr}

	LDR r11, =round_key
	ADD r11, d*int_size
	
	LDR r12, =plain_masked_1
	BL AddRoundKey_last
	LDR r12, =plain_masked_2
	BL AddRoundKey_last
	LDR r12, =plain_masked_3
	BL AddRoundKey_last
	LDR r12, =plain_masked_4
	BL AddRoundKey_last
	LDR r12, =plain_masked_5
	BL AddRoundKey_last
	LDR r12, =plain_masked_6
	BL AddRoundKey_last
	LDR r12, =plain_masked_7
	BL AddRoundKey_last
	LDR r12, =plain_masked_8
	BL AddRoundKey_last
	LDR r12, =plain_masked_9
	BL AddRoundKey_last
	LDR r12, =plain_masked_10
	BL AddRoundKey_last
	LDR r12, =plain_masked_11
	BL AddRoundKey_last
	LDR r12, =plain_masked_12
	BL AddRoundKey_last
	LDR r12, =plain_masked_13
	BL AddRoundKey_last
	LDR r12, =plain_masked_14
	BL AddRoundKey_last
	LDR r12, =plain_masked_15
	BL AddRoundKey_last
	LDR r12, =plain_masked_16
	BL AddRoundKey_last
	
	POP {lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
	SubBytes_online:
	PUSH {lr}

	LDR r12, =plain_masked_1
	LDR r11, =s_address_1
	LDR r10, =t_address_1
	LDR r9, =w_address_1
	BL SBox_SetParameters

	BL MaskedTable_online
	
	LDR r12, =plain_masked_2
	LDR r11, =s_address_2
	LDR r10, =t_address_2
	LDR r9, =w_address_2
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_3
	LDR r11, =s_address_3
	LDR r10, =t_address_3
	LDR r9, =w_address_3
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_4
	LDR r11, =s_address_4
	LDR r10, =t_address_4
	LDR r9, =w_address_4
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_5
	LDR r11, =s_address_5
	LDR r10, =t_address_5
	LDR r9, =w_address_5
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_6
	LDR r11, =s_address_6
	LDR r10, =t_address_6
	LDR r9, =w_address_6
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_7
	LDR r11, =s_address_7
	LDR r10, =t_address_7
	LDR r9, =w_address_7
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_8
	LDR r11, =s_address_8
	LDR r10, =t_address_8
	LDR r9, =w_address_8
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_9
	LDR r11, =s_address_9
	LDR r10, =t_address_9
	LDR r9, =w_address_9
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_10
	LDR r11, =s_address_10
	LDR r10, =t_address_10
	LDR r9, =w_address_10
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_11
	LDR r11, =s_address_11
	LDR r10, =t_address_11
	LDR r9, =w_address_11
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_12
	LDR r11, =s_address_12
	LDR r10, =t_address_12
	LDR r9, =w_address_12
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_13
	LDR r11, =s_address_13
	LDR r10, =t_address_13
	LDR r9, =w_address_13
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_14
	LDR r11, =s_address_14
	LDR r10, =t_address_14
	LDR r9, =w_address_14
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_15
	LDR r11, =s_address_15
	LDR r10, =t_address_15
	LDR r9, =w_address_15
	BL SBox_SetParameters
	BL MaskedTable_online
	
	LDR r12, =plain_masked_16
	LDR r11, =s_address_16
	LDR r10, =t_address_16
	LDR r9, =w_address_16
	BL SBox_SetParameters
	BL MaskedTable_online

    POP {lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
	MixColumns_online:
	PUSH {lr}
	
	LDR r2 ,=MixColumns_table_2
	LDR r3 ,=MixColumns_table_3
	MOV r1, d*int_size

    LDR r12, =plain_masked_1
	LDR r11, =plain_masked_5
	LDR r10, =plain_masked_9
	LDR r9, =plain_masked_13
	BL MixColumns_column
	
    LDR r12, =plain_masked_2
	LDR r11, =plain_masked_6
	LDR r10, =plain_masked_10
	LDR r9, =plain_masked_14
	BL MixColumns_column
	
    LDR r12, =plain_masked_3
	LDR r11, =plain_masked_7
	LDR r10, =plain_masked_11
	LDR r9, =plain_masked_15
	BL MixColumns_column
	
    LDR r12, =plain_masked_4
	LDR r11, =plain_masked_8
	LDR r10, =plain_masked_12
	LDR r9, =plain_masked_16
	BL MixColumns_column

    POP {lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
    MaskedTable_pre:
	PUSH {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	
	LDR r12, =S
	//LDR r11, =t
	LDR r11, =t_address
	LDR r11, [r11]
//------------------------------------------------------	
	MOV r1, #0
    MTP_condition1:
	SUB r0, r1, q_1*int_size
	CBNZ r0, MTP_loop1
	B MTP_exit1
	MTP_loop1:              //

    LDR r10, [r12, r1]
	STR r10, [r11, r1]

	ADD r1, r1, int_size
	B MTP_condition1
	MTP_exit1:
//------------------------------------------------------	
//------------------------------------------------------	
	MOV r1, #0
    MTP_condition2:
	SUB r0, r1, d*int_size
	CBNZ r0, MTP_loop2
	B MTP_exit2
	MTP_loop2:              //
	PUSH {r1}
	
    //LDR r2, =X
	LDR r2, =X_address
	LDR r2, [r2]
	LDR r2, [r2, r1]
	LDR r3, =X_k
	STR r2, [r3]

    BL PackedShiftRefresh   // r1 is used

	POP {r1}
	ADD r1, r1, int_size
	B MTP_condition2
	MTP_exit2:

//------------------------------------------------------
    LDR r9, =s_address
	LDR r9, [r9]
    // Do_LogTable_q3 opA, size, tmp1, tmp2
	// let element of opA be Log_address, opA is a address of an array
	Do_LogTable_q3 r9, s_num, r0, r1

    BL ToAdditiveShares_pre

	POP {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
    MaskedTable_online:
	PUSH {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	
	BL ToAdditiveShares_online
	
	POP {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,lr}
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
    PackedShiftRefresh:     // do not use r8 
	LDR r12, =R
	LDR r7, =random_address_2
	LDR r6, [r7]
//------------------------------------------------------	
	MOV r1, #0
    PSR_condition1:
	SUB r0, r1, d*d*int_size
	CBNZ r0, PSR_loop1
	B PSR_exit1
	PSR_loop1:              // Gennerate R[d][d] in q3
	
	LDR r11, [r6], 4
	STR r11, [r12, r1]
	
	ADD r1, r1, int_size
	B PSR_condition1
	PSR_exit1:
//------------------------------------------------------
    STR r6, [r7]
	
    LDR r11, =R_T
	Matrix_Transpose r0, r1, r2, r3, r4, r12, r11
	
	LDR r12, =R
	// Do_LogTable_q3 opA, size, tmp1, tmp2
	// let element of opA be Log_address, opA is a address of an array
	Do_LogTable_q3 r12, R_num, r1, r2
	
	//LDR r12, =R
	LDR r11, =A
	LDR r10, =W
	LDR r8, =ExpTable_q3
//------------------------------------------------------	
	MOV r1, #0
    PSR_condition2:
	SUB r0, r1, q_1
	CBNZ r0, PSR_loop2
	B PSR_exit2
	PSR_loop2:              // Compute W(q1*d) = A(q1*d) * R(d*d) 
//------------------------------------------------
    MOV r2, #0
    PSR_condition3:
	SUB r0, r2, d*int_size
	CBNZ r0, PSR_loop3
	B PSR_exit3
	PSR_loop3:              // Compute W(q1*d) = A(q1*d) * R(d*d) 
//------------------------------------------
    MOV r3, #0
	MOV r9, #0              // temp
	//LDR r12, =R
	//LDR r11, =A
	//LSL r4, r1, dim_d_int
	MOV r0, d*4
	MUL r4, r1, r0
	ADD r4, r11, r4
	ADD r5, r12, r2
    PSR_condition4:
	SUB r0, r3, d
	CBNZ r0, PSR_loop4
	B PSR_exit4
	PSR_loop4:              // Compute W(q1*d) = A(q1*d) * R(d*d) 
	
	LDR r6, [r4]
	LDR r7, [r5]
	//mult_exp_q3 opA , opB , res , table_address
	mult_exp_q3 r6, r7, r0, r8
	
	EOR r9, r0
	
	ADD r4, r4, int_size
	ADD r5, r5, d*int_size
	ADD r3, r3, 1
	B PSR_condition4
	PSR_exit4:
//------------------------------------------	
	MOV r0, d*4
	MUL r4, r1, r0
	ADD r4, r4, r2
	STR r9, [r10, r4]       // Store a result to W
	
	ADD r2, r2, int_size
	B PSR_condition3
	PSR_exit3:
//------------------------------------------------
	ADD r1, r1, 1
	B PSR_condition2
	PSR_exit2:
//------------------------------------------------------
//------------------------------------------------------
	//LDR r10, =t
	LDR r10, =t_address
	LDR r10, [r10]
	LDR r9, =t_
	
    MOV r5, #0
    PSR_condition7:
	SUB r0, r5, q_1*int_size
	CBNZ r0, PSR_loop7
	B PSR_exit7
	PSR_loop7:              // move t to t_
	
	LDR r11, [r10, r5]
	STR r11, [r9, r5]
	
	ADD r5, r5, int_size
	B PSR_condition7
	PSR_exit7:
//------------------------------------------------------ 
    LDR r2, =X_k    
	LDR r2, [r2]
	LSL r2, r2, dim_int     // r2:i with int size
	LDR r10, =W
	LDR r9, =A
	LDR r6, =u
	//LDR r7, =s
	LDR r7, =s_address
	LDR r7, [r7]
	// Do_LogTable_q3 opA, size, tmp1, tmp2
	// let element of opA be Log_address, opA is a address of an array
	Do_LogTable_q3 r7, s_num, r0, r1
	LDR r8, =ExpTable_q3
//------------------------------------------------------	
    MOV r1, #0
    PSR_condition5:
	SUB r0, r1, q_1*int_size
	CBNZ r0, PSR_loop5
	B PSR_exit5
	PSR_loop5:              //  
	
	EOR r4, r2, r1     
	//LSL r4, r4, dim_d       // r4:i'with d_int size
	MOV r0, d
	MUL r4, r0
	//LSL r3, r1, dim_d		// r3:i with d_int size
	MUL r3, r1, r0
//------------------------------------------------	
	MOV r5, #0
    PSR_condition6:
	SUB r0, r5, d*int_size
	CBNZ r0, PSR_loop6
	B PSR_exit6
	PSR_loop6:              // Compute u = W EOR (A*s)     
	
	ADD r0, r4, r5
	LDR r11, [r9, r0]       
	LDR r12, [r7, r5]
	//mult_exp_q3 opA , opB , res , table_address
	mult_exp_q3 r11 ,r12 ,r0 ,r8

	ADD r12, r3, r5
	LDR r12, [r10, r12]
	EOR r0, r12
	STR r0, [r6, r5]
	
	ADD r5, r5, int_size
	B PSR_condition6
	PSR_exit6:
//------------------------------------------------ 
	//LDR r10, =t
	LDR r10, =t_address
	LDR r10, [r10]
	LDR r9, =t_

	Vector_Add r0, r11, r12, r6, r5 // res in r5
	Small_Field r5, r5              // res in r5
	//LSR r4, r4, dim_d       // r4:i'with int size  // #only when d = 1
	EOR r4, r2, r1 
	LDR r4, [r9, r4]
	EOR r5, r5, r4
    STR	r5, [r10, r1]

	LDR r10, =W
	LDR r9, =A

	ADD r1, r1, int_size
	B PSR_condition5
	PSR_exit5:
//------------------------------------------------------
    LDR r12, =R_T           // Compute s'
	//LDR r11, =s
	LDR r11, =s_address
	LDR r11, [r11]
	Matrix_Add  r0, r1, r2, r3, r4, r12, r11 // res in r11

    BX lr
////////////////////////////////////////////////////////////
	
////////////////////////////////////////////////////////////
	ToAdditiveShares_pre:
	//PUSH {r2,r3,r4,r5,r10,r11,r12}
	
	LDR r12, =R
	LDR r7, =random_address_3
	LDR r6, [r7]
//------------------------------------------------------	
	MOV r0, #0
    TASP_condition1:
	SUB r1, r0, d*d*int_size
	CBNZ r1, TASP_loop1
	B TASP_exit1
	TASP_loop1:              // Gennerate R[d][d] in q2

	LDR r11, [r6], 4
	STR r11, [r12, r0]
	ADD r0, r0, int_size
	B TASP_condition1
	TASP_exit1:
//------------------------------------------------------
    STR r6, [r7]
	
    LDR r11, =R_T
	LDR r12, =R
	Matrix_Transpose r0, r1, r2, r3, r4, r12, r11      // R_T
	LDR r11, =R_T
	LDR r10, =Y_address
	LDR r10, [r10]
	Matrix_Add r0, r1, r2, r3, r4, r11, r10        // Y_ = sum(R_T)

	LDR r9, =w_address
	LDR r9, [r9]
	LDR r12, =R
	//LDR r12, =Rr
	Matrix_Add r0, r1, r2, r3, r4, r12, r9         // w_ = sum(R)

	//POP {r2,r3,r4,r5,r10,r11,r12}	
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
    ToAdditiveShares_online:

	LDR r12, =X_address
	LDR r12, [r12]
	MOV r4, #1         
	//LSL r4, dim_d_int 
	MOV r0, d*4
	MUL r4, r0
	LDR r8, [r12, r4]   // X's last element
	//LSL r9, r8, dim_d_int 
	MUL r9, r8, r0
	LDR r11, =A
	ADD r11, r9
	LDR r10, =y
    //LDR r9, =s
	LDR r9, =s_address
	LDR r9, [r9]
	
	LDR r12, =w_address
	LDR r12, [r12]
	LDR r3, =ExpTable_q3
	MOV r5, #0

	LastShare_CandS r12, r11, r10, r9, r8, r5, r4, r0, r1, r2, r3
	
	BX lr
////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////
    ToAdditiveShares_online_old:
	//PUSH {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12}

	//LDR r12, =X
	LDR r12, =X_address
	LDR r12, [r12]
	MOV r4, #1     
	LDR r8, [r12, r4]   // X's last element
	LDR r11, =A
	ADD r11, r9
	LDR r10, =y
    //LDR r9, =s
	LDR r9, =s_address
	LDR r9, [r9]
	// Do_LogTable_q3 opA, size, tmp1, tmp2
	// let element of opA be Log_address, opA is a address of an array
	Do_LogTable_q3 r9, s_num, r0, r1
	LDR r12, =w_address
	LDR r12, [r12]
	LDR r2, =ExpTable_q3
	MOV r5, #0
//------------------------------------------------------
    // r12=w, r11=A's i th row, r10=y, r9=s, r8=X's last(*), r5=cul=0, r4=2^dim_d_int
	MOV r1, #0
    TASO_condition1:
	SUB r0, r1, d*int_size
	CBNZ r0, TASO_loop1
	B TASO_exit1
	TASO_loop1:              // Compute Y's d+1 th element

	LDR r6, [r11, r1]
	LDR r7, [r9, r1]
	//mult_exp_q3 opA , opB , res , table_address
	mult_exp_q3 r6 ,r7 ,r0 ,r2     //res in r0
	Small_Field r0, r0             //res in r0
	EOR r5, r0
	LDR r0, [r12, r1]
	EOR r5, r0
	
	ADD r1, r1, int_size
	B TASO_condition1
	TASO_exit1:
//------------------------------------------------------
    LSL r8, dim_int
	//LDR r12, =t
	LDR r12, =t_address
	LDR r12, [r12]
	LDR r12, [r12, r8]    // r12 = t[i]
	EOR r5, r12
	
	//LDR r10, =Y
	LDR r10, =Y_address
	LDR r10, [r10]
	STR r5, [r10, r4]     // r4 = d*int

	BX lr
////////////////////////////////////////////////////////////
	
.end