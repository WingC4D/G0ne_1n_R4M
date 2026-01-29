#pragma once
#include <iostream>
#include <Windows.h>

#ifdef _M_X64
#define hUINT unsigned long long
#define TRAMPOLINE_SIZE = 0x0D
#elifdef _M_IX86
	#define hUINT unsigned long
	
#endif
enum Register : BYTE
{
	ax = 0b000,
	bx = 0b001,
	cx = 0b010,
	dx = 0b011,
	sp = 0b100,
	bp = 0b101,
	si = 0b110,
	di = 0b111

};

class LDE
{
public:

	BYTE getGreaterFullInstLen
	(
		_In_ LPVOID lpCodeBuffer
	);

	LPVOID lpFunctionCodeAddress = nullptr;

private:
	enum error_codes : BYTE
	{
		success,
		no_input,
		wrong_input,
		reached_end_of_function,
		opcode_overflow,
		instruction_overflow
	};

	error_codes ecStatus = success;

	enum fb_traits : BYTE
	{
		none = 0x00,
		has_mod_rm = 0x01,
		special = 0x02,
		imm_control = 0x04,
		prefix = 0x08,
		imm_one_byte = 0x10,
		imm_two_bytes = 0x20,
		imm_four_bytes = 0x40,
		imm_eight_bytes = 0x80
	};

	BYTE	curr_instruction_ctx = NULL,
			contexts_arr[TRAMPOLINE_SIZE + 1] = { NULL };

	inline BOOLEAN is_curr_ctx_bREX_w();

	inline BOOLEAN is_RIP_relative();

	inline BYTE	get_curr_ctx_inst_len();

	inline BYTE	get_curr_opcode_len();

	inline BYTE	get_index_ctx_inst_len
	(
		_In_ BYTE cbIndex
	);

	inline BYTE	get_index_opcode_len
	(
		_In_ BYTE cbIndex
	);

	void log_2
	(
		_In_ BYTE cbInstructionCounter
	);

	void   log_1
	(
		_In_ LPBYTE lpReferenceAddress
	);

	inline void increment_opcode_len();

	inline void increment_inst_len();

	inline void	reset_curr_ctx();

	inline void	set_curr_ctx_bRex_w();

	inline void set_curr_ctx_bRIP_relative();

	inline void	set_curr_inst_len
	(
		_In_ BYTE cbInstructionLength
	);

	inline void	set_curr_opcode_len
	(
		_In_ BYTE cbOpcodeLength
	);

	BYTE	analyse_special_group
	(
		_In_ LPBYTE lpCandidate
	);

	inline BYTE	get_instruction_length
	(
		_In_ LPVOID lpCodeBuffer
	);

	BYTE analyse_mod_rm
	(
		_In_ LPBYTE lpCandidate
	);

	BYTE analyse_group3_mod_rm
	(
		_In_ LPBYTE lpCandidate
	);
	BYTE analyse_reg_size_0xF7
	(
		_In_ LPBYTE lpCandidate
	);

	inline BOOLEAN analyse_sib_base
	(
		_In_ BYTE cbCandidate
	);

	LPBYTE analyse_last_valid_instruction
	(
		_In_ BYTE cbLastValidIndex,
		_In_ BYTE cbAccumulatedLength
	);

	WORD analyse_opcode_type
	(
		_In_ LPBYTE  cbOpcode
	);

	enum inst_types : WORD
	{
		inc = 0x0000,
		dec = 0x0001,
		mov = 0x0002,
		call = 0x0003,
		jump = 0x0004,
		pop = 0x0005,
		push = 0x0006,
		lea = 0x0007,
		add = 0x0008,
		sub = 0x0009,
		mul = 0x000A,
		imul = 0x000B,
		div = 0x000C,
		idiv = 0x000D,
		ret = 0x000E,
		exchange = 0x000F,
		loop = 0x0010,
		returns = 0x0100,
		_short = 0x0200,
		_near = 0x0400,
		_far = 0x0800,
		_sys = 0x1000,
		sys_exit = 0x1100,
		sys_enter = 0x1200,
		sys_call = 0x1002,
		sys_ret = 0x1400,
		conditional = 0x2000,
		indirect = 0x3007,
		indirect_inc = 0x3001,
		indirect_dec = 0x3002,
		indirect_call = 0x3003,
		indirect_far_call = 0x3803,
		indirect_jump = 0x3004,
		indirect_far_jump = 0x3804,
		indirect_push = 0x3005,
		indirect_invalid = 0x3006,
		unknown = 0xFFFF
	};

protected:
	UCHAR results[0x100] = {
		has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm | prefix,
		has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
		has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
		has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
		prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix,
		none, none, none, none, none, none, none, none, none, none, none, none, none, none, none, none,
		none, none, prefix, has_mod_rm, prefix, prefix, prefix, prefix, imm_four_bytes, has_mod_rm | imm_eight_bytes | imm_four_bytes, imm_one_byte, has_mod_rm | imm_one_byte, none, none, none, none,
		imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte,
		has_mod_rm | imm_one_byte, has_mod_rm | imm_four_bytes, has_mod_rm | imm_one_byte, has_mod_rm | imm_one_byte, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
		none, none, none, none, none, none, none, none, none, none, none, none, none, none, none, none,
		imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, none, none, none, none, imm_one_byte, imm_eight_bytes | imm_four_bytes, none, none, none, none, none, none,
		imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes,
		has_mod_rm | imm_one_byte, has_mod_rm | imm_one_byte, imm_two_bytes, none, has_mod_rm, has_mod_rm, has_mod_rm | imm_one_byte, has_mod_rm | imm_four_bytes, imm_two_bytes | imm_one_byte, none, imm_two_bytes, none, none, imm_one_byte, none, none,
		has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
		imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, none, none, none, none, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, none, imm_one_byte, none, none, none, none,
		prefix, none, prefix, prefix, none, none, has_mod_rm | special, has_mod_rm | special, none, none, none, none, none, none, has_mod_rm, has_mod_rm
	};
};

