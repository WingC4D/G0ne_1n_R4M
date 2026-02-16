#pragma once
#include <iostream>
#include <Windows.h>

#include "Scanner.h"

constexpr BYTE SIZE_OF_BYTE  = 0x01,
			   SIZE_OF_WORD  = 0x02,
			   SIZE_OF_DWORD = 0x04,
			   SIZE_OF_QWORD = 0x08,
			   SIZE_OF_OWORD = 0x10;

enum Register: BYTE {
	ax, bx, cx, dx,
	sp, bp, si, di
};

enum lde_error_codes: BYTE {
	success,
	no_input,
	wrong_input,
	reached_end_of_function,
	opcode_overflow,
	prefix_overflow,
	instruction_overflow
};

typedef struct LDE_HOOKING_STATE {
	LPVOID			lpFuncAddr;
	lde_error_codes ecStatus = success;
	BYTE			curr_instruction_ctx,
					cb_count_of_instructions,
					cb_count_of_rip_indexes,
					contexts_arr[TRAMPOLINE_SIZE],
					prefix_count_arr[TRAMPOLINE_SIZE],
					rip_relative_indexes[TRAMPOLINE_SIZE];
} *LP_LDE_HOOKING_STATE;

class LDE {
public:
	BYTE get_first_valid_instructions_size_hook(_Inout_ LPVOID* lpCodeBuffer, _Inout_ LDE_HOOKING_STATE& state);

	static BOOLEAN find_n_fix_relocation(_Inout_ LPBYTE lpGateWayTrampoline, _In_ LPVOID lpTargetFunction, _In_  LDE_HOOKING_STATE& state);

private:
	enum first_byte_traits: BYTE {
		none		    = 0x00,
		has_mod_rm      = 0x01,
		special		    = 0x02,
		imm_control     = 0x04,
		prefix		    = 0x08,
		imm_one_byte    = 0x10,
		imm_two_bytes   = 0x20,
		imm_four_bytes  = 0x40,
		imm_eight_bytes = 0x80
	};
	inline static BOOLEAN analyse_sib_base(_In_ BYTE cbCandidate);

	inline static BOOLEAN is_curr_ctx_bREX_w(_In_ const LDE_HOOKING_STATE& state);

	inline static BOOLEAN is_RIP_relative(const _In_ LDE_HOOKING_STATE& state);

	inline static BYTE get_context_instruction_length(_In_ const BYTE& ucCurrentInstruction_ctx);
					   
	inline static BYTE get_curr_opcode_len(_In_ const BYTE& state);

	inline static BYTE get_index_ctx_inst_len(_In_ BYTE cbIndex, _Inout_ const LDE_HOOKING_STATE& state);

	inline static BYTE get_index_opcode_len(_In_ BYTE cbIndex, _In_ const LDE_HOOKING_STATE& state);

	inline static void increment_opcode_len(_Inout_ LDE_HOOKING_STATE& state);

	inline static void increment_inst_len(_Inout_ LDE_HOOKING_STATE& state);

	inline static void reset_curr_ctx(_Inout_ LDE_HOOKING_STATE& lde_state);

	inline static void set_curr_ctx_bRex_w(_Inout_ BYTE& ucInstruction_ctx);

	inline static void set_curr_ctx_bRIP_relative(_Inout_ LDE_HOOKING_STATE& state);

	inline static void set_curr_inst_len(_In_ BYTE cbInstructionLength, _Inout_ LDE_HOOKING_STATE& state);

	inline static void set_curr_opcode_len(_In_ BYTE cbOpcodeLength,_Inout_ LDE_HOOKING_STATE& state);

	static void log_2(_In_ BYTE cbInstructionCounter, _In_ LDE_HOOKING_STATE& lde_state);

	static void log_1(_In_ LPBYTE lpReferenceAddress, _In_ const LDE_HOOKING_STATE& state);

	static BYTE analyse_special_group(_In_ LPBYTE lpCandidate, _Inout_ LDE_HOOKING_STATE& state);

	inline BYTE	get_instruction_length(_In_ LPVOID lpCodeBuffer, _Inout_ LDE_HOOKING_STATE& state);

	static BYTE analyse_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ LDE_HOOKING_STATE& state);

	static BYTE analyse_group3_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ LDE_HOOKING_STATE& state);

	static BYTE analyse_reg_size_0xF7(_In_ LPBYTE lpCandidate, _In_ LDE_HOOKING_STATE& state);

	static WORD analyse_opcode_type(_In_ LPBYTE  lpCandidate_addr, _Inout_ LDE_HOOKING_STATE& state);

	static LPBYTE analyse_last_valid_instruction(_In_ BYTE cbLastValidIndex,_In_ BYTE cbAccumulatedLength, _Inout_ LDE_HOOKING_STATE& state);

	static BYTE get_current_prefix_count(const LDE_HOOKING_STATE& state);

	static BYTE get_index_prefix_count(LDE_HOOKING_STATE& state, const BYTE ucIndex);

	enum instruction_types: WORD {
		inc				  = 0x0000,
		dec				  = 0x0001,
		mov				  = 0x0002,
		call			  = 0x0003,
		jump			  = 0x0004,
		pop				  = 0x0005,
		push			  = 0x0006,
		lea				  = 0x0007,
		add				  = 0x0008,
		sub				  = 0x0009,
		mul				  = 0x000A,
		imul			  = 0x000B,
		div				  = 0x000C,
		idiv			  = 0x000D,
		ret				  = 0x000E,
		exchange		  = 0x000F,
		loop			  = 0x0010,
		returns			  = 0x0100,
		_short			  = 0x0200,
		_near			  = 0x0400,
		_far			  = 0x0800,
		_sys			  = 0x1000,
		sys_exit		  = 0x1100,
		sys_enter		  = 0x1200,
		sys_call		  = 0x1002,
		sys_ret			  = 0x1400,
		conditional		  = 0x2000,
		indirect		  = 0x3007,
		indirect_inc	  = 0x3001,
		indirect_dec	  = 0x3002,
		indirect_call	  = 0x3003,
		indirect_far_call = 0x3803,
		indirect_jump	  = 0x3004,
		indirect_far_jump = 0x3804,
		indirect_push	  = 0x3005,
		indirect_invalid  = 0x3006,
		unknown			  = 0xFFFF
	};

protected:
	UCHAR results[0x100] = {
/*0x00 - 0x0F*/ has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm | prefix,
/*0x10 - 0x1F*/ has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
/*0x20 - 0x2F*/ has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
/*0x30 - 0x3F*/ has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
/*0x40 - 0x4F*/ prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix,
/*0x50 - 0x5F*/ none, none, none, none, none, none, none, none, none, none, none, none, none, none, none, none,
/*0x60 - 0x6F*/ none, none, prefix, has_mod_rm, prefix, prefix, prefix, prefix, imm_four_bytes, has_mod_rm | imm_eight_bytes | imm_four_bytes, imm_one_byte, has_mod_rm | imm_one_byte, none, none, none, none,
/*0x70 - 0x7F*/ imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte,
/*0x80 - 0x8F*/ has_mod_rm | imm_one_byte, has_mod_rm | imm_four_bytes, has_mod_rm | imm_one_byte, has_mod_rm | imm_one_byte, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
/*0x90 - 0x9F*/ none, none, none, none, none, none, none, none, none, none, none, none, none, none, none, none,
/*0xA0 - 0xAF*/ imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, none, none, none, none, imm_one_byte, imm_eight_bytes | imm_four_bytes, none, none, none, none, none, none,
/*0xB0 - 0xBF*/ imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes,
/*0xC0 - 0xCF*/ has_mod_rm | imm_one_byte, has_mod_rm | imm_one_byte, imm_two_bytes, none, has_mod_rm, has_mod_rm, has_mod_rm | imm_one_byte, has_mod_rm | imm_four_bytes, imm_two_bytes | imm_one_byte, none, imm_two_bytes, none, none, imm_one_byte, none, none,
/*0xD0 - 0xDF*/ has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
/*0xE0 - 0xEF*/ imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, none, none, none, none, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, none, imm_one_byte, none, none, none, none,
/*0xF0 - 0xFF*/ prefix, none, prefix, prefix, none, none, has_mod_rm | special, has_mod_rm | special, none, none, none, none, none, none, has_mod_rm, has_mod_rm
	};
};

