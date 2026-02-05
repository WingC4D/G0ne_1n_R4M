#include "LDE.h"

#include "Scanner.h"


LPBYTE LDE::analyse_last_valid_instruction
(
	_In_ BYTE cbLastValidIndex,
	_In_ BYTE cbAccumulatedLength,
	_Inout_ LDE_HOOKING_STATE& state
){
	if (!state.contexts_arr[cbLastValidIndex])
	{
		state.ecStatus = wrong_input;
		return nullptr;
	}

	BYTE	  cbInstructionLength = get_index_ctx_inst_len(cbLastValidIndex, state),
			  cbOpcodeLength = get_index_opcode_len(cbLastValidIndex, state);
	LPBYTE	  lpReferenceAddress = static_cast<LPBYTE>(state.lpFuncAddr) + cbAccumulatedLength - cbInstructionLength,
			  lpDisposition = lpReferenceAddress + cbOpcodeLength;
	BYTE	  cbRVA = cbInstructionLength;
	WORD	  wInstructionType = analyse_opcode_type(lpReferenceAddress, state),
			  wRVA = cbInstructionLength;
	DWORD	  dwRVA = cbInstructionLength;
	ULONGLONG ullRVA = cbInstructionLength;

	switch (wInstructionType)
	{
	case returns:
	case returns | _short:
	case returns | _near:
	case returns | _far:
	case returns | _near | _far:
	case returns | _short | _near:
	case returns | _far | _short:
	case returns | _near | _short | _far:
		std::cout << std::format("found a return: {:#x}", static_cast<unsigned long long>(*lpReferenceAddress));
		state.ecStatus = reached_end_of_function;
		return lpReferenceAddress;

	case jump:
	case call:
		switch (cbOpcodeLength)
		{
		case 2:
			if (*(lpReferenceAddress - 1) != 0x66)
				dwRVA += *reinterpret_cast<LPDWORD>(lpDisposition);
			else
				dwRVA += static_cast<DWORD>(*reinterpret_cast<LPWORD>(lpDisposition));
			break;

		case 3:
			if (*(lpReferenceAddress - 1) != 0x66 && *(lpReferenceAddress - 2) != 0x66)
				dwRVA += *reinterpret_cast<LPDWORD>(lpDisposition);
			else
				dwRVA += static_cast<DWORD>(*reinterpret_cast<LPWORD>(lpDisposition));
			break;

		default:
			dwRVA += *reinterpret_cast<LPDWORD>(lpDisposition);
			break;
		}
		return lpReferenceAddress + dwRVA;

	case indirect_call:
	case indirect_far_call:
	case indirect_jump:
		std::cout << "[i] Found an indirect JMP!\n";

	case indirect_far_jump:
		//set_curr_ctx_bRIP_relative();
		switch (cbInstructionLength - cbOpcodeLength)
		{
		case 1:
			cbRVA += *lpDisposition;
			std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + cbRVA));
			return reinterpret_cast<LPBYTE>(*reinterpret_cast<PULONGLONG>(lpReferenceAddress + cbRVA));

		case 2:
			wRVA += *reinterpret_cast<PWORD>(lpDisposition);
			std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + wRVA));
			return reinterpret_cast<LPBYTE>(*reinterpret_cast<PULONGLONG>(lpReferenceAddress + wRVA));

		case 4:
			dwRVA += *reinterpret_cast<PDWORD>(lpDisposition);
			std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + dwRVA));
			return reinterpret_cast<LPBYTE>(*reinterpret_cast<PULONGLONG>(lpReferenceAddress + dwRVA));

		case 8:
			ullRVA += *reinterpret_cast<PULONGLONG>(lpDisposition);
			std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + ullRVA));
			return reinterpret_cast<LPBYTE>(*reinterpret_cast<PULONGLONG>(lpReferenceAddress + ullRVA));

		default:
			state.ecStatus = wrong_input;
			return nullptr;
		}
	default:
		state.ecStatus = wrong_input;
		return nullptr;
	}
}

void LDE::log_1(LPBYTE lpReferenceAddress, _In_ const BYTE& ucCurrentInstruction_ctx)
const {
	WORD cbAccumulatedLength = lpReferenceAddress - lpFunctionCodeAddress,
		cbCurrentInstructionLength = get_curr_ctx_inst_len(ucCurrentInstruction_ctx);

	std::cout << std::format(
		"[i] Current Instruction Length:      {:#04X}\n[i] Accumulated Instructions Length: {:#06X}\n[i] Found Opcode Bytes: ",
		cbCurrentInstructionLength,
		cbAccumulatedLength,
		(uint8_t)*lpReferenceAddress
	);
	BYTE ucOpcodeLength = get_curr_opcode_len(ucCurrentInstruction_ctx);
	for (unsigned char i = 0; i < ucOpcodeLength; i++)
		std::cout << std::format("{:#X} ", *(lpReferenceAddress + i));

	if (get_curr_ctx_inst_len(ucCurrentInstruction_ctx) > ucOpcodeLength) {
		std::cout << "  |  Found Operands Bytes: ";
		for (BYTE i = ucOpcodeLength; i < cbCurrentInstructionLength; i++)
			std::cout << std::format("{:#04X} ", *(lpReferenceAddress + i));

	}
	std::cout << "\n\n";
}

void LDE::log_2(BYTE cbInstructionCounter, _In_ LDE_HOOKING_STATE& lde_state)
{
	std::cout << "[i] Held contexts: ";
	for (BYTE i = 0; i < cbInstructionCounter; i++)
		std::cout << std::format(
			"{:#4X}, ",
			lde_state.contexts_arr[i]
		);
	std::cout << "\n";
}

BYTE LDE::getGreaterFullInstLen
(
	_In_ LPVOID* lpCodeBuffer,
	_Inout_ LDE_HOOKING_STATE& lde_state
)
{
	if (!lpCodeBuffer)
	{
		lde_state.ecStatus = no_input;
		return NULL;
	}


	BYTE   cbAccumulatedLength = NULL,
		cbInstructionCounter = NULL;
	LPBYTE lpReferenceBuffer = static_cast<LPBYTE>(*lpCodeBuffer);
	lde_state.lpFuncAddr = *lpCodeBuffer;
	while (cbAccumulatedLength < TRAMPOLINE_SIZE && lde_state.ecStatus == success)
	{
		if (*lpReferenceBuffer == 0xC3)
		{
			lde_state.ecStatus = reached_end_of_function;
			break;
		}

		BYTE cbCurrentInstructionLength = get_instruction_length(lpReferenceBuffer, lde_state);

		if (!cbCurrentInstructionLength)
		{
			if (!(lpReferenceBuffer = analyse_last_valid_instruction(cbInstructionCounter - 1, cbAccumulatedLength, lde_state)))
			{
				return NULL;
			}
			lde_state.lpFuncAddr = lpReferenceBuffer;
			*lpCodeBuffer = lpReferenceBuffer;
			cbAccumulatedLength = NULL;

			for (BYTE i = 0; i < cbInstructionCounter; i++)
				lde_state.contexts_arr[i] = NULL;

			cbInstructionCounter = NULL;
			continue;
		}
		cbAccumulatedLength += cbCurrentInstructionLength;
		//log_1(lpReferenceBuffer, lde_state.curr_instruction_ctx);
		lde_state.contexts_arr[cbInstructionCounter] = lde_state.curr_instruction_ctx;
		lde_state.curr_instruction_ctx = NULL;
		cbInstructionCounter++;
		lpReferenceBuffer += cbCurrentInstructionLength;
	}
	//log_1(lpReferenceBuffer, lde_state.curr_instruction_ctx);	
	//log_2(cbInstructionCounter);
	if (lde_state.ecStatus != success && lde_state.ecStatus != reached_end_of_function)
		return NULL;

	return cbAccumulatedLength;
}

BOOLEAN LDE::find_n_fix_relocation
(
	_Inout_ LPBYTE lpGateWayTrampoline,
	_In_	LPVOID lpTargetFunction,
	_In_ LDE_HOOKING_STATE& state
) 
{
	if (!lpTargetFunction)
	{
		state.ecStatus = no_input;
		return FALSE;
	}

	BYTE  j = NULL,
		  cbAccumulatedLength = NULL,
		 *lpRipRelativeAddress = static_cast<LPBYTE>(state.lpFuncAddr),
	     *lpOldTargetAddress = nullptr;
	LONGLONG llLongDispositionLength = NULL;
	int iActualDisposition = NULL;
	for (BYTE i = NULL; i < TRAMPOLINE_SIZE; i++)
	{
		if (!state.contexts_arr[i])
			break;

		BYTE cbInstructionLength = get_index_ctx_inst_len(i, state);

		if (state.contexts_arr[i] & 0x80)
		{
			BYTE cbOpCodeLength = get_index_opcode_len(i, state);

			lpOldTargetAddress = lpRipRelativeAddress + cbInstructionLength + *reinterpret_cast<LPDWORD>(lpRipRelativeAddress + cbOpCodeLength);


			llLongDispositionLength = lpOldTargetAddress - (lpGateWayTrampoline + cbAccumulatedLength + cbInstructionLength);
			iActualDisposition		= static_cast<int>(llLongDispositionLength);
			memcpy(lpGateWayTrampoline + cbAccumulatedLength + cbOpCodeLength, &iActualDisposition, 4);

			state.rip_relative_indexes[j] = i;
			j++;
		}
		lpRipRelativeAddress += cbInstructionLength;
		cbAccumulatedLength += cbInstructionLength;
	}

	return TRUE;
}

BOOLEAN LDE::is_curr_ctx_bREX_w
(
	_In_ const LDE_HOOKING_STATE& state
)
{
	return (state.curr_instruction_ctx & 0x40) >> 6;
}

BOOLEAN LDE::is_RIP_relative
(
	_In_ const LDE_HOOKING_STATE& state
)
{
	return (state.curr_instruction_ctx & 0x80) >> 7;
}

BYTE LDE::get_curr_ctx_inst_len
(
	_In_ const BYTE& ucCurrentInstruction_ctx
)
{
	return static_cast<BYTE>(ucCurrentInstruction_ctx & 0x3C) >> 2;
}

BYTE LDE::get_curr_opcode_len
(
	const _In_ BYTE& state
)
{
	return (state & 0x03) + 1;
}

BYTE LDE::get_index_opcode_len
(
	_In_ BYTE cbIndex,
	_In_ const LDE_HOOKING_STATE& state
)
{
	return (state.contexts_arr[cbIndex] & 0x03) + 1;
}

BYTE LDE::get_index_ctx_inst_len
(
	_In_ BYTE cbIndex,
	_In_ const LDE_HOOKING_STATE& state

)
{
	return (state.contexts_arr[cbIndex] & 0x3C) >> 2;
}


void LDE::reset_curr_ctx(_Inout_ LDE_HOOKING_STATE& lde_state)
{
	lde_state.curr_instruction_ctx &= NULL;
}

void LDE::set_curr_ctx_bRex_w(_Inout_ BYTE& ucInstruction_ctx)
{
	ucInstruction_ctx |= 0x40;
}

void LDE::set_curr_ctx_bRIP_relative
(
	_Inout_ LDE_HOOKING_STATE& state
)
{
	state.curr_instruction_ctx |= 0x80;
}

void LDE::set_curr_inst_len
(
	_In_ BYTE cbInstructionLength,
	_Inout_ LDE_HOOKING_STATE& state
)
{
	if (cbInstructionLength > 15)
	{
		std::cout << std::format("[!] Error @ LDE::set_curr_inst_len, Value is greater than 0xF!\n[i] Received instruction length: {:#X}\n", (int)cbInstructionLength);
		return;
	}
	state.curr_instruction_ctx &= 0b11000011;
	state.curr_instruction_ctx |= (cbInstructionLength << 2);
}

void LDE::set_curr_opcode_len
(
	_In_ BYTE cbOpcodeLength,
	_Inout_ LDE_HOOKING_STATE& lde_state
)
{

	if (cbOpcodeLength < 4)
	{
		lde_state.curr_instruction_ctx &= 0b11111100;
		lde_state.curr_instruction_ctx |= cbOpcodeLength - 1;

	}
	else
	{
		lde_state.ecStatus = opcode_overflow;
	}
}

BYTE LDE::get_instruction_length
(
	_In_	LPVOID lpCodeBuffer,
	_Inout_ LDE_HOOKING_STATE& state
)
{
	if (!lpCodeBuffer)
	{
		state.ecStatus = no_input;
		return NULL;
	}
	if (*static_cast<LPBYTE>(lpCodeBuffer) == 0xCC)
	{
		std::cout << std::format("[!] Found Uninitialised memory @: {:#10X} Now Examining The Last instruction...\n", reinterpret_cast<unsigned long long>(lpCodeBuffer));
		return NULL;
	}
	LPBYTE  lpReferenceBuffer = static_cast<LPBYTE>(lpCodeBuffer);
	increment_inst_len(state);
	state.ecStatus = success;
	if (results[*lpReferenceBuffer] == prefix)
	{
		increment_opcode_len(state);
		set_curr_ctx_bRex_w(state.curr_instruction_ctx);
		increment_inst_len(state);
		lpReferenceBuffer++;
	}

	switch (results[*lpReferenceBuffer])
	{
		case none:
			if (*lpReferenceBuffer == 0xC3 || *lpReferenceBuffer == 0xC2)
				state.ecStatus = reached_end_of_function;
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx), state);
			break;

		case has_mod_rm:
			increment_opcode_len(state);
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_curr_ctx_inst_len(state.curr_instruction_ctx);

		case has_mod_rm | prefix:
			increment_opcode_len(state);
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + analyse_special_group(lpReferenceBuffer + 1, state), state);
			return get_curr_ctx_inst_len(state.curr_instruction_ctx);

		case has_mod_rm | special:
			increment_opcode_len(state);
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + analyse_group3_mod_rm(lpReferenceBuffer, state), state);
			return get_curr_ctx_inst_len(state.curr_instruction_ctx);

		case has_mod_rm | imm_one_byte:
			increment_opcode_len(state);
			set_curr_inst_len(1 + get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_curr_ctx_inst_len(state.curr_instruction_ctx);

		case has_mod_rm | imm_two_bytes:
			increment_opcode_len(state);
			set_curr_inst_len(2 + get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_curr_ctx_inst_len(state.curr_instruction_ctx);


		case has_mod_rm | imm_four_bytes:
			increment_opcode_len(state);
			set_curr_inst_len(4 + get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_curr_ctx_inst_len(state.curr_instruction_ctx);

		case has_mod_rm | imm_eight_bytes:
			increment_opcode_len(state);
			set_curr_inst_len(8 + get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_curr_ctx_inst_len(state.curr_instruction_ctx);

		case has_mod_rm | imm_eight_bytes | imm_four_bytes:
			std::cout << "[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, dumbass..." << std::format("{:#x}\n", (uint8_t)*lpReferenceBuffer);
			break;

		case imm_one_byte:
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 1, state);
			break;

		case imm_two_bytes:
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 2, state);
			break;

		case imm_four_bytes | imm_eight_bytes:
			if (*lpReferenceBuffer == 0xE8 || *lpReferenceBuffer == 0xE9) {
				set_curr_ctx_bRIP_relative(state);
				switch (get_curr_opcode_len(state.curr_instruction_ctx))
				{
					case 2:
						if (*(lpReferenceBuffer - 1) != 0x66) {

							set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 4, state);

						} else {

							set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 2, state);
						}
						break;
						
					case 3:
						if (*(lpReferenceBuffer - 1) != 0x66 && *(lpReferenceBuffer - 2) != 0x66) {

							set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 4, state);

						} else {

							set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 2, state);
						}
						break;

					default:
						set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 4, state);
						break;
				}

			} else if (is_curr_ctx_bREX_w(state)) {

				if (*(lpReferenceBuffer - (get_curr_opcode_len(state.curr_instruction_ctx) - 1)) & 0x08) {

					set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 8, state);
					break;
				}
			}

			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 4, state);
			break;

		case imm_four_bytes:
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 4, state);
			break;

		case imm_eight_bytes:
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 8, state);
			break;

		case prefix:
			increment_opcode_len(state);
			set_curr_ctx_bRex_w(state.curr_instruction_ctx);
			lpReferenceBuffer++;
			increment_inst_len(state);

			switch (results[*lpReferenceBuffer]) {
				case none:
					if (!is_curr_ctx_bREX_w(state))
						std::cout << std::format("[i] found a 1 byte length instruction: {:#X} @{:#X}\n", static_cast<int>(*lpReferenceBuffer), reinterpret_cast<unsigned long long>(lpCodeBuffer));
					break;


				case has_mod_rm:
					increment_opcode_len(state);
					set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
					break;

				case imm_one_byte:

					increment_inst_len(state);
					break;

				case imm_two_bytes:

					set_curr_inst_len(get_curr_ctx_inst_len(state.curr_instruction_ctx) + 2, state);
					break;

				case imm_four_bytes:
					set_curr_inst_len(get_curr_ctx_inst_len(state.curr_instruction_ctx) + 4, state);
					break;
				case imm_eight_bytes:

					set_curr_inst_len(get_curr_ctx_inst_len(state.curr_instruction_ctx) + 8, state);
					break;

				case imm_four_bytes | imm_eight_bytes:
					if (*lpReferenceBuffer == 0xE8 || *lpReferenceBuffer == 0xE9) {
						set_curr_ctx_bRIP_relative(state);
						switch (get_curr_opcode_len(state.curr_instruction_ctx)) {
							case 2:
								if (*(lpReferenceBuffer - 1) != 0x66) {
									set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 4, state);
								} else {
									set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 2, state);
								}
								break;
							case 3:
								if (*(lpReferenceBuffer - 1) != 0x66 && *(lpReferenceBuffer - 2) != 0x66)
								{
									set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 4, state);
								}
								else {
									set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 2, state);
								}
								break;
							default:
								set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 4, state);
								break;
						}

					} else if (is_curr_ctx_bREX_w(state)) {
						if (*(lpReferenceBuffer - (get_curr_opcode_len(state.curr_instruction_ctx) - 1)) & 0x08) {
							set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 8, state);
							break;
						}
					}
					set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 4, state);
					break;

				default:
					state.ecStatus = wrong_input;
					std::cout << "[?] WTH Is Going On?\n" << std::format("{:#X}\n", *lpReferenceBuffer);
					return NULL;
			}
			return get_curr_ctx_inst_len(state.curr_instruction_ctx);

		default:
			state.ecStatus = wrong_input;
			std::cout << "[?] WTH Is Going On?\n";
			return NULL;

	}
	return get_curr_ctx_inst_len(state.curr_instruction_ctx);
}

BYTE LDE::analyse_group3_mod_rm
(
	_In_	LPBYTE lpCandidate,
	_Inout_ LDE_HOOKING_STATE& state
)
{
	if (!*lpCandidate)
	{
		state.ecStatus = no_input;
		return NULL;
	}

	BYTE ucReg				 = *(lpCandidate + 1) & 0x38,
		 ucRM				 = *(lpCandidate + 1) & 0x07,
		 ucMod				 = *(lpCandidate + 1) & 0xC0,
		 uc_added_opcode_len = NULL,
		 uc_added_imm_len	 = NULL;

	switch (*lpCandidate)
	{
		case 0xF6:
			switch (ucMod)
			{
				case 0xC0:
					if (0x10 > ucReg) {
						uc_added_imm_len++;
					}
					break;

				case 0x80:
					uc_added_imm_len++;
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len += 4;
					}

					if (0x10 > ucReg) {
						uc_added_imm_len++;
					}

					break;

				case 0x40:
					uc_added_imm_len++;
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
					}

					if (0x10 > ucReg) {
						uc_added_imm_len++;
					}

					break;

				default:
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
						if (analyse_sib_base(*(lpCandidate + 2))) {
							uc_added_imm_len += 4;
						}

						break;
					}
					if (ucRM == 5) {
						set_curr_ctx_bRIP_relative(state);
						uc_added_opcode_len++;
					}
					break;
			}
			break;

		case 0xF7:
			switch (ucMod) {
				case 0xC0:
					if (0x10 > ucReg) {
						uc_added_imm_len++;
					}
					break;

				case 0x80:
					uc_added_imm_len += 4;
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
						if (analyse_sib_base(*(lpCandidate + 2))) {
							uc_added_imm_len += 4;
						}
					}

					if (0x10 > ucReg) {
						uc_added_imm_len += analyse_reg_size_0xF7(lpCandidate, state);
					}
					break;

				case 0x40:
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
						break;
					}

					if (0x10 > ucReg) {
						uc_added_imm_len += analyse_reg_size_0xF7(lpCandidate, state);
					}
					break;

				default:
					if (!ucReg) {
						uc_added_imm_len += 4;
					}
					break;
			}
			break;

		default:
			state.ecStatus = wrong_input;
			return NULL;
	}
	return uc_added_opcode_len + uc_added_imm_len;
}


BYTE LDE::analyse_reg_size_0xF7
(
	_In_	   LPBYTE lpCandidate,
	_In_ const LDE_HOOKING_STATE& state
)
{
	switch (get_curr_opcode_len(state.curr_instruction_ctx)) {
		case 2:
			if (*(lpCandidate - 1) != 0x66) {
				return 4;
			}
			return 2;

		case 3:
			if (*(lpCandidate - 1) != 0x66 && *(lpCandidate - 2) != 0x66) {
				return 4;
			}
			return 2;
		default:
			std::cout << "[x] Something want wrong.\n";
			return NULL;
	}
}
BYTE LDE::analyse_special_group
(
	_In_ LPBYTE lpCandidate,
	_Inout_ LDE_HOOKING_STATE& state
)
{
	if (!lpCandidate)
	{
		state.ecStatus = no_input;
		return NULL;
	}
	state.ecStatus = success;
	
	switch (*lpCandidate)
	{
	case 0x05:
	case 0x07:
	case 0x34:
	case 0x35:
	case 0x77:
	case 0x31:
	case 0xA2:
	case 0x30:
	case 0x32:
	case 0x06:
	case 0x08:
	case 0x09:
	case 0x0B:
		return NULL;

	case 0xBA:
	case 0x3A:
		increment_opcode_len(state);
		return 2 + analyse_mod_rm(lpCandidate + 1, state);

	case 0x38:
		increment_opcode_len(state);
		return 1 + analyse_mod_rm(lpCandidate + 1, state);
	default:

		if ((*lpCandidate & 0xF0) == 0x80) {
			return 4;
		}
		if (get_curr_opcode_len(state.curr_instruction_ctx) < 4) {
			increment_opcode_len(state);
		}
		return 1 + analyse_mod_rm(lpCandidate + 1, state);
	}
}


BYTE LDE::analyse_mod_rm
(
	_In_	LPBYTE lpCandidate,
	_Inout_ LDE_HOOKING_STATE& state
)
{

	BYTE cbRM = *lpCandidate & 0b00000111,
		 cbReg = *lpCandidate & 0b00111000,
		 cbMod = *lpCandidate & 0b11000000,
		 cb_added_opcode_len = 0;
	state.ecStatus = success;
	if (!lpCandidate) {
		state.ecStatus = no_input;
		return NULL;
	}

	switch (cbMod) {
		case 0xC0:
			break;

		case 0x80:
			cb_added_opcode_len += 4;
			if (cbRM == 4) {
				cb_added_opcode_len++;
				if (get_curr_opcode_len(state.curr_instruction_ctx) < 4) increment_opcode_len(state);
				break;
			}
			if (cbReg < 0x10) {
				cb_added_opcode_len++;
			}
			break;

		case 0x40:
			cb_added_opcode_len++;
			if (cbRM == 4) {
				increment_opcode_len(state);
				cb_added_opcode_len++;
			}
			break;

		default:
			if (cbRM == 4) {
				cb_added_opcode_len++;
				if (get_curr_opcode_len(state.curr_instruction_ctx) < 4)
					increment_opcode_len(state);
				if (analyse_sib_base(*(lpCandidate + 1)))
					cb_added_opcode_len += 4;
				break;
			}

			if (cbRM == 5) {
				set_curr_ctx_bRIP_relative(state);
				cb_added_opcode_len += 4;
				break;
			}

			break;
	}
	return cb_added_opcode_len;
}
void LDE::increment_inst_len
(
	_Inout_ LDE_HOOKING_STATE& state
)
{
	if ((state.curr_instruction_ctx & 0x3C) < 0x3C)
	{
		BYTE cb_new_inst_len = static_cast<BYTE>((get_curr_ctx_inst_len(state.curr_instruction_ctx) + 1) << 2);
		state.curr_instruction_ctx &= 0xC3;
		state.curr_instruction_ctx |= cb_new_inst_len;
	}
	else
		state.ecStatus = instruction_overflow;
}

void LDE::increment_opcode_len(LDE_HOOKING_STATE& state)
{

	if ((state.curr_instruction_ctx & 0x03) < 3)
	{
		BYTE cb_new_opcode_len = (state.curr_instruction_ctx & 0x03) + 1;
		state.curr_instruction_ctx &= 0b11111100;
		state.curr_instruction_ctx |= cb_new_opcode_len;
	}
	else
		state.ecStatus = opcode_overflow;
}

BOOLEAN LDE::analyse_sib_base
(
	_In_ BYTE cbCandidate
)
{
	return (cbCandidate & 7) == 5;
}

WORD LDE::analyse_opcode_type
(
	_In_ LPBYTE lpCandidate_addr,
	_Inout_ LDE_HOOKING_STATE& state
)
{

	switch (*lpCandidate_addr) {
		case 0xE8:
			set_curr_ctx_bRIP_relative(state);
			return call;

		case 0xE9:
		case 0xEB:
			set_curr_ctx_bRIP_relative(state);
			return jump;

		case 0xFF:
			switch ((*(lpCandidate_addr + 1) & 0b00111000) >> 3) {
				case 0:
					return indirect_inc;
				case 1:
					return indirect_dec;
				case 2:
					return indirect_call;
				case 3:
					return indirect_far_call;
				case 4:
					return indirect_jump;
				case 5:
					return indirect_far_jump;
				case 6:
					return indirect_push;
				default:
					return unknown;
			}

		default:
			if ((*lpCandidate_addr & 0x70) == 0x70 || (*lpCandidate_addr & 0xFC) == 0xE0) {
				return conditional | _short | jump;
			}
			if ((*lpCandidate_addr & 0x80) == 0x80) {
				return conditional | _near | jump;
			}
			return unknown;
	}
}
