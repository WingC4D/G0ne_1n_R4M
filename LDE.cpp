#include "LDE.h"

LPBYTE LDE::analyse_last_valid_instruction
(
	_In_ BYTE cbLastValidIndex,
	_In_ BYTE cbAccumulatedLength
)
{
	if (!contexts_arr[cbLastValidIndex])
	{
		ecStatus = wrong_input;
		return nullptr;
	}

	BYTE	  cbInstructionLength = get_index_ctx_inst_len(cbLastValidIndex),
		cbOpcodeLength = get_index_opcode_len(cbLastValidIndex);
	LPBYTE	  lpReferenceAddress = static_cast<LPBYTE>(lpFunctionCodeAddress) + cbAccumulatedLength - cbInstructionLength,
		lpDisposition = lpReferenceAddress + cbOpcodeLength;
	BYTE
		cbRVA = cbInstructionLength;
	WORD	  wInstructionType = analyse_opcode_type(lpReferenceAddress),
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
		std::cout << std::format("found a return: {:#x}", (int)*lpReferenceAddress);
		ecStatus = reached_end_of_function;
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
		set_curr_ctx_bRIP_relative();
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
			ecStatus = wrong_input;
			return nullptr;
		}
	default:
		ecStatus = wrong_input;
		return nullptr;
	}
}

void LDE::log_1(LPBYTE lpReferenceAddress)
{
	WORD cbAccumulatedLength = lpReferenceAddress - lpFunctionCodeAddress,
		cbCurrentInstructionLength = get_curr_ctx_inst_len();

	std::cout << std::format(
		"[i] Current Instruction Length:      {:#04X}\n[i] Accumulated Instructions Length: {:#06X}\n[i] Found Opcode Bytes: ",
		cbCurrentInstructionLength,
		cbAccumulatedLength,
		(uint8_t)*lpReferenceAddress
	);
	BYTE ucOpcodeLength = get_curr_opcode_len();
	for (unsigned char i = 0; i < ucOpcodeLength; i++)
		std::cout << std::format("{:#X} ", *(lpReferenceAddress + i));

	if (get_curr_ctx_inst_len() > ucOpcodeLength) {
		std::cout << "  |  Found Operands Bytes: ";
		for (BYTE i = ucOpcodeLength; i < cbCurrentInstructionLength; i++)
			std::cout << std::format("{:#04X} ", *(lpReferenceAddress + i));

	}
	std::cout << "\n\n";
}

void LDE::log_2(BYTE cbInstructionCounter)
{
	std::cout << "[i] Held contexts: ";
	for (BYTE i = 0; i < cbInstructionCounter; i++)
		std::cout << std::format(
			"{:#4X}, ",
			contexts_arr[i]
		);
	std::cout << "\n";
}

BYTE LDE::getGreaterFullInstLen
(
	_In_ LPVOID lpCodeBuffer
)
{
	if (!lpCodeBuffer)
	{
		ecStatus = no_input;
		return NULL;
	}

	lpFunctionCodeAddress = lpCodeBuffer;
	WORD   cbAccumulatedLength = NULL;
	BYTE   cbInstructionCounter = NULL;
	LPBYTE lpReferenceBuffer = static_cast<LPBYTE>(lpCodeBuffer);

	while (cbAccumulatedLength < TRAMPOLINE_SIZE && ecStatus == success)
	{
		if (*lpReferenceBuffer == 0xC3)
		{
			ecStatus = reached_end_of_function;
			break;
		}
		BYTE cbCurrentInstructionLength = get_instruction_length(lpReferenceBuffer);

		if (!cbCurrentInstructionLength)
		{
			if (!(lpReferenceBuffer = analyse_last_valid_instruction(cbInstructionCounter - 1, cbAccumulatedLength)))
			{
				lpFunctionCodeAddress = nullptr;
				return NULL;
			}

			lpFunctionCodeAddress = lpReferenceBuffer;
			cbAccumulatedLength = NULL;

			for (BYTE i = 0; i < cbInstructionCounter; i++)
				contexts_arr[i] = NULL;

			cbInstructionCounter = NULL;
			continue;
		}
		cbAccumulatedLength += cbCurrentInstructionLength;
		log_1(lpReferenceBuffer);
		contexts_arr[cbInstructionCounter] = curr_instruction_ctx;
		curr_instruction_ctx = NULL;
		cbInstructionCounter++;
		lpReferenceBuffer += cbCurrentInstructionLength;
	}
	log_2(cbInstructionCounter);
	if (ecStatus != success && ecStatus != reached_end_of_function)
		return NULL;

	return cbAccumulatedLength;
}

BOOLEAN LDE::is_curr_ctx_bREX_w(void)
{
	return (curr_instruction_ctx & 0x40) >> 6;
}

BOOLEAN LDE::is_RIP_relative()
{
	return (curr_instruction_ctx & 0x80) >> 7;
}

BYTE LDE::get_curr_ctx_inst_len(void)
{
	return (BYTE)(curr_instruction_ctx & 0x3C) >> 2;
}

BYTE LDE::get_curr_opcode_len(void)
{

	return (curr_instruction_ctx & 0x03) + 1;
}

BYTE LDE::get_index_opcode_len
(
	_In_ BYTE cbIndex
)
{
	return (contexts_arr[cbIndex] & 3) + 1;
}

BYTE LDE::get_index_ctx_inst_len
(
	_In_ BYTE cbIndex
)
{
	return (contexts_arr[cbIndex] & 0x3C) >> 2;
}


void LDE::reset_curr_ctx()
{
	curr_instruction_ctx &= NULL;
}

void LDE::set_curr_ctx_bRex_w()
{
	curr_instruction_ctx |= 0x40;
}

void LDE::set_curr_ctx_bRIP_relative
(
	_In_ void
)
{
	curr_instruction_ctx |= 0x80;
}

void LDE::set_curr_inst_len
(
	_In_ BYTE cbInstructionLength
)
{
	if (cbInstructionLength > 15)
	{
		std::cout << std::format("[!] Error @ LDE::set_curr_inst_len, Value is greater than 0xF!\n[i] Received instruction length: {:#X}\n", (int)cbInstructionLength);
		return;
	}
	curr_instruction_ctx &= 0b11000011;
	curr_instruction_ctx |= (cbInstructionLength << 2);
}

void LDE::set_curr_opcode_len
(
	_In_ BYTE cbOpcodeLength
)
{

	if (cbOpcodeLength < 4)
	{
		curr_instruction_ctx &= 0b11111100;
		curr_instruction_ctx |= cbOpcodeLength - 1;

	}
}

BYTE LDE::get_instruction_length
(
	_In_ LPVOID lpCodeBuffer
)
{
	if (!lpCodeBuffer)
	{
		ecStatus = no_input;
		return NULL;
	}
	if (*(LPBYTE)lpCodeBuffer == 0xCC)
	{
		std::cout << std::format("[!] Found Uninitialised memory @: {:#10X} Now Examining The Last instruction...\n", reinterpret_cast<unsigned long long>(lpCodeBuffer));
		return NULL;
	}

	LPBYTE  lpReferenceBuffer = static_cast<LPBYTE>(lpCodeBuffer);
	increment_inst_len();
	ecStatus = success;
	if (results[*lpReferenceBuffer] == prefix)
	{
		increment_opcode_len();
		set_curr_ctx_bRex_w();
		increment_inst_len();
		lpReferenceBuffer++;
	}

	switch (results[*lpReferenceBuffer])
	{
	case none:
		if (*lpReferenceBuffer == 0xC3 || *lpReferenceBuffer == 0xC2)
			ecStatus = reached_end_of_function;
		set_curr_inst_len(get_curr_opcode_len());
		break;

	case has_mod_rm:
		increment_opcode_len();
		set_curr_inst_len(get_curr_opcode_len() + analyse_mod_rm(lpReferenceBuffer + 1));
		return get_curr_ctx_inst_len();

	case has_mod_rm | prefix:
		increment_opcode_len();
		set_curr_inst_len(get_curr_opcode_len() +
			analyse_special_group(lpReferenceBuffer + 1));
		return get_curr_ctx_inst_len();

	case has_mod_rm | special:
		increment_opcode_len();
		set_curr_inst_len(get_curr_opcode_len() + analyse_group3_mod_rm(lpReferenceBuffer));
		return get_curr_ctx_inst_len();

	case has_mod_rm | imm_one_byte:
		increment_opcode_len();
		set_curr_inst_len(1 + get_curr_opcode_len() + analyse_mod_rm(lpReferenceBuffer + 1));
		return get_curr_ctx_inst_len();

	case has_mod_rm | imm_two_bytes:
		increment_opcode_len();
		set_curr_inst_len(2 + get_curr_opcode_len() + analyse_mod_rm(lpReferenceBuffer + 1));
		return get_curr_ctx_inst_len();


	case has_mod_rm | imm_four_bytes:
		increment_opcode_len();
		set_curr_inst_len(4 + get_curr_opcode_len() + analyse_mod_rm(lpReferenceBuffer + 1));
		return get_curr_ctx_inst_len();

	case has_mod_rm | imm_eight_bytes:
		increment_opcode_len();
		set_curr_inst_len(8 + get_curr_opcode_len() + analyse_mod_rm(lpReferenceBuffer + 1));
		return get_curr_ctx_inst_len();

	case has_mod_rm | imm_eight_bytes | imm_four_bytes:
		std::cout << "[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, dumbass..." << std::format("{:#x}\n", (uint8_t)*lpReferenceBuffer);
		break;

	case imm_one_byte:
		set_curr_inst_len(get_curr_opcode_len() + 1);
		break;

	case imm_two_bytes:
		set_curr_inst_len(get_curr_opcode_len() + 2);
		break;

	case imm_four_bytes | imm_eight_bytes:
		if (*lpReferenceBuffer == 0xE8 || *lpReferenceBuffer == 0xE9)
		{
			set_curr_ctx_bRIP_relative();
			switch (get_curr_opcode_len())
			{
			case 2:
				if (*(lpReferenceBuffer - 1) != 0x66)
					set_curr_inst_len(get_curr_opcode_len() + 4);
				else
					set_curr_inst_len(get_curr_opcode_len() + 2);
				break;
			case 3:
				if (*(lpReferenceBuffer - 1) != 0x66 && *(lpReferenceBuffer - 2) != 0x66)
					set_curr_inst_len(get_curr_opcode_len() + 4);
				else
					set_curr_inst_len(get_curr_opcode_len() + 2);
				break;
			default:
				set_curr_inst_len(get_curr_opcode_len() + 4);
				break;
			}
		}
		else if (is_curr_ctx_bREX_w())
			if (*(lpReferenceBuffer - (get_curr_opcode_len() - 1)) & 0x08)
			{
				set_curr_inst_len(get_curr_opcode_len() + 8);
				break;
			}
		set_curr_inst_len(get_curr_opcode_len() + 4);
		break;

	case imm_four_bytes:
		set_curr_inst_len(get_curr_opcode_len() + 4);
		break;
	case imm_eight_bytes:
		set_curr_inst_len(get_curr_opcode_len() + 8);
		break;

	case prefix:
		increment_opcode_len();
		set_curr_ctx_bRex_w();
		lpReferenceBuffer++;
		increment_inst_len();

		switch (results[*lpReferenceBuffer])
		{

		case none:
			if (!is_curr_ctx_bREX_w())
				std::cout << std::format("[i] found a 1 byte length instruction: {:#X} @{:#X}\n", (int)*lpReferenceBuffer, (unsigned long long) lpCodeBuffer);
			break;


		case has_mod_rm:
			increment_opcode_len();
			set_curr_inst_len(get_curr_opcode_len() + analyse_mod_rm(lpReferenceBuffer + 1));
			break;

		case imm_one_byte:

			increment_inst_len();
			break;

		case imm_two_bytes:

			set_curr_inst_len(get_curr_ctx_inst_len() + 2);
			break;

		case imm_four_bytes:
			set_curr_inst_len(get_curr_ctx_inst_len() + 4);
			break;
		case imm_eight_bytes:

			set_curr_inst_len(get_curr_ctx_inst_len() + 8);
			break;

		case imm_four_bytes | imm_eight_bytes:
			if (*lpReferenceBuffer == 0xE8 || *lpReferenceBuffer == 0xE9)
			{
				set_curr_ctx_bRIP_relative();
				switch (get_curr_opcode_len())
				{
				case 2:
					if (*(lpReferenceBuffer - 1) != 0x66)
						set_curr_inst_len(get_curr_opcode_len() + 4);
					else
						set_curr_inst_len(get_curr_opcode_len() + 2);
					break;
				case 3:
					if (*(lpReferenceBuffer - 1) != 0x66 && *(lpReferenceBuffer - 2) != 0x66)
						set_curr_inst_len(get_curr_opcode_len() + 4);
					else
						set_curr_inst_len(get_curr_opcode_len() + 2);
					break;
				default:
					set_curr_inst_len(get_curr_opcode_len() + 4);
					break;
				}
			}
			else if (is_curr_ctx_bREX_w())
				if (*(lpReferenceBuffer - (get_curr_opcode_len() - 1)) & 0x08)
				{
					set_curr_inst_len(get_curr_opcode_len() + 8);
					break;

				}
			set_curr_inst_len(get_curr_opcode_len() + 4);
			break;

		default:
			ecStatus = wrong_input;
			std::cout << "[?] WTH Is Going On?\n" << std::format("{:#X}\n", *lpReferenceBuffer);
			return NULL;
		}
		return get_curr_ctx_inst_len();
	default:
		ecStatus = wrong_input;
		std::cout << "[?] WTH Is Going On?\n";
		return NULL;

	}

	return get_curr_ctx_inst_len();
}

BYTE LDE::analyse_group3_mod_rm
(
	_In_ LPBYTE lpCandidate
)
{
	if (!*lpCandidate)
	{
		ecStatus = no_input;
		return NULL;
	}

	BYTE ucReg = *(lpCandidate + 1) & 0x38,
		 ucRM  = *(lpCandidate + 1) & 0x07,
		 ucMod = *(lpCandidate + 1) & 0xC0,
		 uc_added_opcode_len = 0,
		 uc_added_imm_len    = 0;
	switch (*lpCandidate)
	{
	case 0xF6:
		switch (ucMod)
		{
		case 0xC0:
			if (0x10 > ucReg)
				uc_added_imm_len++;
			break;

		case 0x80:
			uc_added_imm_len++;
			if (ucRM == 4)
			{
				increment_opcode_len();
				uc_added_opcode_len += 4;

			}
			if (0x10 > ucReg)
				uc_added_imm_len++;
			break;

		case 0x40:
			uc_added_imm_len++;
			if (ucRM == 4)
			{
				increment_opcode_len();
				uc_added_opcode_len++;

			}
			if (0x10 > ucReg)
				uc_added_imm_len++;
			break;

		default:
			if (ucRM == 4)
			{
				increment_opcode_len();
				uc_added_opcode_len++;
				if (analyse_sib_base(*(lpCandidate + 2)))
				{
					uc_added_imm_len += 4;
				}
				break;
			}
			if (ucRM == 5)
			{
				set_curr_ctx_bRIP_relative();
				uc_added_opcode_len++;
			}
			break;
		}
		break;

	case 0xF7:
		switch (ucMod)
		{
		case 0xC0:
			if (0x10 > ucReg)
				uc_added_imm_len++;
			break;
		case 0x80:
			uc_added_imm_len += 4;
			if (ucRM == 4)
			{
				increment_opcode_len();
				uc_added_opcode_len++;
				if (analyse_sib_base(*(lpCandidate + 2)))
					uc_added_imm_len += 4;

			}
			if (0x10 > ucReg)
				uc_added_imm_len += analyse_reg_size_0xF7(lpCandidate);
			break;
		case 0x40:

			if (ucRM == 4)
			{
				increment_opcode_len();
				uc_added_opcode_len++;
				break;
			}
			if (0x10 > ucReg)
				uc_added_imm_len += analyse_reg_size_0xF7(lpCandidate);
			break;
		default:
			if (!ucReg)
				uc_added_imm_len += 4;

			break;
		}
		break;

	default:
		ecStatus = wrong_input;
		return NULL;
	}
	return uc_added_opcode_len + uc_added_imm_len;
}


BYTE LDE::analyse_reg_size_0xF7
(
	_In_ LPBYTE lpCandidate
)
{
	switch (get_curr_opcode_len())
	{
	case 2:
		if (*(lpCandidate - 1) != 0x66)
			return 4;
		return 2;

	case 3:
		if (*(lpCandidate - 1) != 0x66 && *(lpCandidate - 2) != 0x66)
			return 4;
		return 2;
	default:
		std::cout << "[x] Something want wrong.\n";
		return NULL;
	}
}
BYTE LDE::analyse_special_group
(
	_In_ LPBYTE lpCandidate
)
{
	if (!lpCandidate)
	{
		ecStatus = no_input;
		return NULL;
	}

	ecStatus = success;

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
	case 0x3A:
	case 0xBA:
		increment_opcode_len();
		return 2 + analyse_mod_rm(lpCandidate + 1);
	case 0x38:
		increment_opcode_len();
		return 1 + analyse_mod_rm(lpCandidate + 1);
	default:

		if ((*lpCandidate & 0xF0) == 0x80)
		{
			return 4;
		}
		if (get_curr_opcode_len() < 4)
			increment_opcode_len();
		return 1 + analyse_mod_rm(lpCandidate + 1);
	}
}


BYTE LDE::analyse_mod_rm
(
	_In_ LPBYTE lpCandidate

)
{

	BYTE uc_rm_bits   = *lpCandidate & 0x07,
		 uc_reg_bits  = *lpCandidate & 0x38,
		 uc_mod_bits  = *lpCandidate & 0xC0,
		 uc_added_len = NULL;
	ecStatus = success;
	if (!lpCandidate)
	{
		ecStatus = no_input;
		return NULL;
	}

	switch (uc_mod_bits)
	{
	case 0xC0:
		break;

	case 0x80:
		uc_added_len += 4;
		if (uc_rm_bits == 4)
		{
			uc_added_len++;
			if (get_curr_opcode_len() < 4)
				increment_opcode_len();
			break;
		}
		if (uc_reg_bits < 0x10)
			uc_added_len++;
		break;

	case 0x40:
		uc_added_len++;
		if (uc_rm_bits == 4)
		{
			increment_opcode_len();
			uc_added_len++;
			break;
		}
		break;

	default:
		if (uc_rm_bits == 4)
		{
			uc_added_len++;
			if (get_curr_opcode_len() < 4)
				increment_opcode_len();

			if (analyse_sib_base(*(lpCandidate + 1)))
			{
				uc_added_len += 4;
			}
			break;

		}
		if (uc_rm_bits == 5)
		{
			set_curr_ctx_bRIP_relative();
			uc_added_len += 4;
		}
		break;
	}
	return uc_added_len;
}

void    LDE::increment_inst_len()
{
	if ((curr_instruction_ctx & 0x3C) < 0x3C)
	{
		BYTE cb_new_inst_len  = static_cast<BYTE>((get_curr_ctx_inst_len() + 1) << 2);
		curr_instruction_ctx &= 0xC3;
		curr_instruction_ctx |= cb_new_inst_len;
	}
	else
		ecStatus = instruction_overflow;
}

void    LDE::increment_opcode_len()
{
	if ((curr_instruction_ctx & 0x03) < 3)
	{
		BYTE cb_new_opcode_len = (curr_instruction_ctx & 0x03) + 1;
		curr_instruction_ctx  &= 0b11111100;
		curr_instruction_ctx  |= cb_new_opcode_len;
	}
	else
		ecStatus = opcode_overflow;
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
	_In_ LPBYTE lpCandidate_addr
)
{

	switch (*lpCandidate_addr)
	{
	case 0xE8:
		set_curr_ctx_bRIP_relative();
		return call;

	case 0xE9:
	case 0xEB:
		set_curr_ctx_bRIP_relative();
		return jump;

	case 0xFF:
		switch ((*(lpCandidate_addr + 1) & 0b00111000) >> 3)
		{
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
		if ((*lpCandidate_addr & 0x70) == 0x70 || (*lpCandidate_addr & 0xFC) == 0xE0)
		{
			return conditional | _short | jump;
		}
		if ((*lpCandidate_addr & 0x80) == 0x80)
		{
			return conditional | _near | jump;
		}
		return unknown;
	}
}