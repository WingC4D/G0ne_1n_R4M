#include "LDE.h"
#include "Scanner.h"

LPBYTE LDE::analyse_last_valid_instruction(_In_ BYTE cbLastValidIndex, _In_ BYTE cbAccumulatedLength, _Inout_ LDE_HOOKING_STATE& state) {
	if (!state.contexts_arr[cbLastValidIndex]) {
		state.ecStatus = wrong_input;
		return nullptr;
	}
	BYTE	  cbInstructionLength = get_index_ctx_inst_len(cbLastValidIndex, state),
			  cbOpcodeLength	  = get_index_opcode_len(cbLastValidIndex, state);
	LPBYTE	  lpReferenceAddress  = static_cast<LPBYTE>(state.lpFuncAddr) + cbAccumulatedLength - cbInstructionLength,
			  lpDisposition		  = lpReferenceAddress + cbOpcodeLength;
	BYTE	  cbRVA				  = cbInstructionLength;
	WORD	  wInstructionType	  = analyse_opcode_type(lpReferenceAddress, state),
			  wRVA				  = cbInstructionLength;
	DWORD	  dwRVA				  = cbInstructionLength;
	ULONGLONG ullRVA			  = cbInstructionLength;
	switch (wInstructionType) {
		case returns :
		case returns | _short : 
		case returns | _near  :
		case returns | _far	  :
		case returns | _near  | _far   :
		case returns | _short | _near  :
		case returns | _far   | _short : 
		case returns | _near  | _short | _far: {
			state.ecStatus = reached_end_of_function;
			return lpReferenceAddress;
		}
		case jump:
		case call: {
			switch (cbOpcodeLength) {
				case SIZE_OF_WORD: {
					if (*(lpReferenceAddress - SIZE_OF_BYTE) != 0x66) {
						dwRVA += * reinterpret_cast<LPDWORD>(lpDisposition);
					} else {
						dwRVA += static_cast<DWORD>(* reinterpret_cast<LPWORD>(lpDisposition));
					}
					break;
				}
				case 3: {
					if (*(lpReferenceAddress - SIZE_OF_BYTE) != 0x66 && *(lpReferenceAddress - SIZE_OF_WORD) != 0x66) {
						dwRVA += *reinterpret_cast<LPDWORD>(lpDisposition);
					} else {
						dwRVA += static_cast<DWORD>(*reinterpret_cast<LPWORD>(lpDisposition));
					}
					break;
				}
				default: {
					dwRVA += *reinterpret_cast<LPDWORD>(lpDisposition);
					break;
				}
			}
			return lpReferenceAddress + dwRVA;
		}
		case indirect_call:
		case indirect_far_call:
		case indirect_jump:
		case indirect_far_jump: {
			switch (cbInstructionLength - cbOpcodeLength) {
				case SIZE_OF_BYTE: {
					cbRVA += *lpDisposition;
					std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + cbRVA));
					return reinterpret_cast<LPBYTE>(*reinterpret_cast<PULONGLONG>(lpReferenceAddress + cbRVA));
				}
				case SIZE_OF_WORD: {
					wRVA += *reinterpret_cast<PWORD>(lpDisposition);
					std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + wRVA));
					return reinterpret_cast<LPBYTE>(*reinterpret_cast<PULONGLONG>(lpReferenceAddress + wRVA));
				}
				case SIZE_OF_DWORD: {
					dwRVA += *reinterpret_cast<PDWORD>(lpDisposition);
					std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + dwRVA));
					return reinterpret_cast<LPBYTE>(*reinterpret_cast<PULONGLONG>(lpReferenceAddress + dwRVA));
				}
				case SIZE_OF_QWORD: {
					ullRVA += *reinterpret_cast<PULONGLONG>(lpDisposition);
					std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + ullRVA));
					return reinterpret_cast<LPBYTE>(*reinterpret_cast<PULONGLONG>(lpReferenceAddress + ullRVA));
				}
				default: {
					state.ecStatus = wrong_input;
					return nullptr;
				}
			}
		}
		default: {
			state.ecStatus = wrong_input;
			return nullptr;
		}
	}
}

void LDE::log_1(_In_ const LPBYTE lpReferenceAddress, _In_ const LDE_HOOKING_STATE& state) {
	WORD cbAccumulatedLength		= lpReferenceAddress - state.lpFuncAddr,
		 cbCurrentInstructionLength = get_context_instruction_length(state.curr_instruction_ctx);
	BYTE ucOpcodeLength = get_curr_opcode_len(state.curr_instruction_ctx);
	std::cout << std::format(
		"[i] Current Instruction Length:      {:#04X}\n[i] Accumulated Instructions Length: {:#06X}\n[i] Found Opcode Bytes: ",
		cbCurrentInstructionLength,
		cbAccumulatedLength,
		*lpReferenceAddress
	);
	for (unsigned char i = 0; i < ucOpcodeLength; i++) {
		std::cout << std::format("{:#X} ", *(lpReferenceAddress + i));
	}
	if (get_context_instruction_length(state.curr_instruction_ctx) > ucOpcodeLength) {
		std::cout << "  |  Found Operands Bytes: ";
		for (BYTE i = ucOpcodeLength; i < cbCurrentInstructionLength; i++) {
			std::cout << std::format("{:#04X} ", *(lpReferenceAddress + i));
		}
	}
	std::cout << "\n\n";
}

void LDE::log_2(BYTE cbInstructionCounter, _In_ LDE_HOOKING_STATE& lde_state) {
	std::cout << "[i] Held contexts: ";
	for (BYTE i = 0; i < cbInstructionCounter; i++) {
		std::cout << std::format("{:#4X}, ", lde_state.contexts_arr[i]);
	}
	std::cout << "\n";
}

BYTE LDE::getGreaterFullInstLen(_In_ LPVOID *lpCodeBuffer, _Inout_ LDE_HOOKING_STATE& state) {
	if (!lpCodeBuffer) {
		state.ecStatus = no_input;
		return NULL;
	}
	state.lpFuncAddr = *lpCodeBuffer;
	BYTE  cbAccumulatedLength  = NULL,
		 *lpReferenceBuffer	= static_cast<LPBYTE>(*lpCodeBuffer);
	while (cbAccumulatedLength < TRAMPOLINE_SIZE && state.ecStatus == success) {
		if (*lpReferenceBuffer == 0xC3) {
			state.ecStatus = reached_end_of_function;
			break;
		}
		BYTE cbCurrentInstructionLength = get_instruction_length(lpReferenceBuffer, state);
		if (!cbCurrentInstructionLength) {
			if (!(lpReferenceBuffer = analyse_last_valid_instruction(state.cb_count_of_instructions - 1, cbAccumulatedLength, state))) {
				return NULL;
			}
			state.lpFuncAddr	  = lpReferenceBuffer;
			*lpCodeBuffer		  = lpReferenceBuffer;
			cbAccumulatedLength	  = NULL;
			for (BYTE i = 0; i < state.cb_count_of_instructions; i++) {
				state.contexts_arr[i] = NULL;
			}
			for (BYTE i = NULL; i < state.cb_count_of_rip_indexes; i++) {
				state.rip_relative_indexes[i] = NULL;
			}
			state.cb_count_of_instructions = NULL;
			state.cb_count_of_rip_indexes  = NULL;
			continue;
		}
		if (is_RIP_relative(state)) {
			state.rip_relative_indexes[state.cb_count_of_rip_indexes] = state.cb_count_of_instructions;
			state.cb_count_of_rip_indexes++;
		}
		//log_1(lpReferenceBuffer, state);
		state.contexts_arr[state.cb_count_of_instructions] = state.curr_instruction_ctx;
		state.curr_instruction_ctx = NULL;
		state.cb_count_of_instructions++;
		cbAccumulatedLength += cbCurrentInstructionLength;
		lpReferenceBuffer += cbCurrentInstructionLength;
	}
	//log_1(lpReferenceBuffer, state);	
	//log_2(cbInstructionCounter);
	if (state.ecStatus != success && state.ecStatus != reached_end_of_function) {
		return NULL;
	}
	return cbAccumulatedLength;
}

BOOLEAN LDE::find_n_fix_relocation(_Inout_ LPBYTE lpGateWayTrampoline, _In_ LPVOID lpTargetFunction, _In_ LDE_HOOKING_STATE& state) {
	if (!lpTargetFunction) {
		state.ecStatus = no_input;
		return FALSE;
	}
	BYTE *lpRipRelativeAddress		     = static_cast<LPBYTE>(state.lpFuncAddr),
	     cb_count_of_passed_instructions = NULL,
	     uc_size_passed				     = NULL;
	for (BYTE i = NULL; i < state.cb_count_of_rip_indexes; i++) {
		for (cb_count_of_passed_instructions; cb_count_of_passed_instructions < state.rip_relative_indexes[i]; cb_count_of_passed_instructions++) {
			BYTE uc_instruction_size = get_context_instruction_length(state.contexts_arr[cb_count_of_passed_instructions]);
			uc_size_passed += uc_instruction_size;
			lpRipRelativeAddress += uc_instruction_size;
		}
		BYTE   cbInstructionLength = get_context_instruction_length(state.contexts_arr[cb_count_of_passed_instructions]),
			   cbOpCodeLength      = get_index_opcode_len(state.rip_relative_indexes[i], state),
			  *lpOldTargetAddress  = lpRipRelativeAddress +  cbInstructionLength + * reinterpret_cast<LPDWORD>(lpRipRelativeAddress + cbOpCodeLength);
		hkUINT hkiNewDisposition   = lpOldTargetAddress   - (lpGateWayTrampoline + uc_size_passed + cbInstructionLength); 
		int	   iNewDisposition	   = static_cast<int>(hkiNewDisposition);
		memcpy(lpGateWayTrampoline + uc_size_passed + cbOpCodeLength, &iNewDisposition, sizeof(DWORD));
	}
	return TRUE;
}

BOOLEAN LDE::is_curr_ctx_bREX_w(_In_ const LDE_HOOKING_STATE& state) {
	return (state.curr_instruction_ctx & 0x40) >> 6;
}

BOOLEAN LDE::is_RIP_relative (_In_ const LDE_HOOKING_STATE& state) {
	return (state.curr_instruction_ctx & 0x80) >> 7;
}

BYTE LDE::get_context_instruction_length (_In_ const BYTE& ucCurrentInstruction_ctx) {
	return static_cast<BYTE>(ucCurrentInstruction_ctx & 0x3C) >> 2;
}

BYTE LDE::get_curr_opcode_len (const _In_ BYTE& state) {
	return (state & 0x03) + 1;
}

BYTE LDE::get_index_opcode_len(_In_ const BYTE cbIndex, _In_ const LDE_HOOKING_STATE& state) {
	return (state.contexts_arr[cbIndex] & 0x03) + 1;
}

BYTE LDE::get_index_ctx_inst_len(_In_ const BYTE cbIndex, _In_ const LDE_HOOKING_STATE& state) {
	return (state.contexts_arr[cbIndex] & 0x3C) >> 2;
}

void LDE::reset_curr_ctx(_Inout_ LDE_HOOKING_STATE& lde_state) {
	lde_state.curr_instruction_ctx &= NULL;
}

void LDE::set_curr_ctx_bRex_w(_Inout_ BYTE& ucInstruction_ctx) {
	ucInstruction_ctx |= 0x40;
}

void LDE::set_curr_ctx_bRIP_relative(_Inout_ LDE_HOOKING_STATE& state) {
	state.curr_instruction_ctx |= 0x80;
}

void LDE::set_curr_inst_len(_In_ BYTE cbInstructionLength, _Inout_ LDE_HOOKING_STATE& state) {
	if (cbInstructionLength > 15) {
		std::cout << std::format("[!] Error @ LDE::set_curr_inst_len, Value is greater than 0xF!\n[i] Received instruction length: {:#X}\n", static_cast<int>(cbInstructionLength));
		return;
	}
	state.curr_instruction_ctx &= 0xC3;
	state.curr_instruction_ctx |= (cbInstructionLength << 2);
}

void LDE::set_curr_opcode_len(_In_ BYTE cbOpcodeLength, _Inout_ LDE_HOOKING_STATE& lde_state) {
	
	if (cbOpcodeLength < SIZE_OF_DWORD) {
		lde_state.curr_instruction_ctx &= 0xFC;
		lde_state.curr_instruction_ctx |= cbOpcodeLength - 1;
	} else {
		lde_state.ecStatus = opcode_overflow;
	}
	return;
}

BYTE LDE::get_instruction_length(_In_ LPVOID lpCodeBuffer, _Inout_ LDE_HOOKING_STATE& state) {
	if (!lpCodeBuffer) {
		state.ecStatus = no_input;
		return NULL;
	}
	if (*static_cast<LPBYTE>(lpCodeBuffer) == 0xCC) {
		std::cout << std::format("[!] Found Uninitialised memory @: {:#10X} Now Examining The Last instruction...\n", reinterpret_cast<DWORD64>(lpCodeBuffer));
		return NULL;
	}
	LPBYTE lpReferenceBuffer = static_cast<LPBYTE>(lpCodeBuffer);
	increment_inst_len(state);
	state.ecStatus = success;
	switch (results[*lpReferenceBuffer]) {
		case none: {
			if (*lpReferenceBuffer == 0xC3 ||
				*lpReferenceBuffer == 0xC2) {
				state.ecStatus = reached_end_of_function;
			}
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx), state);
			break;
		}
		case has_mod_rm: {
			increment_opcode_len(state);
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_context_instruction_length(state.curr_instruction_ctx);
		}
		case has_mod_rm | prefix: {
			increment_opcode_len(state);
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) +
			analyse_special_group(lpReferenceBuffer + 1, state), state);

			return get_context_instruction_length(state.curr_instruction_ctx);
		}
		case has_mod_rm | special: {
			increment_opcode_len(state);
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + analyse_group3_mod_rm(lpReferenceBuffer, state), state);
			return get_context_instruction_length(state.curr_instruction_ctx);
		}
		case has_mod_rm | imm_one_byte: {
			increment_opcode_len(state);
			set_curr_inst_len(SIZE_OF_BYTE + get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_context_instruction_length(state.curr_instruction_ctx);
		}
		case has_mod_rm | imm_two_bytes: {
			increment_opcode_len(state);
			set_curr_inst_len(SIZE_OF_WORD + get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_context_instruction_length(state.curr_instruction_ctx);
		}
		case has_mod_rm | imm_four_bytes: {
			increment_opcode_len(state);
			set_curr_inst_len(SIZE_OF_DWORD + get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_context_instruction_length(state.curr_instruction_ctx);
		}
		case has_mod_rm | imm_eight_bytes: {
			increment_opcode_len(state);
			set_curr_inst_len(SIZE_OF_QWORD + get_curr_opcode_len(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			return get_context_instruction_length(state.curr_instruction_ctx);
		}
		case has_mod_rm | imm_eight_bytes | imm_four_bytes: {
			std::cout << "[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, (Found @" << std::format("{:#x})\n",*lpReferenceBuffer);
			break;
		}
		case imm_one_byte: {
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + SIZE_OF_BYTE, state);
			break;
		}
		case imm_two_bytes: {
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + SIZE_OF_WORD, state);
			break;
		}
		case imm_four_bytes: {
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + SIZE_OF_DWORD, state);
			break;
		}
		case imm_eight_bytes: {
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + SIZE_OF_QWORD, state);
			break;
		}
		case imm_four_bytes | imm_eight_bytes: {
			if (*lpReferenceBuffer == 0xE8 || *lpReferenceBuffer == 0xE9)  {
				set_curr_ctx_bRIP_relative(state);
				switch (get_curr_opcode_len(state.curr_instruction_ctx)) {
					case 2: {
						if (*(lpReferenceBuffer - SIZE_OF_BYTE) != 0x66) {
							set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + SIZE_OF_DWORD, state);
						} else {
							set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 2, state);
						}
						break;
					}
					case 3: {
						if (*(lpReferenceBuffer - SIZE_OF_BYTE) != 0x66 && *(lpReferenceBuffer - SIZE_OF_WORD) != 0x66) {
								set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + SIZE_OF_DWORD, state);
							} else {
								set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + 2, state);
							}
						break;
					}
					default: {
						set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + SIZE_OF_DWORD, state);
						break;
					}
				}
			}
			else if (is_curr_ctx_bREX_w(state)) {
				if ( *(lpReferenceBuffer - (get_curr_opcode_len(state.curr_instruction_ctx) - SIZE_OF_BYTE)) & 0x08) {
					set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + SIZE_OF_QWORD, state);
					break;
				}
			}
			set_curr_inst_len(get_curr_opcode_len(state.curr_instruction_ctx) + SIZE_OF_DWORD, state);
			break;
		}
		case prefix: {
			increment_opcode_len(state);
			set_curr_ctx_bRex_w(state.curr_instruction_ctx);
			lpReferenceBuffer++;
			return get_instruction_length(lpReferenceBuffer, state);
		}
		default: {
			state.ecStatus = wrong_input;
			std::cout << "[?] WTH Is Going On?\n";
			return NULL;
		}
	}
	return get_context_instruction_length(state.curr_instruction_ctx);
}

BYTE LDE::analyse_group3_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ LDE_HOOKING_STATE& state) {
	if (!*lpCandidate) {
		state.ecStatus = no_input;
		return NULL;
	}
	BYTE ucReg				 = *(lpCandidate + SIZE_OF_BYTE) & 0x38,
		 ucRM				 = *(lpCandidate + SIZE_OF_BYTE) & 0x07,
		 ucMod				 = *(lpCandidate + SIZE_OF_BYTE) & 0xC0,
		 uc_added_opcode_len = NULL,
		 uc_added_imm_len	 = NULL;
	switch (*lpCandidate) {
		case 0xF6: {
			switch(ucMod) {
				case 0xC0: {
					if (0x10 > ucReg) {
						uc_added_imm_len++;
					}
					break;
				}
				case 0x80: {
					uc_added_imm_len ++;
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len += SIZE_OF_DWORD;
					}
					if (0x10 > ucReg) {
						uc_added_imm_len++;
					}
					break;
				}
				case 0x40: {
					uc_added_imm_len++;
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
					}
					if (0x10 > ucReg) {
						uc_added_imm_len++;
					}
					break;
				}
				default: {
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
						if (analyse_sib_base(*(lpCandidate + 2))) {
							uc_added_imm_len += SIZE_OF_DWORD;
						}
						break;
					}
					if (ucRM == 5) {
						set_curr_ctx_bRIP_relative(state);
						uc_added_opcode_len++;
					}
					break;
				}
			}
			break;
		}
		case 0xF7: {
			switch (ucMod) {
				case 0xC0: {
					if (0x10 > ucReg) {
						uc_added_imm_len++;
					}
					break;
				}
				case 0x80: {
					uc_added_imm_len += 4;
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
						if (analyse_sib_base(*(lpCandidate + SIZE_OF_WORD))) {
							uc_added_imm_len += SIZE_OF_DWORD;
						}
					}
					if (0x10 > ucReg) {
						uc_added_imm_len += analyse_reg_size_0xF7(lpCandidate, state);
					}
					break;
				}
				case 0x40: {
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
						break;
					}
					if (0x10 > ucReg) {
						uc_added_imm_len += analyse_reg_size_0xF7(lpCandidate, state);
					}
					break;
				}
				default: {
					if (!ucReg) {
						uc_added_imm_len += SIZE_OF_DWORD;
					}
					break;
				}
			}
			break;
		}
		default: {
			state.ecStatus = wrong_input;
			return NULL;
		}
	}
	return uc_added_opcode_len + uc_added_imm_len;
}

BYTE LDE::analyse_reg_size_0xF7(_In_ const LPBYTE lpCandidate, _In_ const LDE_HOOKING_STATE& state) {
	switch (get_curr_opcode_len(state.curr_instruction_ctx)) {
		case 2: {
			if (*(lpCandidate - SIZE_OF_BYTE) != 0x66) {
				return SIZE_OF_DWORD;
			}
			return SIZE_OF_WORD;
		}
		case 3: {
			if (*(lpCandidate - SIZE_OF_BYTE) != 0x66 && *(lpCandidate - SIZE_OF_WORD) != 0x66) {
				return SIZE_OF_DWORD;
			}
			return SIZE_OF_WORD;
		}
		default: {
			std::cout << "[x] Something went wrong.\n";
			return NULL;
		}
	}
}

BYTE LDE::analyse_special_group(_In_ LPBYTE lpCandidate, _Inout_ LDE_HOOKING_STATE& state) {
	if (!lpCandidate) {
		state.ecStatus = no_input;
		return NULL;
	}
	state.ecStatus = success;
	switch (*lpCandidate) {
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
		case 0x0B: {
			return NULL;
		}
		case 0x3A:
		case 0xBA: {
			increment_opcode_len(state);
			return SIZE_OF_WORD + analyse_mod_rm(lpCandidate + SIZE_OF_BYTE, state);
		}
		case 0x38: {
			increment_opcode_len(state);
			return SIZE_OF_BYTE + analyse_mod_rm(lpCandidate + SIZE_OF_BYTE, state);
		}
		default: {
			if ((*lpCandidate & 0xF0) == 0x80) {
				return SIZE_OF_DWORD;
			}
			if (get_curr_opcode_len(state.curr_instruction_ctx) < 4) {
				increment_opcode_len(state);
			}
			return SIZE_OF_BYTE + analyse_mod_rm(lpCandidate + SIZE_OF_BYTE, state);
		}
	}
}

BYTE LDE::analyse_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ LDE_HOOKING_STATE& state) {
	BYTE cbRM				 = *lpCandidate & 0x07,
		 cbReg				 = *lpCandidate & 0x38,
	     cbMod				 = *lpCandidate & 0xC0,
		 cb_added_opcode_len = NULL;
	state.ecStatus = success;
	if (!lpCandidate) {
		state.ecStatus = no_input;
		return NULL;
	}
	switch (cbMod) {
		case 0xC0: {
			break;
		}
		case 0x80: {
			cb_added_opcode_len += SIZE_OF_DWORD;
			if (cbRM == 4) {
				cb_added_opcode_len++;
				if (get_curr_opcode_len(state.curr_instruction_ctx) < SIZE_OF_DWORD) {
					increment_opcode_len(state);
				}
				break;
			}
			if (cbReg < 0x10) {
				cb_added_opcode_len++;
			}
			break;
		}
		case 0x40: {
			cb_added_opcode_len++;
			if (cbRM == 4) {
				increment_opcode_len(state);
				cb_added_opcode_len++;
			}
			break;
		}
		default: {
			if (cbRM == 4) {
				cb_added_opcode_len++;
				if (get_curr_opcode_len(state.curr_instruction_ctx) < 4) {
					increment_opcode_len(state);
				}
				if (analyse_sib_base(*(lpCandidate + SIZE_OF_BYTE))) {
					cb_added_opcode_len += SIZE_OF_DWORD;
				}
				break;
			}
			if (cbRM == 5) {
				set_curr_ctx_bRIP_relative(state);
				cb_added_opcode_len += SIZE_OF_DWORD;
				break;
			}
			break;
		}
	}
	return cb_added_opcode_len;
}

void LDE::increment_inst_len(_Inout_ LDE_HOOKING_STATE& state) {
	if ((state.curr_instruction_ctx & 0x3C) < 0x3C) {
		BYTE cb_new_inst_len	    = static_cast<BYTE>((get_context_instruction_length(state.curr_instruction_ctx)+ 1) << 2);
		state.curr_instruction_ctx &= 0xC3;
		state.curr_instruction_ctx |= cb_new_inst_len;
	} else {
		state.ecStatus = instruction_overflow;
	}
	return;
}

void LDE::increment_opcode_len(LDE_HOOKING_STATE&state) {
	if ((state.curr_instruction_ctx & 0x03) < 3) {
		BYTE cb_new_opcode_len = (state.curr_instruction_ctx & 0x03) + SIZE_OF_BYTE;
		state.curr_instruction_ctx &= 0xFC;
		state.curr_instruction_ctx |= cb_new_opcode_len;
	} else {
		state.ecStatus = opcode_overflow;
	}
	return;
}

BOOLEAN LDE::analyse_sib_base(_In_ BYTE cbCandidate) {
	return (cbCandidate & 0x07) == 5;
}

WORD LDE::analyse_opcode_type(_In_ LPBYTE lpCandidate_addr, _Inout_ LDE_HOOKING_STATE& state) {
	switch (*lpCandidate_addr)  {
		case 0xE8: {
			set_curr_ctx_bRIP_relative(state);
			return call;
		}
		case 0xE9:
		case 0xEB: {
			set_curr_ctx_bRIP_relative(state);
			return jump;
		}
		case 0xFF: {
			switch ((*(lpCandidate_addr + 1) & 0x38) >> 3) {
				case 0: {
					return indirect_inc;
				}
				case 1: {
					return indirect_dec;
				}
				case 2: {
					return indirect_call;
				}
				case 3: {
					return indirect_far_call;
				}
				case 4: {
					return indirect_jump;
				}
				case 5: {
					return indirect_far_jump;
				}
				case 6: {
					return indirect_push;
				}
				default: {
					return unknown;
				}
			}
		}
		default: {
			if ((*lpCandidate_addr & 0x70) == 0x70 || (*lpCandidate_addr & 0xFC) == 0xE0) {
				return conditional | _short | jump;
			}
			if ((*lpCandidate_addr & 0x80) == 0x80) {
				return conditional | _near | jump;
			}
			return unknown;
		}
	}
}