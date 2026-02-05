#I don't care about performance here (yes, I know I could've used match/case statement here, I didn't feel like it though.)
def gen_mod()->None:
    text_arr: list[str] = []
    for i in range(0x100):
        if i > 0 and i % 16 == 0:
            text_arr.append('\n')
        if i <= 0x3F:
            text_arr.append("has_mod_rm, ")
        elif i <= 0x4F:
            text_arr.append("prefix, ")
        elif i <= 0x5F:
            text_arr.append("none, ")
        elif i <= 0x6F:
            if i in [0x62, 0x64, 0x65, 0x66, 0x67]:
                text_arr.append("prefix, ")
            elif i in [0x60, 0x61, 0x6C, 0x6D, 0x6E, 0x6F]:
                text_arr.append("none, ")
            elif i == 0x63:
                text_arr.append("has_mod_rm, ")
            elif i == 0x68:
                text_arr.append("imm_four_bytes, ")
            elif i == 0x69:   
                text_arr.append("has_mod_rm | imm_eight_bytes | imm_four_bytes, ")
            elif i == 0x6A:
                text_arr.append("imm_one_byte, ")
            elif i  == 0x6B:
                text_arr.append("has_mod_rm | imm_one_byte, ")
        elif i <= 0x7F:
            text_arr.append("imm_one_byte, ")
        elif i <= 0x8F:
            if i in [0x80, 0x82, 0x83]:
                text_arr.append("has_mod_rm | imm_one_byte, ")
            elif i == 0x81:
                text_arr.append("has_mod_rm | imm_eight_bytes | imm_four_bytes, ")
            else:
                text_arr.append("has_mod_rm, ")
        elif i <= 0x9F:
            text_arr.append("none, ")
        elif i <= 0xAF:
            if i <= 0xA3:
                text_arr.append("imm_eight_bytes, ")
            elif i <= 0xA7:
                text_arr.append("none, ")
            elif i == 0xA8:
                text_arr.append("imm_one_byte, ") 
            elif i == 0xA9:
                text_arr.append("imm_eight_bytes | imm_four_bytes, ")
            elif i <= 0xAF:
                text_arr.append("none, ")
        elif i <= 0xBF:
            if i <= 0xB7:
                text_arr.append("imm_one_byte, ")
            else:
                text_arr.append("imm_eight_bytes, ")
        elif i <= 0xCF:
            if i in [0xC0, 0xC1, 0xC6]:
                text_arr.append("has_mod_rm | imm_one_byte, ")
            elif i in [0xC2, 0xCA]:
                text_arr.append("imm_two_bytes, ")
            elif i in [0xC3, 0xC9, 0xCB, 0xCC, 0xCE, 0xCF]:
                text_arr.append("none, ")
            elif i <= 0xC5: 
                text_arr.append("has_mod_rm, ")
            elif i == 0xC7:
                text_arr.append("has_mod_rm | imm_eight_bytes | imm_four_bytes, ")
            elif i == 0xC8: 
                text_arr.append("imm_two_bytes | imm_one_byte, ") 
            elif i == 0xCD:
                text_arr.append("imm_one_byte, ") 
        elif i <= 0xDF:
            text_arr.append("has_mod_rm, ")
        else:
            if i in [0xF1,0xF4, 0xF5, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,]:
                text_arr.append("none, ")
            elif i in [0xF0, 0xF2, 0xF3]: 
                text_arr.append("prefix, ")
            elif i <= 0xF7:       
                text_arr.append("has_mod_rm | special, ") 
            else:
                text_arr.append("has_mod_rm,")
    
    text: str = ''.join(text_arr).rstrip(", ")
    with open ("./traits.txt", "w") as f:
        f.write(text)
    return
    
if __name__ == "__main__":
    gen_mod()