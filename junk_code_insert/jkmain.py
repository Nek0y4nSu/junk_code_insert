import random
import sys
from core import disasm
from core import junk_code


INSERT_COUNT = 20

def read_file_lines(file_path):
    try:
        fo = open(file_path,'r')
    except BaseException as e:
        return False
    content_list = fo.readlines()
    fo.close()
    return content_list

def write_file_lines(file_path,content_list):
    try:
        fo = open(file_path,'w')
    except BaseException as e:
        print(str(e))
        return False
    fo.writelines(content_list)
    fo.close()
    return True

def random_line_pos(b):
    a = 1
    return random.randint(a,b-1)

def Insert_junk_code_rand(asm_list,insert_count):

    for i in range(0,insert_count):
        #每次插入后推，随机行也后推
        cur_pos = random_line_pos(len(asm_list))
        print("[+] Count %d ,Pos: %d" % (i,cur_pos))
        asm_list.insert(cur_pos,junk_code.rand_junk_code())

    return asm_list

def Insert_junk_code(asm_list,insert_count):
    new_asm_list = []
    for x in range(0,10):
        new_asm_list.append(junk_code.rand_junk_code())

    for i in range(0,len(asm_list)):
        new_asm_list.append(asm_list[i])
        if i%2 == 0:
            new_asm_list.append(junk_code.rand_junk_code())
        else:
            continue

    return new_asm_list

def bin_to_asm_list(buf):
    ins_list = disasm.disasm(buf)
    disasm.add_code_cf_lable(ins_list)
    asm_code="\n".join([i.lable+": "+i.mnemonic+" "+i.op_str for i in ins_list])
    asm_list = asm_code.split('\n')
    for n in range(0,len(asm_list)):
        asm_list[n] = asm_list[n] + "\n"

    return asm_list


def main(shellcode_buf):
    print("[!]Convert bin to asm list...")
    asm_list = bin_to_asm_list(shellcode_buf)
    print("[!]Line num: %d" % len(asm_list))
    print("[+]Start insert code...")
    finished_code_list = Insert_junk_code_rand(asm_list,INSERT_COUNT)
    final_asm_code = ''.join([i for i in finished_code_list])
    print(final_asm_code)
    print("[*]Compile asm code...")
    hex_arr = disasm.assemble(final_asm_code)
    #print("[*]Compile ok. Length: %s" % (len(hex_arr)))
    print("unsigned char buf[]="+str(hex_arr).replace("\'","").replace("[","{").replace("]","}")+";")



if __name__ == "__main__":
    bin_path = input("Input file path(eg. reverse_tcp.bin):")
    i_c = input("Inser count(eg.  20):")
    INSERT_COUNT = int(i_c)
    try:
        fo = open(bin_path,"rb")
        sc_buf = fo.read()
        fo.close()
    except  BaseException as e:
        print(e)

    main(sc_buf)


    
        
    
    