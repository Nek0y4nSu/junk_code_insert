from capstone import *
from keystone import *
import os

my_path = os.path.split(os.path.realpath(__file__))[0]
controlflow=["jmp","jz","jnz","je","jne","call","jl","ja","loop","jecxz","jle","jge","jg","jp","jnl"]
registers=["eax","ebx","edx","ebp","esp","edi","esi"]


class instruction():
	def __init__(self):
		self.address = 0
		self.lable = ""
		self.mnemonic = ""
		self.op_str = ""
		self.size = 0

def assemble(code):
	try:
		ks = Ks(KS_ARCH_X86, KS_MODE_32)
		encoding, count = ks.asm(code)
		return [hex(i) for i in encoding]
	except KsError as e:
		print(e)
		return -1

def byteoffset2index(offset):
	temp=offset
	a=0
	for i in md.disasm(CODE, 0x0):
		temp-=len(i.bytes)
		a+=1
		if temp==0:
			return a

def build_shellcode(asm_code):
	print("unsigned char buf[]="+str(assemble(asm_code)).replace("\'","").replace("[","{").replace("]","}")+";")

def save_asm_code(asm_code):
	f = open(my_path + "/asm.txt","w")
	f.write(asm_code)
	f.close()

def disasm(bin_code):
	ins_list = []
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	for i in md.disasm(bin_code,0x00):
		ins = instruction()
		ins.address = i.address
		ins.mnemonic = i.mnemonic
		ins.op_str = i.op_str
		ins.size = i.size
		ins.lable = "LA" + str(i.address)
		ins_list.append(ins)
	
	return ins_list

def isCf_no_reg(ins):
	for r in registers:
		if ins.op_str.find(r) != -1:
			return False
		else:
			continue
	
	for cf in controlflow:
		if ins.mnemonic.find(cf) != -1:
			return True
	
	return False

def hex_str_to_int(hex_str):
	h = hex_str[hex_str.index("0x"):]
	return int(h, 16)  

def calc_change_ins(ins):
	new_ins = ins
	if ins.mnemonic == "call":
		addr = hex_str_to_int(ins.op_str)
		new_ins.op_str = "LA" + str(addr)
	else:
		addr = hex_str_to_int(ins.op_str)
		new_ins.op_str = "LA" + str(addr)
	
	return	new_ins

def add_code_cf_lable(ins_list):
	for n in range(0,len(ins_list)):
		i = ins_list[n]
		if isCf_no_reg(i):
			print("Address(DEC): %s find controlflow but no register: %s %s" % (i.address,i.mnemonic,i.op_str))
			new_ins = calc_change_ins(i)
			ins_list[n] = new_ins
		else:
			continue
		

if __name__ == "__main__":
	#ins_list = disasm(CODE)
	#change_code_cf_lable(ins_list)
	#for i in ins_list:
	#	print("LA%s: %s %s" % (i.address,i.mnemonic,i.op_str))
	
	#asm_code="\n".join([i.lable+": "+i.mnemonic+" "+i.op_str+"\nnop" for i in ins_list])
	#save_asm_code(asm_code)
	#print("unsigned char buf[]="+str(assemble(asm_code)).replace("\'","").replace("[","{").replace("]","}")+";")
	#md = Cs(CS_ARCH_X86, CS_MODE_32)
	#asm_code="\n".join(['LA'+str(i.address)+": "+i.mnemonic+" "+i.op_str+"  size:"+str(i.size) for i in md.disasm(CODE, 0x0)])
	#save_asm_code(asm_code)
	print("Disasm Core load...")
