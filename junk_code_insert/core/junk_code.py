import random
junk_code_list = [
'  nop\n',
'  inc eax\n dec eax\n',
'  add edx,1\n dec edx\n',
'  xchg eax,eax\n',
'  xchg ebx,ebx\n',
'  xchg edx,edx\n',
'  xchg ecx,ecx\n',
]

def rand_junk_code():
    n = len(junk_code_list)
    index = random.randint(0,n-1)
    return junk_code_list[index]

