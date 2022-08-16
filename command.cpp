#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include "command.h"

#include <capstone/capstone.h>
using namespace std;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

int load(char *prog, long *entry, unsigned long *textsize){
    FILE *fp;
    if((fp = fopen(prog, "r")) == NULL)
        errquit("fopen");
    //read entry point
    fseek(fp, 0x18, SEEK_SET);
    fread(entry, 1, 8, fp); 
    
    //read text size
    int shnum = 0;
    fseek(fp, 0x3c, SEEK_SET);
    fread(&shnum, 1, 2, fp);

    unsigned long shoff = 0;
    fseek(fp, 0x28, SEEK_SET);
    fread(&shoff, 1, 8, fp);

    int shstrndx = 0;
    fseek(fp, 0x3e, SEEK_SET);
    fread(&shstrndx, 1, 2, fp);
    
    unsigned long shstr_header = shoff + shstrndx * 0x40;

    unsigned long shstr = 0;
    fseek(fp, shstr_header + 0x18, SEEK_SET);
    fread(&shstr, 1, 8, fp);

    unsigned long shstr_size = 0;
    fseek(fp, shstr_header + 0x20, SEEK_SET);
    fread(&shstr_size, 1, 8, fp);

    char *sec_name = (char *)malloc(shstr_size);
    fseek(fp, shstr, SEEK_SET);
    fread(sec_name, 1, shstr_size, fp);

    for(int i=0; i<shnum; i++){
        unsigned long ptr = shoff + i * 0x40;
        int nameoff = 0;
        fseek(fp, ptr, SEEK_SET);
        fread(&nameoff, 1, 4, fp);
        if(!strcmp(sec_name + nameoff, ".text\0")){
            fseek(fp, ptr + 0x20, SEEK_SET);
            fread(textsize, 1, 8, fp);
            break;
        }
    } 
    fclose(fp);
    return 0;
}

pid_t start(BP *bp, int bpn){
    //start the program and stop at the first instruction
    state = 2;
	pid_t child;	
    if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
		execlp(prog, prog, NULL);
		errquit("execvp");
	}
    else {
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        waitpid(child, &status, 0);
        fprintf(stderr, "** pid %d\n", child);
        for(int i=0; i<bpn; i++){
            breakpoint(child, bp[i].addr, NULL);
        }
    }
    return child;
}
int breakpoint(pid_t child, long long target, char *byte){
    long code = ptrace(PTRACE_PEEKTEXT, child, target, 0);
    if(code == -1){
        fprintf(stderr, "** the address 0x%llx is out of the range of the text segment\n", target);
        return -1;
    }
    if(ptrace(PTRACE_POKETEXT, child, target, (code & 0xffffffffffffff00) | 0xcc) != 0)
        errquit("ptrace(POKETEXT)");
    if(byte != NULL)
        *byte = (char)(code & 0xff);
    return 0;
}
void del(pid_t child, char *target, BP *bp){
    int a = atoi(target);
    bp[a].enable = 0;

    unsigned long long rip = bp[a].addr;
    long code = ptrace(PTRACE_PEEKTEXT, child, rip, 0);
    if((code & 0xff) == 0xcc){
        code &= 0xffffffffffffff00;
        code |= (unsigned char)bp[a].code;
        if(ptrace(PTRACE_POKETEXT, child, rip, code) != 0)
            errquit("ptrace(POKETEXT)");
    }
    return;
}

void list(BP *bp, int bpn){
    int index = 0;
    for(int i = 0; i < bpn; i++) {
        if(bp[i].enable){
            fprintf(stderr, "%d: %lx\n", index++, bp[i].addr);
        }
    }      
    return;
}

void si(pid_t child, int *stop_break, BP *bp, int bpn){
    char temp[4] = "rip";
    unsigned long long rip;
    get(child, temp, &rip);
    long code = ptrace(PTRACE_PEEKTEXT, child, rip, 0);
    if(*stop_break && ((code & 0xff) == 0xcc)){
        for(int i=0; i<bpn; i++){
            if(bp[i].addr == rip){
                code &= 0xffffffffffffff00;
                code |= (unsigned char)bp[i].code;
                if(ptrace(PTRACE_POKETEXT, child, rip, code) != 0)
                    errquit("ptrace(POKETEXT)");
                break;
            }
        }
        ptrace(PTRACE_SINGLESTEP, child, 0, 0);
        waitpid(child , &status, 0);
         breakpoint(child, rip, NULL);
    }
    else{
        ptrace(PTRACE_SINGLESTEP, child, 0, 0);
        waitpid(child , &status, 0);
    }
    
        
    return;
}

void cont(pid_t child, int *stop_break, BP *bp, int bpn){
    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child , &status, 0);
    char temp[4] = "rip";
    unsigned long long rip;
    get(child, temp, &rip);
    // long code = ptrace(PTRACE_PEEKTEXT, child, rip-1, 0);
    for(int i=0; i<bpn; i++){
        if(bp[i].addr == rip-1){
            set(child, temp, rip-1);
            *stop_break = 1;
            map<long long, instruction1>::iterator insi;
            insi = instructions.find(rip-1);
            char bytes[128] = "";
            for(int i = 0; i < insi->second.size; i++) {
                snprintf(&bytes[i*3], 4, "%2.2x ", insi->second.bytes[i]);}
            fprintf(stderr, "** breakpoint @ %12llx: %-36s%-8s\t%s\n", insi->first, bytes, insi->second.opr.c_str(), insi->second.opnd.c_str());
            break;
        }

    }
    return;
}


void vmmap(map<range_t, map_entry_t>& m){
    //print show memory layout 
    map<range_t, map_entry_t>::iterator mi;
    for(mi = m.begin(); mi != m.end(); mi++) {
        fprintf(stderr, "%016lx-%016lx ",
                mi->second.range.begin, mi->second.range.end);
        if(mi->second.perm & 0x04) 
            fprintf(stderr, "r");
        else
            fprintf(stderr,"-");
        if(mi->second.perm & 0x02)
            fprintf(stderr, "w");
        else
            fprintf(stderr,"-");
        if(mi->second.perm & 0x01) 
            fprintf(stderr, "x");
        else
            fprintf(stderr,"-");
        
        fprintf(stderr, " %-20ld\t%s\n", mi->second.offset, mi->second.name.c_str()); 
    }
    return;
}

struct user_regs_struct getregs(pid_t child){
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) {
         fprintf(stderr, "** GETREGS fail.\n");
    }
    return regs;
}

int get(pid_t child, char *reg, unsigned long long int *ret){
    GEN_GET_REG("r15\0", 8*0);
    GEN_GET_REG("r14\0", 8*1);
    GEN_GET_REG("r13\0", 8*2);
    GEN_GET_REG("r12\0", 8*3);
    GEN_GET_REG("rbp\0", 8*4);
    GEN_GET_REG("rbx\0", 8*5);
    GEN_GET_REG("r11\0", 8*6);
    GEN_GET_REG("r10\0", 8*7);
    GEN_GET_REG("r9\0",  8*8);
    GEN_GET_REG("r8\0",  8*9);
    GEN_GET_REG("rax\0", 8*10);
    GEN_GET_REG("rcx\0", 8*11);
    GEN_GET_REG("rdx\0", 8*12);
    GEN_GET_REG("rsi\0", 8*13);
    GEN_GET_REG("rdi\0", 8*14);
    GEN_GET_REG("orig_rax\0", 8*15);
    GEN_GET_REG("rip\0", 8*16);
    GEN_GET_REG("cs\0",  8*17);
    GEN_GET_REG("flags\0", 8*18);
    GEN_GET_REG("rsp\0", 8*19);
    GEN_GET_REG("ss\0",  8*20);
    GEN_GET_REG("fs_base\0", 8*21);
    GEN_GET_REG("gs_base\0", 8*22);
    GEN_GET_REG("ds\0",  8*23);
    GEN_GET_REG("es\0",  8*24);
    GEN_GET_REG("fs\0",  8*25);
    GEN_GET_REG("gs\0",  8*26);

    fprintf(stderr, "** register not exist\n");
    return -1;
}

int set(pid_t child, char *reg, long long val){
    GEN_SET_REG("r15\0", 8*0);
    GEN_SET_REG("r14\0", 8*1);
    GEN_SET_REG("r13\0", 8*2);
    GEN_SET_REG("r12\0", 8*3);
    GEN_SET_REG("rbp\0", 8*4);
    GEN_SET_REG("rbx\0", 8*5);
    GEN_SET_REG("r11\0", 8*6);
    GEN_SET_REG("r10\0", 8*7);
    GEN_SET_REG("r9\0",  8*8);
    GEN_SET_REG("r8\0",  8*9);
    GEN_SET_REG("rax\0", 8*10);
    GEN_SET_REG("rcx\0", 8*11);
    GEN_SET_REG("rdx\0", 8*12);
    GEN_SET_REG("rsi\0", 8*13);
    GEN_SET_REG("rdi\0", 8*14);
    GEN_SET_REG("orig_rax\0", 8*15);
    GEN_SET_REG("rip\0", 8*16);
    GEN_SET_REG("cs\0",  8*17);
    GEN_SET_REG("flags\0", 8*18);
    GEN_SET_REG("rsp\0", 8*19);
    GEN_SET_REG("ss\0",  8*20);
    GEN_SET_REG("fs_base\0", 8*21);
    GEN_SET_REG("gs_base\0", 8*22);
    GEN_SET_REG("ds\0",  8*23);
    GEN_SET_REG("es\0",  8*24);
    GEN_SET_REG("fs\0",  8*25);
    GEN_SET_REG("gs\0",  8*26);

    fprintf(stderr, "** register not exist\n");
    return -1;
}

void help(){
    fprintf(stderr, "- break {instruction-address}: add a break point\n"
"- cont: continue execution\n"
"- delete {break-point-id}: remove a break point\n"
"- disasm addr: disassemble instructions in a file or a memory region\n"
"- dump addr: dump memory content\n"
"- exit: terminate the debugger\n"
"- get reg: get a single value from a register\n"
"- getregs: show registers\n"
"- help: show this message\n"
"- list: list break points\n"
"- load {path/to/a/program}: load a program\n"
"- run: run the program\n"
"- vmmap: show memory layout\n"
"- set reg val: get a single value to a register\n"
"- si: step into instruction\n"
"- start: start the program and stop at the first instruction\n");
}




int disasm(pid_t proc, unsigned long long rip, unsigned long textsize){
    csh cshandle = 0;
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
        return -1;
    int count;
    char *buf = (char *)malloc(textsize);
    unsigned long long ptr = rip;
    cs_insn *insn;
    map<long long, instruction1>::iterator mi; // from memory addr to instruction

    for(ptr = rip; ptr < rip + textsize; ptr += 8) {
        long long peek;
		errno = 0;
		peek = ptrace(PTRACE_PEEKTEXT, proc, ptr, NULL);
		if(errno != 0) break;
		memcpy(buf + (ptr - rip) , &peek, 8);
    }
	if((count = cs_disasm(cshandle, (uint8_t*) buf, textsize, rip, 0, &insn)) > 0) {
		int i;
		for(i = 0; i < count; i++) {
			instruction1 in;
			in.size = insn[i].size;
			in.opr  = insn[i].mnemonic;
			in.opnd = insn[i].op_str;
            memcpy(in.bytes, insn[i].bytes, insn[i].size);
            instructions[insn[i].address] = in;
        }
        cs_free(insn, count); 
    }
    return count;
}

void dump(pid_t child, long long target){
    

    char buf[80] = "";
    long long peek;
    for(int i = 0; i < 80; i += 8){
        peek = ptrace(PTRACE_PEEKTEXT, child, target + i, 0);
        memcpy(buf + i, &peek, 8);
    }

    for(int i = 0; i < 5; i++){
        fprintf(stderr, "%12llx: ", target + 16 * i);
        for(int j = 0; j < 16; j++){
            fprintf(stderr, "%02x ", (unsigned)(unsigned char)(buf[i * 16 + j]));}
        fprintf(stderr, "|");
        for(int j = 0; j < 16; j++){
            if(isprint(buf[i * 16 + j]))
                fprintf(stderr, "%c", buf[i * 16 + j]);
            else
                fprintf(stderr, ".");
        }
        fprintf(stderr, "|\n");
    }
    return;
}




