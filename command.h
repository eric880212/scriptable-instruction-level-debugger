#include <map>
#include <sys/types.h>
#include <sys/ptrace.h>
#include "ptools.h"
#include <string.h>
#include <string>

#define NOT_LOADED 0
#define LOADED 1
#define RUNNING 2
#define GEN_GET_REG(reg_compare, offset){ \
    if(!strcmp(reg, reg_compare)){ \
        *ret = ptrace(PTRACE_PEEKUSER, child, offset, 0); \
        return 0; \
    }\
} 

#define GEN_SET_REG(reg_compare, offset){ \
    if(!strcmp(reg, reg_compare)){ \
        ptrace(PTRACE_POKEUSER, child, offset, val); \
        return 0; \
    }\
} 
typedef struct breakpoint{
   unsigned long addr;
   char code;
   int enable;
}BP;

class instruction1 {
public:
	unsigned char bytes[16];
	int size;
    std::string opr, opnd;
};

extern int state;
extern char prog[];
extern int status;
extern pid_t child;
extern std::map<long long, instruction1> instructions;

void errquit(const char *msg);
int load(char *prog, long *entry, unsigned long *textsize); //return prog exist(0) or not(-1)
pid_t start(BP *bp, int bpn); //return child process pid
void vmmap(std::map<range_t, map_entry_t>& load_map);
struct user_regs_struct getregs(pid_t child);
int get(pid_t child, char *reg, unsigned long long *ret); // return valid register(0) or not(-1) 
int  set(pid_t child, char *reg, long long val); // return valid register(0) or not(-1) 
void help();
int breakpoint(pid_t child, long long target, char *byte); // return valid register(0) or not(-1)
void list(BP *bp, int bpn);
void del(pid_t child, char *target, BP *bp);
int disasm(pid_t proc, unsigned long long rip, unsigned long textsize); //return # of instruction
void dump(pid_t child, long long target);
void si(pid_t child, int *stop_break, BP *bp, int bpn);
void cont(pid_t child, int *stop_break, BP *bp, int bpn);
