#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <capstone/capstone.h>

#include "ptools.h"
#include "command.h"

#include <string>
#include <map>

using namespace std;


int state = 0;
char prog[50] = {0};
int status = 0;
map<long long, instruction1> instructions;

int main(int argc, char *argv[]) {
    map<range_t, map_entry_t> m;
    map<range_t, map_entry_t>::iterator mi;
    BP bp[100];
    int bpn = 0;
    pid_t child = 0;

    long entry = 0;
    unsigned long textsize = 0;
    int stop_break = 0;
    
    int sflag = 0;
    char ch;
    FILE *s;
    while((ch = getopt(argc, argv, "s:")) != -1){
        switch(ch){
            case 's':
                if((s = fopen(optarg, "r")) == NULL)
                    errquit("fopen");
                sflag = 1;
                break;
            case '?':
            default:
                fprintf(stderr, "** bad option: %c\n", ch);
        }
    }
    if(*(argv + optind)){
        strcpy(prog, *(argv + optind));
        load(prog, &entry, &textsize);
        fprintf(stderr, "** program '%s' loaded. entry point 0x%lx\n", prog, entry);
        state = 1;
    } 

    while(1){
        if(WIFEXITED(status) && state == RUNNING){
            //child terminated
            fprintf(stderr, "** child process %d terminiated normally (code 0)\n", child);
            state = 1;
            m.clear();
        }
        char cmd[50] = "";
        if(sflag){
            if(fgets(cmd, sizeof(cmd), s) == NULL){
                strcpy(cmd, "exit\n");
            }
        }
        else{
            fprintf(stderr, "sdb> ");
            fgets(cmd, sizeof(cmd), stdin);
        }
        char *arg[3] = {0};
        int arg_ptr = 0;
        int ptr = 0;
        int cmd_len = strlen(cmd);
        for(int i = 0; i < cmd_len; i++){
            if(cmd[i] == ' '){
                cmd[i] = '\0';
                arg[arg_ptr++] = cmd + ptr;
                ptr = i+1;
            }
            if(cmd[i] == '\n'){
                arg[arg_ptr++] = cmd + ptr;
                cmd[i] = '\0';
            }
        }

        if(!strcmp(arg[0],"load\0")){
            if(state != NOT_LOADED){
                printf("** You have loaded already\n");
                continue;
            } 
            if(arg[1] == NULL){
                fprintf(stderr,"** uasge: load [program]\n");
                continue;
            }
            strcpy(prog, arg[1]);
            if((load(prog, &entry, &textsize)) < 0)
                continue;
            else{
                fprintf(stderr, "** program '%s' loaded. entry point 0x%lx\n", prog, entry);
                state = 1;
            }
            //textsize = get_text_size(prog);
        }
        else if(!strcmp(arg[0],"start\0")){
            if(state == NOT_LOADED){
                fprintf(stderr, "** You should load a program first.\n");
                continue;
            }
            if(state == RUNNING){
                fprintf(stderr, "** Program %s is already running.\n", prog);
                continue;
            }
            child = start( bp, bpn);
            
            if(load_maps(child, m) < 0) {		
                fprintf(stderr, "** map size is 0\n");
            }
            disasm(child, entry, textsize);
        }
        else if(!strcmp(arg[0], "break\0") || !strcmp(arg[0], "b\0")){
            if(state != RUNNING){
                fprintf(stderr, "** Program is not running.\n");
                continue;
            }
            if(arg[1] == NULL){
                fprintf(stderr, "** usage: b/break [address].\n");
                continue;
            }
            long long target = 0;
            int i;
            if((arg[1][0] == '0') && (arg[1][1] == 'x'))
                i = 2; 
            else
                i = 0;
            while(arg[1][i]){
                if(*(arg[1]+i) >= '0' && arg[1][i] <= '9'){
                    target += (arg[1][i] - '0');}
                else
                    target += ((arg[1][i] - 'a') + 10);
                if(arg[1][i+1])
                    target *= 16;
                i++;
            }
            
            char byte;
            if(breakpoint(child,  target, &byte) == -1)
                continue;
            bp[bpn].addr = target;
            bp[bpn].code = byte;
            bp[bpn].enable = 1;
            bpn++;
        }
        else if(!strcmp(arg[0], "delete\0")){
            del(child, arg[1], bp);
        }
        else if(!strcmp(arg[0], "list\0") || !strcmp(arg[0],"l\0")){
            if(bpn == 0){
                fprintf(stderr, "** There isn't any breakpoint.\n");
                continue;
            }
            list(bp, bpn);
        }
        else if(!strcmp(arg[0], "si\0")){
            if(state != RUNNING){
                fprintf(stderr, "** Program is not running.\n");
                continue;
            }
            
            si(child, &stop_break, bp, bpn);
            char temp[4] = "rip";
            unsigned long long rip;
            get(child, temp,  &rip);
            for(int i = 0; i < bpn; i++){
                if(bp[i].enable && bp[i].addr == rip){
                    stop_break = 1;

                    map<long long, instruction1>::iterator insi;
                    insi = instructions.find(rip);
                    char bytes[128] = "";
                    for(int i = 0; i < insi->second.size; i++) {
                        snprintf(&bytes[i*3], 4, "%2.2x ", insi->second.bytes[i]);}
                    fprintf(stderr, "** breakpoint @ %12llx: %-36s%-8s\t%s\n", insi->first, bytes, insi->second.opr.c_str(), insi->second.opnd.c_str());

                    break;
                }
            }
        }
        else if(!strcmp(arg[0], "cont\0") || !strcmp(arg[0], "c\0")){
            if(state != RUNNING){
                fprintf(stderr, "** Program is not running.\n");
                continue;
            }
            si(child, &stop_break, bp, bpn);
            cont(child, &stop_break, bp, bpn);
        }
        else if(!strcmp(arg[0],"run\0") || !strcmp(arg[0],"r\0")){
            if(state == NOT_LOADED){
                fprintf(stderr, "** You should  load a program first.\n");
                continue;
            }
            else if(state == LOADED){
                child = start(bp, bpn);
            }
            else
                fprintf(stderr, "** program %s  is already running\n", prog);
            
            si(child, &stop_break, bp, bpn);
            cont(child, &stop_break, bp, bpn);
        }

        else if(!strcmp(arg[0],"vmmap\0")){
            if(state != RUNNING){
                fprintf(stderr, "** Program is not running.\n");
                continue;
            }
            vmmap(m);
        }
        else if(!strcmp(arg[0],"getregs\0")){
            if(state != RUNNING){
                fprintf(stderr, "** Program is not running.\n");
                continue;
            }
            struct user_regs_struct regs;
            regs = getregs(child);
            fprintf(stderr, "RAX %-15llx\tRBX %-15llx\tRCX %-15llx\tRDX %-15llx\n"
                    "R8  %-15llx\tR9  %-15llx\tR10 %-15llx\tR11 %-15llx\n"
                    "R12 %-15llx\tR13 %-15llx\tR14 %-15llx\tR15 %-15llx\n"
                    "RDI %-15llx\tRSI %-15llx\tRBP %-15llx\tRSP %-15llx\n"
                    "RIP %-15llx\tFLAGS %016llx\n",regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.rdi, regs.rsi, regs.rbp, regs.rsp, regs.rip, regs.eflags);
        }

        else if(!strcmp(arg[0],"get\0") || !strcmp(arg[0],"g\0")){
            if(state != RUNNING){
                fprintf(stderr, "** Program is not running.\n");
                continue;
            }
            unsigned long long temp;
            if(get(child, arg[1], &temp) == 0)
                fprintf(stderr, "%s = %lld (0x%llx)\n", arg[1], temp, temp);
        }
        else if(!strcmp(arg[0], "set\0") || !strcmp(arg[0], "s\0")){
            if(state != RUNNING){
                fprintf(stderr, "** Program is not running.\n");
                continue;
            }
            long long value = 0;
            int i;
            if(*arg[2] == '0' && *(arg[2]+1) == 'x')
                i = 2;
            else
                i = 0;

            while(arg[2][i]){
                if(*(arg[2]+i) >= '0' && arg[2][i] <= '9'){
                    value += (arg[2][i] - '0');}
                else
                    value += ((arg[2][i] - 'a') + 10);
                if(arg[2][i+1])
                    value *= 16;    
                i++;
            }
            
            set(child, arg[1], value);
        }
        else if(!strcmp(arg[0], "help\0") || !strcmp(arg[0], "h\0")){
            help();
        } 
        
        else if(!strcmp(arg[0], "disasm\0") || !strcmp(arg[0], "d\0")){
            if(state != RUNNING){
                fprintf(stderr, "** Program is not running.\n");
                continue;
            }
            if(arg[1] == NULL){
                fprintf(stderr, "** no addr is given\n");
                continue;
            }
            map<long long, instruction1>::iterator insi;
            long long target = 0;
            int i;
            if((arg[1][0] == '0') && (arg[1][1] == 'x')) 
                i = 2;
            else
                i = 0;
            while(arg[1][i]){
                if(*(arg[1]+i) >= '0' && arg[1][i] <= '9'){
                    target += (arg[1][i] - '0');}
                else
                    target += ((arg[1][i] - 'a') + 10);
                if(arg[1][i+1])
                    target *= 16;
                i++;
            }
            int ins = 0;
            for(insi = instructions.find(target); insi != instructions.end(); insi++){
                char bytes[128] = "";
                for(int i = 0; i < insi->second.size; i++) {
                    snprintf(&bytes[i*3], 4, "%2.2x ", insi->second.bytes[i]);
                }
                fprintf(stderr, "%12llx: %-36s%-8s\t%s\n", insi->first, bytes, insi->second.opr.c_str(), insi->second.opnd.c_str());
                ins++;
                if(ins == 10)
                    break;
            }
            if(ins != 10)
                fprintf(stderr, "** the address is out of the range of the text segment\n");
        }
        else if(!strcmp(arg[0], "dump\0") || !strcmp(arg[0], "x\0")){
            if(state != RUNNING){
                fprintf(stderr, "** Program is not running.\n");
                continue;
            }
            if(arg[1] == NULL){
                fprintf(stderr, "** no addr is given\n");
                continue;
            }
            long long target = 0;
            int i;
            if((arg[1][0] == '0') && (arg[1][1] == 'x')) 
                i = 2;
            else
                i = 0; 
             while(arg[1][i]){
                if(*(arg[1]+i) >= '0' && arg[1][i] <= '9'){
                    target += (arg[1][i] - '0');}
                else
                    target += ((arg[1][i] - 'a') + 10);
                if(arg[1][i+1])
                    target *= 16;
                i++;
            }

            dump(child, target);
        }
        else if(!strcmp(arg[0], "exit\0") || !strcmp(arg[0], "q\0")){
            kill(child, SIGINT);
            if(sflag)
                fclose(s);
            return 0;
        }
        else{
            fprintf(stderr, "** wrong command\n");
        }
        
    }
    return 0;
}


