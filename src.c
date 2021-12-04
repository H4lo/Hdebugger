#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#define true 1
#define false 0


const int long_size = sizeof(long);
//const int long_size = 1;
struct registers{
	long rax;
	long rbx;
	long rcx;
	long rdx;
	long rip;
}regs;


struct user_regs_struct regs1;



void getdata(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * (long_size),
                          NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * (long_size),
                          NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}


int putdata(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;


	
	char tmp_buf[0x1000]; 
	memset(tmp_buf,'\0',sizeof(tmp_buf));

	// 对齐
	if(len%long_size != 0){
		getdata(child,addr,tmp_buf,(len/long_size+1)*long_size);

		memcpy(tmp_buf,str,len);
		laddr = tmp_buf;
	}else{
		laddr = str;
	}
	

    i = 0;
    j = len / long_size;
    //laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * (long_size), data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * (long_size), data.val);
    }
	return 1;
}

int ptrace_attach(pid_t pid){
	long status = ptrace(PTRACE_ATTACH,pid,NULL,0);
	if(status < 0){
		return -1;
	}else{
		return 0;
	}
}

int ptrace_detach(pid_t pid)    
{    
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {    
        return -1;    
    }    
    return 0;    
}

int format_hex(long addr,char *input,char *format_buf,unsigned int len){
	int i;

	if(len <= 0){
		return false;
	}
	sprintf(format_buf,"0x%lx    ",addr);
	format_buf = format_buf + strlen(format_buf);


	for(i = 0;i < len;i++){

		unsigned char ch = *(input+i) - '0' + 0x30;
		
		if(i > 0 && i % 16 == 0){
			char addr_buf[20];
			memset(addr_buf,'0',sizeof(addr_buf));
			sprintf(addr_buf,"\n0x%lx    ",addr+i);
			memcpy(format_buf+i*2,addr_buf,strlen(addr_buf));
			//sprintf(format_buf+i*2,"\n0x%lx    ",addr+i);

			format_buf = format_buf+strlen(addr_buf);
		}
		
		sprintf(format_buf+i*2,"%02x ",ch);
		format_buf++;

	}
	return true;
}


int get_signal_info(pid_t pid){
	siginfo_t info;
	int signal_type = -1;
	ptrace(PTRACE_SINGLESTEP, pid, NULL, &info);

	
	switch (info.si_signo){
		case SIGTRAP:
			signal_type = 1;
			break;
		case SIGSEGV:
			signal_type = 2;
			break;
		default:
			signal_type = 0;
	}
	return signal_type;
}

int format_register(struct user_regs_struct regs,char *buf){
	//char buf[0x1000];
	sprintf(buf,"$rax\t\t0x%llx\n$rbx\t\t0x%llx\n$rcx\t\t0x%llx\n$rdx\t\t0x%llx\n$rsi\t\t0x%llx\n$rdi\t\t0x%llx\n$rsp\t\t0x%llx\n$rbp\t\t0x%llx\n$rip\t\t0x%llx\n\n",
		regs.rax,
		regs.rbx,
		regs.rcx,
		regs.rdx,
		regs.rsi,
		regs.rdi,
		regs.rsp,
		regs.rbp,
		regs.rip
		);
	//puts(buf);
}


void help(){
	puts("help				show the help information.");
	puts("print [addr]			print the content of the memory address.");
	puts("set [addr] [content]		fill content to address.");
	puts("break/c [addr]			breakpoint in addr.");
	puts("continue/c			continue.");
	puts("next/n				step over.");
	puts("exit/q				exit the debugger.");

}

// 刷新缓冲区
void init(){
	setbuf(stdin,0);
	setbuf(stdout,0);
	setbuf(stderr,0);
}


int main(int argc, char **argv,char **env){
	if(argc < 2){
		printf("%s [PID] (debug with root permission)\n",argv[0]);
		exit(0);
	}
	
	pid_t pid = (pid_t)atoi(argv[1]);

	//long addr = 0x7f6d53dd2020;

	//char str[200] = "test123\0";
	char buf[100];
	memset(buf,'\0',sizeof(buf));

	init();
	if(ptrace_attach(pid) < 0){
		perror("ptrace attach process error!\n");
		exit(-1);
	}
	printf("Attach process '%d' success!\n",pid);
	//wait(&pid);		//暂时停止目前进程的执行, 直到有信号来到或子进程结束

	
	/* wait for the attach request to complete */
	waitpid(pid, NULL, 0);

	sleep(1);


	int is_break = 0;
	long break_addr = 0;
	char orig[1];

	while(1){

		char *cmd_buf = malloc(0x100);

		printf("Enter the command(Type help for more.)\n");
		printf(">> ");
		
		
		read(0,cmd_buf,sizeof(cmd_buf));
		cmd_buf[strlen(cmd_buf)-1] = '\0';

		
		if(!strcmp(cmd_buf,"print")){
			long addr;
			int len;

			printf("Enter the address (hex): ");
			//getint(addr);


			scanf("%lx",&addr);
			//printf("addr: %ld\n",addr);
			printf("Enter the len: ");
			scanf("%d",&len);		

			char *buf = malloc(len+1);
			char *format_buf = calloc(4*len+(len/16+4)*18+4,1);
			
			if(buf == NULL || format_buf == NULL){
				perror("malloc error\n");
				return -1;
			}
			
			getdata(pid,addr,buf,len);
			
			if(format_hex(addr,buf,format_buf,len)){
				printf("read memory success!\n\n");
			}else{
				printf("error happened!\n");
				break;
			}
			puts(format_buf);

			free(buf);
			free(format_buf);
			
		}else if(!strcmp(cmd_buf,"break") || !strcmp(cmd_buf,"b")){
			
			int len = 1;
			char break_point[] = {0xcc};

			printf("Enter the address (hex): ");
			scanf("%lx",&break_addr);

			getdata(pid,break_addr,orig,1);
			putdata(pid,break_addr,break_point,1);

			is_break = 1;
			printf("Breakpoint in %lx.\n",break_addr);
			continue;
			 
		}else if(!strcmp(cmd_buf,"set")){
			long addr;

			char input[0x1000];
			char tmp_input[0x1000];
			memset(input,'\0',sizeof(input));
			memset(tmp_input,'\0',sizeof(tmp_input));

			printf("Enter the address (hex): ");
			scanf("%lx",&addr);
			printf("Enter the content (\\n to end.): ");
			read(0,tmp_input,sizeof(tmp_input));

			tmp_input[strlen(tmp_input)-1] = '\0';
			memcpy(input,tmp_input,strlen(tmp_input));
			//printf("len: %d\n",strlen(input));

			if(putdata(pid,addr,input,strlen(input))){
				printf("set content to memory success!\n\n");
			}else{
				printf("error happened!\n");
				break;
			}
		}else if(!strcmp(cmd_buf,"info") || !strcmp(cmd_buf,"i")){


			char regs_buf[0x1000];


			long ins = 0;
			ptrace(PTRACE_GETREGS,pid,NULL,&regs1);

			/*
			
			ins = ptrace(PTRACE_PEEKTEXT,pid,regs1.rip,NULL);
			ptrace(PTRACE_PEEKTEXT,pid,regs1.rax,NULL);
			ptrace(PTRACE_PEEKTEXT,pid,regs1.rbx,NULL);
			ptrace(PTRACE_PEEKTEXT,pid,regs1.rcx,NULL);
			ptrace(PTRACE_PEEKTEXT,pid,regs1.rdx,NULL);
			ptrace(PTRACE_PEEKTEXT,pid,regs1.rsi,NULL);
			ptrace(PTRACE_PEEKTEXT,pid,regs1.rdi,NULL);
			ptrace(PTRACE_PEEKTEXT,pid,regs1.rsp,NULL);
			ptrace(PTRACE_PEEKTEXT,pid,regs1.rbp,NULL);
			*/

			format_register(regs1,regs_buf);

			
			printf("RIP: %lx Instruction "
                       "executed: %lx\n",
                       (long unsigned int)regs1.rip, ins);
			
			puts(regs_buf);

		}else if(!strcmp(cmd_buf,"next") || !strcmp(cmd_buf,"n")){
			long status;
			// PTRACE_SINGLESTEP
			// PTRACE_SYSCALL
			status = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
			//printf("single instruction result: %ld\n",status);
			if(status == 0){
				printf("single step success!\n");
			}else{
				printf("single step fail!\n");
				continue;
			}

		}else if(!strcmp(cmd_buf,"continue") || !strcmp(cmd_buf,"c")){
			struct user_regs_struct recover_regs;
			int wait_status;

			ptrace(PTRACE_CONT, pid, NULL, NULL);
			//waitpid(pid,NULL,0);


			wait(&wait_status);
			if (WIFSTOPPED(wait_status)) {
    			printf("Program got a signal: %s\n", strsignal(WSTOPSIG(wait_status)));
			}
			else {
				perror("wait");
				return -1;
			}

			/*
			int signal = get_signal_info(pid);
			printf("signal type: %d\n",signal);
			*/

			// SIGTRAP
			if(WSTOPSIG(wait_status) == 5){
				printf("\nThe process stopped in breakpoint.\n");
				printf("Break address: 0x%lx\n\n",break_addr);
				if(is_break == 1 && break_addr != 0){
					ptrace(PTRACE_GETREGS, pid, NULL, &recover_regs);
					
					putdata(pid,break_addr,orig,1);

					recover_regs.rip--;
					ptrace(PTRACE_SETREGS, pid, NULL, &recover_regs);

					is_break = 0;
					break_addr = 0;
				}else{
					continue;
				}
			}else if(WSTOPSIG(wait_status) == 11){
				printf("Program is dead, Exit!\n");
				break;
			}else{

			}
			
			continue;

		}else if(!strcmp(cmd_buf,"exit") || !strcmp(cmd_buf,"q")){
			break;
		}else if(!strcmp(cmd_buf,"help")){
			help();

		/* error command input */
		}else{
			printf("error command, type `help` for help.\n");
			continue;
		}

		free(cmd_buf);

	}

	if(ptrace_detach(pid) < 0){
		perror("ptrace detach process error!\n");
		exit(-1);
	}
	
}	
