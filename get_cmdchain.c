#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <sys/types.h>
// #include "get_sysboot_time.c"


char * read_cmdline(int pid);
long get_file_length(char *path);


typedef struct cmdchain_struct {

int array_pids[100];
char *arr_cmdline[100];
char *arr_proc_path[100];
long long unsigned int start_time[100];
}cmd_chain_struct;


typedef struct proc_stat {
    int pid; //process ID.
    char* comm; //可执行文件名称, 会用()包围
    char state; //进程状态
    int ppid;   //父进程pid
    int pgid;
    int session;    //sid
    int tty_nr;
    int tpgid;
    unsigned int flags;
    long unsigned int minflt;
    long unsigned int cminflt;
    long unsigned int majflt;
    long unsigned int cmajflt;
    long unsigned int utime;
    long unsigned int stime;
    long int cutime;
    long int cstime;
    long int priority;
    long int nice;
    long int num_threads;
    long int itrealvalue;
    long long unsigned int starttime;
    long unsigned int vsize;
    long int rss;
    long unsigned int rsslim;
    long unsigned int startcode;
    long unsigned int endcode;
    long unsigned int startstack;
    long unsigned int kstkesp;
    long unsigned int kstkeip;
    long unsigned int signal;   //The bitmap of pending signals
    long unsigned int blocked;
    long unsigned int sigignore;
    long unsigned int sigcatch;
    long unsigned int wchan;
    long unsigned int nswap;
    long unsigned int cnswap;
    int exit_signal;
    int processor;
    unsigned int rt_priority;
    unsigned int policy;
    long long unsigned int delayacct_blkio_ticks;
    long unsigned int guest_time;
    long int cguest_time;
    long unsigned int start_data;
    long unsigned int end_data;
    long unsigned int start_brk;
    long unsigned int arg_start;    //参数起始地址
    long unsigned int arg_end;      //参数结束地址
    long unsigned int env_start;    //环境变量在内存中的起始地址
    long unsigned int env_end;      //环境变量的结束地址
    int exit_code; //退出状态码
    }proc_stat;


 proc_stat get_proc_stat(int Pid) {
    FILE *f = NULL;
    proc_stat stat = {0};
    char tmp[100] = "0";
    stat.comm = tmp;
    char stat_path[20];
    char* pstat_path = stat_path;
    if (Pid != -1) {
        sprintf(stat_path, "/proc/%d/stat", Pid);
    } else {
        pstat_path = "/proc/self/stat";
    }
    if ((f = fopen(pstat_path, "r")) == NULL) {
        printf("open file error,pid:%d\n",Pid);
        return stat;
    }
    fscanf(f, "%d ", &stat.pid);
    fscanf(f, "(%99s ", stat.comm);
    tmp[strlen(tmp)-1] = '\0';
    fscanf(f, "%c ", &stat.state);
    fscanf(f, "%d ", &stat.ppid);
    fscanf(f, "%d ", &stat.pgid);
    fscanf (
            f,
            "%d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %d",
            &stat.session, &stat.tty_nr, &stat.tpgid, &stat.flags, &stat.minflt,
            &stat.cminflt, &stat.majflt, &stat.cmajflt, &stat.utime, &stat.stime,
            &stat.cutime, &stat.cstime, &stat.priority, &stat.nice, &stat.num_threads,
            &stat.itrealvalue, &stat.starttime, &stat.vsize, &stat.rss, &stat.rsslim,
            &stat.startcode, &stat.endcode, &stat.startstack, &stat.kstkesp, &stat.kstkeip,
            &stat.signal, &stat.blocked, &stat.sigignore, &stat.sigcatch, &stat.wchan,
            &stat.nswap, &stat.cnswap, &stat.exit_signal, &stat.processor, &stat.rt_priority,
            &stat.policy, &stat.delayacct_blkio_ticks, &stat.guest_time, &stat.cguest_time, &stat.start_data,
            &stat.end_data, &stat.start_brk, &stat.arg_start, &stat.arg_end, &stat.env_start,
            &stat.env_end, &stat.exit_code
	    );
    fclose(f);
    return stat;
    }


char * read_proc_path(int pid)
{
 
 char *Str_Proc_Path=NULL;
 char pid_proc_path[1024]={0};

 Str_Proc_Path = (char *)malloc(1024);
 if (Str_Proc_Path == NULL) {
       perror("malloc failed");
       return NULL;  // 或者处理错误
   }
 memset(Str_Proc_Path,0,1024);
 snprintf(pid_proc_path,1024,"/proc/%d/exe",pid);

 //printf("pid_proc_path:%s\n",pid_proc_path);

 if(readlink(pid_proc_path,Str_Proc_Path,1024) <=0){

      printf("ERROR: Read cmdline function:Couldn't open %s\n", pid_proc_path);
      return Str_Proc_Path;
   }

  return Str_Proc_Path;

}

char * read_cmdline(int pid)
{
 FILE *fp=NULL;
 char *pcmdline=NULL;
 char pid_cmd_path[1024]={0};
 snprintf(pid_cmd_path,1024,"/proc/%d/cmdline",pid);
 
 //printf("pid_cmd_path:%s\n",pid_cmd_path);
 
 fp=fopen(pid_cmd_path,"rb");
 if(!fp) {
  printf("open %s error!\n",pid_cmd_path);
  return pcmdline ;
 
 }
 //printf("malloc size is :%d\n",get_file_length(pid_cmd_path));
 int cmdline_file_len=get_file_length(pid_cmd_path);
 pcmdline = (char *)malloc((size_t)cmdline_file_len+1);
 memset(pcmdline,0,cmdline_file_len+1);
 char ch;
 int c=0;
 ch = (char)getc(fp);
 for (int i = 0;ch != EOF; i++ ) {
    *(pcmdline + i) = ch;
    ch = (char)getc(fp);
    if ((int)ch == 0) {
         ch = ' ';
	 c++;
    }else
    {
       c=0;
    }
    if(c>1){
      *(pcmdline+i+1)='\0';
      break;
    }
 }
 fclose(fp);
 //printf("cmdline function:%s\n",pcmdline);
 return pcmdline;

}

long get_file_length(char *path) {
    FILE *fp=NULL;
    fp=fopen(path,"rb");
    if(!fp) {
        printf("open %s error!\n",path);
        return 0 ;
    }
    fseek(fp,0,SEEK_SET);
    char ch;
    ch = (char)getc(fp);
    long i,file_length;
    for (i = 0;ch != EOF; i++ ) {
        ch = (char)getc(fp);
    }
    i++;
    file_length=i;
    //printf("file length is %ld\n",file_length);
    fclose(fp);
    return file_length;
}


void get_cmd_chain(int pid ,cmd_chain_struct *chain_struct_info)
{
  proc_stat stat_info;
  /* 定义为静态变量，返回地址不释放*/
  int array_ppid[100]={0};
  int i=0;

  stat_info=get_proc_stat(pid);
  
  while(stat_info.ppid!=0 && i<100)
  {
	   
      array_ppid[i]=stat_info.pid;
      chain_struct_info->array_pids[i]=stat_info.pid;
      chain_struct_info->start_time[i]=stat_info.starttime/sysconf(_SC_CLK_TCK);
      stat_info=get_proc_stat(stat_info.ppid);
      i++;
  }
   /*循环结束后再补充下pid 是1的记录*/ 
   array_ppid[i]=stat_info.pid;
   chain_struct_info->array_pids[i]=stat_info.pid;
   chain_struct_info->start_time[i]=stat_info.starttime/sysconf(_SC_CLK_TCK);

  for(i=0;i<100;i++){
     if(array_ppid[i]==0){
	     //printf("ai:%d\n",i);
	     break;
     }
     //printf("%d\n",array_ppid[i]);
     chain_struct_info->arr_cmdline[i]=read_cmdline(array_ppid[i]);
     chain_struct_info->arr_proc_path[i]=read_proc_path(array_ppid[i]);
  }

  //return arr_cmd_line;
  return;
}

/*
int main(int argc ,char *argv[])
{

 
    char    strCmdChain[102400] = {0};
    char    *cmdline=NULL;
    int     cmd_len=0;
    //定义cmdchain 结构体用于存放信息
    cmd_chain_struct chain_struct_info;
    memset(&chain_struct_info,0,sizeof(chain_struct_info));
    get_cmd_chain(getpid(),&chain_struct_info);
    
    //获取系统启动时间，用于后续计算进程启动时间
    long int boot_time=get_system_boot_time();
    int chain_len=0;
    char progname[1024]={0};
    sprintf(progname,"%s",argv[0]);
    
    //获取 argv 内容 
    for(int i=0;argv[i]!=NULL;i++){
     cmd_len+=strlen(argv[i])+1; 
    }

    cmdline=malloc(cmd_len+1);
    memset(cmdline,0,cmd_len+1);
    for (int i=0,n=0;argv[i]!=NULL;i++){
        if (n >=cmd_len) {
            break;
        }
        n += snprintf(cmdline+n,cmd_len-n, "%s", argv[i]);
        if (n >=cmd_len) {
            break;
        }
        cmdline[n] = ' ';
        n++;
    }
  
    for(int i=0;i<100;i++){
        if(NULL==chain_struct_info.arr_cmdline[i]){
            break;
        }

        if (i != 0) {
            chain_len+=snprintf(strCmdChain + chain_len, 102400-chain_len, ",");
        }

        if(102400-chain_len>0){
            chain_len+=snprintf(strCmdChain+chain_len,102400-chain_len,
            "{\"pid\":%d,\"cmdline\":\"%s\",\"proc_path\":\"%s\",\"start_time\":%lld}",
            chain_struct_info.array_pids[i],
            chain_struct_info.arr_cmdline[i],
            chain_struct_info.arr_proc_path[i],
            // i==0?cmdline:chain_struct_info.arr_cmdline[i],
            // i==0?progname:chain_struct_info.arr_proc_path[i],
            boot_time+chain_struct_info.start_time[i]);
        }
        //释放内存
        if(NULL!=chain_struct_info.arr_cmdline[i]){
	    //printf("cmdline free,address:%u\n",chain_struct_info.arr_cmdline[i]);
            free(chain_struct_info.arr_cmdline[i]);
        }
        if(NULL!=chain_struct_info.arr_proc_path[i]){
	    //printf("proc path free,address:%u\n",chain_struct_info.arr_proc_path[i]);
            free(chain_struct_info.arr_proc_path[i]);
        }
    }
  free(cmdline);
  printf("Cmd_Chain:[%s]\n",strCmdChain);
    

}

*/