#include <Security/Security.h>
#include <Security/SecStaticCode.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>

#ifndef UNFAIRPLAY_SHA256
#define UNFAIRPLAY_SHA256 "unconfigured"
#endif
#ifndef ROOT_HELPER_SHA256
#define ROOT_HELPER_SHA256 "unconfigured"
#endif

static int configureInvokingUser(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    if (!pw || uid == 0) return 0;
    char a[32], b[32]; snprintf(a,sizeof(a),"%u",uid); snprintf(b,sizeof(b),"%u",pw->pw_gid);
    return !setenv("SUDO_USER",pw->pw_name,1) && !setenv("SUDO_UID",a,1) && !setenv("SUDO_GID",b,1);
}
static int validUUID(const char *s) {
    if (strlen(s) != 36) return 0;
    for (int i=0;i<36;i++) if (i==8||i==13||i==18||i==23) { if(s[i]!='-')return 0; } else if(!isxdigit((unsigned char)s[i]))return 0;
    return 1;
}
static int validateSetup(int argc, char **args, uid_t uid) {
    if(argc!=7 || strcmp(args[0],"setup") || strcmp(args[1],"--app") || strcmp(args[3],"--ipa") || strcmp(args[5],"--model-dir"))return 0;
    struct passwd *pw=getpwuid(uid); if(!pw||!uid)return 0;
    char base[PATH_MAX], canonical[PATH_MAX], app[PATH_MAX], ipa[PATH_MAX];
    snprintf(base,sizeof(base),"%s/Library/Application Support/UnfairPlayDesk/Models/",pw->pw_dir);
    if(strncmp(args[6],base,strlen(base)) || !validUUID(args[6]+strlen(base)))return 0;
    if(!realpath(args[6],canonical)||strcmp(canonical,args[6]))return 0;
    struct stat state;
    if(lstat(canonical,&state)||!S_ISDIR(state.st_mode)||state.st_uid!=uid||(state.st_mode&0077))return 0;
    if(!realpath(args[2],app)||!realpath(args[4],ipa))return 0;
    char userApps[PATH_MAX]; snprintf(userApps,sizeof(userApps),"%s/Applications/",pw->pw_dir);
    if(strncmp(app,"/Applications/",14)&&strncmp(app,userApps,strlen(userApps)))return 0;
    size_t length=strlen(app); if(length<4||strcmp(app+length-4,".app"))return 0;
    // The app reads the user-selected file before requesting authorization.
    // The helper accepts only its private, canonical staging copy.
    char stagePrefix[PATH_MAX];
    snprintf(stagePrefix,sizeof(stagePrefix),"%s/Library/Application Support/UnfairPlayDesk/.unfairplay-work-",pw->pw_dir);
    size_t prefixLength=strlen(stagePrefix);
    if(strcmp(ipa,args[4]) || strncmp(ipa,stagePrefix,prefixLength))return 0;
    const char *stage=ipa+prefixLength;
    if(strlen(stage)<36 || strcmp(stage+36,"/result.ipa"))return 0;
    char stageID[37];
    memcpy(stageID,stage,36); stageID[36]=0;
    if(!validUUID(stageID))return 0;
    if(stat(ipa,&state)||!S_ISREG(state.st_mode)||state.st_uid!=uid)return 0;
    return 1;
}
static int trustedBinary(const char *path, const char *expectedHash) {
    struct stat state; if(lstat(path,&state)||!S_ISREG(state.st_mode)||S_ISLNK(state.st_mode)||(state.st_mode&0022))return 0;
    FILE *f=fopen(path,"rb"); if(!f)return 0;
    CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx); unsigned char bytes[8192], digest[CC_SHA256_DIGEST_LENGTH]; size_t n;
    while((n=fread(bytes,1,sizeof(bytes),f))>0) CC_SHA256_Update(&ctx,bytes,(CC_LONG)n);
    int ok=!ferror(f); fclose(f); CC_SHA256_Final(digest,&ctx);
    char hex[65]; for(int i=0;i<32;i++)snprintf(hex+i*2,3,"%02x",digest[i]);
    if(!ok||strcmp(hex,expectedHash))return 0;
    CFURLRef url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8 *)path,strlen(path),false);
    SecStaticCodeRef code=NULL;
    OSStatus result=SecStaticCodeCreateWithPath(url,kSecCSDefaultFlags,&code);
    if(result==errSecSuccess)result=SecStaticCodeCheckValidity(code,kSecCSStrictValidate,NULL);
    if(code)CFRelease(code); CFRelease(url); return result==errSecSuccess;
}
static int trustedTool(const char *path) { return trustedBinary(path, UNFAIRPLAY_SHA256); }
static int removeTemporary(const char *path, const struct stat *state, int kind, struct FTW *walk) {
    (void)state; (void)walk;
    return kind == FTW_DP ? rmdir(path) : unlink(path);
}
static int runRoot(const char *tool, char **args, pid_t parent) {
    pid_t child=fork(); if(child<0)return 1;
    if(child==0){ setpgid(0,0); umask(0077); dup2(STDOUT_FILENO,STDERR_FILENO); execv(tool,args); _exit(127); }
    setpgid(child,child); int status=0,ticks=0;
    while(1){
        pid_t r=waitpid(child,&status,WNOHANG); if(r==child)break;
        if(r<0&&errno!=EINTR)return 1;
        if(kill(parent,0)!=0){ kill(-child,ticks++<20?SIGTERM:SIGKILL); }
        usleep(100000);
    }
    kill(-child,SIGTERM);
    return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
}
#ifndef DESK_ROOT_ONLY
static char *shellQuote(const char *value) {
    size_t length=strlen(value); char *quoted=malloc(length*4+3), *out=quoted;
    if(!quoted)return NULL;
    *out++='\'';
    for(const char *p=value;*p;p++){
        if(*p=='\''){ memcpy(out,"'\\''",4); out+=4; }
        else *out++=*p;
    }
    *out++='\'';*out=0;return quoted;
}
static const char *authScript(void) {
    static const char script[] =
        "set -eu\nexec 2>&1\numask 077\n"
        "work=$(/usr/bin/mktemp -d /private/tmp/unfairplay-auth-XXXXXX)\n"
        "trap '/bin/rm -rf \"$work\"' EXIT HUP INT TERM\n"
        "/bin/cp \"$3/root-helper\" \"$work/root-helper\"\n"
        "/bin/cp \"$3/unfairplay\" \"$work/unfairplay\"\n"
        "printf '%s  %s\\n' '" ROOT_HELPER_SHA256 "' \"$work/root-helper\" '" UNFAIRPLAY_SHA256 "' \"$work/unfairplay\" | /usr/bin/shasum -a 256 -c - > /dev/null\n"
        "/usr/bin/codesign --verify --strict \"$work/root-helper\"\n"
        "/usr/bin/codesign --verify --strict \"$work/unfairplay\"\n"
        "\"$work/root-helper\" --root \"$2\" \"$1\" setup --app \"$4\" --ipa \"$5\" --model-dir \"$6\"\n";
    return script;
}
#endif
int main(int argc,char **argv){
    char self[PATH_MAX],tool[PATH_MAX],resolved[PATH_MAX]; uint32_t size=sizeof(self);
    if(_NSGetExecutablePath(self,&size)||!realpath(self,resolved))return 2;
    strcpy(self,resolved); char *slash=strrchr(resolved,'/'); if(!slash)return 2; *slash=0;
    if(snprintf(tool,sizeof(tool),"%s/unfairplay",resolved)>=(int)sizeof(tool))return 2;
#ifdef DESK_ROOT_ONLY
    if(argc==11&&!strcmp(argv[1],"--root")){
        char *end; unsigned long number=strtoul(argv[2],&end,10); if(*end||!number||number>UINT_MAX||geteuid()!=0)return 2;
        uid_t uid=(uid_t)number; long pid=strtol(argv[3],&end,10); if(*end||pid<=1||pid>INT_MAX||kill((pid_t)pid,0)!=0)return 2;
        if(!validateSetup(argc-4,&argv[4],uid)||!trustedTool(tool)||!configureInvokingUser(uid))return 2;
        char *args[9]={tool}; for(int i=4;i<argc;i++)args[i-3]=argv[i];
        char temporary[]="/private/tmp/unfairplay-desk-XXXXXX";
        if(!mkdtemp(temporary)||setenv("TMPDIR",temporary,1))return 1;
        int code=runRoot(tool,args,(pid_t)pid);
        if(nftw(temporary,removeTemporary,32,FTW_DEPTH|FTW_PHYS)!=0){fprintf(stderr,"初始化临时数据清理失败。\n");code=1;}
        printf("\nUNFAIRPLAY_DESK_EXIT_STATUS:%d\n",code); fflush(stdout); return code;
    }
    return 2;
#else
    if(!validateSetup(argc-1,&argv[1],getuid())||!trustedTool(tool)){
        fprintf(stderr,"初始化参数、数据目录或内置工具完整性检查失败。\n");return 2;
    }
    char rootHelper[PATH_MAX];
    if(snprintf(rootHelper,sizeof(rootHelper),"%s/root-helper",resolved)>=(int)sizeof(rootHelper)||!trustedBinary(rootHelper,ROOT_HELPER_SHA256)){
        fprintf(stderr,"管理员辅助工具完整性检查失败。\n");return 2;
    }
    char workspace[]="/private/tmp/unfairplay-launch-XXXXXX",fifo[PATH_MAX];
    if(!mkdtemp(workspace))return 1;
    snprintf(fifo,sizeof(fifo),"%s/output",workspace);
    if(mkfifo(fifo,0600)){rmdir(workspace);return 1;}
    int stream=open(fifo,O_RDWR|O_NONBLOCK|O_NOFOLLOW);
    if(stream<0){unlink(fifo);rmdir(workspace);return 1;}
    char uid[32],pid[32];snprintf(uid,sizeof(uid),"%u",getuid());snprintf(pid,sizeof(pid),"%d",getpid());
    const char *values[]={"/usr/bin/env","-i","PATH=/usr/bin:/bin:/usr/sbin:/sbin","/bin/sh","-p","-c",authScript(),"--",pid,uid,resolved,argv[3],argv[5],argv[7],NULL};
    char *quoted[16]={0},*output=shellQuote(fifo);size_t capacity=64;int count=0;
    if(!output){close(stream);unlink(fifo);rmdir(workspace);return 1;}
    capacity+=strlen(output);
    for(;values[count];count++){
        quoted[count]=shellQuote(values[count]);
        if(!quoted[count]){for(int j=0;j<count;j++)free(quoted[j]);free(output);close(stream);unlink(fifo);rmdir(workspace);return 1;}
        capacity+=strlen(quoted[count])+1;
    }
    char *command=calloc(capacity,1);
    if(!command){for(int j=0;j<count;j++)free(quoted[j]);free(output);close(stream);unlink(fifo);rmdir(workspace);return 1;}
    for(int j=0;j<count;j++){strcat(command,quoted[j]);strcat(command," ");free(quoted[j]);}
    strcat(command,"> ");strcat(command,output);strcat(command," 2>&1");free(output);
    // The system-owned interpreter requests administrator authorization. The
    // root command remains inline and all user paths are shell-quoted arguments.
    const char *appleScript="on run argv\n do shell script (item 1 of argv) with administrator privileges\nend run";
    pid_t launcher=fork();
    if(launcher==0){close(stream);execl("/usr/bin/osascript","osascript","-e",appleScript,"--",command,NULL);_exit(127);}
    free(command);
    if(launcher<0){close(stream);unlink(fifo);rmdir(workspace);return 1;}
    char buffer[4096],tail[16384]={0};size_t used=0;int ended=0,status=0;
    while(1){
        ssize_t n=read(stream,buffer,sizeof(buffer));
        if(n>0){
            fwrite(buffer,1,(size_t)n,stdout);fflush(stdout);
            if(used+(size_t)n>=sizeof(tail)){memmove(tail,tail+used-4096,4096);used=4096;}
            memcpy(tail+used,buffer,(size_t)n);used+=(size_t)n;tail[used]=0;
            continue;
        }
        if(!ended){pid_t done=waitpid(launcher,&status,WNOHANG);ended=done==launcher||(done<0&&errno!=EINTR);}
        if(ended)break;
        usleep(50000);
    }
    close(stream);unlink(fifo);rmdir(workspace);
    const char *marker="\nUNFAIRPLAY_DESK_EXIT_STATUS:";char *last=NULL,*p=tail;
    while((p=strstr(p,marker))){last=p;p++;}
    if(!last)return 1;
    char *end;long code=strtol(last+strlen(marker),&end,10);
    return (*end=='\n'&&code>=0&&code<=255)?(int)code:1;
#endif
}
