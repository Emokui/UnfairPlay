#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static char testHome[4096];
static struct passwd *testPW(uid_t uid) {
    struct passwd *real=getpwuid(uid); if(!real)return NULL;
    static struct passwd copy;copy=*real;if(testHome[0])copy.pw_dir=testHome;return &copy;
}
#define getpwuid testPW
#define main authorizationHelperMain
#include "../Sources/authorize.c"
#undef main
#undef getpwuid
static void copyFile(const char *from,const char *to){
    int input=open(from,O_RDONLY),output=open(to,O_CREAT|O_EXCL|O_WRONLY,0700);assert(input>=0&&output>=0);
    char bytes[8192];ssize_t n;while((n=read(input,bytes,sizeof(bytes)))>0)assert(write(output,bytes,n)==n);assert(n==0);close(input);close(output);
}
static int bridgeTest(const char *tools,const char *app,const char *ipa,const char *model){
    char uid[32],parent[32];snprintf(uid,sizeof(uid),"%u",getuid());snprintf(parent,sizeof(parent),"%d",getpid());
    pid_t child=fork();assert(child>=0);
    if(child==0){int null=open("/dev/null",O_WRONLY);dup2(null,1);dup2(null,2);execl("/usr/bin/env","env","-i","PATH=/usr/bin:/bin:/usr/sbin:/sbin","/bin/sh","-p","-c",authScript(),"--",parent,uid,tools,app,ipa,model,(char *)NULL);_exit(127);}
    int status;assert(waitpid(child,&status,0)==child);return WIFEXITED(status)?WEXITSTATUS(status):255;
}
static void dirs(const char *path){char p[4096];snprintf(p,sizeof(p),"%s",path);for(char *c=p+1;*c;c++)if(*c=='/'){*c=0;mkdir(p,0700);*c='/';}assert(!mkdir(p,0700)||errno==EEXIST);}
int main(int argc,char **argv){
    assert(!configureInvokingUser(0));assert(configureInvokingUser(getuid()));
    assert(strtoul(getenv("SUDO_UID"),NULL,10)==getuid());assert(strtoul(getenv("SUDO_GID"),NULL,10)==getgid());
    char path[]="/private/tmp/desk-helper-test-XXXXXX";assert(mkdtemp(path));snprintf(testHome,sizeof(testHome),"%s",path);
    char model[4096],app[4096],ipa[4096];
    snprintf(model,sizeof(model),"%s/Library/Application Support/UnfairPlayDesk/Models/11111111-1111-1111-1111-111111111111",path);
    snprintf(app,sizeof(app),"%s/Applications/Test.app",path);snprintf(ipa,sizeof(ipa),"%s/Test.ipa",path);dirs(model);dirs(app);
    int fd=open(ipa,O_CREAT|O_WRONLY,0600);assert(fd>=0);close(fd);
    char *valid[]={"setup","--app",app,"--ipa",ipa,"--model-dir",model};
    assert(validateSetup(7,valid,getuid()));assert(!validateSetup(6,valid,getuid()));
    char *old=valid[0];valid[0]="/usr/bin/true";assert(!validateSetup(7,valid,getuid()));valid[0]=old;
    chmod(model,0777);assert(!validateSetup(7,valid,getuid()));chmod(model,0700);
    assert(!validUUID("../../other"));assert(validUUID("11111111-1111-1111-1111-111111111111"));
    if(argc==2){
        assert(trustedTool(argv[1]));
        char original[4096],copied[4096],copyRoot[4096],target[4096];snprintf(original,sizeof(original),"%s",argv[1]);*strrchr(original,'/')=0;
        assert(bridgeTest(original,app,ipa,model)==2); // signed root helper safely rejects an unprivileged launch.
        snprintf(copyRoot,sizeof(copyRoot),"%s/bridge-tools",path);dirs(copyRoot);
        snprintf(target,sizeof(target),"%s/unfairplay",copyRoot);copyFile(argv[1],target);
        snprintf(copied,sizeof(copied),"%s/root-helper",original);snprintf(target,sizeof(target),"%s/root-helper",copyRoot);copyFile(copied,target);
        snprintf(target,sizeof(target),"%s/unfairplay",copyRoot);int tamper=open(target,O_WRONLY);assert(tamper>=0);assert(pwrite(tamper,"broken",6,0)==6);close(tamper);
        assert(!trustedTool(target));assert(bridgeTest(copyRoot,app,ipa,model)==1);
    }
    char *child[]={"sh","-c","printf 'synthetic-success-marker\\n'; exit 7",NULL};assert(runRoot("/bin/sh",child,getpid())==7);
    assert(nftw(path,removeTemporary,32,FTW_DEPTH|FTW_PHYS)==0);
    puts("PASS: strict setup arguments, private user-owned destination, fixed UUID boundary, tool digest/signature, protected-copy authorization bridge, tampering rejection, real exit status, SUDO identity");return 0;
}
