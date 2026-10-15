/* Disposable, per-share virtiofs integrity probe. Output: one JSON line per case. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>
#define SIZE 512
#define COUNT 32
static const char *dir;
static const char *self;
static int failures;
static char pathbuf[4096];

static const char *path(const char *name) {
    if (snprintf(pathbuf, sizeof pathbuf, "%s/probe-%s", dir, name) >= (int)sizeof pathbuf) exit(2);
    return pathbuf;
}
static void report(const char *name, int ok, const char *detail) {
    if (!ok) failures++;
    printf("{\"case\":\"%s\",\"passed\":%s,\"detail\":\"%s\"}\n", name, ok ? "true" : "false", detail);
    fflush(stdout);
}
static void fill(unsigned char *b, int rec, size_t n) {
    for (size_t j=0;j<n;j++) b[j]=(unsigned char)((rec*37+j*13)&255);
}
static int write_all(int fd, const void *p, size_t n) {
    const char *b=p;
    while (n) { ssize_t k=write(fd,b,n); if (k<=0) return 0; b+=k;n-=k; }
    return 1;
}
static int read_exact(int fd, void *p, size_t n) {
    char *b=p;
    while (n) { ssize_t k=read(fd,b,n); if (k<=0) return 0; b+=k;n-=k; }
    return 1;
}
static int close_ok(int fd) { return close(fd)==0; }
static int file_equals(const char *p, int first, int count) {
    int fd=open(p,O_RDONLY); if(fd<0)return 0;
    unsigned char got[SIZE], want[SIZE]; int ok=1;
    for(int i=0;i<count && ok;i++) { fill(want,first+i,SIZE); ok=read_exact(fd,got,SIZE) && memcmp(got,want,SIZE)==0; }
    unsigned char extra; if(ok)ok=read(fd,&extra,1)==0;
    return close_ok(fd) && ok;
}
static int write_record(int fd,int i,int sync_mode) {
    unsigned char b[SIZE]; fill(b,i,SIZE);
    if(!write_all(fd,b,SIZE))return 0;
    if(sync_mode==1)return fsync(fd)==0;
    if(sync_mode==2)return fdatasync(fd)==0;
    return 1;
}
static void append_case(const char *name,int flags,int sync_mode,int seed) {
    char p[4096]; snprintf(p,sizeof p,"%s",path(name));
    int ok=1,fd;
    if(seed) {
        fd=open(p,O_WRONLY|O_CREAT|O_EXCL,0600);
        ok=fd>=0;
        for(int i=0;i<3 && ok;i++)ok=write_record(fd,i,0);
        if(fd>=0)ok=close_ok(fd)&&ok;
    }
    fd=ok?open(p,flags|(seed?0:O_CREAT|O_EXCL),0600):-1;
    if(fd<0)ok=0;
    for(int i=seed?3:0;i<COUNT && ok;i++)ok=write_record(fd,i,sync_mode);
    if(fd>=0)ok=close_ok(fd)&&ok;
    ok=ok&&file_equals(p,0,COUNT);
    report(name,ok,ok?"":"write, sync, close, or readback failed");
}
static void mixed_idle(void) {
    const char *name="mixed-idle-append"; char p[4096];snprintf(p,sizeof p,"%s",path(name));
    int a=open(p,O_RDWR|O_CREAT|O_EXCL,0600),b=a>=0?open(p,O_RDWR|O_APPEND):-1;
    int ok=a>=0&&b>=0;
    for(int i=0;i<COUNT&&ok;i++)ok=lseek(a,(off_t)i*SIZE,SEEK_SET)==(off_t)i*SIZE&&write_record(a,i,1);
    if(b>=0)ok=close_ok(b)&&ok;
    if(a>=0)ok=close_ok(a)&&ok;
    ok=ok&&file_equals(p,0,COUNT);report(name,ok,ok?"":"mixed handle failed");
}
static void permission_fallback(void) {
    const char *name="mixed-permission-fallback";char p[4096];snprintf(p,sizeof p,"%s",path(name));
    int a=open(p,O_RDWR|O_APPEND|O_CREAT|O_EXCL,0600),b=-1,ok=a>=0;
    for(int i=0;i<16&&ok;i++)ok=write_record(a,i,1);
    if(ok)ok=chmod(p,0200)==0;
    if(ok){b=open(p,O_WRONLY|O_APPEND);ok=b>=0;}
    for(int i=16;i<COUNT&&ok;i++)ok=write_record(a,i,1);
    if(b>=0)ok=close_ok(b)&&ok;
    if(a>=0)ok=close_ok(a)&&ok;
    ok=(chmod(p,0600)==0)&&ok;
    ok=ok&&file_equals(p,0,COUNT);report(name,ok,ok?"":"permission fallback failed");
}
static void mmap_case(void) {
    const char *name="mmap-msync";char p[4096];snprintf(p,sizeof p,"%s",path(name));
    const size_t n=16384;int fd=open(p,O_RDWR|O_CREAT|O_EXCL,0600),ok=fd>=0;
    if(ok)ok=ftruncate(fd,n)==0;
    unsigned char *m=ok?mmap(NULL,n,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0):MAP_FAILED;
    if(m==MAP_FAILED)ok=0;
    if(ok){for(size_t i=0;i<n;i++)m[i]=(unsigned char)((i*97+13)&255);ok=msync(m,n,MS_SYNC)==0;}
    if(m!=MAP_FAILED)ok=(munmap(m,n)==0)&&ok;
    if(fd>=0)ok=close_ok(fd)&&ok;
    fd=ok?open(p,O_RDONLY):-1;if(fd<0)ok=0;
    if(ok){unsigned char b[16384],extra;ok=read_exact(fd,b,n)&&read(fd,&extra,1)==0;for(size_t i=0;i<n&&ok;i++)ok=b[i]==(unsigned char)((i*97+13)&255);}
    if(fd>=0)ok=close_ok(fd)&&ok;
    report(name,ok,ok?"":"mapping, sync, or readback failed");
}
static int sql(sqlite3 *db,const char *q){return sqlite3_exec(db,q,NULL,NULL,NULL)==SQLITE_OK;}
static int rows(sqlite3 *db) {
    sqlite3_stmt *st=NULL;int ok=sqlite3_prepare_v2(db,"SELECT v FROM t ORDER BY v",-1,&st,NULL)==SQLITE_OK;
    for(int i=0;i<32&&ok;i++)ok=sqlite3_step(st)==SQLITE_ROW&&sqlite3_column_int(st,0)==i;
    if(ok)ok=sqlite3_step(st)==SQLITE_DONE;
    if(st)ok=sqlite3_finalize(st)==SQLITE_OK&&ok;
    return ok;
}
static int sqlite_child(const char *p,int result_fd,int signal_fd) {
    sqlite3 *db=NULL;
    int ok=sqlite3_open(p,&db)==SQLITE_OK;
    if(ok)ok=sql(db,"PRAGMA busy_timeout=0;");
    int busy=ok?sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL):0;
    char result=busy==SQLITE_BUSY?'B':'F';
    if(!write_all(result_fd,&result,1))return 2;
    char go=0;if(!read_exact(signal_fd,&go,1)||go!='C')return 3;
    if(ok&&result=='B')ok=sql(db,"BEGIN IMMEDIATE;");
    for(int i=16;i<32&&ok;i++){char q[80];snprintf(q,sizeof q,"INSERT INTO t VALUES(%d)",i);ok=sql(db,q);}
    if(ok)ok=sql(db,"COMMIT;");
    if(db)ok=sqlite3_close(db)==SQLITE_OK&&ok;
    return ok&&result=='B'?0:4;
}
static void sqlite_case(void) {
    const char *name="sqlite-wal-two-process";char p[4096];snprintf(p,sizeof p,"%s",path("sqlite-wal.db"));
    sqlite3 *db=NULL;int ok=sqlite3_open(p,&db)==SQLITE_OK;
    if(ok)ok=sql(db,"PRAGMA journal_mode=WAL; CREATE TABLE t(v INTEGER PRIMARY KEY); BEGIN IMMEDIATE;");
    for(int i=0;i<16&&ok;i++){char q[80];snprintf(q,sizeof q,"INSERT INTO t VALUES(%d)",i);ok=sql(db,q);}
    int result_pipe[2]={-1,-1},signal_pipe[2]={-1,-1};
    if(ok)ok=pipe(result_pipe)==0&&pipe(signal_pipe)==0;
    pid_t child=ok?fork():-1;if(child<0)ok=0;
    if(child==0){
        close(result_pipe[0]);close(signal_pipe[1]);
        char result_fd[20],signal_fd[20];
        snprintf(result_fd,sizeof result_fd,"%d",result_pipe[1]);
        snprintf(signal_fd,sizeof signal_fd,"%d",signal_pipe[0]);
        execl(self,self,"--sqlite-child",p,result_fd,signal_fd,(char *)NULL);
        _exit(5);
    }
    if(child>0){
        close(result_pipe[1]);close(signal_pipe[0]);
        char result=0;int busy=read_exact(result_pipe[0],&result,1)&&result=='B';
        int committed=sql(db,"COMMIT;");
        char go='C';int signaled=write_all(signal_pipe[1],&go,1);
        close(result_pipe[0]);close(signal_pipe[1]);
        int status=0;int waited=waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0;
        ok=busy&&committed&&signaled&&waited&&ok;
    }
    if(db)ok=sqlite3_close(db)==SQLITE_OK&&ok;
    db=NULL;if(ok)ok=sqlite3_open(p,&db)==SQLITE_OK;
    if(ok)ok=rows(db);
    if(db)ok=sqlite3_close(db)==SQLITE_OK&&ok;
    report(name,ok,ok?"busy,commit,retry,rows=0..31":"SQLite contention or rows failed");
}
static void rename_case(void) {
    const char *name="rename";char src[4096],dst[4096];snprintf(src,sizeof src,"%s",path("rename-src"));snprintf(dst,sizeof dst,"%s",path("rename-dst-nonexistent"));
    int fd=open(src,O_WRONLY|O_CREAT|O_EXCL,0600),ok=fd>=0;
    if(ok)ok=write_record(fd,7,1);
    if(fd>=0)ok=close_ok(fd)&&ok;
    if(ok)ok=rename(src,dst)==0;
    ok=ok&&access(src,F_OK)<0&&errno==ENOENT&&file_equals(dst,7,1);
    report(name,ok,ok?"":"rename to absent destination failed");
}
struct reader_state {char dst[4096];atomic_int stop,seen_old,seen_new,invalid;};
static void *rename_reader(void *arg) {
    struct reader_state *s=arg;unsigned char old[SIZE],newer[SIZE],got[SIZE],extra;
    fill(old,22,SIZE);fill(newer,11,SIZE);
    while(!s->stop){int fd=open(s->dst,O_RDONLY);if(fd<0){s->invalid++;continue;}
        int ok=read_exact(fd,got,SIZE)&&read(fd,&extra,1)==0&&close_ok(fd);
        if(!ok)s->invalid++;else if(memcmp(got,old,SIZE)==0)s->seen_old++;else if(memcmp(got,newer,SIZE)==0)s->seen_new++;else s->invalid++;
    }return NULL;
}
static void rename_over(void) {
    const char *name="rename-over-existing";char src[4096],dst[4096];snprintf(src,sizeof src,"%s",path("rename-over-src"));snprintf(dst,sizeof dst,"%s",path("rename-over-dst"));
    int a=open(src,O_WRONLY|O_CREAT|O_EXCL,0600),b=open(dst,O_WRONLY|O_CREAT|O_EXCL,0600),ok=a>=0&&b>=0;
    if(a>=0){ok=write_record(a,11,1)&&ok;ok=close_ok(a)&&ok;}
    if(b>=0){ok=write_record(b,22,1)&&ok;ok=close_ok(b)&&ok;}
    struct reader_state s={.stop=0,.seen_old=0,.seen_new=0,.invalid=0};snprintf(s.dst,sizeof s.dst,"%s",dst);
    pthread_t thread;int started=0;
    if(ok){started=pthread_create(&thread,NULL,rename_reader,&s)==0;ok=started;}
    if(started){
        for(int i=0;i<1000000&&s.seen_old==0;i++)sched_yield();
        ok=s.seen_old>0&&ok;
        if(ok)ok=rename(src,dst)==0;
        for(int i=0;i<1000000&&s.seen_new==0;i++)sched_yield();
        s.stop=1;ok=pthread_join(thread,NULL)==0&&ok;
        ok=s.seen_new>0&&s.invalid==0&&ok;
    }
    ok=ok&&access(src,F_OK)<0&&errno==ENOENT&&file_equals(dst,11,1);
    report(name,ok,ok?"old-and-new-whole-reads":"atomic replacement or reader failed");
}
static void visibility(void) {
    const char *name="host-to-guest-visibility";char ready[4096],data[4096],ack[4096];
    snprintf(ready,sizeof ready,"%s",path("h2g-ready"));snprintf(data,sizeof data,"%s",path("h2g-data"));snprintf(ack,sizeof ack,"%s",path("h2g-ack"));
    int seen=0;for(int i=0;i<100;i++){if(access(ready,F_OK)==0){seen=1;break;}usleep(100000);}
    int ok=seen&&file_equals(data,42,1);
    int fd=ok?open(ack,O_WRONLY|O_CREAT|O_EXCL,0600):-1;ok=fd>=0&&ok;if(fd>=0)ok=close_ok(fd)&&ok;
    report(name,ok,ok?"":"host marker or bytes not visible");
    name="guest-to-host-ready";snprintf(data,sizeof data,"%s",path("g2h-data"));snprintf(ready,sizeof ready,"%s",path("g2h-ready"));
    fd=open(data,O_WRONLY|O_CREAT|O_EXCL,0600);ok=fd>=0;if(ok)ok=write_record(fd,77,1);if(fd>=0)ok=close_ok(fd)&&ok;
    fd=ok?open(ready,O_WRONLY|O_CREAT|O_EXCL,0600):-1;ok=fd>=0&&ok;if(fd>=0)ok=close_ok(fd)&&ok;
    report(name,ok,ok?"":"guest data or marker failed");
}
int main(int argc,char **argv) {
    if(argc==5&&strcmp(argv[1],"--sqlite-child")==0)return sqlite_child(argv[2],atoi(argv[3]),atoi(argv[4]));
    if(argc!=2){fprintf(stderr,"usage: %s <disposable-share-subdir>\n",argv[0]);return 2;}dir=argv[1];self=argv[0];
    append_case("append-wronly-fsync",O_WRONLY|O_APPEND,1,0);
    append_case("append-rdwr-fsync",O_RDWR|O_APPEND,1,0);
    append_case("append-wronly-fdatasync",O_WRONLY|O_APPEND,2,0);
    append_case("append-wronly-existing",O_WRONLY|O_APPEND,1,1);
    append_case("append-rdwr-existing",O_RDWR|O_APPEND,1,1);
    append_case("plain-write-fsync",O_WRONLY,1,0);
    mixed_idle();permission_fallback();mmap_case();sqlite_case();rename_case();rename_over();visibility();
    return failures?1:0;
}
