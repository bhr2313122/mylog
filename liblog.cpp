#include "liblog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <pthread.h>

#define FILESIZE_LEN        (10*1024*1024UL)

typedef struct log_handle {
   int (*open)(const char *path);
   ssize_t (*write)(struct iovec *vec, int n);
   int (*close)(void);
} log_handle_t;

typedef struct log_driver {
   int (*init)(const char *ident);
   void (*destroy)();
} log_driver_t;

static unsigned long long g_log_file_size = FILESIZE_LEN;
static log_type_t g_log_type = LOG_NOFILE;
static char *g_log_obj = NULL;
static char g_log_path[256] = {'/','t','m','p','/','\0'};
static char g_filename[256] = {0};
static char g_no_file_name = 0;
static FILE *g_log_fp = NULL;
static int g_log_fd = 0;
static struct log_handle *g_log_handle = NULL;
static struct log_driver *g_log_driver = NULL;
static pthread_mutex_t g_log_mutex;
static int g_log_init = 0;
static char g_base_name[256] = {0};

static const char *g_log_level_str[] = {
    "EMERG",
    "ALERT",
    "CRIT",
    "ERR",
    "WARN",
    "NOTICE",
    "INFO",
    "DEBUG",
    NULL
};

static const char *get_dir(const char *path)
{
    char *p = (char *)path + strlen(path);
    for (; p != path; p--) {
       if (*p == '/') {
           *(p + 1) = '\0';
           break;
       }
    }
    return path;
}

static int check_dir(const char *path)
{
   char *path_dup = NULL;
   const char *dir = NULL;
   if(strstr(path, "/"))
   {
   	  path_dup = strdup(path);
   	  dir = get_dir(path_dup);
   	  if(access(dir, F_OK|W_OK|R_OK) == -1){
         fprintf(stderr, "check_dir %s fail\n",path_dup);
         return -1;
   	  }
   }
   return 0;
}

static int get_prog_name(char *name, size_t len)
{
   int i, ret;
   char proc_name[255] = {0};
   char *ptr = NULL;
   if (-1 == readlink("/proc/self/exe", proc_name, sizeof(proc_name))) {
      fprintf(stderr, "readlink failed!\n");
      return -1;
   }
   ret = strlen(proc_name);
   for(i = ret, ptr = proc_name; i > 0; --i)
   {
      if (ptr[i] == '/') {
         ptr+= i+1;
         break;
      }
   }
   if (i == 0) {
       fprintf(stderr, "proc path %s is invalid\n", proc_name);
       return -1;
   }
   if (ret-i > (int)len) {
       fprintf(stderr, "proc name length %d is larger than %d\n", ret-i, (int)len);
       return -1;
   }
   strncpy(name, ptr, ret - i);
   return 0;
}

static unsigned long long get_file_size(const char *path)
{
   struct stat buf;
   if (stat(path, &buf) < 0){ 
      return 0;
   }
   return (unsigned long long)buf.st_size;
}

static unsigned long long get_file_size_by_fp(FILE *fp)
{
   unsigned long long size;
   if(!fp || fp == stderr)
   {
      return 0;
   }
   long tmp = ftell(fp);
   fseek(fp, 0L, SEEK_END);
   size = ftell(fp);
   fseek(fp, tmp, SEEK_SET);
   return size;
}


static void log_get_time(char *str, int len )
{
   char date[32] = {0};
   time_t t;
   struct tm *info;

   time(&t);
   info = localtime(&t);
   strftime(date, 32, "%Y-%m-%d %H:%M:%S", info);
   snprintf(str, len, "%s.log", date);
}

static int open_new_file()
{
    int ret;
    char rename_file[256] = {0};
    if(g_no_file_name)
    {   
	log_get_time(rename_file, sizeof(rename_file));
	g_log_driver->init(rename_file);
        g_no_file_name = 1;	
    }   
    else
    {   
        char date[32] = {0};
	log_get_time(date, sizeof(date));
	strncpy(rename_file, g_base_name, sizeof(rename_file));
	strcat(rename_file, "_");
	strcat(rename_file, date);
	if(ret == -1) 
	{   
            fprintf(stderr, "rename log file fail: %s\n", strerror(errno));
	    return -1; 
	}   
	g_log_driver->init(rename_file);
    }   
    return 0;
}


static int io_open(const char* path)
{
   g_log_fd = open(path, O_RDWR|O_CREAT|O_APPEND, 0644);
   if(g_log_fd == -1)
   {
      fprintf(stderr, "open %s failed: %s\n", path, strerror(errno));
      return -1;
   }
   return 0;
}

static int io_close()
{
   return close(g_log_fd);
}

static ssize_t io_write(struct iovec *vec, int n)
{
   int ret;
   char path[1024] = {0};
   strncpy(path, g_log_path, strlen(g_log_path));
   strcat(path, g_filename);
   unsigned long long tmp_size = get_file_size(path);
   if(tmp_size > g_log_file_size){
      io_close();
      ret = open_new_file();
      if(ret != 0)
         return ret;
   }

   return writev(g_log_fd, vec, n);  
}

static int fio_open(const char* path)
{
   g_log_fp = fopen(path, "a+");
   if(g_log_fp < 0)
   {
      fprintf(stderr, "open %s failed: %s\n", path, strerror(errno));
      return -1;
   }
   return 0;   
}

static int fio_close()
{
   return fclose(g_log_fp);
}

ssize_t fio_write(struct iovec *vec, int n)
{
   int i, ret;
   unsigned long long tmp_size = get_file_size_by_fp(g_log_fp);
   if(tmp_size > g_log_file_size){
      fio_close();
      ret = open_new_file();
      if(ret != 0)
         return ret;
   }
   for(i = 0; i < n; ++i)
   {
      ret = fprintf(g_log_fp, "%s", (char*)vec[i].iov_base);
      if(ret != (int)vec[i].iov_len){
         fprintf(stderr, "fprintf failed:%s\n", strerror(errno));
         return -1;
      }
      if(fflush(g_log_fp) == EOF){
         fprintf(stderr, "fflush failed:%s\n", strerror(errno));
         return -1; 
      }
   }
   return 0;
}

static int log_init_stderr(const char *log_obj)
{
   g_log_fp = stderr;
   g_log_fd = STDERR_FILENO;
   return 0;
}

static int log_init_file(const char *log_obj)
{
   char path[1024] = {0};
   memset(g_filename, 0, 256);
   if(log_obj == NULL)
   {
      g_no_file_name = 1;
      log_get_time(g_filename, sizeof(g_filename));
   } else{
      g_no_file_name = 0;
      strncpy(g_filename, log_obj, sizeof(g_filename));
   }
   g_log_fp = NULL;
   g_log_fd = 0;
   strncpy(path, g_log_path, strlen(g_log_path));
   strcat(path, g_filename);
   assert(g_log_handle->open(path) != -1);
   return 0;
}

static void log_destroy_stderr()
{

}

static void log_destroy_file()
{
   g_log_handle->close();
}

static struct log_handle io_handle = {
   .open = io_open,
   .write = io_write,
   .close = io_close
};

static struct log_handle fio_handle = {
   .open = fio_open,
   .write = fio_write,
   .close = fio_close
};

static struct log_driver log_stderr_driver = { 
   .init = log_init_stderr,
   .destroy = log_destroy_stderr
};

static struct log_driver log_file_driver = { 
   .init = log_init_file,
   .destroy = log_destroy_file
};


static void log_init_once()
{
   log_type_t type = g_log_type;
   const char* ident = g_log_obj;
   if(g_log_init){
      return;
   }
#ifdef LOG_IO_OPS
   g_log_handle = &io_handle;
#else
   g_log_handle = &fio_handle;
#endif
   switch(type)
   {
   case LOG_NOFILE:
      g_log_driver = &log_stderr_driver;
      break;
   case LOG_FILE:
      g_log_driver = &log_file_driver;
      break;
   default:
      fprintf(stderr, "unsupport log type!\n");
      break;
   }
   g_log_driver->init(ident);
   g_log_init = 1;
   pthread_mutex_init(&g_log_mutex, NULL);
}

static int _log_print(int level, const char *tag, const char *file, int line, 
        const char* func, const char *msg)
{
   int ret = 0;
   struct iovec vec[10];
   char s_time[32] = {0};
   char s_level[16] = {0};
   char s_prog_name[255] = {0};
   char s_pid[8] = {0};
   char s_tid[8] = {0};
   char s_tag[32] = {0};
   char s_file[256] = {0};
   char s_msg[1024] = {0};

   pthread_mutex_lock(&g_log_mutex);
   /*time*/
   log_get_time(s_time, 32);
   /*level*/
   snprintf(s_level, 16, "[%s]", g_log_level_str[level]);
   /*program name*/
   if(get_prog_name(s_prog_name, 255) == -1)
   {
      fprintf(stderr, "%s\n", "get_prog_name error");
      snprintf(s_prog_name, 255, "%s", "Unknown");
   }
   /*pid*/
   snprintf(s_pid, 8, "[%s pid:%d ", s_prog_name, getpid());
   /*tid*/
   snprintf(s_tid, 8, "tid:%d]",syscall(SYS_gettid));
   /*tag*/
   snprintf(s_tag, 32, "[%s]", tag);
   /*s_file*/
   snprintf(s_file, 256, "[%s:%d %s]", file, line, func);
   /*message*/
   snprintf(s_msg, 1024, " %s", msg);
   
   int i = -1;
   vec[++i].iov_base = (void *)s_time;
   vec[i].iov_len = strlen(s_time);
   vec[++i].iov_base = (void *)s_level;
   vec[i].iov_len = strlen(s_level);
   vec[++i].iov_base = (void *)s_tag;
   vec[i].iov_len = strlen(s_tag);
   vec[++i].iov_base = (void *)s_prog_name;
   vec[i].iov_len = strlen(s_prog_name);
   vec[++i].iov_base = (void *)s_pid;
   vec[i].iov_len = strlen(s_pid);
   vec[++i].iov_base = (void *)s_tid;
   vec[i].iov_len = strlen(s_tid);
   vec[++i].iov_base = (void *)s_msg;
   vec[i].iov_len = strlen(s_msg);

   ret = g_log_handle->write(vec, i+1);

   pthread_mutex_unlock(&g_log_mutex);
   return ret;
}

int log_print(int level, const char *tag, const char *file, int line, 
        const char* func, const char *fomat, ...)
{
   va_list ap;
   char buf[1024] = {0};
   int n,ret;
   if(!g_log_init){
      log_init(LOG_NOFILE,NULL);
   }
   if(level > LOG_DEBUG)
      return 0;
   va_start(ap, fomat);
   n = vsnprintf(buf, sizeof(buf), fomat, ap);
   va_end(ap);
   if(n < 0)
   {
      fprintf(stderr, "vsnprintf error:%d\n", errno);
      return -1;
   }
   ret = _log_print(level, tag, file, line, func, buf);
   return ret;
}

pthread_once_t thread_once = PTHREAD_ONCE_INIT;
int log_init(log_type_t type, const char *log_obj)
{
   g_log_type = type;
   g_log_obj = const_cast<char *>(log_obj);
   if(log_obj)
      strncpy(g_base_name, log_obj, strlen(log_obj));
   if (pthread_once(&thread_once, log_init_once) != 0)
   {
      fprintf(stderr, "pthread_once failed\n");
   }
   return 0;
}

void log_set_file_size(int size)
{
   if((size > FILESIZE_LEN) || size < 0)
   {
      g_log_file_size = FILESIZE_LEN;
   }
   else{
      g_log_file_size = size;
   }
}

int log_set_path(const char* path)
{
   if(!path)
   {
      fprintf(stderr, "empty path\n");
      return -1;
   }
   if(strlen(path) == 0)
   {
      fprintf(stderr, "invalid path\n");
      return -1;
   }
   if(check_dir(path) == -1)
   {
   	  fprintf(stderr, "invalid path!\n");
      return -1;
   }
   strncpy(g_log_path, path, sizeof(g_log_path));
   return 0;
}

void log_destroy()
{
   if(!g_log_init){
      return ;
   }
   if(g_log_driver){
      g_log_driver->destroy();
      g_log_driver = NULL;
   }
   g_log_init = 0;
   pthread_mutex_destroy(&g_log_mutex);
}
