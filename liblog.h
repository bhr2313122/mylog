#ifndef __LOG_H__
#define __LOG_H__

extern "C"{

#define	LOG_EMERG   0  /* system is unusable */
#define	LOG_ALERT   1  /* action must be taken immediately */
#define	LOG_CRIT    2  /* critical conditions */
#define	LOG_ERR     3  /* error conditions */
#define	LOG_WARNING 4  /* warning conditions */
#define	LOG_NOTICE  5  /* normal but significant condition */
#define	LOG_INFO    6  /* informational */
#define	LOG_DEBUG   7  /* debug-level messages */
	
#define LOG_IO_OPS
#define LOG_TAG "tag"

typedef enum 
{
   LOG_NOFILE = 0,
   LOG_FILE   = 1
}log_type_t;

int log_init(log_type_t type, const char *log_obj);
void log_destroy();

void log_set_file_size(int size);
void log_set_rewrite(int enable);
int log_set_path(const char* path);
int log_print(int level, const char *tag, const char *file, int line, 
        const char* func, const char *fomat, ...);

#define log_err(...) log_print(LOG_ERR, LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_warning(...) log_print(LOG_WARNING, LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_info(...) log_print(LOG_INFO, LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_debug(...) log_print(LOG_DEBUG, LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__)


}

#endif
