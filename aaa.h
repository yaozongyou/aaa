#ifndef AAA_H
#define AAA_H

#include <cxxabi.h>
#include <execinfo.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#ifdef __cplusplus
#include <iostream>
#include <sstream>
#include <cstring>
#endif

#define aaa_printf(format, ...)                                                                \
    do {                                                                                        \
        FILE* ffff = fopen("/tmp/debug.log", "a");                                              \
        if (ffff == NULL) {                                                                     \
            break;                                                                              \
        }                                                                                       \
        struct timeval tv = {0};                                                                \
        struct tm tm = {0};                                                                     \
        gettimeofday(&tv, NULL);                                                                \
        localtime_r(&(tv.tv_sec), &tm);                                                         \
        fprintf(ffff, "[%d-%02d-%02d %02d:%02d:%02d.%03d][%d:%d][%s:%d] " format "",            \
                1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, \
                (int)(tv.tv_usec / 1000),                                            \
                (int)(getpid()), (int)(syscall(SYS_gettid)),              \
                __FILE__, __LINE__,                                                             \
                ##__VA_ARGS__);                                                                 \
        fclose(ffff);                                                                           \
    } while (0)

#ifdef __cplusplus
class LogMessage {
public:
    LogMessage(const char* file, int line) {
        Init(file, line);
    }

    ~LogMessage() {
        FILE* fp = fopen("/tmp/debug.log", "a");
        if (fp == NULL) {
            return;
        }
        fprintf(fp, "%s\n", stream_.str().c_str());
        fclose(fp);
    }

    std::ostream& stream() { return stream_; }

private:
    void Init(const char* file, int line) {
        char buf[256] = {0};
        struct timeval tv = {0};
        struct tm tm = {0};
        gettimeofday(&tv, NULL);
        localtime_r(&(tv.tv_sec), &tm);
        sprintf(buf, "[%d-%02d-%02d %02d:%02d:%02d.%03d][%d:%d][%s:%d] ",
                1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                static_cast<int>(tv.tv_usec / 1000),
                static_cast<int>(getpid()), static_cast<int>(syscall(SYS_gettid)),
                file, line);
        stream_ << buf;
    }

    std::ostringstream stream_;
};

#define LOG(AAA) LogMessage(__FILE__, __LINE__).stream()

#define DEBUG_PRINT_BACKTRACE() debug_print_backtrace_impl(__FILE__, __LINE__)

inline void debug_print_backtrace_impl(const char* file, int line) {
    void *buffer[256] = {0};
    int nptrs = backtrace(buffer, 256);
    char **strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        LogMessage(file, line).stream() << "failed to backtrace_symbols";
        return;
    }

    std::stringstream ss;
    ss << "backstrace:" << std::endl;
    for (int i = 0; i < nptrs; i++) {
        size_t sz = 1024; // just a guess, template names will go much wider
        char *function = (char *)malloc(sz);
        if (!function)
            return;
        char *begin = 0, *end = 0;
        for (char *j = strings[i]; *j; ++j) {
            if (*j == '(')
                begin = j+1;
            else if (*j == '+')
                end = j;
        }

        if (begin && end) {
            int len = end - begin;
            char *foo = (char *)malloc(len+1);
            if (!foo) {
                free(function);
                return;
            }
            memcpy(foo, begin, len);
            foo[len] = 0;

            int status;
            char *ret = nullptr;
            // only demangle a C++ mangled name
            if (foo[0] == '_' && foo[1] == 'Z')
                ret = abi::__cxa_demangle(foo, function, &sz, &status);
            if (ret) {
                // return value may be a realloc() of the input
                function = ret;
            } else {
                // demangling failed, just pretend it's a C function with no args
                strncpy(function, foo, sz);
                strncat(function, "()", sz);
                function[sz-1] = 0;
            }
            ss << " " << (i+1) << ": " << '(' << function << end << std::endl;
            free(foo);
        } else {
            // didn't find the mangled name, just print the whole line
            ss << " " << (i+1) << ": " << strings[i] << std::endl;
        }
    }
    LogMessage(file, line).stream() << ss.str();

    free(strings);
}

#endif

#endif // AAA_H
