#include "m_pd.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#endif

#define INBUFSIZE 65536
#define MAX_ARGS 256

static t_class *command_class;

typedef struct _command
{
    t_object x_obj;
#ifdef _WIN32
    PROCESS_INFORMATION pi;
    HANDLE stdin_pipe[2];
    HANDLE stdout_pipe[2];
    HANDLE stderr_pipe[2];
#else
    pid_t pid;
    int stdin_pipe[2];
    int stdout_pipe[2];
    int stderr_pipe[2];
#endif
    int x_del;
    int x_bin;  // -b flag: binary output
    int x_sync; // -s flag: synchronous (blocking) mode of operation
    t_outlet* x_done;
    t_outlet* x_stdout;
    t_outlet* x_stderr;
    t_clock* x_clock;
    t_symbol *path;
} t_command;

static void command_read(t_command *x, int is_stderr)
{
    char buf[INBUFSIZE];
    int ret;

#ifdef _WIN32
    DWORD bytes_read;
    BOOL success = ReadFile(is_stderr ? x->stderr_pipe[0] : x->stdout_pipe[0], 
                            buf, INBUFSIZE - 1, &bytes_read, NULL);
    ret = success ? bytes_read : -1;
#else
    ret = read(is_stderr ? x->stderr_pipe[0] : x->stdout_pipe[0], buf, INBUFSIZE - 1);
#endif

    if (ret > 0) {
        buf[ret] = '\0';
        if (x->x_bin) {
            // Binary mode: output as list of floats
            t_atom *outv = (t_atom *)getbytes(ret * sizeof(t_atom));
            for (int i = 0; i < ret; i++) {
                SETFLOAT(outv + i, (t_float)(unsigned char)buf[i]);
            }
            outlet_list(is_stderr ? x->x_stderr : x->x_stdout, &s_list, ret, outv);
            freebytes(outv, ret * sizeof(t_atom));
        } else {
            // Text mode: output as symbol
            outlet_symbol(is_stderr ? x->x_stderr : x->x_stdout, gensym(buf));
        }
    }
}

static void command_check(t_command *x)
{
#ifdef _WIN32
    DWORD exit_code;
    if (GetExitCodeProcess(x->pi.hProcess, &exit_code) && exit_code != STILL_ACTIVE) {
        command_read(x, 0);  // Read remaining stdout
        command_read(x, 1);  // Read remaining stderr
        CloseHandle(x->pi.hProcess);
        CloseHandle(x->pi.hThread);
        CloseHandle(x->stdin_pipe[0]);
        CloseHandle(x->stdin_pipe[1]);
        CloseHandle(x->stdout_pipe[0]);
        CloseHandle(x->stdout_pipe[1]);
        CloseHandle(x->stderr_pipe[0]);
        CloseHandle(x->stderr_pipe[1]);
        outlet_float(x->x_done, (t_float)exit_code);
    } else {
        if (x->x_del < 100) x->x_del += 2;
        clock_delay(x->x_clock, x->x_del);
    }
#else
    int status;
    pid_t result = waitpid(x->pid, &status, WNOHANG);
    if (result == x->pid) {
        command_read(x, 0);  // Read remaining stdout
        command_read(x, 1);  // Read remaining stderr
        close(x->stdin_pipe[0]);
        close(x->stdin_pipe[1]);
        close(x->stdout_pipe[0]);
        close(x->stdout_pipe[1]);
        close(x->stderr_pipe[0]);
        close(x->stderr_pipe[1]);
        outlet_float(x->x_done, (t_float)WEXITSTATUS(status));
    } else if (result == 0) {
        if (x->x_del < 100) x->x_del += 2;
        clock_delay(x->x_clock, x->x_del);
    } else {
        pd_error(x, "command: waitpid() failed");
    }
#endif
}

static void command_exec(t_command *x, t_symbol *s, int ac, t_atom *at)
{
    char *argv[MAX_ARGS];
    int i;

    if (ac > MAX_ARGS - 1) {
        pd_error(x, "command: too many arguments");
        return;
    }

    for (i = 0; i < ac; i++) {
        argv[i] = atom_getsymbol(at + i)->s_name;
    }
    argv[i] = NULL;

#ifdef _WIN32
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    if (!CreatePipe(&x->stdin_pipe[0], &x->stdin_pipe[1], &sa, 0) ||
        !CreatePipe(&x->stdout_pipe[0], &x->stdout_pipe[1], &sa, 0) ||
        !CreatePipe(&x->stderr_pipe[0], &x->stderr_pipe[1], &sa, 0)) {
        pd_error(x, "command: failed to create pipes");
        return;
    }

    STARTUPINFO si = {sizeof(STARTUPINFO)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = x->stdin_pipe[0];
    si.hStdOutput = x->stdout_pipe[1];
    si.hStdError = x->stderr_pipe[1];

    char command_line[INBUFSIZE] = "";
    for (i = 0; i < ac; i++) {
        if (i > 0) strcat(command_line, " ");
        strcat(command_line, "\"");
        strcat(command_line, argv[i]);
        strcat(command_line, "\"");
    }

    post("command: Attempting to execute: %s", command_line);
    post("command: Working directory: %s", x->path->s_name);

    BOOL result = CreateProcess(
        NULL,                   // No module name (use command line)
        command_line,           // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        TRUE,                   // Set handle inheritance to TRUE
        0,                      // No creation flags
        NULL,                   // Use parent's environment block
        NULL,                   // Use parent's starting directory 
        &si,                    // Pointer to STARTUPINFO structure
        &x->pi                  // Pointer to PROCESS_INFORMATION structure
    );

    if (!result) {
        DWORD error = GetLastError();
        char error_msg[1024];
        FormatMessage(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            error_msg,
            1024,
            NULL
        );
        pd_error(x, "command: failed to create process. Error %d: %s", error, error_msg);
        return;
    }

    CloseHandle(x->stdin_pipe[0]);
    CloseHandle(x->stdout_pipe[1]);
    CloseHandle(x->stderr_pipe[1]);
#else
    if (pipe(x->stdin_pipe) == -1 || pipe(x->stdout_pipe) == -1 || pipe(x->stderr_pipe) == -1) {
        pd_error(x, "command: failed to create pipes");
        return;
    }

    x->pid = fork();
    if (x->pid == -1) {
        pd_error(x, "command: fork failed");
        return;
    } else if (x->pid == 0) {
        // Child process
        dup2(x->stdin_pipe[0], STDIN_FILENO);
        dup2(x->stdout_pipe[1], STDOUT_FILENO);
        dup2(x->stderr_pipe[1], STDERR_FILENO);
        
        close(x->stdin_pipe[0]);
        close(x->stdin_pipe[1]);
        close(x->stdout_pipe[0]);
        close(x->stdout_pipe[1]);
        close(x->stderr_pipe[0]);
        close(x->stderr_pipe[1]);

        if (chdir(x->path->s_name) == -1) {
            pd_error(x, "command: chdir failed");
            exit(1);
        }

        execvp(argv[0], argv);
        pd_error(x, "command: exec failed");
        exit(1);
    } else {
        // Parent process
        close(x->stdin_pipe[0]);
        close(x->stdout_pipe[1]);
        close(x->stderr_pipe[1]);
    }
#endif

    if (x->x_sync) {
        while (1) {
            command_check(x);
#ifdef _WIN32
            DWORD exit_code;
            if (GetExitCodeProcess(x->pi.hProcess, &exit_code) && exit_code != STILL_ACTIVE) {
                break;
            }
#else
            int status;
            if (waitpid(x->pid, &status, WNOHANG) == x->pid) {
                break;
            }
#endif
        }
    } else {
        x->x_del = 4;
        clock_delay(x->x_clock, x->x_del);
    }
}

static void command_send(t_command *x, t_symbol *s, int ac, t_atom *at)
{
    char buf[INBUFSIZE];
    int len = 0;
    
    for (int i = 0; i < ac && len < INBUFSIZE - 1; i++) {
        atom_string(at + i, buf + len, INBUFSIZE - len - 1);
        len += strlen(buf + len);
        if (i < ac - 1 && len < INBUFSIZE - 1) {
            buf[len++] = ' ';
        }
    }
    
    if (len > 0) {
#ifdef _WIN32
        DWORD bytes_written;
        WriteFile(x->stdin_pipe[1], buf, len, &bytes_written, NULL);
#else
        write(x->stdin_pipe[1], buf, len);
#endif
    }
}

static void command_kill(t_command *x)
{
#ifdef _WIN32
    if (x->pi.hProcess) {
        TerminateProcess(x->pi.hProcess, 1);
    }
#else
    if (x->pid > 0) {
        kill(x->pid, SIGTERM);
    }
#endif
}

static void *command_new(t_symbol *s, int argc, t_atom *argv)
{
    t_command *x = (t_command *)pd_new(command_class);
    
    x->x_done = outlet_new(&x->x_obj, &s_float);
    x->x_stdout = outlet_new(&x->x_obj, &s_anything);
    x->x_stderr = outlet_new(&x->x_obj, &s_anything);
    x->x_clock = clock_new(x, (t_method)command_check);
    x->path = canvas_getdir(canvas_getcurrent());
    x->x_bin = 0;
    x->x_sync = 0;

#ifdef _WIN32
    x->pi.hProcess = NULL;
#else
    x->pid = -1;
#endif

    // Parse flags
    while (argc > 0 && argv->a_type == A_SYMBOL && *argv->a_w.w_symbol->s_name == '-') {
        if (strcmp(argv->a_w.w_symbol->s_name, "-b") == 0) {
            x->x_bin = 1;
        } else if (strcmp(argv->a_w.w_symbol->s_name, "-s") == 0) {
            x->x_sync = 1;
        }
        argc--;
        argv++;
    }

    return (x);
}

static void command_free(t_command *x)
{
    command_kill(x);
    clock_free(x->x_clock);
}

void command_setup(void)
{
    command_class = class_new(gensym("command"), (t_newmethod)command_new,
                        (t_method)command_free, sizeof(t_command), 0, A_GIMME, 0);
    class_addmethod(command_class, (t_method)command_exec, gensym("exec"),
        A_GIMME, 0);
    class_addmethod(command_class, (t_method)command_kill, gensym("kill"), 0);
    class_addmethod(command_class, (t_method)command_send, gensym("send"),
        A_GIMME, 0);
}