/*************************************************************************
*
* Copyright 2020 highstreet technologies GmbH and others
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
***************************************************************************/

#define _GNU_SOURCE

#include "supervisor.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include <stdio.h>
#include <assert.h>

#include "core/framework.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>

typedef struct {
    char *name;
    char *path;
    char **args;
    bool nomanual;
    bool autorestart;
    char *stdout_path;
    char *stderr_path;

    pid_t pid;
    int running;
} supervisor_control_block_t;

static void supervisor_spawn(supervisor_control_block_t *scb);
static void supervisor_free_scb(int count, supervisor_control_block_t *scb);
static void supervisor_on_signal(int signo);
static void supervisor_on_sigusr(int signo);

static volatile sig_atomic_t supervisor_got_signal_stop = 0;
static volatile sig_atomic_t supervisor_got_signal_reload = 0;
static bool nts_manual;

int supervisor_run(int argc, char **argv) {
supervisor_start:
    if(file_exists("/opt/dev/deploy/.env")) {
        FILE * fp;
        char * line = 0;
        size_t len = 0;
        ssize_t read;

        fp = fopen("/opt/dev/deploy/.env", "r");
        if(fp) {
            log_add_verbose(1, "[supervisor] found /opt/dev/deploy/.env\n");

            while ((read = getline(&line, &len, fp)) != -1) {
                if(line[strlen(line) - 1] == '\n') {
                    line[strlen(line) - 1] = 0;
                }

                log_add_verbose(1, "[supervisor] adding .env var: %s\n", line);
                putenv(strdup(line));
            }

            fclose(fp);
            free(line);
        }
    }

    supervisor_got_signal_reload = 0;
    supervisor_got_signal_stop = 0;

    int scb_count = framework_config.supervisor.rules_count;
    supervisor_control_block_t *scb = (supervisor_control_block_t*)malloc(sizeof(supervisor_control_block_t) * framework_config.supervisor.rules_count);
    if(scb == 0) {
        log_error("malloc failed\n");
        return NTS_ERR_FAILED;
    }

    for(int i = 0; i < scb_count; i++) {
        scb[i].name = strdup(framework_config.supervisor.rules[i].name);
        scb[i].path = strdup(framework_config.supervisor.rules[i].path);
        scb[i].args = malloc(sizeof(char *) * (framework_config.supervisor.rules[i].args_count + 2));
        scb[i].args[0] = strdup(framework_config.supervisor.rules[i].path);
        for(int j = 0; j < framework_config.supervisor.rules[i].args_count; j++) {
            scb[i].args[j + 1] = strdup(framework_config.supervisor.rules[i].args[j]);
        }
        scb[i].args[framework_config.supervisor.rules[i].args_count + 1] = 0;
        scb[i].autorestart = framework_config.supervisor.rules[i].autorestart;
        scb[i].nomanual = framework_config.supervisor.rules[i].nomanual;
        scb[i].stdout_path = framework_config.supervisor.rules[i].stdout_path ? strdup(framework_config.supervisor.rules[i].stdout_path) : 0;
        scb[i].stderr_path = framework_config.supervisor.rules[i].stderr_path ? strdup(framework_config.supervisor.rules[i].stderr_path) : 0;
        scb[i].pid = 0;
        scb[i].running = 0;
    }

    nts_manual = framework_environment.nts.manual;
    
    signal(SIGINT, supervisor_on_signal);
    signal(SIGTERM, supervisor_on_signal);
    signal(SIGQUIT, supervisor_on_signal);
    signal(SIGUSR1, supervisor_on_sigusr);

    for(int i = 0; i < scb_count; i++) {
        supervisor_spawn(&scb[i]);
        log_add_verbose(1, "[supervisor] spawning %s... with pid %lu\n", scb[i].name, scb[i].pid);
    }

    int running = 1;
    while(running) {
        int defunct_status;
        pid_t defunct_pid = waitpid(-1, &defunct_status, WNOHANG);
        if(defunct_pid > 0) {
            for(int i = 0; i < scb_count; i++) {
                if(scb[i].pid == defunct_pid) {
                    log_add_verbose(1, "[supervisor] process %s (pid=%lu) exited with status %d\n", scb[i].name, defunct_pid, defunct_status);
                    scb[i].running = 0;
                    if(scb[i].autorestart) {
                        supervisor_spawn(&scb[i]);
                        log_add_verbose(1, "[supervisor] respawned %s (pid=%lu)\n", scb[i].name, scb[i].pid);
                    }
                }
            }
        }

        if(supervisor_got_signal_stop) {
            for(int i = 0; i < scb_count; i++) {
                if(scb[i].running) {
                    log_add_verbose(1, "[supervisor] sending %d to %s (pid=%lu)...\n", supervisor_got_signal_stop, scb[i].name, scb[i].pid);
                    kill(scb[i].pid, supervisor_got_signal_stop);
                }
            }
            supervisor_got_signal_stop = 0;
            running = 0;
        }

        sleep(1);
    }
    
    //after SIGTERM was forwarded
    running = 1;
    while(running) {
        int defunct_status;
        pid_t defunct_pid = waitpid(-1, &defunct_status, WNOHANG);
        if(defunct_pid > 0) {
            char *name = 0;
            for(int i = 0; i < scb_count; i++) {
                if(scb[i].pid == defunct_pid) {
                    scb[i].running = 0;
                    name = scb[i].name;
                }
            }
            log_add_verbose(1, "[supervisor] process %s (pid=%d) exited with status %d\n", name, defunct_pid, defunct_status);
        }

        running = 0;
        for(int i = 0; i < scb_count; i++) {
            if(scb[i].running == 1) {
                running = 1;
            }
        }
    }

    supervisor_free_scb(scb_count, scb);
    framework_free();

    if(supervisor_got_signal_reload) {
        if(framework_init(argc, argv) != NTS_ERR_OK) {
            log_error(LOG_COLOR_BOLD_RED"framework_init() error\n");
            framework_free();
            return EXIT_FAILURE;
        }

        log_add_verbose(1, "[supervisor] SIGUSR1 received, restarting everything... (this is a *new* logfile)\n");

        goto supervisor_start;
    }

    return NTS_ERR_OK;
}

static void supervisor_spawn(supervisor_control_block_t *scb) {
    if(nts_manual && scb->nomanual) {
        return;
    }

    scb->running = 1;
    scb->pid = fork();
    if(scb->pid == -1) {
        log_error("fork() failed\n");
        return;
    }

    if(scb->pid == 0) {
        //child process
        int stdout_fd = 0;
        int stderr_fd = 0;

        signal(SIGINT, 0);
        signal(SIGTERM, 0);
        signal(SIGQUIT, 0);
        framework_free();
        setsid();

        if(scb->stdout_path) {
            if(scb->stdout_path[0] == 0) {
                free(scb->stdout_path);
                scb->stdout_path = strdup("/dev/null");
            }
            stdout_fd = open(scb->stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            dup2(stdout_fd, STDOUT_FILENO);
        }

        if(scb->stderr_path) {
            if(scb->stderr_path[0] == 0) {
                free(scb->stderr_path);
                scb->stderr_path = strdup("/dev/null");
            }
            stderr_fd = open(scb->stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            dup2(stderr_fd, STDERR_FILENO);
        }

        execv(scb->path, scb->args);
        _exit(0);
    }
}

static void supervisor_free_scb(int count, supervisor_control_block_t *scb) {
    for(int i = 0; i < count; i++) {
        free(scb[i].name);
        free(scb[i].path);
        int j = 0;
        while(scb[i].args[j]) {
            free(scb[i].args[j]);
            j++;
        }
        free(scb[i].args);
        free(scb[i].stdout_path);
        free(scb[i].stderr_path);
    }

    free(scb);
}

static void supervisor_on_signal(int signo) {
    supervisor_got_signal_stop = signo;
}

static void supervisor_on_sigusr(int signo) {
    supervisor_got_signal_stop = SIGTERM;
    supervisor_got_signal_reload = 1;
}
