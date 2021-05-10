/*************************************************************************
*
* Copyright 2021 highstreet technologies GmbH and others
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

#include "blank.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/nts_utils.h"
#include <stdio.h>
#include <assert.h>

#include "core/framework.h"
#include "core/container.h"
#include "core/session.h"
#include "core/nc_config.h"

#define DOCKER_DEPLOY_ZIP   "/opt/dev/deploy.zip"
#define FTP_DEPLOY_ZIP      "/ftp/deploy.zip"

//checkAL: see all todos if doing also YANG-install through netopeer

int blank_run(void) {
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"running as BLANK NTS daemon...\n"LOG_COLOR_RESET);
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"Docker IP:"LOG_COLOR_RESET" %s\n", framework_environment.settings.ip_v6_enabled ? framework_environment.settings.ip_v6 : framework_environment.settings.ip_v4);

    char shell_command[512];

    if(session_init() != NTS_ERR_OK) {
        log_error("session_init() failed\n");
        return NTS_ERR_FAILED;
    }

    if(netconf_configure() != NTS_ERR_OK) {
        log_error("netconf_configure() failed\n")
        return NTS_ERR_FAILED;
    }

    session_free();

    vsftp_daemon_init();
    sftp_daemon_init();

    //todo: run netopeer

    char *zipfile = DOCKER_DEPLOY_ZIP;
    if(file_exists(zipfile)) {
        goto blank_install_zip;
    }
    else {
        log_add_verbose(2, "%s was not found, waiting for deploy.zip on other means...\n");
    }

blank_run_wait_for_file:
    while(!framework_sigint) {
        zipfile = FTP_DEPLOY_ZIP;
        if(file_exists(zipfile)) {
            goto blank_install_zip;
        }

        //todo: check netopeer for data

        sleep(1);
    }

    vsftp_daemon_deinit();
    sftp_daemon_deinit();

    log_error("blank image daemon was called to stop before installing anything\n");
    return NTS_ERR_FAILED;


blank_install_zip: {
        log_add_verbose(1, "found deploy.zip in "LOG_COLOR_BOLD_BLUE"%s"LOG_COLOR_RESET"\n", zipfile);
        log_add_verbose(1, "starting install...\n");
        
        //check if zip is ok
        sprintf(shell_command, "unzip -qq -t %s", zipfile);
        if(system(shell_command) != 0) {
            log_error("%s invalid ZIP file\n", zipfile);
            goto blank_install_failed;
        }
        
        //unzip to /opt/dev/deploy
        sprintf(shell_command, "unzip -qq %s -d /opt/dev/deploy", zipfile);
        if(system(shell_command) != 0) {
            log_error("unzip filed for unknown reason\n", zipfile);
            goto blank_install_failed;
        }

        if(strcmp(zipfile, FTP_DEPLOY_ZIP) == 0) {
            sprintf(shell_command, "rm -f %s", zipfile);
            if(system(shell_command) != 0) {
                log_error("failed to remove %s\n", zipfile);
            }
        }

        if(!file_exists("/opt/dev/deploy/config.json")) {
            log_error("/opt/dev/deploy/config.json not found!\n");
            goto blank_install_failed;
        }

        //move /opt/dev/deploy/config.json to /opt/dev/ntsim-ng/config/config.json
        system("mv /opt/dev/deploy/config.json /opt/dev/ntsim-ng/config/config.json");

        //todo: kill netopeer

        //run container_self_init()
        if(!container_self_init()) {
            log_error("container_self_init() error\n");
            goto blank_install_failed;
        }

        //send SIGUSR1 to supervisor to reload everything and start fresh
        kill(1, SIGUSR1);

        log_add_verbose(1, LOG_COLOR_BOLD_GREEN"blank image successfully replaced!"LOG_COLOR_RESET"\n");
        vsftp_daemon_deinit();
        sftp_daemon_deinit();

        return NTS_ERR_OK;
    }

blank_install_failed: {
        //remove zipfile
        sprintf(shell_command, "rm -rf %s", zipfile);
        system(shell_command);

        system("rm -rf /opt/dev/deploy");

        log_error("%s failed to install...\n", zipfile);
        log_error("try again with new file...\n");
        goto blank_run_wait_for_file;
    }
}
