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

#include "manager.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "core/framework.h"
#include "core/session.h"
#include "core/xpath.h"

static manager_operation_t *manager_operations;
static pthread_mutex_t manager_operations_mutex;
static sem_t manager_operations_sem;

manager_protocol_type_t manager_port[65536];

static int manager_operations_execute(manager_operation_t *oper);

int manager_operations_init(void) {
    manager_operations = 0;
    if(pthread_mutex_init(&manager_operations_mutex, NULL) != 0) { 
        log_error("mutex init has failed\n"); 
        return NTS_ERR_FAILED; 
    }

    if(sem_init(&manager_operations_sem, 0, 0) != 0) {
        log_error("sem init has failed\n"); 
        return NTS_ERR_FAILED; 
    }

    //checkAL ar fi misto sa stim ce porturi sunt si ce porturi nu sunt available...
    for(int i = 0; i < 1000; i++) {
        manager_port[i] = MANAGER_PROTOCOL_UNAVAILABLE;
    }

    for(int i = 1000; i < 65536; i++) {
        manager_port[i] = MANAGER_PROTOCOL_UNUSED;
    }

    return NTS_ERR_OK;
}

void manager_operations_loop(void) {
    int rc;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;

    if(sem_timedwait(&manager_operations_sem, &ts) == 0) {
        int retries = 10;
        while(retries) {
            rc = sr_lock(session_running, NTS_MANAGER_MODULE);
            if(rc == SR_ERR_OK) {
                break;
            }
            else {
                sleep(1);
            }
            retries--;
        }

        if(retries == 0) {
            log_error("sr_lock failed\n");
            //checkAL ce facem acum ?
        }

        pthread_mutex_lock(&manager_operations_mutex);

        const char *status = "SUCCESS";
        char errmsg[256];
        errmsg[0] = 0;

        while(manager_operations) {
            //pop operation from list
            manager_operation_t *oper = manager_operations;
            manager_operations = manager_operations->next;       
            
            //if operation is RPC first update any *other* fields

            rc = manager_operations_execute(oper);
            if(rc != NTS_ERR_OK) {
                log_error("manager_operations_execute failed\n");
                status = "FAILED";
                strcpy(errmsg, oper->errmsg);
                manager_operations_free_oper(oper);
                break;
            }

            manager_operations_free_oper(oper);
        }

        for(int i = 0; i < docker_context_count; i++) {
            //do any reconfig necesarry
            for(int j = 0; j < manager_context[i].started_instances; j++) {
                if(manager_context[i].instance[j].is_configured == false) {
                    rc = manager_actions_config_instance(&manager_context[i], &manager_context[i].instance[j]);
                    if(rc != NTS_ERR_OK) {
                        status = "reconfig FAILED";
                        sprintf(errmsg, "reconfig FAILED - instance %s", manager_context[i].instance[j].container.name);
                        log_error("%s\n", errmsg);
                    }
                }
            }
        }

        rc = manager_sr_on_last_operation_status(status, errmsg);
        if(rc != NTS_ERR_OK) {
            log_error("manager_sr_on_last_operation_status failed\n");
        }

        pthread_mutex_unlock(&manager_operations_mutex);
        rc = sr_unlock(session_running, NTS_MANAGER_MODULE);    //release datastore
        if(rc != SR_ERR_OK) {
            log_error("sr_unlock failed\n");
        }
    }
}

void manager_operations_free(void) {
    //terminate all containers
    for(int i = 0; i < docker_context_count; i++) {
        while(manager_context[i].started_instances) {
            manager_actions_stop(&manager_context[i]);
        }
    }

    sem_destroy(&manager_operations_sem);
    pthread_mutex_destroy(&manager_operations_mutex);
}

manager_operation_t *manager_operations_new_oper(manager_operation_type_t type) {
    manager_operation_t *new_oper = malloc(sizeof(manager_operation_t));
    if(new_oper == 0) {
        log_error("malloc failed\n");
        return 0;
    }

    new_oper->type = type;

    new_oper->ft_index = -1;
    new_oper->function_type = 0;

    new_oper->started_instances = -1;
    new_oper->mounted_instances = -1;
    
    new_oper->docker_instance_name = 0;
    new_oper->docker_version_tag = 0;
    new_oper->docker_repository = 0;

    new_oper->mount_point_addressing_method = 0;

    new_oper->fault_generation.delay_period = 0;
    new_oper->fault_generation.delay_period_count = -1;

    new_oper->netconf.faults_enabled = -1;
    new_oper->netconf.call_home = -1;

    new_oper->ves.faults_enabled = -1;
    new_oper->ves.pnf_registration = -1;
    new_oper->ves.heartbeat_period = -1;

    new_oper->errmsg = 0;
    new_oper->next = 0;
    
    return new_oper;
}

int manager_operations_free_oper(manager_operation_t *oper) {
    assert(oper);

    free(oper->function_type);
    free(oper->docker_instance_name);
    free(oper->docker_repository);
    free(oper->docker_version_tag);
    free(oper->mount_point_addressing_method);
    free(oper->errmsg);

    free(oper);
    return NTS_ERR_OK;
}

int manager_operations_begin(void) {
    return pthread_mutex_lock(&manager_operations_mutex);
}

int manager_operations_add(manager_operation_t *oper) {
    assert(oper);

    if(manager_operations == 0) {
        manager_operations = oper;
    }
    else {
        manager_operation_t *h = manager_operations;
        while(h->next) {
            h = h->next;
        }
        h->next = oper;
    }

    return NTS_ERR_OK;
}

void manager_operations_finish_and_execute(void) {
    pthread_mutex_unlock(&manager_operations_mutex);
    sem_post(&manager_operations_sem);
}

void manager_operations_finish_with_error(void) {
    while(manager_operations) {
        manager_operation_t *h = manager_operations->next;
        manager_operations_free_oper(manager_operations);
        manager_operations = h;
    }
    pthread_mutex_unlock(&manager_operations_mutex);
    sem_post(&manager_operations_sem);
}



int manager_operations_validate(manager_operation_t *oper) {
    assert(oper);
    
    //prepopulate unset values
    if(oper->docker_instance_name == 0) {
        oper->docker_instance_name = strdup(manager_context[oper->ft_index].docker_instance_name);
    }

    if(oper->docker_repository == 0) {
        oper->docker_repository = strdup(manager_context[oper->ft_index].docker_repository);
    }

    if(oper->docker_version_tag == 0) {
        oper->docker_version_tag = strdup(manager_context[oper->ft_index].docker_version_tag);
    }

    if(oper->started_instances == -1) {
        oper->started_instances = manager_context[oper->ft_index].started_instances;
    }

    if(oper->mounted_instances == -1) {
        oper->mounted_instances = manager_context[oper->ft_index].mounted_instances;
    }

    //check docker image if exists
    bool found = false;
    for(int i = 0; i < docker_context[oper->ft_index].available_images_count; i++) {
        if(strcmp(docker_context[oper->ft_index].available_images[i].repo, oper->docker_repository) == 0) {
            if(strcmp(docker_context[oper->ft_index].available_images[i].tag, oper->docker_version_tag) == 0) {
                found = true;
                break;
            }
        }
    }

    if(found == false) {
        log_error("could not find image: %s/%s:%s\n", oper->docker_repository, docker_context[oper->ft_index].image, oper->docker_version_tag);
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int manager_operations_execute(manager_operation_t *oper) {
    assert(oper);

    int k = oper->ft_index;
    int rc;

    //operation --> actions
    if(manager_context[k].started_instances > oper->started_instances) {
        //stop instances
        while(manager_context[k].started_instances > oper->started_instances) {

            rc = manager_actions_stop(&manager_context[k]);
            if(rc != NTS_ERR_OK) {
                asprintf(&oper->errmsg, "stop FAILED - function-type %s", manager_context[k].function_type);
                log_error("%s\n", oper->errmsg);
                
                return NTS_ERR_FAILED;
            }

            rc = manager_sr_update_context(&manager_context[k]);
            if(rc != NTS_ERR_OK) {
                log_error("manager_sr_update_context failed\n");
            }
        }

    }
    else if(manager_context[k].started_instances < oper->started_instances) {
        //start instances     
        while(manager_context[k].started_instances < oper->started_instances) {

            rc = manager_actions_start(&manager_context[k]);
            if(rc != NTS_ERR_OK) {
                asprintf(&oper->errmsg, "start FAILED - function-type %s", manager_context[k].function_type);
                log_error("%s\n", oper->errmsg);
                return NTS_ERR_FAILED;
            }
          
            rc = manager_sr_update_context(&manager_context[k]);
            if(rc != NTS_ERR_OK) {
                log_error("manager_sr_update_context failed\n");
            }

            rc = manager_actions_config_instance(&manager_context[k], &manager_context[k].instance[manager_context[k].started_instances - 1]);
            if(rc != NTS_ERR_OK) {
                asprintf(&oper->errmsg, "config FAILED - instance %s", manager_context[k].instance[manager_context[k].started_instances - 1].container.name);
                log_error("%s\n", oper->errmsg);
            }
        }
    }

    if(manager_context[k].mounted_instances > oper->mounted_instances) {
        //unmount instances
        while(manager_context[k].mounted_instances > oper->mounted_instances) {
            rc = manager_actions_unmount(&manager_context[k]);
            if(rc != NTS_ERR_OK) {
                asprintf(&oper->errmsg, "unmount FAILED - instance %s", manager_context[k].instance[manager_context[k].mounted_instances - 1].container.name);
                log_error("%s\n", oper->errmsg);
                return NTS_ERR_FAILED;
            }

            rc = manager_sr_update_context(&manager_context[k]);
            if(rc != NTS_ERR_OK) {
                log_error("manager_sr_update_context failed\n");
            }
        }

    }
    else if(manager_context[k].mounted_instances < oper->mounted_instances) {
        //mount instances     
        while(manager_context[k].mounted_instances < oper->mounted_instances) {
            rc = manager_actions_mount(&manager_context[k]);
            if(rc != NTS_ERR_OK) {
                asprintf(&oper->errmsg, "mount FAILED - instance %s", manager_context[k].instance[manager_context[k].mounted_instances].container.name);
                log_error("%s\n", oper->errmsg);
                return NTS_ERR_FAILED;
            }
            
            rc = manager_sr_update_context(&manager_context[k]);
            if(rc != NTS_ERR_OK) {
                log_error("manager_sr_update_context failed\n");
            }
        }
    }

    return NTS_ERR_OK;
}
