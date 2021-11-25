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

#pragma once


#define NTS_MANAGER_MODULE                                      "nts-manager"
#define NTS_MANAGER_SIMULATION_SCHEMA_XPATH                     "/nts-manager:simulation"
#define NTS_MANAGER_AVAILABLE_IMAGES_SCHEMA_XPATH               "/nts-manager:simulation/available-images"
#define NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH                  "/nts-manager:simulation/network-functions/network-function"
#define NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH                 "/nts-manager:simulation/sdn-controller"
#define NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH                   "/nts-manager:simulation/ves-endpoint"

#define NTS_NETWORK_FUNCTION_MODULE                             "nts-network-function"
#define NTS_NF_INFO_SCHEMA_XPATH                                "/nts-network-function:info"
#define NTS_NF_NETWORK_FUNCTION_SCHEMA_XPATH                    "/nts-network-function:simulation/network-function"
#define NTS_NF_NETWORK_FUNCTION_FTYPE_SCHEMA_XPATH              "/nts-network-function:simulation/network-function/function-type"
#define NTS_NF_NETWORK_FUNCTION_MPAM_SCHEMA_XPATH               "/nts-network-function:simulation/network-function/mount-point-addressing-method"
#define NTS_NF_FAULT_GENERATION_SCHEMA_XPATH                    "/nts-network-function:simulation/network-function/fault-generation"
#define NTS_NF_FAULT_COUNT_LIST_SCHEMA_XPATH                    "/nts-network-function:simulation/network-function/fault-generation/fault-count"
#define NTS_NF_NETCONF_SCHEMA_XPATH                             "/nts-network-function:simulation/network-function/netconf"
#define NTS_NF_NETCONF_CALLHOME_ENABLED_SCHEMA_PATH             "/nts-network-function:simulation/network-function/netconf/call-home"
#define NTS_NF_NETCONF_FAULTS_ENABLED_SCHEMA_PATH               "/nts-network-function:simulation/network-function/netconf/faults-enabled"
#define NTS_NF_VES_SCHEMA_XPATH                                 "/nts-network-function:simulation/network-function/ves"
#define NTS_NF_VES_FAULTS_ENABLED_SCHEMA_XPATH                  "/nts-network-function:simulation/network-function/ves/faults-enabled"
#define NTS_NF_VES_HEARTBEAT_SCHEMA_XPATH                       "/nts-network-function:simulation/network-function/ves/heartbeat-period"
#define NTS_NF_VES_PNF_REGISTRATION_SCHEMA_XPATH                "/nts-network-function:simulation/network-function/ves/pnf-registration"
#define NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH                   "/nts-network-function:simulation/network-emulation"
#define NTS_NF_HARDWARE_EMULATION_SCHEMA_XPATH                  "/nts-network-function:simulation/hardware-emulation"
#define NTS_NF_HE_NETCONF_DELAY_SCHEMA_XPATH                    "/nts-network-function:simulation/hardware-emulation/netconf-delay"
#define NTS_NF_VES_ENDPOINT_CONFIG_XPATH                        "/nts-network-function:simulation/ves-endpoint"
#define NTS_NF_SDN_CONTROLLER_CONFIG_XPATH                      "/nts-network-function:simulation/sdn-controller"

#define NTS_NF_RPC_POPULATE_SCHEMA_XPATH                        "/nts-network-function:datastore-populate"
#define NTS_NF_RPC_FEATURE_CONTROL_SCHEMA_XPATH                 "/nts-network-function:feature-control"
#define NTS_NF_RPC_FAULTS_CLEAR_SCHEMA_XPATH                    "/nts-network-function:clear-fault-counters"
#define NTS_NF_RPC_MANUAL_NOTIF_SCHEMA_XPATH                    "/nts-network-function:invoke-notification"
#define NTS_NF_RPC_FILE_READY_SCHEMA_XPATH                      "/nts-network-function:invoke-ves-pm-file-ready"
#define NTS_NF_RPC_EMULATE_TOTAL_LOSS_SCHEMA_XPATH              "/nts-network-function:emulate-total-loss"

#define NTS_NF_ORAN_DU_MODULE                                   "o-ran-sc-du-hello-world"
#define NTS_NF_ORAN_DU_PM_JOBS_SCHEMA_XPATH                     "/o-ran-sc-du-hello-world:network-function/performance-measurement-jobs"
#define NTS_NF_ORAN_DU_SUBSCRIPTION_STREAMS_SCHEMA_XPATH        "/o-ran-sc-du-hello-world:network-function/subscription-streams"

#define IETF_KEYSTORE_MODULE                                    "ietf-keystore"
#define IETF_KEYSTORE_SCHEMA_XPATH                              "/ietf-keystore:keystore"
#define IETF_KEYSTORE_ASYMETRIC_KEY_SCHEMA_XPATH                "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']"

#define IETF_TRUSTSTORE_MODULE                                  "ietf-truststore"
#define IETF_TRUSTSTORE_CERT_PATH_SCHEMA_XPATH                  "/ietf-truststore:truststore/certificates[name='clientcerts']/certificate[name='clientcert']/cert"
#define IETF_TRUSTSTORE_CA_CERT_PATH_SCHEMA_XPATH               "/ietf-truststore:truststore/certificates[name='cacerts']/certificate[name='cacert']/cert"

#define IETF_NETCONF_ACM_MODULE                                 "ietf-netconf-acm"
#define IETF_NETCONF_ACM_ENABLE_NACM_SCHEMA_XPATH               "/ietf-netconf-acm:nacm/enable-nacm"
#define IETF_NETCONF_ACM_GROUPS_SCHEMA_XPATH                    "/ietf-netconf-acm:nacm/groups"
#define IETF_NETCONF_ACM_RULE_LIST_SCHEMA_XPATH                 "/ietf-netconf-acm:nacm/rule-list"

#define IETF_NETCONF_MONITORING_MODULE                          "ietf-netconf-monitoring"
#define IETF_NETCONF_MONITORING_STATE_SCHEMAS_SCHEMA_XPATH      "/ietf-netconf-monitoring:netconf-state/schemas"

#define IETF_NETCONF_SERVER_MODULE                              "ietf-netconf-server"
#define IETF_NETCONF_SERVER_SCHEMA_XPATH                        "/ietf-netconf-server:netconf-server"
#define IETF_NETCONF_SERVER_CH_SSH_TCP_CLIENT_SCHEMA_XPATH      "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='default-client']/endpoints/endpoint[name='callhome-ssh']/ssh/tcp-client-parameters"
#define IETF_NETCONF_SERVER_CH_SSH_SERVER_PARAMS_SCEHMA_XPATH   "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='default-client']/endpoints/endpoint[name='callhome-ssh']/ssh/ssh-server-parameters"
#define IETF_NETCONF_SERVER_CH_CONN_PERSISTENT_SCHEMA_XPATH     "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='default-client']/connection-type/persistent"
#define IETF_NETCONF_SERVER_CH_TLS_TCP_CLIENT_SCHEMA_XPATH      "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='default-client']/endpoints/endpoint[name='callhome-tls']/tls/tcp-client-parameters"
#define IETF_NETCONF_SERVER_CH_TLS_SERVER_PARAMS_SCEHMA_XPATH   "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='default-client']/endpoints/endpoint[name='callhome-tls']/tls/tls-server-parameters"

#define IETF_NETCONF_SERVER_SSH_TCP_SERVER_PARAM_SCHEMA_XPATH   "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/tcp-server-parameters"
#define IETF_NETCONF_SERVER_SSH_SERVER_PARAM_SCHEMA_XPATH       "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters"
#define IETF_NETCONF_SERVER_TLS_TCP_SERVER_PARAM_SCHEMA_XPATH   "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tcp-server-parameters"
#define IETF_NETCONF_SERVER_TLS_SERVER_PARAM_SCHEMA_XPATH       "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters"

#define IETF_SYSTEM_NAME_SCHEMA_XPATH                           "/ietf-system:system/onap-system:name"
#define IETF_SYSTEM_WEB_UI_SCHEMA_XPATH                         "/ietf-system:system/onap-system:web-ui"
#define IETF_SYSTEM_CONTACT_SCHEMA_XPATH                        "/ietf-system:system/contact"
#define IETF_SYSTEM_HOSTNAME_SCHEMA_XPATH                       "/ietf-system:system/hostname"
#define IETF_SYSTEM_LOCATION_SCHEMA_XPATH                       "/ietf-system:system/location"
#define IETF_SYSTEM_TIMEZONE_NAME_SCHEMA_XPATH                  "/ietf-system:system/clock/timezone-name"
#define IETF_SYSTEM_NTP_ENABLED_SCHEMA_XPATH                    "/ietf-system:system/ntp/enabled"

#define NC_NOTIFICATIONS_MODULE                                 "nc-notifications"
#define NC_NOTIFICATIONS_STREAMS_SCHEMA_XPATH                   "/nc-notifications:netconf/streams"
