#!/bin/bash

echo $(date) " - Starting Script"

set -e

SUDOUSER=$1
PASSWORD="$2"
PRIVATEKEY=$3
MASTER=$4
MASTERPUBLICIPHOSTNAME=$5
MASTERPUBLICIPADDRESS=$6
ROUTING=${7}
TENANTID=${8}
SUBSCRIPTIONID=${9}
AADCLIENTID=${10}
AADCLIENTSECRET="${11}"
RESOURCEGROUP=${12}
LOCATION=${13}

BASTION=$(hostname -f)

echo "$SUDOUSER - $PASSWORD - $MASTER - $MASTERPUBLICIPHOSTNAME - $MASTERPUBLICIPADDRESS - $ROUTING "
echo "$TENANTID - $SUBSCRIPTIONID - $AADCLIENTID - $AADCLIENTSECRET - $RESOURCEGROUP - $LOCATION"
echo "$BASTION"

# Generate private keys for use by Ansible
echo $(date) " - Generating Private keys for use by Ansible for OpenShift Installation"

echo "Generating Private Keys"

runuser -l $SUDOUSER -c "echo \"$PRIVATEKEY\" > ~/.ssh/id_rsa"
runuser -l $SUDOUSER -c "chmod 600 ~/.ssh/id_rsa*"

echo "Configuring SSH ControlPath to use shorter path name"

sed -i -e "s/^# control_path = %(directory)s\/%%h-%%r/control_path = %(directory)s\/%%h-%%r/" /etc/ansible/ansible.cfg
sed -i -e "s/^#host_key_checking = False/host_key_checking = False/" /etc/ansible/ansible.cfg
sed -i -e "s/^#pty=False/pty=False/" /etc/ansible/ansible.cfg

# Create Ansible Playbooks for Post Installation tasks
echo $(date) " - Create Ansible Playbooks for Post Installation tasks"

# Run on all masters - Create Inital OpenShift User on all Masters
cat > /home/${SUDOUSER}/addocpuser.yml <<EOF
---
- hosts: masters
  gather_facts: no
  remote_user: ${SUDOUSER}
  become: yes
  become_method: sudo
  vars:
    description: "Create OpenShift Users"
  tasks:
  - name: create directory
    file: path=/etc/origin/master state=directory
  - name: add initial OpenShift user
    shell: htpasswd -cb /etc/origin/master/htpasswd ${SUDOUSER} "${PASSWORD}"
EOF

# Run on only MASTER-0 - Make initial OpenShift User a Cluster Admin
cat > /home/${SUDOUSER}/assignclusteradminrights.yml <<EOF
---
- hosts: nfs
  gather_facts: no
  remote_user: ${SUDOUSER}
  become: yes
  become_method: sudo
  vars:
    description: "Make user cluster admin"
  tasks:
  - name: make OpenShift user cluster admin
    shell: oadm policy add-cluster-role-to-user cluster-admin $SUDOUSER --config=/etc/origin/master/admin.kubeconfig
EOF

# Run on all nodes - Set Root password on all nodes
cat > /home/${SUDOUSER}/assignrootpassword.yml <<EOF
---
- hosts: nodes
  gather_facts: no
  remote_user: ${SUDOUSER}
  become: yes
  become_method: sudo
  vars:
    description: "Set password for Cockpit"
  tasks:
  - name: configure Cockpit password
    shell: echo "${PASSWORD}"|passwd root --stdin
EOF

# Run on all masters
cat > /home/${SUDOUSER}/dockerregistry.yml <<EOF
---
- hosts: masters
  remote_user: ${SUDOUSER}
  become: yes
  become_method: sudo
  vars:
    description: "Unset default registry DNS name"
  tasks:
  - name: copy atomic-openshift-master file
    copy:
      src: /tmp/atomic-openshift-master
      dest: /etc/sysconfig/atomic-openshift-master
      owner: root
      group: root
      mode: 0644
EOF

# Run on MASTER-0 node - configure Storage Class
cat > /home/${SUDOUSER}/configurestorageclass.yml <<EOF
---
- hosts: master0
  gather_facts: no
  remote_user: ${SUDOUSER}
  become: yes
  become_method: sudo
  vars:
    description: "Create Storage Class"
  tasks:
  - name: Create Storage Class with StorageAccountPV1
    shell: oc create -f /home/${SUDOUSER}/scgeneric1.yml
EOF

# Create vars.yml file for use by setup-azure-config.yml playbook
cat > /home/${SUDOUSER}/vars.yml <<EOF
g_tenantId: $TENANTID
g_subscriptionId: $SUBSCRIPTIONID
g_aadClientId: $AADCLIENTID
g_aadClientSecret: $AADCLIENTSECRET
g_resourceGroup: $RESOURCEGROUP
g_location: $LOCATION
EOF

# Create Azure Cloud Provider configuration Playbook for Master Config
cat > /home/${SUDOUSER}/setup-azure-master.yml <<EOF
#!/usr/bin/ansible-playbook 
- hosts: masters
  gather_facts: no
  serial: 1
  vars_files:
  - vars.yml
  become: yes
  vars:
    azure_conf_dir: /etc/azure
    azure_conf: "{{ azure_conf_dir }}/azure.conf"
    master_conf: /etc/origin/master/master-config.yaml
  handlers:
  - name: restart atomic-openshift-master-api
    systemd:
      state: restarted
      name: atomic-openshift-master-api

  - name: restart atomic-openshift-master-controllers
    systemd:
      state: restarted
      name: atomic-openshift-master-controllers

  post_tasks:
  - name: make sure /etc/azure exists
    file:
      state: directory
      path: "{{ azure_conf_dir }}"

  - name: populate /etc/azure/azure.conf
    copy:
      dest: "{{ azure_conf }}"
      content: |
        {
          "aadClientID" : "{{ g_aadClientId }}",
          "aadClientSecret" : "{{ g_aadClientSecret }}",
          "subscriptionID" : "{{ g_subscriptionId }}",
          "tenantID" : "{{ g_tenantId }}",
          "resourceGroup": "{{ g_resourceGroup }}",
        } 
    notify:
    - restart atomic-openshift-master-api
    - restart atomic-openshift-master-controllers

  - name: insert the azure disk config into the master
    modify_yaml:
      dest: "{{ master_conf }}"
      yaml_key: "{{ item.key }}"
      yaml_value: "{{ item.value }}"
    with_items:
    - key: kubernetesMasterConfig.apiServerArguments.cloud-config
      value:
      - "{{ azure_conf }}"

    - key: kubernetesMasterConfig.apiServerArguments.cloud-provider
      value:
      - azure

    - key: kubernetesMasterConfig.controllerArguments.cloud-config
      value:
      - "{{ azure_conf }}"

    - key: kubernetesMasterConfig.controllerArguments.cloud-provider
      value:
      - azure
    notify:
    - restart atomic-openshift-master-api
    - restart atomic-openshift-master-controllers
EOF

# Create Azure Cloud Provider configuration Playbook for Node Config (Master Nodes)
cat > /home/${SUDOUSER}/setup-azure-node-master.yml <<EOF
#!/usr/bin/ansible-playbook 
- hosts: masters
  serial: 1
  gather_facts: no
  vars_files:
  - vars.yml
  become: yes
  vars:
    azure_conf_dir: /etc/azure
    azure_conf: "{{ azure_conf_dir }}/azure.conf"
    node_conf: /etc/origin/node/node-config.yaml
  handlers:
  - name: restart atomic-openshift-node
    systemd:
      state: restarted
      name: atomic-openshift-node
  post_tasks:
  - name: make sure /etc/azure exists
    file:
      state: directory
      path: "{{ azure_conf_dir }}"

  - name: populate /etc/azure/azure.conf
    copy:
      dest: "{{ azure_conf }}"
      content: |
        {
          "aadClientID" : "{{ g_aadClientId }}",
          "aadClientSecret" : "{{ g_aadClientSecret }}",
          "subscriptionID" : "{{ g_subscriptionId }}",
          "tenantID" : "{{ g_tenantId }}",
          "resourceGroup": "{{ g_resourceGroup }}",
        } 
    notify:
    - restart atomic-openshift-node
  - name: insert the azure disk config into the node
    modify_yaml:
      dest: "{{ node_conf }}"
      yaml_key: "{{ item.key }}"
      yaml_value: "{{ item.value }}"
    with_items:
    - key: kubeletArguments.cloud-config
      value:
      - "{{ azure_conf }}"

    - key: kubeletArguments.cloud-provider
      value:
      - azure
    notify:
    - restart atomic-openshift-node
EOF

# Create Azure Cloud Provider configuration Playbook for Node Config (Non-Master Nodes)
cat > /home/${SUDOUSER}/setup-azure-node.yml <<EOF
#!/usr/bin/ansible-playbook 
- hosts: nodes:!masters
  serial: 1
  gather_facts: no
  vars_files:
  - vars.yml
  become: yes
  vars:
    azure_conf_dir: /etc/azure
    azure_conf: "{{ azure_conf_dir }}/azure.conf"
    node_conf: /etc/origin/node/node-config.yaml
  handlers:
  - name: restart atomic-openshift-node
    systemd:
      state: restarted
      name: atomic-openshift-node
  post_tasks:
  - name: make sure /etc/azure exists
    file:
      state: directory
      path: "{{ azure_conf_dir }}"

  - name: populate /etc/azure/azure.conf
    copy:
      dest: "{{ azure_conf }}"
      content: |
        {
          "aadClientID" : "{{ g_aadClientId }}",
          "aadClientSecret" : "{{ g_aadClientSecret }}",
          "subscriptionID" : "{{ g_subscriptionId }}",
          "tenantID" : "{{ g_tenantId }}",
          "resourceGroup": "{{ g_resourceGroup }}",
        } 
    notify:
    - restart atomic-openshift-node
  - name: insert the azure disk config into the node
    modify_yaml:
      dest: "{{ node_conf }}"
      yaml_key: "{{ item.key }}"
      yaml_value: "{{ item.value }}"
    with_items:
    - key: kubeletArguments.cloud-config
      value:
      - "{{ azure_conf }}"

    - key: kubeletArguments.cloud-provider
      value:
      - azure
    notify:
    - restart atomic-openshift-node
  - name: delete the node so it can recreate itself
    command: oc delete node {{inventory_hostname}}
    delegate_to: ${MASTER}-0
  - name: sleep to let node come back to life
    pause:
       seconds: 90
EOF

# Create Playbook to delete stuck Master nodes and set as not schedulable
cat > /home/${SUDOUSER}/deletestucknodes.yml <<EOF
- hosts: masters
  gather_facts: no
  become: yes
  vars:
    description: "Delete stuck nodes"
  tasks:
  - name: Delete stuck nodes so it can recreate itself
    command: oc delete node {{inventory_hostname}}
    delegate_to: ${MASTER}-0
  - name: sleep between deletes
    pause:
      seconds: 25
  - name: set masters as unschedulable
    command: oadm manage-node {{inventory_hostname}} --schedulable=false
EOF

# Create Ansible Hosts File
echo $(date) " - Create Ansible Hosts file"

cat > /etc/ansible/hosts <<EOF
# Create an OSEv3 group that contains the masters and nodes groups
[OSEv3:children]
masters
nodes
etcd
master0
nfs

# Set variables common for all OSEv3 hosts
[OSEv3:vars]
ansible_ssh_user=$SUDOUSER
ansible_become=yes
openshift_install_examples=true
deployment_type=openshift-enterprise
openshift_release=v3.6
docker_udev_workaround=true
openshift_use_dnsmasq=true

openshift_master_default_subdomain=$ROUTING
openshift_override_hostname_check=true
osm_use_cockpit=true
os_sdn_network_plugin_name='redhat/openshift-ovs-multitenant'
openshift_cloudprovider_kind=azure
osm_default_node_selector='environment=test'
openshift_disable_check=disk_availability,memory_availability

# default selectors for router and registry services
openshift_router_selector='region=infra'
openshift_registry_selector='region=infra'

openshift_master_cluster_method=native
openshift_master_cluster_hostname=$MASTERPUBLICIPHOSTNAME
openshift_master_cluster_public_hostname=$MASTERPUBLICIPHOSTNAME
#openshift_master_cluster_public_vip=$MASTERPUBLICIPADDRESS

# Enable HTPasswdPasswordIdentityProvider
openshift_master_identity_providers=[{'name': 'htpasswd_auth', 'login': 'true', 'challenge': 'true', 'kind': 'HTPasswdPasswordIdentityProvider', 'filename': '/etc/origin/master/htpasswd'}]

# Configure persistent storage via nfs server on master
openshift_hosted_registry_storage_kind=nfs
openshift_hosted_registry_storage_access_modes=['ReadWriteMany']
openshift_hosted_registry_storage_host=${MASTER}-0
openshift_hosted_registry_storage_nfs_directory=/exports
openshift_hosted_registry_storage_volume_name=registry
openshift_hosted_registry_storage_volume_size=5Gi

# Setup metrics
openshift_hosted_metrics_deploy=true
# As of this writing, there's a bug in the metrics deployment.
# You'll see the metrics failing to deploy 59 times, it will, though, succeed the 60'th time.
openshift_hosted_metrics_storage_kind=nfs
openshift_hosted_metrics_storage_access_modes=['ReadWriteOnce']
openshift_hosted_metrics_storage_host=${MASTER}-0
openshift_hosted_metrics_storage_nfs_directory=/exports
openshift_hosted_metrics_storage_volume_name=metrics
openshift_hosted_metrics_storage_volume_size=10Gi
openshift_hosted_metrics_public_url=https://hawkular-metrics.$ROUTING/hawkular/metrics

# Setup logging
openshift_hosted_logging_deploy=true
openshift_hosted_logging_storage_kind=nfs
openshift_hosted_logging_storage_access_modes=['ReadWriteOnce']
openshift_hosted_logging_storage_host=${MASTER}-0
openshift_hosted_logging_storage_nfs_directory=/exports
openshift_hosted_logging_storage_volume_name=logging
openshift_hosted_logging_storage_volume_size=10Gi
openshift_master_logging_public_url=https://kibana.$ROUTING

# host group for masters
[masters]
EOF

for node in ocpm-{0..3}; do
	ping -c 1 $node 2>/dev/null|grep ocp|grep PING|awk '{ print $2 }'|cut -d'.' -f1
done|grep ocpm >>/etc/ansible/hosts

cat >> /etc/ansible/hosts <<EOF
# host group for etcd
[etcd]
EOF

for node in ocpm-{0..3}; do
	ping -c 1 $node 2>/dev/null|grep ocp|grep PING|awk '{ print $2 }'|cut -d'.' -f1 
done|grep ocpm >>/etc/ansible/hosts

cat >> /etc/ansible/hosts <<EOF
[nfs]
$MASTER-0

[master0]
$MASTER-0

# host group for nodes
[nodes]
EOF

for node in ocpm-{0..3}; do
	echo $(ping -c 1 $node 2>/dev/null|grep ocp|grep PING|awk '{ print $2 }'|cut -d'.' -f1) openshift_node_labels=\"{\'region\': \'master\', \'zone\': \'default\'}\" openshift_hostname=$node
done|grep ocpm >>/etc/ansible/hosts
for node in ocpip-{0..5}; do
	echo $(ping -c 1 $node 2>/dev/null|grep ocp|grep PING|awk '{ print $2 }'|cut -d'.' -f1) openshift_node_labels=\"{\'region\': \'infra\', \'zone\': \'default\', \'router\': \'public\'}\" openshift_hostname=$node
done|grep ocpip >>/etc/ansible/hosts
for node in ocpir-{0..5}; do
	echo $(ping -c 1 $node 2>/dev/null|grep ocp|grep PING|awk '{ print $2 }'|cut -d'.' -f1) openshift_node_labels=\"{\'region\': \'infra\', \'zone\': \'default\', \'router\': \'restricted\'}\" openshift_hostname=$node
done|grep ocpir >>/etc/ansible/hosts
for node in ocpii-{0..5}; do
	echo $(ping -c 1 $node 2>/dev/null|grep ocp|grep PING|awk '{ print $2 }'|cut -d'.' -f1) openshift_node_labels=\"{\'region\': \'infra\', \'zone\': \'default\', \'router\': \'internal\'}\" openshift_hostname=$node
done|grep ocpii >>/etc/ansible/hosts
for node in ocpnt-{0..30}; do
	echo $(ping -c 1 $node 2>/dev/null|grep ocp|grep PING|awk '{ print $2 }'|cut -d'.' -f1) openshift_node_labels=\"{\'region\': \'nodes\', \'zone\': \'default\', \'environment\': \'test\'}\" openshift_hostname=$node
done|grep ocpnt >>/etc/ansible/hosts
for node in ocpnp-{0..30}; do
	echo $(ping -c 1 $node 2>/dev/null|grep ocp|grep PING|awk '{ print $2 }'|cut -d'.' -f1) openshift_node_labels=\"{\'region\': \'nodes\', \'zone\': \'default\', \'environment\': \'production\'}\" openshift_hostname=$node
done|grep ocpnp >>/etc/ansible/hosts

echo $(date) " - Running network_manager.yml playbook" 
DOMAIN=`domainname -d` 

# Setup NetworkManager to manage eth0 
runuser -l $SUDOUSER -c "ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/byo/openshift-node/network_manager.yml" 

# Configure resolv.conf on all hosts through NetworkManager 
echo $(date) " - Setting up NetworkManager on eth0" 

runuser -l $SUDOUSER -c "ansible all -b -m service -a \"name=NetworkManager state=restarted\"" 
sleep 5 
runuser -l $SUDOUSER -c "ansible all -b -m command -a \"nmcli con modify eth0 ipv4.dns-search $DOMAIN\"" 
runuser -l $SUDOUSER -c "ansible all -b -m service -a \"name=NetworkManager state=restarted\"" 

# Initiating installation of OpenShift Container Platform using Ansible Playbook
echo $(date) " - Installing OpenShift Container Platform via Ansible Playbook"

runuser -l $SUDOUSER -c "ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/byo/config.yml"

if [ $? -eq 0 ]
then
   echo $(date) " - OpenShift Cluster installed successfully"
else
   echo $(date) " - OpenShift Cluster failed to install"
   exit 6
fi

echo $(date) " - Modifying sudoers"

sed -i -e "s/Defaults    requiretty/# Defaults    requiretty/" /etc/sudoers
sed -i -e '/Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"/aDefaults    env_keep += "PATH"' /etc/sudoers

# Deploying Registry
echo $(date) "- Registry automatically deployed to infra nodes"

# Deploying Router
echo $(date) "- Router automaticaly deployed to infra nodes"

echo $(date) "- Re-enabling requiretty"

sed -i -e "s/# Defaults    requiretty/Defaults    requiretty/" /etc/sudoers

# Adding user to OpenShift authentication file
echo $(date) "- Adding OpenShift user"

runuser -l $SUDOUSER -c "ansible-playbook ~/addocpuser.yml"

# Assigning cluster admin rights to OpenShift user
echo $(date) "- Assigning cluster admin rights to user"

runuser -l $SUDOUSER -c "ansible-playbook ~/assignclusteradminrights.yml"

# Setting password for Cockpit
echo $(date) "- Assigning password for root, which is used to login to Cockpit"

runuser -l $SUDOUSER -c "ansible-playbook ~/assignrootpassword.yml"

echo $(date) "- Unset OPENSHIFT_DEFAULT_REGISTRY"

# Unset of OPENSHIFT_DEFAULT_REGISTRY. Just the easiest way out.
cat > /tmp/atomic-openshift-master <<EOF
OPTIONS=--loglevel=2
CONFIG_FILE=/etc/origin/master/master-config.yaml
#OPENSHIFT_DEFAULT_REGISTRY=docker-registry.default.svc:5000

# Proxy configuration
# See https://docs.openshift.com/enterprise/latest/install_config/install/advanced_install.html#configuring-global-proxy
# Origin uses standard HTTP_PROXY environment variables. Be sure to set
# NO_PROXY for your master
#NO_PROXY=master.example.com
#HTTP_PROXY=http://USER:PASSWORD@IPADDR:PORT
#HTTPS_PROXY=https://USER:PASSWORD@IPADDR:PORT
EOF

chmod a+r /tmp/atomic-openshift-master

# Unset default registry DNS name
runuser -l $SUDOUSER -c "ansible-playbook ~/dockerregistry.yml"

# OPENSHIFT_DEFAULT_REGISTRY UNSET MAGIC
for item in ocpm-0 ocpm-1 ocpm-2; do
	runuser -l $SUDOUSER -c "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $item 'sudo sed -i \"s/OPENSHIFT_DEFAULT_REGISTRY/#OPENSHIFT_DEFAULT_REGISTRY/g\" /etc/sysconfig/atomic-openshift-master-api'"
	runuser -l $SUDOUSER -c "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $item 'sudo sed -i \"s/OPENSHIFT_DEFAULT_REGISTRY/#OPENSHIFT_DEFAULT_REGISTRY/g\" /etc/sysconfig/atomic-openshift-master-controllers'"
	runuser -l $SUDOUSER -c "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $item 'sudo systemctl restart atomic-openshift-master-api'"
	runuser -l $SUDOUSER -c "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $item 'sudo systemctl restart atomic-openshift-master-controllers'"
done

# Making sure the ansible modify_yaml module is found
echo $(date) "- Create ~/ansible.cfg"

cat > /home/${SUDOUSER}/.ansible.cfg <<EOF
[defaults]
library=/usr/share/ansible/openshift-ansible/library
EOF

# Create Storage Classes
echo $(date) "- Creating Storage Classes"

runuser -l $SUDOUSER -c "ansible-playbook ~/configurestorageclass.yml"

echo $(date) "- Sleep for 120"

sleep 120

exit 0
echo $(date) " - Ending the script here temporarily."

# Execute setup-azure-master and setup-azure-node playbooks to configure Azure Cloud Provider
echo $(date) "- Configuring OpenShift Cloud Provider to be Azure"

runuser -l $SUDOUSER -c "ansible-playbook ~/setup-azure-master.yml"

if [ $? -eq 0 ]
then
    echo $(date) " - Cloud Provider setup of master config on Master Nodes completed successfully"
else
    echo $(date) "- Cloud Provider setup of master config on Master Nodes failed to completed"
    exit 7
fi

runuser -l $SUDOUSER -c "ansible-playbook ~/setup-azure-node-master.yml"

if [ $? -eq 0 ]
then
    echo $(date) " - Cloud Provider setup of node config on Master Nodes completed successfully"
else
    echo $(date) "- Cloud Provider setup of node config on Master Nodes failed to completed"
    exit 8
fi

runuser -l $SUDOUSER -c "ansible-playbook ~/setup-azure-node.yml"

if [ $? -eq 0 ]
then
    echo $(date) " - Cloud Provider setup of node config on App Nodes completed successfully"
else
    echo $(date) "- Cloud Provider setup of node config on App Nodes failed to completed"
    exit 9
fi

runuser -l $SUDOUSER -c "ansible-playbook ~/deletestucknodes.yml"

if [ $? -eq 0 ]
then
    echo $(date) " - Cloud Provider setup of OpenShift Cluster completed successfully"
else
    echo $(date) "- Cloud Provider setup failed to delete stuck Master nodes or was not able to set them as unschedulable"
    exit 10
fi

echo $(date) " - Script complete"
