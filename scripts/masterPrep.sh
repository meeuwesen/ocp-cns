#!/bin/bash
echo $(date) " - Starting Script"

RHN_ORGANIZATIONID=$1
RHN_ACTIVATIONKEY=$2
SUDOUSER=$3
STORAGEACCOUNT1=$4

# Verify that we have access to Red Hat Network
ITER=0
while true; do
	curl -kv https://access.redhat.com >/dev/null 2>&1
	if [ "$?" -eq 0 ]; then
		echo "We have a working network connection to Red Hat."
		break
	else
		ITER=$(expr $ITER + 1)
		echo "We do not yet have a working network connection to Red Hat. Try: $ITER"
	fi
	if [ "$ITER" -eq 10 ]; then
      		echo "Error: we are experiencing some network error to Red Hat."
		exit 1
	fi
	sleep 60
done

# Register Host with Cloud Access Subscription
echo $(date) " - Register host with Cloud Access Subscription"

subscription-manager register --activationkey="$RHN_ACTIVATIONKEY" --org="$RHN_ORGANIZATIONID" --force
if [ $? -eq 0 ]; then
   echo "Subscribed successfully"
else
   sleep 5
   subscription-manager register --activationkey="$RHN_ACTIVATIONKEY" --org="$RHN_ORGANIZATIONID" --force
   if [ "$?" -eq 0 ]; then
      echo "Subscribed successfully."
   else
      echo "Registering the subscription failed."
      exit 3
   fi
fi

# Disable all repositories and enable only the required ones
echo $(date) " - Disabling all repositories and enabling only the required repos"

subscription-manager repos --disable="*"

subscription-manager repos \
    --enable="rhel-7-server-rpms" \
    --enable="rhel-7-server-extras-rpms" \
    --enable="rhel-7-server-ose-3.6-rpms" \
    --enable="rhel-7-fast-datapath-rpms"

# Install and enable Cockpit
echo $(date) " - Installing and enabling Cockpit"

yum -y install cockpit

systemctl enable cockpit.socket
systemctl start cockpit.socket

# Install base packages and update system to latest packages
echo $(date) " - Install base packages and update system to latest packages"

yum -y install wget git net-tools bind-utils iptables-services bridge-utils bash-completion kexec-tools sos psacct httpd-tools
yum -y update --exclude=WALinuxAgent

# Install OpenShift utilities
echo $(date) " - Installing OpenShift utilities"

yum -y install atomic-openshift-utils

# Install Docker 1.13.1
echo $(date) " - Installing Docker 1.13.1"

yum -y install docker-1.13.1
sed -i -e "s#^OPTIONS='--selinux-enabled'#OPTIONS='--selinux-enabled --insecure-registry 172.30.0.0/16'#" /etc/sysconfig/docker

# Create thin pool logical volume for Docker
echo $(date) " - Creating thin pool logical volume for Docker and staring service"

DOCKERVG=$(parted -m /dev/sda print all 2>/dev/null | grep unknown | grep /dev/sd | cut -d':' -f1)

echo "DEVS=${DOCKERVG}" >> /etc/sysconfig/docker-storage-setup
echo "VG=docker-vg" >> /etc/sysconfig/docker-storage-setup
docker-storage-setup
if [ $? -eq 0 ]
then
   echo "Docker thin pool logical volume created successfully"
else
   echo "Error creating logical volume for Docker"
   exit 5
fi

# Enable and start Docker services

systemctl enable docker
systemctl start docker

# Prereqs for NFS, if we're $MASTER-0
# Create a lv with what's left in the docker-vg VG, which depends on disk size defined (100G disk = 60G free)

if hostname -f|grep -- "-0" >/dev/null
then
   echo $(date) " - We are on master-0 ($(hostname)): Setting up NFS server for persistent storage"
   yum -y install nfs-utils
   VGCALC=$(vgs|grep docker-vg|awk '{ print $7 }'|sed -e 's/.[0-9][0-9]g//' -e 's/<//g')
   VGFREESPACE=$(echo $VGCALC - 1|bc)
   lvcreate -n lv_nfs -L+$VGFREESPACE docker-vg
   mkfs.xfs /dev/mapper/docker--vg-lv_nfs
   echo "/dev/mapper/docker--vg-lv_nfs /exports xfs defaults 0 0" >>/etc/fstab
   mkdir /exports
   mount -a
   if [ "$?" -eq 0 ]
   then
      echo "$(date) Successfully setup NFS."
   else
      echo "$(date) Failed to mount filesystem which is to host the NFS share."
      exit 6
   fi
   
   lvextend -L+20G /dev/docker-vg/lv_nfs
   xfs_growfs /dev/docker-vg/lv_nfs
   
   for item in registry metrics jenkins
   do 
      mkdir -p /exports/$item
   done
   
   chown nfsnobody:nfsnobody /exports -R
   chmod a+rwx /exports -R  
fi

# Create Storage Class yml files on MASTER-0

if hostname -f|grep -- "-0" >/dev/null
then

cat <<EOF > /home/${SUDOUSER}/scgeneric1.yml
kind: StorageClass
apiVersion: storage.k8s.io/v1beta1
metadata:
  name: generic
  annotations:
    storageclass.beta.kubernetes.io/is-default-class: "true"
provisioner: kubernetes.io/azure-disk
parameters:
  storageAccount: ${STORAGEACCOUNT1}
EOF

fi

echo $(date) " - Script Complete"
