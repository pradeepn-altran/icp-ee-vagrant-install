# Licensed under Apache License Version 2.0
#
# @ Authur Tim Pouyer tpouyer@us.ibm.com
# https://raw.githubusercontent.com/IBM/deploy-ibm-cloud-private/master/LICENSE

# Modified: Pradeep Nambiar pradeep.nambiar@altran.com 6/13/2019
# Modified from original script to install IBM Cloud Private EE Tar Image
# Script creates 4 nodes (worker1, worker2, vulnerability advidor & management node) 
#                + master node in the primary VM 
# The base box needs to be resized from the default 64GB to 500GB to include space for 
# all images from ICP EE. The script uses the resized box available from 
# https://app.vagrantup.com/pradeepn-altran/boxes/bento-ubuntu-1604-500gb-4icpee
# You can change this suite your requirements.
# 
# Changes from original script - tagged as #ICP-EE
# This version of script tested to work with ICP 3.1.2
# Laptop spec tested with: 
#    Intel iCore 7-7700HQ CPU @2.80GHz, 4 cores, 8 Logical Cores
#    32GB Memory, 1TB Disk, Windows 10, Vagrant 2.2.4, VirtualBox 6.0

#The ICP 3.1.2 Tar ball is made available from the host machine via the IIS Web Server
#Enable IIS Web Server and move the ICP 3.1.2 Tar to the C:\inetpub\wwwroot folder
#Edit the  

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#NOTE: Before running vagrant up, review the settings below
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Software License Terms Acceptence (see https://hub.docker.com/r/ibmcom/icp-inception/)
# If you accept the Software license terms please change the value below to 'accept'
license = "not accepted"

# most laptops have at least 8 cores nowadays (adjust based on your laptop hardware)
cpus = '7'

# should be sufficent on laptops or Windows VM with 32GiB of RAM (but you won't want to run any apps
# while this vm is running)
#ICP-EE - changed to 26GB from 8GB
memory = '26576'

# Update version to pull a specific version i.e. version = '2.1.0-beta-1'
version = "3.1.2"

# Default admin password - ICP 3.1.2 now requires 32 characters by default
default_admin_password = "S3cure-icp-admin-passw0rd-default"

# host-only network segment - in most cases you do not have to change this value
# on some systems this network segment may overlap another network already on your
# system. In those cases you will need to change this value to another value
# i.e. 192.168.56 or 192.168.16 etc...
base_segment = '192.168.27'

# use apt-cacher-ng & docker registry cache servers
# see instructions in the `README.md` under #Advanced Cache Setup
use_cache = 'false'
cache_host = '192.168.27.99'
apt_cache_port = '3142'
docker_registry_port = '5000'

#ICP-EE - Customization for EE install - to download the ICP EE Tar File
#Hostname of your windows host where IIS web server is running - enable using windows features 
#and place the tar file in the public root folder: C:\inetpub\wwwroot
#NOTE: Update the host IP Address here.
icpEE_TarWebServerHost='XX.XX.XX.XX'
icpEE_TarFileName='ibm-cloud-private-x86_64-3.1.2.tar.gz'
#Used in folders e.g. /opt/
icpEE_versionLabel='ibm-cloud-private-3.1.2'
icpEE_ContainerNameAndTag='ibmcom/icp-inception-amd64:3.1.2-ee'

###############################################################################
#                  DO NOT MODIFY ANYTHING BELOW THIS POINT                    #
###############################################################################
#ICP-EE - Enabled vulnerability-advisor, istio, metrics-server and logging

cfc_config = "
---
# Network CNI
network_type: calico

# Network in IPv4 CIDR format
network_cidr: 10.1.0.0/16

# Kubernetes service IP range
service_cluster_ip_range: 10.0.0.1/24

# Flag to enable ldap with true, disabled by default.
ldap_enabled: false

ansible_user: vagrant
ansible_become: true
#ICP-EE
ansible_become_password: vagrant
ansible_ssh_pass: vagrant


# enabled/disable python docker install
install_docker_py: false

# etcd_extra_args: [\"--max-wal=5\"]
# kube_proxy_extra_args: [\"--proxy-mode=ipvs\"]

management_services:
  istio: disabled
  vulnerability-advisor: enabled
  storage-glusterfs: disabled
  storage-minio: disabled
  custom-metrics-adapter: disabled
  image-security-enforcement: disabled
  metering: enabled
  monitoring: enabled
  service-catalog: enabled
  logging: enabled
  nvidia-device-plugin: disabled
  metrics-server: enabled

# following variables are used to pickup internal builds
version: latest
image_tag: latest
image_repo: ibmcom
private_registry_enabled: false
private_registry_server: placeholder.com
docker_username: placeholder
docker_password: placeholder
default_admin_password: placeholder
"

#ICP-EE
##vm_name = "IBM-Cloud-Private-dev-edition"
vm_name = "IBM-Cloud-Private-EE-edition"
user_home_path = ENV['HOME']
if Vagrant::Util::Platform.windows?
  user_home_path = Vagrant::Util::Platform.fs_real_path(ENV['USERPROFILE'])
end
#base_storage_disk_path = Vagrant::Util::Platform.fs_real_path("#{user_home_path}/VirtualBox VMs/#{vm_name}/ubuntu-16.04-amd64-disk001.vmdk")
base_storage_disk_path = Vagrant::Util::Platform.fs_real_path("#{user_home_path}/VirtualBox VMs/#{vm_name}/box-disk001.vmdk")
lxd_storage_disk_path = Vagrant::Util::Platform.fs_real_path("#{user_home_path}/VirtualBox VMs/#{vm_name}/lxd_storage_disk.vmdk")
extra_storage_disk_path = Vagrant::Util::Platform.fs_real_path("#{user_home_path}/VirtualBox VMs/#{vm_name}/nfs_storage_disk.vmdk")
rsa_private_key = IO.read(Vagrant::Util::Platform.fs_real_path("#{Vagrant.user_data_path}/insecure_private_key"))

if !license.eql? 'accept'
  if !File.exists?("license_accepted")
    puts("################################################################################")
    puts("# You must accept the terms of the Software License under which we are         #")
    puts("# providing the IBM Cloud Private community edition software.                  #")
    puts("#                                                                              #")
    puts("# See license terms here: https://hub.docker.com/r/ibmcom/icp-inception/       #")
    puts("################################################################################")
    puts("Do You Accept the Terms of the Software License? [Y|n]")
    response = STDIN.gets.chomp
    if ['y','accept',''].include?(response.downcase)
      license = 'accept'
      puts("License Terms Accepted!")
      File.write('license_accepted', 'license accepted')
    else
      puts("License Terms Not Accepted... exiting.")
      exit 1
    end
  else # if we found the license_accepted file then proceed
    license = 'accept'
  end
end

image_repo = 'ibmcom'
private_registry_enabled = 'false'
private_registry_server = 'placeholder.com'
docker_username = 'placeholder'
docker_password = 'placeholder'

if File.exist?(".private")
  load File.expand_path(".private")
  version = $version
  image_repo = $image_repo
  private_registry_enabled = $private_registry_enabled
  private_registry_server = $private_registry_server
  docker_username = $docker_username
  docker_password = $docker_password
  default_admin_password = $default_admin_password
end

docker_mirror = ''
apt_proxy_conf = ''

if use_cache.downcase.eql? 'true'
	docker_mirror = ",
                \"registry-mirrors\": [\"http://#{cache_host}:#{docker_registry_port}\"]"
	apt_proxy_conf = "
            Acquire {
            	http {
            		Proxy \"http://#{cache_host}:#{apt_cache_port}/\";
            		security.ubuntu.com \"DIRECT\";
            		get.docker.com \"DIRECT\";
            	};
            };"
end

configure_master_ssh_keys = <<SCRIPT
echo "#{rsa_private_key}" >> /home/vagrant/.ssh/id_rsa
#ICP-EE - fix permission
sudo chmod og-rw /home/vagrant/.ssh/id_rsa
echo "$(cat /home/vagrant/.ssh/authorized_keys)" >> /home/vagrant/.ssh/id_rsa.pub
echo 'StrictHostKeyChecking no\nUserKnownHostsFile /dev/null\nLogLevel QUIET' >> /home/vagrant/.ssh/config
SCRIPT

configure_swap_space = <<SCRIPT
sudo rm -f /mnt/swap
#ICP-EE Changed swap size from 8gb to 26g
sudo fallocate -l 26g /mnt/swap
sudo chmod 600 /mnt/swap
sudo mkswap /mnt/swap
sudo swapon /mnt/swap
echo "/mnt/swap swap swap defaults 0 0" | sudo tee --append /etc/fstab > /dev/null
echo "vm.swappiness = 60" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "vm.vfs_cache_pressure = 10" | sudo tee --append /etc/sysctl.conf > /dev/null
sudo sysctl -p
SCRIPT

configure_performance_settings = <<SCRIPT
echo "net.ipv4.ip_forward = 1" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.rp_filter = 0" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.proxy_arp = 1" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_keepalive_time = 600" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_keepalive_intvl = 60" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_keepalive_probes = 20" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.ip_nonlocal_bind = 1" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.accept_redirects = 1" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.send_redirects = 1" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.accept_source_route = 1" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_mem = 182757 243679 365514" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv4.conf.all.shared_media = 1" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.core.netdev_max_backlog = 182757" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "net.bridge.bridge-nf-call-iptables = 1" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "fs.inotify.max_queued_events = 1048576" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "fs.inotify.max_user_instances = 1048576" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "fs.inotify.max_user_watches = 1048576" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "vm.max_map_count = 262144" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "kernel.dmesg_restrict = 0" | sudo tee --append /etc/sysctl.conf > /dev/null
echo "* soft nofile 1048576" | sudo tee --append /etc/security/limits.conf > /dev/null
echo "* hard nofile 1048576" | sudo tee --append /etc/security/limits.conf > /dev/null
echo "root soft nofile 1048576" | sudo tee --append /etc/security/limits.conf > /dev/null
echo "root hard nofile 1048576" | sudo tee --append /etc/security/limits.conf > /dev/null
echo "* soft memlock unlimited" | sudo tee --append /etc/security/limits.conf > /dev/null
echo "* hard memlock unlimited" | sudo tee --append /etc/security/limits.conf > /dev/null
sudo sysctl -p

echo Y | sudo tee /sys/module/fuse/parameters/userns_mounts
echo Y | sudo tee /sys/module/ext4/parameters/userns_mounts
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="cgroup_enable=memory swapaccount=1 /g' /etc/default/grub
sudo update-grub
SCRIPT

load_ipvs_module = <<SCRIPT
echo ip_vs_dh >> /etc/modules
echo ip_vs_ftp >> /etc/modules
echo ip_vs >> /etc/modules
echo ip_vs_lblc >> /etc/modules
echo ip_vs_lblcr >> /etc/modules
echo ip_vs_lc >> /etc/modules
echo ip_vs_nq >> /etc/modules
echo ip_vs_rr >> /etc/modules
echo ip_vs_sed >> /etc/modules
echo ip_vs_sh >> /etc/modules
echo ip_vs_wlc >> /etc/modules
echo ip_vs_wrr >> /etc/modules
modprobe ip_vs_dh
modprobe ip_vs_ftp
modprobe ip_vs
modprobe ip_vs_lblc
modprobe ip_vs_lblcr
modprobe ip_vs_lc
modprobe ip_vs_nq
modprobe ip_vs_rr
modprobe ip_vs_sed
modprobe ip_vs_sh
modprobe ip_vs_wlc
modprobe ip_vs_wrr
SCRIPT

configure_apt_proxy = <<SCRIPT
sudo bash -c 'cat > /etc/apt/apt.conf.d/02apt-cacher' <<'EOF'
Acquire::http::Proxy "http://#{cache_host}:#{apt_cache_port}/";
Acquire::http::Proxy::security.ubuntu.com "DIRECT";
Acquire::http::Proxy::get.docker.com "DIRECT";
EOF
SCRIPT

install_icp_prereqs = <<SCRIPT
export DEBIAN_FRONTEND=noninteractive
sudo bash -c 'cat > /etc/apt/apt.conf.d/01lean' <<'EOF'
APT::Install-Suggests "0";
APT::Install-Recommends "0";
APT::AutoRemove::SuggestsImportant "false";
APT::AutoRemove::RecommendsImportant "false";
Dir::Cache "";
Dir::Cache::archives "";
EOF
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] http://download.docker.com/linux/ubuntu $(lsb\_release -cs) stable"
sudo apt-get update --yes --quiet
sudo apt-get install --yes --quiet --target-release=xenial-backports lxd lxd-client bridge-utils dnsmasq thin-provisioning-tools \
    curl linux-image-extra-$(uname -r) linux-image-extra-virtual apt-transport-https ca-certificates software-properties-common \
    docker-ce python-setuptools python-pip build-essential python-dev nfs-kernel-server nfs-common aufs-tools ntp criu ipvsadm \
    rng-tools util-linux socat openssh-server openssl
sudo -H pip install --upgrade pip
sudo -H pip install docker
sudo usermod -aG lxd vagrant
newgrp lxd
sudo usermod -aG docker vagrant
newgrp docker
sudo bash -c 'cat > /etc/docker/daemon.json' <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m"
  }#{docker_mirror}
}
EOF
sudo systemctl daemon-reload
sudo systemctl restart docker
sudo bash -c 'cat > /etc/ntp.conf' <<'EOF'
server time1.google.com
server time2.google.com
server time3.google.com
server time4.google.com
EOF
sudo systemctl restart ntp
sudo bash -c 'cat >> /etc/ssh/sshd_config' <<'EOF'
GatewayPorts yes
AllowAgentForwarding yes
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
PermitTunnel yes
EOF
sudo systemctl restart sshd.service
sudo bash -c 'cat >> /etc/default/rng-tools' <<'EOF'
HRNGDEVICE=/dev/urandom
EOF
sudo /etc/init.d/rng-tools restart
sudo apt-get update --yes --quiet
sudo DEBIAN_FRONTEND=noninteractive apt-get -y --quiet -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade
sudo apt autoremove --yes --quiet
SCRIPT

add_storage_vol = <<SCRIPT
sudo pvcreate /dev/sdb
sudo vgextend vagrant-vg /dev/sdb
sudo lvcreate -l 100%FREE -n storage vagrant-vg
sudo mkfs -t ext4 /dev/mapper/vagrant--vg-storage
sudo mkdir /storage
sudo mount -t ext4 /dev/mapper/vagrant--vg-storage /storage
echo "/dev/mapper/vagrant--vg-storage /storage        ext4  defaults  0    0"  | sudo tee --append /etc/fstab > /dev/null
sudo chmod 777 /storage
SCRIPT

setup_nfs_shares = <<SCRIPT
# share the '/storage' directory on the nfs server
sudo mkdir /storage/share01 -p
sudo chmod 777 /storage/share01
sudo mkdir /storage/share02 -p
sudo chmod 777 /storage/share02
sudo mkdir /storage/share03 -p
sudo chmod 777 /storage/share03
sudo mkdir /storage/share04 -p
sudo chmod 777 /storage/share04
sudo mkdir /storage/share05 -p
sudo chmod 777 /storage/share05
sudo mkdir /storage/share06 -p
sudo chmod 777 /storage/share06
sudo mkdir /storage/share07 -p
sudo chmod 777 /storage/share07
sudo mkdir /storage/share08 -p
sudo chmod 777 /storage/share08
sudo mkdir /storage/share09 -p
sudo chmod 777 /storage/share09
sudo mkdir /storage/share10 -p
sudo chmod 777 /storage/share10
sudo mkdir /storage/share11 -p
sudo chmod 777 /storage/share11
sudo mkdir /storage/share12 -p
sudo chmod 777 /storage/share12
sudo mkdir /storage/share13 -p
sudo chmod 777 /storage/share13
sudo mkdir /storage/share14 -p
sudo chmod 777 /storage/share14
sudo mkdir /storage/share15 -p
sudo chmod 777 /storage/share15
sudo mkdir /storage/share16 -p
sudo chmod 777 /storage/share16
sudo mkdir /storage/share17 -p
sudo chmod 777 /storage/share17
sudo mkdir /storage/share18 -p
sudo chmod 777 /storage/share18
sudo mkdir /storage/share19 -p
sudo chmod 777 /storage/share19
sudo mkdir /storage/share20 -p
sudo chmod 777 /storage/share20
echo "/storage           *(rw,sync,no_subtree_check,async,insecure,no_root_squash)" | sudo tee --append /etc/exports > /dev/null
sudo systemctl restart nfs-kernel-server
SCRIPT

configure_nat_iptable_rules = <<SCRIPT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A INPUT -p icmp -j ACCEPT
sudo iptables -A INPUT -p ipencap -j ACCEPT
SCRIPT

#ICP-EE - added va-node and mgmt-node
#Increased Volume Size to 275GB
configure_lxd = <<SCRIPT
sudo bash -c 'cat >> /etc/network/interfaces' <<'EOF'
    post-up ifconfig eth1 promisc on

iface eth1 inet manual
EOF
sudo ufw disable
mkdir -p /home/vagrant/cluster
cat <<EOF | sudo -H lxd init --preseed
config:
  images.auto_update_interval: 15
storage_pools:
  - name: lxd
    driver: lvm
    config:
      volume.size: 275GB
      source: /dev/sdc
networks:
  - name: lxdbr0
    type: bridge
    config:
      bridge.driver: native
      bridge.external_interfaces: eth1
      bridge.mode: standard
      ipv4.address: "#{base_segment}.100/24"
      ipv4.dhcp: true
      ipv4.dhcp.ranges: "#{base_segment}.100-#{base_segment}.254"
      ipv4.firewall: false
      ipv4.nat: true
      ipv4.routing: true
      ipv6.address: none
      dns.domain: icp
      dns.mode: managed
      raw.dnsmasq: |
        dhcp-option-force=26,9000
        server=127.0.0.1
profiles:
  - name: default
    config:
      boot.autostart: true
      linux.kernel_modules: bridge,br_netfilter,x_tables,ip_tables,ip6_tables,ip_vs,ip_vs,ip_vs_rr,ip_vs_wrr,ip_vs_sh,nf_conntrack_ipv4,ip_set,ipip,xt_mark,xt_multiport,ip_tunnel,tunnel4,netlink_diag,nf_conntrack,nfnetlink,nf_nat,overlay
      raw.lxc: |
        lxc.apparmor.profile=unconfined
        lxc.mount.auto=proc:rw sys:rw cgroup:rw
        lxc.cgroup.devices.allow=a
        lxc.cap.drop=
      security.nesting: "true"
      security.privileged: "true"
      user.network-config: |
        version: 1
        config:
          - type: physical
            name: eth0
            subnets:
              - type: dhcp
      user.user-data: |
        #cloud-config
        disable_root: false
        disable_root_opts:
        users:
          - default
          - name: vagrant
            sudo: ['ALL=(ALL:ALL) NOPASSWD:ALL']
            groups: sudo, admin, users, vagrant
            primary-group: vagrant
            home: /home/vagrant
            shell: /bin/bash
            ssh-authorized-keys:
              - $(cat ~/.ssh/id_rsa.pub)
        ntp:
          servers:
            - time1.google.com
            - time2.google.com
            - time3.google.com
            - time4.google.com
        apt:
          preserve_sources_list: true
          conf: |
            APT {
              Get {
                Assume-Yes "true";
                Fix-Broken "true";
              };
              Install-Suggests "false";
              Install-Recommends "false";
              AutoRemove {
                SuggestsImportant "false";
                RecommendsImportant "false";
              };
            };
            Dir {
              Cache {
                archives "";
              };
            };#{apt_proxy_conf}
          sources:
            source1:
              source: "deb [arch=amd64] http://download.docker.com/linux/ubuntu $(lsb\_release -cs) stable"
              key: |
$(curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sed  's/^/                /')
        package_update: true
        package_upgrade: true
        package_reboot_if_required: true
        packages:
          - linux-image-extra-$(uname -r)
          - linux-image-extra-virtual
          - apt-transport-https
          - ca-certificates
          - curl
          - software-properties-common
          - squashfuse
          - docker-ce
          - python-setuptools
          - python-pip
          - build-essential
          - python-dev
          - aufs-tools
          - nfs-common
        runcmd:
          - [ /sbin/iptables, -A, INPUT, -p, icmp, -j, ACCEPT ]
          - [ /sbin/iptables, -A, INPUT, -p, ipencap, -j, ACCEPT ]
          - [ mkdir, -p, /var/lib/kubelet ]
          - [ mount, -o, bind, /var/lib/kubelet, /var/lib/kubelet ]
          - [ mount, --make-shared, /var/lib/kubelet ]
          - [ mkdir, -p, /var/run/calico ]
          - [ mount, -o, bind, /var/run/calico, /var/run/calico ]
          - [ mount, --make-shared, /var/run/calico ]
          - [ ln, -s, /bin/true, /usr/local/bin/udevadm ]
          - [ pip, install, --upgrade, pip ]
          - [ pip, install, docker ]
          - [ usermod, -aG, docker, vagrant ]
          - [ ufw, disable ]
          - [ touch, /DONE ]
        write_files:
          - content: |
              {
                "log-driver": "json-file",
                "log-opts": {
                  "max-size": "10m"
                }#{docker_mirror}
              }
            path: /etc/docker/daemon.json
    devices:
      aadisable:
        path: /sys/module/nf_conntrack/parameters/hashsize
        source: /dev/null
        type: disk
      aadisable1:
        path: /sys/module/apparmor/parameters/enabled
        source: /dev/null
        type: disk
      eth0:
        name: eth0
        nictype: bridged
        parent: lxdbr0
        type: nic
      root:
        path: /
        pool: lxd
        type: disk
      mem:
        type: unix-char
        path: /dev/mem
  - name: worker1
    config:
      boot.autostart.delay: 15
      boot.autostart.priority: 4
      user.meta-data: |
        hostname: worker1
        fqdn: worker1.icp
        manage_etc_hosts: true
    devices:
      eth0:
        name: eth0
        nictype: bridged
        parent: lxdbr0
        type: nic
        ipv4.address: #{base_segment}.101
  - name: worker2
    config:
      boot.autostart.delay: 15
      boot.autostart.priority: 5
      user.meta-data: |
        hostname: worker2
        fqdn: worker2.icp
        manage_etc_hosts: true
    devices:
      eth0:
        name: eth0
        nictype: bridged
        parent: lxdbr0
        type: nic
        ipv4.address: #{base_segment}.102
  - name: worker3
    config:
      boot.autostart.delay: 15
      boot.autostart.priority: 6
      user.meta-data: |
        hostname: worker3
        fqdn: worker3.icp
        manage_etc_hosts: true
    devices:
      eth0:
        name: eth0
        nictype: bridged
        parent: lxdbr0
        type: nic
        ipv4.address: #{base_segment}.103
  - name: va-node
    config:
      boot.autostart.delay: 45
      boot.autostart.priority: 7	  
      user.meta-data: |
        hostname: va-node
        fqdn: va-node.icp
        manage_etc_hosts: true
    devices:
      eth0:
        name: eth0
        nictype: bridged
        parent: lxdbr0
        type: nic
        ipv4.address: #{base_segment}.104
  - name: mgmt-node
    config:
      boot.autostart.delay: 100
      boot.autostart.priority: 10
      user.meta-data: |
        hostname: mgmt-node
        fqdn: mgmt-node.icp
        manage_etc_hosts: true
    devices:
      eth0:
        name: eth0
        nictype: bridged
        parent: lxdbr0
        type: nic
        ipv4.address: #{base_segment}.105
EOF
sudo sed -i 's/127.0...1\tmaster.icp/#{base_segment}.100\tmaster.icp/g' /etc/hosts
SCRIPT

bring_up_icp_host_interface = <<SCRIPT
sudo ip link set dev eth1 up
SCRIPT

set_dnsnameserver_to_lxd_dnsmasq = <<SCRIPT
echo "nameserver #{base_segment}.100\nsearch icp\n" | sudo tee /etc/resolv.conf > /dev/null
SCRIPT

#ICP-EE
#Added va-node and mgmt-node containers

configure_icp_install = <<SCRIPT
cat > /home/vagrant/cluster/hosts <<'EOF'
[master]
#{base_segment}.100 kubelet_extra_args='["--fail-swap-on=false","--eviction-hard=memory.available<1Mi,nodefs.available<1Mi,nodefs.inodesFree<1%,imagefs.available<1Mi,imagefs.inodesFree<1%", "--image-gc-high-threshold=100%", "--image-gc-low-threshold=99%"]'

[worker]
#{base_segment}.101 kubelet_extra_args='["--fail-swap-on=false"]'
#{base_segment}.102 kubelet_extra_args='["--fail-swap-on=false"]'

[proxy]
#{base_segment}.100

[management]
#{base_segment}.105

[va]
#{base_segment}.104

EOF

#ICP-EE
echo '#{cfc_config}' > /home/vagrant/cluster/config.yaml
sed -i "s/image_tag\: latest/image_tag\: #{version}/g" /home/vagrant/cluster/config.yaml
sed -i "s/version\: latest/version\: #{version}/g" /home/vagrant/cluster/config.yaml
sed -i "s|image_repo\: ibmcom|image_repo\: #{image_repo}|g" /home/vagrant/cluster/config.yaml
sed -i "s|private_registry_enabled\: false|private_registry_enabled\: #{private_registry_enabled}|g" /home/vagrant/cluster/config.yaml
sed -i "s|private_registry_server\: placeholder.com|private_registry_server\: #{private_registry_server}|g" /home/vagrant/cluster/config.yaml
sed -i "s|docker_username\: placeholder|docker_username\: #{docker_username}|g" /home/vagrant/cluster/config.yaml
sed -i "s|docker_password\: placeholder|docker_password\: #{docker_password}|g" /home/vagrant/cluster/config.yaml
sed -i "s|default_admin_password\: placeholder|default_admin_password\: #{default_admin_password}|g" /home/vagrant/cluster/config.yaml
cat /home/vagrant/cluster/config.yaml
SCRIPT

boot_lxd_worker_nodes = <<SCRIPT
lxc launch -p default -p worker1 ubuntu:16.04 worker1
lxc launch -p default -p worker2 ubuntu:16.04 worker2
lxc launch -p default -p va-node ubuntu:16.04 va-node
lxc launch -p default -p mgmt-node ubuntu:16.04 mgmt-node
SCRIPT

wait_for_worker_nodes_to_boot = <<SCRIPT
echo ""
echo "Preparing nodes for IBM Cloud Private Enterprise Edition cluster installation."
echo "This process will take approximately 20-40 minutes depending on network speeds."
echo "Take a break and go grab a cup of coffee, we'll keep working on this while you're away ;-)"
echo ""
FILES="/home/vagrant/worker1
/home/vagrant/worker2
/home/vagrant/va-node
/home/vagrant/mgmt-node"
for file in $FILES
do
  while [ ! -f "$file" ]
  do
    filename=$(basename "$file")
    lxc file pull -p $filename/DONE /home/vagrant/$filename &> /dev/null
    printf "."
    sleep 10
  done
done

# sanity check (eth0 should be assigned on all 4 lxc nodes)
if [ "2" -gt "$(lxc list | grep -o eth0 | wc -l)" ]; then
    echo "Failed to assign IP to lxc nodes..."
    lxc exec worker1 -- cat /var/log/cloud-init-output.log | grep -C 3 error
    lxc exec worker2 -- cat /var/log/cloud-init-output.log | grep -C 3 error
	lxc exec va-node -- cat /var/log/cloud-init-output.log | grep -C 3 error
	lxc exec mgmt-node -- cat /var/log/cloud-init-output.log | grep -C 3 error
    echo "You may need to change the 'base_segment' value in the 'Vagrantfile' to another subnet like '192.168.56'."
    exit 1
fi

# sanity check (docker0 should be assigned on all 4 lxc nodes)
if [ "2" -gt "$(lxc list | grep -o docker0 | wc -l)" ]; then
    echo "Failed to install docker on lxc nodes..."
    lxc exec worker1 -- cat /var/log/cloud-init-output.log | grep -C 3 error
    lxc exec worker2 -- cat /var/log/cloud-init-output.log | grep -C 3 error
	lxc exec va-node -- cat /var/log/cloud-init-output.log | grep -C 3 error
	lxc exec mgmt-node -- cat /var/log/cloud-init-output.log | grep -C 3 error
    echo "You may need to change the 'base_segment' value in the 'Vagrantfile' to another subnet like '192.168.56'."
    exit 1
fi

echo "worker1.icp\t\t ready"
echo "worker2.icp\t\t ready"
echo "va-node.icp\t\t ready"
echo "mgmt-node.icp\t\t ready"
SCRIPT

docker_login = <<SCRIPT
curl -fsSL https://clis.ng.bluemix.net/install/linux | bash &> /dev/null
bx plugin install container-registry -r Bluemix &> /dev/null
docker login -u #{docker_username} -p #{docker_password} #{private_registry_server}
SCRIPT

#ICP-EE - New function to import the icp-ee image into docker
download_and_import_icp_ee = <<SCRIPT
# import previously downloaded image and then run the docker container
# Alternativelly could provide this image via vagrant synced folder instead of a local web server
#resize lv
sudo lvresize -l +100%FREE /dev/mapper/vagrant--vg-root
curl -o #{icpEE_TarFileName} -fsSL http://#{icpEE_TarWebServerHost}/#{icpEE_TarFileName}
tar xf #{icpEE_TarFileName} -O | sudo docker load
sudo docker images
#Not sure if the images need to be available locally on other nodes also.. as it was failing
#Push the image and load in worker1 and worker2 and other nodes also
#Probably there is a better way to handle this.. for now this worked.

NODES="worker1
worker2
va-node
mgmt-node"
for node in $NODES
do
  	lxc file push #{icpEE_TarFileName} $node/tmp/#{icpEE_TarFileName}
	lxc exec $node -- sh -c "tar xf /tmp/#{icpEE_TarFileName} -O | sudo docker load"
	#This is to fix an error where there is a wrong reference from install script - creat an alias tag
	lxc exec $node -- sh -c "sudo docker tag ibmcom/hyperkube-amd64:v1.12.4-ee ibmcom/hyperkube:v1.12.4-ee"
	#When enabling Vulnerability advisor, lot of images is not being referenced correctly resulting in 
	#Back-off pulling image error and hence not deployed. Need to retag the following images to the referenced image name
	lxc exec $node -- sh -c "sudo docker tag ibmcom/compliance-annotator-amd64:3.1.2 ibmcom/compliance-annotator:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/config-parser-amd64:3.1.2 ibmcom/config-parser:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/cos-indexer-amd64:3.1.2 ibmcom/cos-indexer:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/k8szk-amd64:v4 ibmcom/k8szk:v4"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/kafka-amd64:0.10.0.3 ibmcom/kafka:0.10.0.3"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/live-crawler-amd64:3.1.2 ibmcom/live-crawler:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/ma-file-annotator-amd64:3.1.2 ibmcom/ma-file-annotator:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/ma-file-wl-gen-amd64:3.1.2 ibmcom/ma-file-wl-gen:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/notification-dispatcher-amd64:3.1.2 ibmcom/notification-dispatcher:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/password-annotator-amd64:3.1.2 ibmcom/password-annotator:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/process-ma-hf-amd64:3.1.2 ibmcom/process-ma-hf:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/py-generic-indexer-amd64:3.1.2 ibmcom/py-generic-indexer:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/reg-crawler-amd64:3.1.2 ibmcom/reg-crawler:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/rootkit-annotator-amd64:3.1.2 ibmcom/rootkit-annotator:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/sas-base-amd64:3.1.2 ibmcom/sas-base:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/secure-config-annotator-amd64:3.1.2 ibmcom/secure-config-annotator:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/statsd-amd64:0.7.2.1 ibmcom/statsd:0.7.2.1"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/usncrawler-amd64:3.1.2 ibmcom/usncrawler:3.1.2"
	lxc exec $node -- sh -c "sudo docker tag ibmcom/vulnerability-annotator-amd64:3.1.2 ibmcom/vulnerability-annotator:3.1.2"
	lxc exec $node -- sh -c "rm -f /tmp/#{icpEE_TarFileName}"
done


#Preparing
sudo mkdir /opt/#{icpEE_versionLabel}
cd /opt/#{icpEE_versionLabel}
sudo mkdir /opt/#{icpEE_versionLabel}/cluster
ssh-keygen -b 4096 -f /home/vagrant/cluster/ssh_key -N ""
#Add this key to authorized_keys to master, worker1 and worker2, va-node and mgmt-node
cat /home/vagrant/cluster/ssh_key.pub >> /home/vagrant/.ssh/authorized_keys
lxc file push /home/vagrant/cluster/ssh_key.pub worker1/tmp/ssh_key.pub
lxc exec worker1 -- sh -c "cat /tmp/ssh_key.pub >> /home/vagrant/.ssh/authorized_keys"
lxc file push /home/vagrant/cluster/ssh_key.pub worker2/tmp/ssh_key.pub
lxc exec worker2 -- sh -c "cat /tmp/ssh_key.pub >> /home/vagrant/.ssh/authorized_keys"
lxc file push /home/vagrant/cluster/ssh_key.pub va-node/tmp/ssh_key.pub
lxc exec va-node -- sh -c "cat /tmp/ssh_key.pub >> /home/vagrant/.ssh/authorized_keys"
lxc file push /home/vagrant/cluster/ssh_key.pub mgmt-node/tmp/ssh_key.pub
lxc exec mgmt-node -- sh -c "cat /tmp/ssh_key.pub >> /home/vagrant/.ssh/authorized_keys"


sudo cp -rv /home/vagrant/cluster/* /opt/#{icpEE_versionLabel}/cluster
sudo mkdir /opt/#{icpEE_versionLabel}/cluster/images
sudo mv /home/vagrant/ibm-cloud-private-x86_64-3.1.2.tar.gz /opt/#{icpEE_versionLabel}/cluster/images
#rename to avoid an error
sudo docker tag ibmcom/hyperkube-amd64:v1.12.4-ee ibmcom/hyperkube:v1.12.4-ee
#echo "checking before install"
#sudo docker run --net=host -t -e LICENSE=accept -v /opt/#{icpEE_versionLabel}/cluster:/installer/cluster #{icpEE_ContainerNameAndTag} check
SCRIPT

#ICP-EE
post_ee_install_checks = <<SCRIPT
# 
echo "post install health check"
cd /opt/#{icpEE_versionLabel}/; sudo docker run --net=host -t -e LICENSE=accept -v /opt/#{icpEE_versionLabel}/cluster:/installer/cluster #{icpEE_ContainerNameAndTag} healthcheck

SCRIPT

# ICP-EE - Changed to use the ICP EE container image name and tag from previously imported tar image from local docker image repositor
install_icp = <<SCRIPT
exec 3>&1 1>>icp_install_log 2>&1
cd /opt/#{icpEE_versionLabel}; sudo docker run -e LICENSE=#{license} --net=host -v /opt/#{icpEE_versionLabel}/cluster:/installer/cluster #{icpEE_ContainerNameAndTag} install | tee /dev/fd/3
#if grep -q fatal icp_install_log; then
# 	echo "FATAL ERROR OCCURRED DURING INSTALLATION :-(" 1>&3
# 	cat icp_install_log | grep -C 3 fatal 1>&3
# 	echo "The install log can be view with: " 1>&3
# 	echo "vagrant ssh" 1>&3
# 	echo "cat icp_install_log" 1>&3
# 	exit 1
#fi
SCRIPT

create_persistant_volumes = <<SCRIPT
sleep 120
cat > volumes.yaml <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol01
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share01
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol02
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share02
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol03
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share03
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol04
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share04
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol05
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share05
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol06
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share06
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol07
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share07
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol08
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share08
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol09
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share09
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol10
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteMany
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share10
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol11
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share11
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol12
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share12
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol13
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share13
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol14
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share14
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol15
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share15
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol16
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share16
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol17
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share17
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol18
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share18
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol19
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share19
      server: #{base_segment}.100
---
apiVersion: v1
kind: PersistentVolume
metadata:
   name: vol20
spec:
   capacity:
      storage: 20Gi
   accessModes:
      - ReadWriteOnce
   persistentVolumeReclaimPolicy: Recycle
   nfs:
      path: /storage/share20
      server: #{base_segment}.100
EOF
kubectl create -f /home/vagrant/volumes.yaml
SCRIPT

install_kubectl = <<SCRIPT
sudo curl -ko /tmp/kubectl -LO https://#{base_segment}.100:8443/api/cli/kubectl-linux-amd64
sudo chmod +x /tmp/kubectl
sudo mv /tmp/kubectl /usr/local/bin/kubectl
sudo mkdir /home/vagrant/kubectl-certs
SCRIPT

install_helm = <<SCRIPT
sudo curl -kLo /tmp/helm.tar.gz https://#{base_segment}.100:8443/api/cli/helm-linux-amd64.tar.gz
sudo tar xzf /tmp/helm.tar.gz -C /tmp/
sudo mv /tmp/linux-amd64/helm /usr/local/bin/helm
sudo rm -f /tmp/helm.tar.gz
sudo rm -rf /tmp/linux-amd64/ \
export HELM_HOME=/usr/local/bin/helm &> /dev/null
echo "HELM_HOME=/usr/local/bin/helm" >> ~/.bash_profile &> /dev/null
sudo chown -R vagrant:vagrant /usr/local/bin/helm &> /dev/null
helm init --client-only &> /dev/null
SCRIPT

install_cloudctl = <<SCRIPT
#ICP-EE - Put some sleep to let the services get time to run
echo "install_cloudctl: Sleep for a while..."
sleep 30
sudo wget https://#{base_segment}.100:8443/api/cli/cloudctl-linux-amd64 --no-check-certificate
sudo chmod 755 cloudctl-linux-amd64
sudo mv cloudctl-linux-amd64 /usr/local/bin/cloudctl
cloudctl login -a https://#{base_segment}.100:8443 --skip-ssl-validation -u admin -p #{default_admin_password} -c id-mycluster-account -n default
SCRIPT

install_startup_script = <<SCRIPT
sudo bash -c 'cat > /usr/local/bin/icp-ce-startup.sh' <<'EOF'
#!/bin/bash

sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo ip link set dev eth1 up
echo "nameserver #{base_segment}.100" | sudo tee /etc/resolv.conf > /dev/null
echo "search icp" | sudo tee --append /etc/resolv.conf > /dev/null
sudo docker ps -a | grep Exit | cut -d ' ' -f 1 | xargs sudo docker rm > /dev/null || true
sleep 180
kubectl config set-cluster icp --server=https://#{base_segment}.100:8001 --insecure-skip-tls-verify=true
kubectl config set-context icp --cluster=icp
kubectl config set-credentials icp --client-certificate=/home/vagrant/kubectl-certs/kubecfg.crt --client-key=/home/vagrant/kubectl-certs/kubecfg.key
kubectl config set-context icp --user=icp
kubectl config use-context icp
kubectl get pods -o wide -n kube-system | grep "icp-ds" | cut -d ' ' -f 1 | xargs kubectl -n kube-system delete pods
sleep 120
while [[ '' != $(kubectl get pods --namespace kube-system | sed -n '1!p' | grep -v Running) ]]
do
  kubectl get pods -o wide -n kube-system | grep "CrashLoopBackOff\\|Init" | cut -d ' ' -f 1 | xargs kubectl -n kube-system delete pods
  sleep 120
done
EOF
sudo chmod 744 /usr/local/bin/icp-ce-startup.sh

sudo bash -c 'cat > /etc/systemd/system/icp-ce-startup.service' <<'EOF'
[Unit]
After=network.target

[Service]
ExecStart=/usr/local/bin/icp-ce-startup.sh

[Install]
WantedBy=default.target
EOF
sudo chmod 644 /etc/systemd/system/icp-ce-startup.service
sudo systemctl daemon-reload
sudo systemctl enable icp-ce-startup.service
SCRIPT

install_shutdown_script = <<SCRIPT
sudo bash -c 'cat > /usr/local/bin/icp-ce-shutdown.sh' <<'EOF'
#!/bin/bash

lxc stop worker1 --stateful
lxc stop worker2 --stateful
lxc stop va-node --stateful
lxc stop mgmt-node --stateful
EOF
sudo chmod 744 /usr/local/bin/icp-ce-shutdown.sh

sudo bash -c 'cat > /etc/systemd/system/icp-ce-shutdown.service' <<'EOF'
[Unit]
Description=stops lxc containers preserving state at system shutdown
Conflicts=reboot.target
After=network.target

[Service]
ExecStop=/usr/local/bin/icp-ce-shutdown.sh

[Install]
WantedBy=default.target
EOF
sudo chmod 644 /etc/systemd/system/icp-ce-shutdown.service
sudo systemctl daemon-reload
sudo systemctl enable icp-ce-shutdown.service
SCRIPT

install_shellinabox = <<SCRIPT
sudo apt-get install -y shellinabox &> /dev/null
SCRIPT

ensure_services_up = <<SCRIPT
sleep 120
echo "Waiting for all IBM Cloud Private Services to start..."
count=0
while [[ '' != $(kubectl get pods --namespace kube-system | sed -n '1!p' | grep -v Running) ]]
do
  if [ "60" -lt "$count" ]; then
  	echo "The following services are still not available after 30 minutes..."
  	kubectl get pods --namespace kube-system | grep -v Running
  	exit
  fi
  count=$(($count+1))
  echo "."
  sleep 30
done
if [ "60" -gt "$count" ]; then
	echo "All IBM Cloud Private Services have been successfully started..."
	kubectl get pods --namespace kube-system &> kube-system-services.list
	cat kube-system-services.list
	rm -f kube-system-services.list
fi
SCRIPT

happy_dance = <<SCRIPT
curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.89 Safari/537.36" -s 'http://bit.ly/2fqp98V' > /dev/null || true
cat << 'EOF'

                                O MMM .MM  MM7
                         ..M MMMM MMM DMMM MMM.MMMMO.
                       M.MM MMMM..MMM MMMM.MMM.NMMMMMM.
                     MM MM+MMM:. ,MM: MMMM MMM  MMMMMM
                    MM=.MM MMM   MMM. MMMM?MMM  MMM ..~ :MMM.
                MM..MM.MM,OMMI   MMM .MMMMMMMM  MMM    MMMMMMM
              MMMM MM.NMM ~MMM   MMM..MMMMMMMM  MMM.  OMMMMMMMM
           ..MM.MMNMM.MM?  MMM  .MMM..MMMMMMMM  MMM   ~MM+  ,MM
          .MMM.MM:MM.?MM. .MMM  IMMM :MMMMMMMM  MMM   .MMM.  .
         .MMMMMMMMMM.MMM  .MMM~.MMMD MMMIMMMMM  MMMMMM. MMM   .,MMMM.
         NMMMMMM.MM: MM.    MMM.MMM, MMM.MMMMM  MMMMMM: =MMM   MMMMMM
      ..=MM,MMM.MMM MMM.   .MMM.MMM  MMM.8MMMM  MMM.  ,  .MMM .MMM  :
     MM MMM.MMM.MMM MMM     MMM MMM. MMM  MMMM  MMM.      MMMM.MMMM8.
   M . MMM.MMMZ7MM  MM.    .MMM MMM  MMM. MMMM  MMM.      .MMMM. MMMMMM   .
  M M.:MMMMMMM MMM.=MM      MMM.MMM  MMM  MMMM  MMM         MMM   .,MMMM MM
  M, M.7MMMMM..MMMMMMM.M   ~MMM.MMM .MMM. MMMM  MMM        .MMM ?   .MMM.M.M.
   MM. N       MMMMMM MMM=MMMM  MMM. MMM  MMMM  MMM. .DMM, MMMM MMMMMMMM  M M
   MMMM.  MM.   MMMM..MMMMMMM   MMM. MMM  MMMM :MMMMMZMMMMMMMMM  MMMMM  .M.$M
   MM.MMMMM.. MMM   .  ,MMM8    MMM .MMM  .MMM DMMMMM,  MMMMM      ..MM.. MM
   MM MM.MMMMMMM:   ~MMMM?       ... :IZ   MM,.NNO?,..         ZMM7.. MMMMMM
   MM MM MM MMMMMMMMMMMM=     .=MMMMMMMMMMMMNNMMMMMMMMMMMO...  .8MMMMMMMMMMM
   MM MM .M.M:  .MZMMMMMMMMMMMMMMMMMZ: .  . ......:INMMMMMMMMMMMMMMMMM :MMMM
   MM MM..M.MM,7MM :  MM  .MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM.MMM  MM :MMMM
   MM MM M..MM,7MM :MMMM MM.MM  MM =MMM.MM:  ...M .MM.. .MM.:M MMM. MM :MMMM
   NMMMM M..MM,7MM  .:MM MM MM ..M =MM   MMMM MMM .M MMM MM. M MM8~ MM :M MM
    $MMMMMM.MM,7MM :MMMM .  MM Z.M =MM M MMMM MMM .M MMM =M..  MM +.MM  .NM8
      .MMMMMMM+7MM ~MMMM M: MM ZM .=MM M =MMM MMM .M.MMM.MM.M. MM.MMIMMMMMM
     MM  . MMMMMMMMMN.MM MM.MM ZM, =M .   MMM MMM .M .MI MM.MM M?MMMMMMMM
     MMM    ..  8MMMMMMMMMMMMMDOMM.~M.MMM.MMM.MMM..MM, 7MMMMMMMMMMMMM.
     MMMM  MMM  :   ..,MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM$   .
     .MMMMMMMM  MM$       .  .. ..:$MMMMMMMMMMMMMMMN=..     .    MMMMMMM.
      MMMMMMMM  MMM     MMMM  MMM. .,..   .   . .  IMM  MMMMMM  MMM7. I.
       MMMMOMM.~MMM.   MMMMM7.MMZ  ,MM: .MMM .MMM  MMM .MMMMMM $MM,
       DM M MM MMMM   MMM  8  MM,  OMM   MMM .MMM. MMM ?MM      MMMM.
       .MMZ MM.MM=MN  MMM     MM   MMM  .MMM  MMMM MMM MMM       MMMM
         ,  MM MM MM  MM+     MM.  MMM.  MMM  MMMM:MMM MMMMMM    MMMM
          ..MM MM MM. MMI    .MM=  MMM   MMM .MMMMMMM..MMMMMM    MMM
            MMM7MMMMM MMM     MMMMMMMM. .MMM $MMMMMMM  MMM    .MMMM.
             $M.MMMMM MMM     MMMMMMMM. .MMM.MMMMMMMM.=MM~     MMM
              . MMMMMM MM    .MMM. MMM. ZMM: MMMMMMMM MMM. IMM..
                 M :MM MM:    MMM. MMM  MMM  MMMMMMM  MMMMMMMM
                    MMM7MM. . MMM  MMM. MMM  MMMDMMM  MMMMMM+
                     MM.MMMMMMMMM  MMM..MMM ?MM=~MMM.~MMMM
                       . MMMM OMM. MMM .MMM MMM .MM= MM
                         . M   MMI MMM  MM  MMM..MM
                              ..NM =MM .MM .MD..  .


###############################################################################
#          IBM Cloud Private enterprise edition installation complete!         #
#                  The web console is now available at:                       #
#                                                                             #
#                          https://#{base_segment}.100:8443                        #
#        username/password is admin/#{default_admin_password}         #
#                                                                             #
#                          Documentation available at:                        #
#               https://www.ibm.com/support/knowledgecenter/SSBS6K            #
#                                                                             #
#                 Request access to the ICP-ce Public Slack!:                 #
#                            http://ibm.biz/BdsHmN                            #
###############################################################################
EOF
SCRIPT

Vagrant.configure(2) do |config|

  if Vagrant.has_plugin?("vagrant-vbguest")
    config.vbguest.auto_update = false
  end
	
  #----------------------------------------------	
  #Use base box with 500GB root partition for EE install
  #Use instructions on from here to resize the base box : https://gist.github.com/jj-meyer/a9d878b004542e825b47
  required_plugins = %w( vagrant-vbguest vagrant-disksize )
    _retry = false
    required_plugins.each do |plugin|
        unless Vagrant.has_plugin? plugin
            system "vagrant plugin install #{plugin}"
            _retry=true
        end
    end

    if (_retry)
        exec "vagrant " + ARGV.join(' ')
    end

    #ICP-EE
    #config.vm.box = "bento/ubuntu-16.04"
	#New custom box with root partition upto 500GB created from above box.
    config.vm.box = "pradeepn-altran/bento-ubuntu-1604-500gb-4icpee"
    config.vm.box_version = "2019.01"
  #----------------------------------

  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.ssh.forward_agent = true
  config.ssh.forward_x11 = true
  config.ssh.insert_key = false
  config.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"

  config.vm.provision "shell", privileged: false, inline: configure_master_ssh_keys, keep_color: true, name: "configure_master_ssh_keys"
  config.vm.provision "shell", privileged: false, inline: configure_swap_space, keep_color: true, name: "configure_swap_space"
  config.vm.provision "shell", privileged: false, inline: configure_performance_settings, keep_color: true, name: "configure_performance_settings"
  config.vm.provision "shell", privileged: true, inline: load_ipvs_module, keep_color: true, name: "load_ipvs_module"
  if use_cache.downcase.eql? 'true'
  	config.vm.provision "shell", privileged: false, inline: configure_apt_proxy, keep_color: true, name: "configure_apt_proxy"
  end
  
  config.vm.provision "shell", privileged: false, inline: install_icp_prereqs, keep_color: true, name: "install_icp_prereqs"
  config.vm.provision "shell", privileged: false, inline: add_storage_vol, keep_color: true, name: "add_storage_vol"
  config.vm.provision "shell", privileged: false, inline: setup_nfs_shares, keep_color: true, name: "setup_nfs_shares"
  config.vm.provision "shell", privileged: false, inline: configure_nat_iptable_rules, keep_color: true, name: "configure_nat_iptable_rules"
  config.vm.provision "shell", privileged: false, inline: configure_lxd, keep_color: true, name: "configure_lxd"
  config.vm.provision "shell", privileged: false, inline: bring_up_icp_host_interface, keep_color: true, name: "bring_up_icp_host_interface"
  config.vm.provision "shell", privileged: false, inline: set_dnsnameserver_to_lxd_dnsmasq, keep_color: true, name: "set_dnsnameserver_to_lxd_dnsmasq"
  config.vm.provision "shell", privileged: false, inline: configure_icp_install, keep_color: true, name: "configure_icp_install"
  config.vm.provision "shell", privileged: false, inline: boot_lxd_worker_nodes, keep_color: true, name: "boot_lxd_worker_nodes"
  config.vm.provision "shell", privileged: false, inline: wait_for_worker_nodes_to_boot, keep_color: true, name: "wait_for_worker_nodes_to_boot"
  if !private_registry_enabled.eql? 'false'
    config.vm.provision "shell", inline: docker_login, keep_color: true, name: "docker_login"
  end
  
  #ICP-EE - download icp-ee image and import into docker 
  config.vm.provision "shell", privileged: false, inline: download_and_import_icp_ee, keep_color: true, name: "download_and_import_icp_ee"
  
  config.vm.provision "shell", privileged: false, inline: install_icp, keep_color: true, name: "install_icp"
  config.vm.provision "shell", privileged: false, inline: install_kubectl, keep_color: true, name: "install_kubectl"
  config.vm.provision "shell", privileged: false, inline: install_helm, keep_color: true, name: "install_helm"
  
  config.vm.provision "shell", privileged: false, inline: install_cloudctl, keep_color: true, name: "install_cloudctl"
  
  config.vm.provision "shell", privileged: false, inline: create_persistant_volumes, keep_color: true, name: "create_persistant_volumes"
  config.vm.provision "shell", privileged: false, inline: install_startup_script, keep_color: true, name: "install_startup_script"
  config.vm.provision "shell", privileged: false, inline: install_shutdown_script, keep_color: true, name: "install_shutdown_script"
  config.vm.provision "shell", privileged: false, inline: install_shellinabox, keep_color: true, name: "install_shellinabox"
  # config.vm.provision "shell", privileged: false, inline: ensure_services_up, keep_color: true, name: "ensure_services_up", run: "always"
  config.vm.provision "shell", privileged: false, inline: happy_dance, keep_color: true, name: "happy_dance"

  config.vm.define "icp" do |icp|
    #icp.vm.box = "bento/ubuntu-16.04"
	#ICP-EE change to use a larger size primary disk for the VM
    config.vm.box = "pradeepn-altran/bento-ubuntu-1604-500gb-4icpee"
    config.vm.box_version = "2019.01"
	    
    icp.vm.hostname = "master.icp"
    icp.vm.box_check_update = true
    icp.vm.network "private_network", ip: "#{base_segment}.100", adapter_ip: "#{base_segment}.1", netmask: "255.255.255.0", auto_config: false
    icp.vm.provider "virtualbox" do |virtualbox|
      virtualbox.name = "#{vm_name}"
      virtualbox.gui = false
      virtualbox.customize ["modifyvm", :id, "--apic", "on"] # turn on I/O APIC
      virtualbox.customize ["modifyvm", :id, "--ioapic", "on"] # turn on I/O APIC
      virtualbox.customize ["modifyvm", :id, "--x2apic", "on"] # turn on I/O APIC
      virtualbox.customize ["modifyvm", :id, "--biosapic", "x2apic"] # turn on I/O APIC
      virtualbox.customize ["modifyvm", :id, "--cpus", "#{cpus}"] # set number of vcpus
      virtualbox.customize ["modifyvm", :id, "--memory", "#{memory}"] # set amount of memory allocated vm memory
      virtualbox.customize ["modifyvm", :id, "--ostype", "Ubuntu_64"] # set guest OS type
      # virtualbox.customize ["modifyvm", :id, "--natdnspassdomain", "off" ] # enables use of network dns domain to resolve host
      virtualbox.customize ["modifyvm", :id, "--natdnshostresolver1", "off"] # enables DNS resolution from guest using host's DNS
      virtualbox.customize ["modifyvm", :id, "--natdnsproxy1", "off"] # enables DNS requests to be proxied via the host
      virtualbox.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"] # turn on promiscuous mode on nic 2
      virtualbox.customize ["modifyvm", :id, "--nictype1", "virtio"]
      virtualbox.customize ["modifyvm", :id, "--nictype2", "virtio"]
      virtualbox.customize ["modifyvm", :id, "--pae", "on"] # enables PAE
      virtualbox.customize ["modifyvm", :id, "--longmode", "on"] # enables long mode (64 bit mode in GUEST OS)
      virtualbox.customize ["modifyvm", :id, "--hpet", "on"] # enables a High Precision Event Timer (HPET)
      virtualbox.customize ["modifyvm", :id, "--hwvirtex", "on"] # turn on host hardware virtualization extensions (VT-x|AMD-V)
      virtualbox.customize ["modifyvm", :id, "--nestedpaging", "on"] # if --hwvirtex is on, this enables nested paging
      virtualbox.customize ["modifyvm", :id, "--largepages", "on"] # if --hwvirtex & --nestedpaging are on
      virtualbox.customize ["modifyvm", :id, "--vtxvpid", "on"] # if --hwvirtex on
      virtualbox.customize ["modifyvm", :id, "--vtxux", "on"] # if --vtux on (Intel VT-x only) enables unrestricted guest mode
      virtualbox.customize ["modifyvm", :id, "--boot1", "disk"] # tells vm to boot from disk only
      virtualbox.customize ["modifyvm", :id, "--rtcuseutc", "on"] # lets the real-time clock (RTC) operate in UTC time
      virtualbox.customize ["modifyvm", :id, "--audio", "none"] # turn audio off
      virtualbox.customize ["modifyvm", :id, "--clipboard", "disabled"] # disable clipboard
      virtualbox.customize ["modifyvm", :id, "--usbehci", "off"] # disable usb hot-plug drivers
      virtualbox.customize ["modifyvm", :id, "--vrde", "off"]
      virtualbox.customize ["setextradata", :id, "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled", 0] # turns the timesync on
      virtualbox.customize ["guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-interval", 10000] # sync time every 10 seconds
      virtualbox.customize ["guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-min-adjust", 100] # adjustments if drift > 100 ms
      virtualbox.customize ["guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-on-restore", 1] # sync time on restore
      virtualbox.customize ["guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-start", 1] # sync time on start
      virtualbox.customize ["guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 1000] # at 1 second drift, the time will be set and not "smoothly" adjusted
      virtualbox.customize ['modifyvm', :id, '--cableconnected1', 'on'] # fix for https://github.com/mitchellh/vagrant/issues/7648
      virtualbox.customize ['modifyvm', :id, '--cableconnected2', 'on'] # fix for https://github.com/mitchellh/vagrant/issues/7648
      virtualbox.customize ['storagectl', :id, '--name', 'SATA Controller', '--hostiocache', 'on'] # use host I/O cache
      virtualbox.customize ['storageattach', :id, '--storagectl', 'SATA Controller', '--port', 0, '--device', 0, '--type', 'hdd', '--nonrotational', 'on', '--medium', "#{base_storage_disk_path}"]
      if !File.exists?("#{extra_storage_disk_path}")
        virtualbox.customize ['createhd', '--filename', "#{extra_storage_disk_path}", '--format', 'VMDK', '--size', 500 * 1024]
      end
      if !File.exists?("#{lxd_storage_disk_path}")
        virtualbox.customize ['createhd', '--filename', "#{lxd_storage_disk_path}", '--format', 'VMDK', '--size', 1200 * 1024]
      end
      virtualbox.customize ['storageattach', :id, '--storagectl', 'SATA Controller', '--port', 1, '--device', 0, '--type', 'hdd', '--nonrotational', 'on', '--medium', "#{extra_storage_disk_path}"]
      virtualbox.customize ['storageattach', :id, '--storagectl', 'SATA Controller', '--port', 2, '--device', 0, '--type', 'hdd', '--nonrotational', 'on', '--medium', "#{lxd_storage_disk_path}"]
    end
  end
end
