# icp-ee-vagrant-install
## IBM Cloud Private EE Install using Vagrant 

This repository contains documentation and Vagrant file with changes made to the original ICP (IBM Cloud Private) CE Install using Vagrant from this repo: https://github.com/IBM/deploy-ibm-cloud-private/blob/master/docs/deploy-vagrant.md . 

This script requires you to have the ICP Enterprise Edition tar ball for IBM Cloud Private. IBM Cloud Private EE is a licensed product from IBM. If you are a IBM Business Parter it may be available as part of your Software Access Catalog entitlements or your company should have license to download licensed version from IBM Passport Advantage site.

This vagrant script is intended to install ICP EE on to a  laptop or local desktop computer or a virtualized Windows 10 VM with sufficient RAM (atleast 32GB, CPU (8 cores) core and disk space (1TB). NOTE: This is for development, evaluation, testing and demo purposes only and is not recommended for production deployments. You should have an entitled version of ICP Enterprise Edition tar file available separately.

I would like to thank the original authors of the Vagrant file from the repo at https://github.com/IBM/deploy-ibm-cloud-private/blob/master/docs/deploy-vagrant.md as it was very easy to get IBM Cloud Private CE up and running in about 60 minutes!  Being in the security domain, I wanted to get more insight on Vulnerability Advisor and monitoring/logging components of ICP  which is not part of the CE. Hence I wanted to extend the script to install the enterprise edition on my demo laptop. 

The script uses LXD containers - https://linuxcontainers.org/lxd/  to create multiple nodes inside the main Ubuntu VM. LXD containers are light weight and efficiently uses memory, cpu and disk space. The script creates 4 LXD conainers for worker1, worker2, vulnerability advisor and management nodes. Each of the master node and LXD containers gets access to the full memory, cpu and assigned disk space from the storage pools. This enables efficient use of your full computer memory and cpu.

I am providing the script in the hope it will be useful for others who may be looking to install the ICP Enterprise Edition in their on-premise environment for testing, demo and learning purposes. It took quite a few weeks of efforts in my spare time with help from original authors and countless issue resolution to get this working with two node worker cluster, vulnerability advisor and management nodes. The script is tested with ICP EE version 3.1.2.

Steps to install and run ICP EE is given below.


1. Install VirtualBox for Windows 64bit : https://www.virtualbox.org/
2. Install Vagrant for Windows 64bit : https://www.vagrantup.com/
3. Get the ICP EE 3.1.2 tar ball from your licensed source (IBM Partner World or IBM Passport Advantage)
4. Enable IIS on Windows 10. This is used to get the tar ball into your virtual machine. (Example steps here https://www.itnota.com/install-iis-windows/)
5. Move the ICP EE 3.1.2 tar ball to your default C:\inetpub\wwwroot folder
6. Determine your local Windows host IP Address and test you can download the tar file using URL http://IPAddress/ibm-cloud-private-x86_64-3.1.2.tar.gz
7. Download the Vagrantfile from this repo or clone this repo and edit the Vagrantfile - variable icpEE_TarWebServerHost with your IP Address
8. Review other configuration parameters from line #1 to #70 or so in the Vagrantfile
9. In the command shell type vagrant up  to start the vagrant script
10. The process will take about 3 hours or so.
11. If everything goes well, you should see the success message 
12. Follow the instructions to login and initialize the kubectl as described from this page : https://github.com/IBM/deploy-ibm-cloud-private/blob/master/README.md
13. You can login and goto the [Dashboard](images/ICP-Dashboard.PNG) and see the health of your install 
14. Deploy a sample application from the public catalog. Click [Catalog](images/ICP-Catalog.PNG) -> Search for Node JS Sample. 
15. [Configure](images/NodeJSSample-Configure.PNG) and deploy - follow wizard - specify a release name and choose default namespace
16. From ICP menu -> Tools -> Vulnerability Advisor -> default - See the scanned results of the deployed application
  
Happy Exploring IBM Cloud Private Enterprise Edition !


## Misc handy commands to explore your VM and Nodes
* log in to master vm
```
$ vagrant ssh
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

```
* List the LXD Containers
```
vagrant@master:~$ lxc list
+-----------+---------+-----------------------+------+------------+-----------+
|   NAME    |  STATE  |         IPV4          | IPV6 |    TYPE    | SNAPSHOTS |
+-----------+---------+-----------------------+------+------------+-----------+
| mgmt-node | RUNNING | 192.168.27.105 (eth0) |      | PERSISTENT | 0         |
|           |         | 172.17.0.1 (docker0)  |      |            |           |
|           |         | 10.1.2.192 (tunl0)    |      |            |           |
+-----------+---------+-----------------------+------+------------+-----------+
| va-node   | RUNNING | 192.168.27.104 (eth0) |      | PERSISTENT | 0         |
|           |         | 172.17.0.1 (docker0)  |      |            |           |
|           |         | 10.1.172.128 (tunl0)  |      |            |           |
+-----------+---------+-----------------------+------+------------+-----------+
| worker1   | RUNNING | 192.168.27.101 (eth0) |      | PERSISTENT | 0         |
|           |         | 172.17.0.1 (docker0)  |      |            |           |
|           |         | 10.1.235.128 (tunl0)  |      |            |           |
+-----------+---------+-----------------------+------+------------+-----------+
| worker2   | RUNNING | 192.168.27.102 (eth0) |      | PERSISTENT | 0         |
|           |         | 172.17.0.1 (docker0)  |      |            |           |
|           |         | 10.1.189.64 (tunl0)   |      |            |           |
+-----------+---------+-----------------------+------+------------+-----------+
```
* Log in to worker1 node
```
vagrant@master:~$ lxc exec worker1 -- sudo --login --user vagrant
vagrant@worker1:~$ df -h
Filesystem                    Size  Used Avail Use% Mounted on
/dev/lxd/containers_worker1   271G   38G  220G  15% /
none                          492K     0  492K   0% /dev
udev                           13G     0   13G   0% /dev/fuse
tmpfs                         100K     0  100K   0% /dev/lxd
/dev/mapper/vagrant--vg-root  491G   77G  394G  17% /dev/mem
tmpfs                         100K     0  100K   0% /dev/.lxd-mounts
tmpfs                          13G     0   13G   0% /dev/shm
tmpfs                          13G   34M   13G   1% /run
tmpfs                         5.0M     0  5.0M   0% /run/lock
tmpfs                          13G     0   13G   0% /sys/fs/cgroup
tmpfs                         2.6G     0  2.6G   0% /run/user/1000
vagrant@worker1:~$

```

## IBM Cloud Private resources

There are numerouse resources on IBM Cloud Private, such as:

1. IBM Skills Gateway: https://www-03.ibm.com/services/learning/ites.wss/zz-en?pageType=journey_description&journeyId=ICP-LJ02&tag=o-itns-01-02#
2. IBM Cloud Private System Administrator's Guide: http://www.redbooks.ibm.com/abstracts/sg248440.html?Open
3. IBM Cloud Private Application Developers Guide http://www.redbooks.ibm.com/abstracts/sg248441.html?Open
4. IBM Cloud Private Overview:  https://www.coursera.org/lecture/deploy-micro-kube-icp/what-is-ibm-cloud-private-ZoWVi
5. IBM Cloud Private Knowledge Center: https://www.ibm.com/support/knowledgecenter/SSBS6K_3.1.2/kc_welcome_containers.html

Feel free to send me a note or create an issue if you run into any issues.
