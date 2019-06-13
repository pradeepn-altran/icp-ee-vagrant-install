# icp-ee-vagrant-install
IBM Cloud Private EE Install using Vagrant 

This repository contains documentation and Vagrant file with changes made to the original ICP CE Install using Vagrant from this repo: https://github.com/IBM/deploy-ibm-cloud-private/blob/master/docs/deploy-vagrant.md . 

This script requires you to have the ICP Enterprise Edition tar ball for IBM Cloud Private. IBM Cloud Private EE is a licensed product from IBM. If you are a IBM Business Parter it may be available as part of your Software Access Catalog entitlements or your company should have license to download licensed version from IBM Passport Advantage site.

This file is intended to be installed on to a  laptop or local desktop computer or a virtualized Windows 10 VM with sufficient RAM (atleast 32GB, CPU (8 cores) core and disk space (1TB). NOTE: This is for development, evaluation and demo purposes only and is not recommended for production deployments. You should have an entitled version of ICP Enterprise Edition available separately.

I would like to thank the original authors of the Vagrant file from the repo at https://github.com/IBM/deploy-ibm-cloud-private/blob/master/docs/deploy-vagrant.md as it was very easy to get IBM Cloud Private CE up and running in about 60 minutes!  Being in the security domain, I wanted to get more insight on Vulnerability Advisor and monitoring/logging components, which is not part of the CE. Hence I wanted to extend the script to install the enterprise edition on my demo laptop. 

I am providing the script in the hope it will be useful for others who may be looking to install the ICP Enterprise Editon in their on-premise environment for testing, demo and learning purposes. It took quite a few weeks of efforts in my spare time with help from original authors to get this working finally. The script is tested with ICP EE version 3.1.2.

Following the pre-requiste steps, before running this script using vagrant.



