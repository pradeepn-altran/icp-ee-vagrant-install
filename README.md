# icp-ee-vagrant-install
IBM Cloud Private EE Install using Vagrant 

This repository contains documentation and Vagrant file with changes I had to make from the original ICP CE Install using Vagrant File from this repo: https://github.com/IBM/deploy-ibm-cloud-private/blob/master/docs/deploy-vagrant.md . 

This script requires you to have the ICP Enterprise Edition tar ball of IBM Cloud Private. This is meant to be installed on a  laptop or local desktop computer with sufficient RAM (atleast 32GB, CPU (8 cores) core and disk space (1TB). Note: This is for development, evaluation and demo purposes only and is not recommended for production deployments. You should have an entitled version of ICP Enterprise Edition. If you are an IBM Business Parter it may be available as part of your Software Access Catalog entitlements or your company should have access to IBM Passport Advantage Software Access.

I would like to thank the original authors of the Vagrant file from the repo at https://github.com/IBM/deploy-ibm-cloud-private/blob/master/docs/deploy-vagrant.md as it was easy to get IBM Cloud Private CE up and running in about 60 minutes !  Being in the security domain, I wanted to get more insight Vulnerability Advisor and monitoring/logging components, which is not part of the CE. Hence I wanted to extend the script to install the enterprise edition. I am providing the script in the hope it will be useful for others, as it took a few weeks and number of tries to get this working finally. The script is tested with ICP version 3.1.2.

