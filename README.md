# icp-ee-vagrant-install
IBM Cloud Private EE Install using Vagrant 

This repository contains documentation and Vagrant file with changes I had to make from the original ICD CE Install using Vagrant File from this repo: https://github.com/IBM/deploy-ibm-cloud-private/blob/master/docs/deploy-vagrant.md . 

This script requires you to have the ICP enterprise edition tar ball of IBM Cloud Private. This is meant to be installed on a powerfull laptop or local desktop computer for evaluation and demo purposes only and is not recommended for production deployments. You should have an entitled version of ICP Enterprise Edition. If you are an IBM Business Parter it may be available as part of your Software Access Catalog entitlements or your company would have to purchase it from the IBM Passport Advantage.

I would like to thank the original authors of the Vagrant file from the repo at https://github.com/IBM/deploy-ibm-cloud-private/blob/master/docs/deploy-vagrant.md as it was easy to get IBM Cloud Private CE up and running in about 60 minutes !  Being in the security domain, I wanted to play around with the Vulnerability Advisor component, whichi is not part of the CE. Hence I wanted to extend the script to install the enterprise edition to evaluate the Vulnerability Advisor and other monitoring and management components.

The modified file contains my changes to get the ICP Enterprise Edition up and running with Vulnerability Advisor, monitoring components. 

This is still work in progress. I will post the Vagrant file soon once I have the above deployed successfuly. Stay tuned.
