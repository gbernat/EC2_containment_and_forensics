# How to deploy the environment:

0. Install Terraform
1.  $ git clone https://github.com/gbernat/EC2_containment_and_forensics
2.  $ cd EC2_containment_and_forensics/terraform
3.  Set variables as needed in the variables.tf and main.tf files
4.  Get Paramiko module from pip, preferably downloada in a lambda environment compatible (i.e. Amazon Linux 2 AMI)<br>
    $ pip install parmiko -t lambda/packages/paramiko_src<br>
    Copy lambda/EC2ForensicsEvidence.py to lambda/packages/paramiko_src/

5.  $ terraform init
6.  $ terraform plan
7.  $ terraform apply -auto-approve

8. Create test events (i.e. lambda/test_events)
