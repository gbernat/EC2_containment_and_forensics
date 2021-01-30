# How to deploy the environment:

0. Install Terraform
1.  $ git clone https://github.com/gbernat/EC2_containment_and_forensics
2.  $ cd EC2_containment_and_forensics/terraform
3.  Set variables as needed in the variables.tf and main.tf files
4.  Get Paramiko module from pip, preferably downloaded in a lambda environment compatible (i.e. Amazon Linux 2 AMI)<br>
    ```
    $ mkdir paramiko_for_lambda_layer; cd paramiko_for_lambda_layer
    $ mkdir python; cd python
    $ pip3 install paramiko -t .
    $ cd ..; zip -r /tmp/paramico-2.7.2_src.zip .
    ```

    Get the zip file and copy it to lambda/packages/<br>
    >    Alternatively, don't do any of that and use the version provided of Paramiko in lambda/packages/paramiko-2.7.2_src.zip

5.  $ terraform init
6.  $ terraform plan
7.  $ terraform apply -auto-approve

8. Create test events (i.e. lambda/test_events)
