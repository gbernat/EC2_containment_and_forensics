# EC2_containment_and_forensics
Remotely retrieves artifacts like files and commands output from a vulnerated EC2 Linux server, and performs a memory dump.<br>
Everything collected is sent compressed to an S3 bucket.<br>
Artifacts are detailed in a separate artifacs.json file (Wildcards are allowed to filenames and directories). Resources files (for example artifacs.json) are taken from S3.<br>
In addition, preserves AMI/EBS snapshot and executes EC2 instance containment procedure.<br>
<br>
# Architecture
![](https://github.com/gbernat/EC2_containment_and_forensics/blob/master/forensics_arch_black.PNG)

* Example Config file on S3
```json
{
"working_path": "/tmp/forensics/",
"S3_bucket": "my-forensics",
"S3_resources": ["forensics/resources/artifacts.json", "forensics/resources/collectLocalForensics.py"],
"S3_evidence_path": "forensics/evidence/",
"EC2_key": "forensics/config/EC2-key.pem",
"ec2_local_user": "ec2-user",
"isolation_security_groups": ["sg-1119773906990d7bc","sg-22243d7ebc40c2609"]
}
```

* Script help:
```cmd
$ python3 containmentAndForensicsEC2ToS3_lambda.py -h

usage: containmentAndForensicsEC2ToS3_lambda.py [-h] -id INSTANCE_ID
                                                [--no-memory-dump]
                                                [--no-ami-snapshot]
                                                [--conserve-local-forensics]
                                                [--no-send-to-S3]
                                                [--S3-data-format {individual,packed}]

optional arguments:
  -h, --help            show this help message and exit
  -id INSTANCE_ID, --InstanceId INSTANCE_ID
                        Instance id of the server to take forensics data from.
  --no-memory-dump      Do not execute memory dump. --> default: false (make
                        memory dump)
  --no-ami-snapshot     Do not snapshot entire AMI. --> default: false (make
                        EBS snapshot. Otherwise only EBS snapshot will be
                        taken)
  --conserve-local-forensics
                        Do not delete forensic files gathered in destination
                        server after finishing tasks. --> default: false
                        (delete tmp files in remote server)
  --no-send-to-S3       Do not copy forensic files to S3 bucket. --> default:
                        false (copy forensic files to S3)
  --S3-data-format {individual,packed}
                        Choose how forensic data is stored in S3, as an
                        individual compressed file, or individually. -->
                        default: packed (save one compressed file to S3
                        containing all forensic files)
```

* Usage script example and output:
```cmd
$ python3 containmentAndForensicsEC2ToS3_lambda.py -id i-4857abcd0957dc81a --no-memory-dump --no-ami-snapshot --conserve-local-forensics

I'm going to do this:
instance_id: i-4857abcd0957dc81a
 memory_dump: False
 ami_snapshot: False
 conserve_files: True
 send_to_s3: True
 s3_data_format: packed

Geting configuration parameters from S3: my-forensics/forensics/config/containmentAndForensicsEC2ToS3_conf.json
Getting Instance i-4857abcd0957dc81a data...
[OK] Instance found:
     ImageId: ami-123482b7f1da62478
     InstanceType: t2.micro
     LaunchTime: 2021-01-17 18:44:15+00:00
     AZ: sa-east-1a
     PrivateIP: 172.31.6.167

This data was uploaded to forensics/evidence/instance_data_i-4857abcd0957dc81a_20210117_1925.json

Creating EBS snapshots...
> Creating snapshot of volume: vol-05eaaafe5ccc79932
[OK] EBS snapshot created snap-0837ed4eddd1d173e

Connecting to ec2-55-66-77-111.sa-east-1.compute.amazonaws.com (PublicIP: 55.66.77.111)
Retrieving from S3: forensics/resources/artifacts.json to /tmp/artifacts.json
Sending: /tmp/artifacts.json to EC2: /tmp/forensics/artifacts.json
Retrieving from S3: forensics/resources/collectLocalForensics.py to /tmp/collectLocalForensics.py
Sending: /tmp/collectLocalForensics.py to EC2: /tmp/forensics/collectLocalForensics.py

Running forensic tasks!...
> I'm going to execute:
  # cd /tmp/forensics/; sudo python3 collectLocalForensics.py --no-memory-dump --conserve-local-forensics --output-filename forensics_complete_i-4857abcd0957dc81a_20210117_1925.tar.gz

Getting from EC2: /tmp/forensics/forensics_complete_i-4857abcd0957dc81a_20210117_1925.tar.gz
Uploading evidence file: /tmp/forensics_complete_i-4857abcd0957dc81a_20210117_1925.tar.gz to S3: forensics/evidence/

Containment - Removing SGs...
-> Attaching SG sg-11197739b43d7ebc4 (first step: change all connections to untracked)
-> Attaching SG sg-22260906990d7adbc (second step: dropping all connections with isolation SG)
[OK] SGs removed

Tagging instance id i-4857abcd0957dc81a as Security_status: quarantined
[OK] instance tagged


Done!
```

* AWS required permissions:
> S3: GetObjet y PutObject<br>
> EC2: DescribeInstances, CreateTags, CreateSnapshot, ModifyInstanceAttribute


