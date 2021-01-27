import argparse
import time
import boto3
import botocore.config
import os, shutil
import json
import paramiko

# Get script configuration parameters from lambda environment variables. 
# TODO If SSM is used, replace env vars for SSM parameters.
working_path = "/tmp/forensics/"
S3_bucket = os.environ['FORENSICS_BUCKET']
S3_resources = ["forensics/resources/artifacts.json", "forensics/resources/collectLocalForensics.py"]
S3_evidence_path = os.environ['FORENSICS_EVIDENCE_PATH']
S3_EC2_key = "forensics/config/EC2-key.pem"
ec2_local_user = os.environ["EC2_LOCAL_USER"]
region = os.environ['REGION']

# Global variables
s3_client = boto3.client('s3', region_name=region, config=botocore.config.Config(s3={'addressing_style':'path'}))

local_tmp = '/tmp/{}/'.format(int(time.time()))


print("""
////////////////////////////////////////////////////////////////////////////////
| Script to retrieve artifacts like files and commands output,                 |
| and perform a memory dump from a Linux server.                               |
| Everything collected is sended compressed to an S3 bucket.                   |
| Artifacts are described in artifacs.json file.                               |
| Wildcards are allowed to filenames and directories.                          |
| Multiple files/directories are allowed per name.                             |
| Only one COMMAND is allowed per name.                                        |
|                                                                              |
| Author: Guido Bernat.                                                        |
///////////////////////////////////////////////////////////////////////////////
""")


def forensics(tasks):
    # Get .pem ec2 key from S3 and put it in local temp
    EC2_key = local_tmp + os.path.basename(S3_EC2_key)
    s3_client.download_file(S3_bucket, S3_EC2_key, EC2_key)
    # Change pem permissions to 0600
    os.chmod(EC2_key, 0o600)

    # ssh connection pre-steps
    key = paramiko.RSAKey.from_private_key_file(EC2_key)
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # TODO check if EC2 is running

    # Copy resource files from S3 to EC2 
    try:
        print('Connecting to EC2 IP: {}'.format(tasks['ec2_ip']))
        ssh_client.connect(hostname=tasks['ec2_ip'], username=ec2_local_user, pkey=key)

        # Create remote working tmp dirs
        cmd = 'mkdir -p ' + working_path
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        #print('stdout {}: {}'.format(cmd, stdout.read()))
        if len(stderr.read()): 
            raise Exception ('Failed tu execute: {}. stderr: {}'.format(cmd,sdterr.read()))

        # Retrieve resources from S3 and send to EC2
        ftp_client=ssh_client.open_sftp()
        for r in S3_resources:
            loc_tmp = local_tmp + os.path.basename(r)
            print('Retrieving from S3: {} to {}'.format(str(r), loc_tmp))
            s3_client.download_file(S3_bucket, r, loc_tmp)

            print('Sending: {} to EC2: {}'.format(loc_tmp, working_path+os.path.basename(r)))
            ftp_client.put(loc_tmp, working_path+os.path.basename(r))

    except Exception as e:
        print('[ERROR] '+ str(e))
        return False

    
    # RUN Forensic taks on remote server!
    print('\nRunning forensic tasks!...')
    packed_evidence_filename = 'forensics_complete_{}_{}.tar.gz'.format(tasks['instance_id'], time.strftime('%Y%m%d_%H%M'))
    # TODO remove hardcoded collectLocalForensics.py
    cmd = 'cd {}; sudo python3 collectLocalForensics.py {} {} {}'.format(
                                                working_path,
                                                '' if tasks['memory_dump'] else '--no-memory-dump',
                                                '--conserve-local-forensics',
                                                '--output-filename ' + packed_evidence_filename)
    print("> I'm going to execute:\n  # {}".format(cmd))
    # TODO try except
    stdin, stdout, stderr = ssh_client.exec_command(cmd)
    #print('stdout {}: {}'.format(cmds, stdout.read()))
    if len(stderr.read()): 
        print('Failed to execute: {}. stderr: {}'.format(cmd, stderr.read()))


    if tasks['send_to_s3']:
        # Get forensics_complete.tar.gz file from remote server
        print('\nGetting from EC2: {}'.format(working_path+packed_evidence_filename))
        # TODO try except
        ftp_client.get(working_path+packed_evidence_filename, local_tmp+packed_evidence_filename)

        if tasks['s3_data_format'] == 'packed':
            # Send packed file to S3
            print('Uploading evidence file: {} to S3: {}'.format(local_tmp+packed_evidence_filename, S3_evidence_path))
            s3_client.upload_file(local_tmp+packed_evidence_filename, S3_bucket, S3_evidence_path+packed_evidence_filename)
        else:
            # untar packed and send individual files to S3
            # TODO
            pass

    # Cleaning
    if not tasks['conserve_files']:
        # TODO instead of send rm, do it by collecLocalForensics.py arg
        # rm files on remote server
        print('Cleaning all the mess...')
        cmd = 'rm -rf {}'.format(working_path)
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        #print('stdout {}: {}'.format(cmds, stdout.read()))
        if len(stderr.read()): 
            print('Failed to execute {}. stderr: {}'.format(cmd, stderr.read()))


    ftp_client.close()
    ssh_client.close()



######################################################
# Main from command line Arguments or Lambda execution
######################################################


def main(params):

    if os.path.exists(local_tmp):
        shutil.rmtree(local_tmp)
    os.mkdir(local_tmp)

    print("I'm going to do this:\n"+str(params).replace('\'','').replace('{', '').replace('}','').replace(',','\n')+'\n')

    forensics(params)

    shutil.rmtree(local_tmp)

    print('\nDone!\n')




# From AWS lambda:    
def lambda_handler(event, context):
    """
    Example input lambda event:
    event = {
    "instance_id": "",
    "ec2_ip": "",
    "no_memory_dump": true/false,           --> default: false (make memory dump)
    "conserve_local_forensics": true/false, --> default: false (delete tmp files in remote server)
    "no_send_to_s3": true/false,            --> default: false (copy forensis files to S3)
    "s3_data_format": "individual"/"packed" --> default: packed (save one compressed file to S3 containing all forensic files)
    }
    """   
    print("Received event: {}".format(event))

    if not event['instance_id']:
        raise ValueError('Target instance Id is required.')

    argsh = { 
        'instance_id': event['instance_id'],
        'ec2_ip': event['ec2_ip'],
        'memory_dump': False if 'no_memory_dump' in event and event['no_memory_dump'] else True,
        'conserve_files': True if 'conserve_local_forensics' in event and event['conserve_local_forensics'] else False,
        'send_to_s3': False if 'no_send_to_s3' in event and event['no_send_to_s3'] else True,
        's3_data_format': event['s3_data_format'] if 's3_data_format' in event else 'packed' 
    }

    print('Starting for instance: ' + event['instance_id'])

    main(argsh)
