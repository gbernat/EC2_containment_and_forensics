import argparse
import time
import boto3
import botocore.config
import os, shutil
import json
import paramiko

# Get script configuration parameters form S3 file. 
# TODO If SSM is used, replace S3 conf for SSM parameters.
S3_conf_bucket = 'my-conf-forensics'
S3_conf_params = 'forensics/config/containmentAndForensicsEC2ToS3_conf.json'

# S3_conf_params example:
#{
#    "working_path": "/tmp/forensics/",
#    "S3_bucket": "my-forensics",
#    "S3_resources": ["forensics/resources/artifacts.json", "forensics/resources/collectLocalForensics.py"],
#    "S3_evidence_path": "forensics/evidence/",
#    "EC2_key": "forensics/config/EC2-key.pem",
#    "ec2_local_user": "ec2-user",
#    "isolation_security_groups": ["sg-09e9773906990d7bc","sg-adb43d7ebc40c2609"],
#    "region": "sa-east-1"
#}

# Conf params to get from S3_conf_params (or SSM)
working_path = None
S3_bucket = None
S3_resources = None
S3_evidence_path = None
EC2_key = None
ec2_local_user = None
region = None

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

def get_config_params():
    global working_path
    global S3_bucket
    global S3_resources
    global S3_evidence_path
    global ec2_local_user
    global EC2_key
    global region
    print('Getting configuration parameters from S3: {}/{}\n'.format(S3_conf_bucket, S3_conf_params))
    try:
        confS3 = s3_client.get_object(Bucket= S3_conf_bucket, Key=S3_conf_params)
        conf = json.loads(confS3['Body'].read().decode("utf-8")) 

        working_path = conf['working_path']
        S3_bucket = conf['S3_bucket']
        S3_resources = conf['S3_resources']
        S3_evidence_path= conf['S3_evidence_path']
        ec2_local_user = conf['ec2_local_user']
        region = conf['region']

        # Put .pem ec2 key to local temp
        EC2_key = local_tmp + os.path.basename(conf['EC2_key'])
        s3_client.download_file(S3_conf_bucket, conf['EC2_key'], EC2_key)
        # Change pem permissions to 0600
        os.chmod(EC2_key, 0o600)

    except Exception as e:
        #TODO: Better error msg
        print('[ERROR] {}'.format(str(e)))



def forensics(tasks):
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

    get_config_params()

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




# From command line arguments (not useful from lambda. Only for stand-alone tests):
if __name__=='__main__':
    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-id', '--InstanceId', type=str, required=True, dest='instance_id', help='Instance id of the server to take forensics data from.')
    my_parser.add_argument('--ec2-ip', type=str, required=True, dest='ec2_ip', help='Instance IP.')
    my_parser.add_argument('--no-memory-dump', required=False, dest='no_memory_dump', action='store_true', help='Do not execute memory dump. --> default: false (make memory dump)')
    my_parser.add_argument('--conserve-local-forensics', required=False, dest='conserve_forensics', action='store_true', help='Do not delete forensic files gathered in destination server after finishing tasks. --> default: false (delete tmp files in remote server)')
    my_parser.add_argument('--no-send-to-S3', required=False, dest='no_send_to_s3', action='store_true', help='Do not copy forensic files to S3 bucket. --> default: false (copy forensic files to S3)')
    my_parser.add_argument('--S3-data-format', required=False, dest='s3_data_format', type=str, choices=['individual', 'packed'], default='packed', action='store', help='Choose how forensic data is stored in S3, as an individual compressed file, or individually. --> default: packed (save one compressed file to S3 containing all forensic files)')
    args = my_parser.parse_args()

    argsh = { 
        'instance_id': args.instance_id,
        'ec2_ip': args.ec2_ip,
        'memory_dump': not args.no_memory_dump,
        'conserve_files': args.conserve_forensics,
        'send_to_s3': not args.no_send_to_s3,
        's3_data_format': args.s3_data_format
    } 

    main(argsh)