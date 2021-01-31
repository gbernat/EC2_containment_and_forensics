import time
import argparse
import boto3
import botocore.config
import os, shutil
import json
import paramiko

# Get script configuration parameters form S3 file. 
# TODO If SSM is used, replace S3 conf for SSM parameters.
S3_conf_bucket = 'my-forensics'
S3_conf_params = 'forensics/config/containmentAndForensicsEC2_conf.json'

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
isolation_security_groups = None  # To drop established connections: apply First SG (inbound/outbound 0.0.0.0/0), wait, apply Second SG (restricted)
region = None

# Global variables
ec2_client = boto3.client('ec2', region_name=region)
#ec2_resource = boto3.resource('ec2', region_name=region)
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
| Must run as root on remote server.                                           |
|                                                                              | 
| In addition preserves AMI/EBS snapshot and executes EC2 instance containment |
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
    global isolation_security_groups
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
        isolation_security_groups = conf['isolation_security_groups']
        region = conf['region']

        # Put .pem ec2 key to local temp
        EC2_key = local_tmp + os.path.basename(conf['EC2_key'])
        s3_client.download_file(S3_conf_bucket, conf['EC2_key'], EC2_key)
        # Change pem permissions to 0600
        os.chmod(EC2_key, 0o600)

    except Exception as e:
        #TODO: Better error msg
        print('[ERROR] {}'.format(str(e)))


def get_instance_data(Iid):
    res = False
    print('Getting Instance {} data...'.format(Iid))
    try:
        res = ec2_client.describe_instances(InstanceIds=[Iid])
        if res['ResponseMetadata']['HTTPStatusCode'] == 200:
            pd = res['Reservations'][0]['Instances'][0]
            print('[OK] Instance found:\n     ImageId: {}\n     InstanceType: {}\n     LaunchTime: {}\n     AZ: {}\n     PrivateIP: {}\n     PublicIP: {}\n'.format(pd['ImageId'], pd['InstanceType'], str(pd['LaunchTime']), pd['Placement']['AvailabilityZone'], pd['PrivateIpAddress'], pd['PublicIpAddress']))
            # Upload instance data to S3:
            instance_data_filename = '{}instance_data_{}_{}.json'.format(S3_evidence_path, Iid, time.strftime('%Y%m%d_%H%M'))
            s3_client.put_object(Body= json.dumps(res, default=str).encode('utf-8'), Bucket= S3_bucket, Key=instance_data_filename)
            print('This data was uploaded to {}\n'.format(instance_data_filename))
        else:
            print('[ERROR] {}'.format(str(res)))
    except Exception as e:
        #TODO: Better error msg
        print('[ERROR] {}'.format(str(e)))

    return res


def preserve_status(Iid, do_ami_snapshot, volumes):
    if do_ami_snapshot:
        # Create AMI of running Instance this process creates also EBS snapshot
        print('Creating AMI from instance id: {}...'.format(Iid))
        try:
            res = ec2_client.create_image(InstanceId=Iid, NoReboot=True, Name="ami_preserved_from_"+Iid)
            #print(res)
            if res['ResponseMetadata']['HTTPStatusCode'] == 200:
                print('[OK] AMI created {}\n'.format(res['ImageId']))
            else:
                print('[ERROR] {}\n'.format(str(res)))
        except:
            #TODO: Better error msg
            print('[ERROR]\n')
    else:
        # Only take EBS Snapshot
        print('Creating EBS snapshots...')
        for vol in volumes:   
            print('> Creating snapshot of volume: {}'.format(vol['Ebs']['VolumeId']))
            try:
                res = ec2_client.create_snapshot(VolumeId=vol['Ebs']['VolumeId'], Description="vol_snapshot_from_"+Iid)
                if res['ResponseMetadata']['HTTPStatusCode'] == 200:
                    print('[OK] EBS snapshot created {}\n'.format(res['SnapshotId']))
                else:
                    print('[ERROR] {}\n'.format(str(res)))
            except:
                #TODO: Better error msg
                print('[ERROR]\n')
            

def ec2_containment(Iid):
    # Remove original SGs and set very restrictive containment SG
    print('\nContainment - Removing SGs...')
    try:
        sg_id = ec2_client.describe_security_groups(Filters=[ {'Name': 'group-name', 'Values': [isolation_security_groups[0]]} ])['SecurityGroups'][0]['GroupId']
        print('-> Attaching SG {} - {} (first step: change all connections to untracked)'.format(isolation_security_groups[0], sg_id))
        res = ec2_client.modify_instance_attribute(InstanceId=Iid, Groups=[sg_id])
        time.sleep(2)   # just wait 2 seconds...
        sg_id = ec2_client.describe_security_groups(Filters=[ {'Name': 'group-name', 'Values': [isolation_security_groups[1]]} ])['SecurityGroups'][0]['GroupId']
        print('-> Attaching SG {} - {} (second step: dropping all connections with isolation SG)'.format(isolation_security_groups[1], sg_id))
        res = ec2_client.modify_instance_attribute(InstanceId=Iid, Groups=[sg_id])
        if res['ResponseMetadata']['HTTPStatusCode'] == 200:
            print('[OK] SGs removed\n')
        else:
            print('[ERROR] {}\n'.format(str(res)))
    except Exception as e:
        #TODO: Better error msg
        print('[ERROR] {}'.format(str(e)))

    # Tag as quarantined
    print('Tagging instance id {} as Security_status: quarantined'.format(Iid))
    try:
        res = ec2_client.create_tags(Resources=[Iid], Tags=[ { 'Key': 'Security_status', 'Value': 'quarantined' }])
        if res['ResponseMetadata']['HTTPStatusCode'] == 200:
            print('[OK] instance tagged\n')
        else:
            print('[ERROR] {}\n'.format(str(res)))
    except Exception as e:
        #TODO: Better error msg
        print('[ERROR] {}'.format(str(e)))


def forensics(tasks, i_data):
    # ssh connection pre-steps
    key = paramiko.RSAKey.from_private_key_file(EC2_key)
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    inst = i_data['Reservations'][0]['Instances'][0]
    if not inst['State']['Name'] == 'running':
        print('[ERROR] EC2 instance not running. Cannot do forensics local tasks.')
        return False

    # Copy resource files from S3 to EC2 
    try:
        if tasks['ssh_public_ip']:
            print('Connecting to {} (PublicIP: {})'.format(inst['PublicDnsName'], inst['PublicIpAddress']))
            ssh_client.connect(hostname=inst['PublicIpAddress'], username=ec2_local_user, pkey=key)
        else:
            print('Connecting to {} (PrivateIP: {})'.format(inst['PrivateDnsName'], inst['PrivateIpAddress']))
            ssh_client.connect(hostname=inst['PrivateIpAddress'], username=ec2_local_user, pkey=key)

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

    inst_id = params['instance_id']

    inst_data = get_instance_data(inst_id)
    #print(str(inst_data))
    if not inst_data:
        raise ValueError('Target instance Id does no exist.')

    preserve_status(inst_id, params['ami_snapshot'], inst_data['Reservations'][0]['Instances'][0]['BlockDeviceMappings'])

    forensics(params, inst_data)

    ec2_containment(inst_id)

    shutil.rmtree(local_tmp)

    print('\nDone!\n')



# From command line arguments:
if __name__=='__main__':
    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-id', '--InstanceId', type=str, required=True, dest='instance_id', help='Instance id of the server to take forensics data from.')
    my_parser.add_argument('--no-memory-dump', required=False, dest='no_memory_dump', action='store_true', help='Do not execute memory dump. --> default: false (make memory dump)')
    my_parser.add_argument('--no-ami-snapshot', required=False, dest='no_ami_snapshot', action='store_true', help='Do not snapshot entire AMI. --> default: false (make EBS snapshot. Otherwise only EBS snapshot will be taken)')
    my_parser.add_argument('--conserve-local-forensics', required=False, dest='conserve_forensics', action='store_true', help='Do not delete forensic files gathered in destination server after finishing tasks. --> default: false (delete tmp files in remote server)')
    my_parser.add_argument('--no-send-to-S3', required=False, dest='no_send_to_s3', action='store_true', help='Do not copy forensic files to S3 bucket. --> default: false (copy forensic files to S3)')
    my_parser.add_argument('--S3-data-format', required=False, dest='s3_data_format', type=str, choices=['individual', 'packed'], default='packed', action='store', help='Choose how forensic data is stored in S3, as an individual compressed file, or individually. --> default: packed (save one compressed file to S3 containing all forensic files)')
    my_parser.add_argument('--ssh_use_public_ip', required=False, dest='ssh_public_ip', action='store_true', help='Use instance Public IP to connect by ssh to execute and get forensics data. --> default: false (use Private IP)')
    args = my_parser.parse_args()

    argsh = { 
        'instance_id': args.instance_id,
        'memory_dump': not args.no_memory_dump,
        'ami_snapshot': not args.no_ami_snapshot,
        'conserve_files': args.conserve_forensics,
        'send_to_s3': not args.no_send_to_s3,
        's3_data_format': args.s3_data_format,
        'ssh_public_ip': args.ssh_public_ip
    } 

    main(argsh)
