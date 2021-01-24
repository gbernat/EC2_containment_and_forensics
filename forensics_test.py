import time
import argparse
import boto3
import botocore.config
import os, shutil
import json
import paramiko

# Get script configuration parameters form S3 file. 
# TODO If SSM is used, replace S3 conf for SSM parameters.
S3_conf_bucket = 'gb-forensics'
S3_conf_params = 'forensics/config/containmentAndForensicsEC2ToS3_conf.json'


# Conf params to get from S3_conf_params (or SSM)
working_path = None
S3_bucket = None
S3_resources = None
S3_evidence_path = None
EC2_key = None
ec2_local_user = None
isolation_security_groups = None  # To drop established connections: apply First SG (inbound/outbound 0.0.0.0/0), wait, apply Second SG (restricted)

# Global variables
ec2_client = boto3.client('ec2', region_name='sa-east-1')
ec2_resource = boto3.resource('ec2', region_name='sa-east-1')
#s3_client = boto3.client('s3')
s3_client = boto3.client('s3', region_name='sa-east-1', config=botocore.config.Config(s3={'addressing_style':'path'}))


local_tmp = '/tmp/{}/'.format(int(time.time()))


def get_config_params():
    global working_path
    global S3_bucket
    global S3_resources
    global S3_evidence_path
    global ec2_local_user
    global isolation_security_groups
    global EC2_key
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

        # Put .pem ec2 key to local temp
        EC2_key = local_tmp + os.path.basename(conf['EC2_key'])
        s3_client.download_file(S3_conf_bucket, conf['EC2_key'], EC2_key)
        # Change pem permissions to 0600
        os.chmod(EC2_key, 0o600)

        print('lambda /tmp/ content: {}'.format(str(os.listdir('/tmp/'))))
        print('lambda {} content: {}'.format(local_tmp, str(os.listdir(local_tmp))))
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
            print('[OK] Instance found:\n     ImageId: {}\n     InstanceType: {}\n     LaunchTime: {}\n     AZ: {}\n     PrivateIP: {}\n'.format(pd['ImageId'], pd['InstanceType'], str(pd['LaunchTime']), pd['Placement']['AvailabilityZone'], pd['PrivateIpAddress']))
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


def ec2_containment(Iid):

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


def forensics(tasks):
    # ssh connection pre-steps
    key = paramiko.RSAKey.from_private_key_file(EC2_key)
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if not tasks['use_this_ip']:
        inst_resource = ec2_resource.Instance(tasks['instance_id'])
        if not inst_resource.state['Name'] == 'running':
            print('[ERROR] EC2 instance not running. Cannot do forensics local tasks.')
            return False

    # Copy resource files from S3 to EC2 
    try:
        if not tasks['use_this_ip']:
            if tasks['ssh_public_ip']: 
                print('Connecting to {} (PublicIP: {})'.format(inst_resource.public_dns_name, inst_resource.public_ip_address))
                ssh_client.connect(hostname=inst_resource.public_ip_address, username=ec2_local_user, pkey=key)
            else:
                print('Connecting to {} (PrivateIP: {})'.format(inst_resource.public_dns_name, inst_resource.private_ip_address))
                ssh_client.connect(hostname=inst_resource.private_ip_address, username=ec2_local_user, pkey=key)
        else:
            print('Connecting to CUSTOM IP: {}'.format(tasks['use_this_ip']))
            ssh_client.connect(hostname=tasks['use_this_ip'], username=ec2_local_user, pkey=key)

        # Create remote working tmp dirs
        cmd = 'mkdir -p ' + working_path
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        print('stdout {}: {}'.format(cmd, stdout.read()))
        if len(stderr.read()): 
            raise Exception ('Failed tu execute: {}. stderr: {}'.format(cmd,stderr.read()))

        # Retrieve resources from S3 and send to EC2
        ftp_client=ssh_client.open_sftp()
        for r in S3_resources:
            loc_tmp = local_tmp + os.path.basename(r)
            print('Retrieving from S3: {} to {}'.format(str(r), loc_tmp))
            s3_client.download_file(S3_bucket, r, loc_tmp)

            print('Sending: {} to EC2: {}'.format(loc_tmp, working_path+os.path.basename(r)))
            ftp_client.put(loc_tmp, working_path+os.path.basename(r))

        print('lambda {} content: {}'.format(local_tmp, str(os.listdir(local_tmp))))
    except Exception as e:
        print('[ERROR] '+ str(e))
        return False

    


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

    if params['todo_param'] == 'instancedata':
        inst_data = get_instance_data(inst_id)
        #print(str(inst_data))
        if not inst_data:
            raise ValueError('Target instance Id does no exist.')

    if params['todo_param'] == 'forensics':
        forensics(params)

    if params['todo_param'] == 'containment':
        ec2_containment(inst_id)


    print('\nDone!\n')




# From AWS lambda:    
def lambda_handler(event, context):
    print("Received event: {}".format(event))

    if not event['instance_id']:
        raise ValueError('Target instance Id is required.')

    argsh = { 
        'instance_id': event['instance_id'],
        'todo_param': event['todo_param'],
        'ssh_public_ip': event['ssh_public_ip'],
        'use_this_ip': event['use_this_ip']
    }

    print('Starting for instance: ' + event['instance_id'])

    main(argsh)


# From command line arguments:
if __name__=='__main__':
    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-id', '--InstanceId', type=str, required=True, dest='instance_id', help='Instance id of the server to take forensics data from.')
    my_parser.add_argument('--todo_param', required=False, dest='todo_param', type=str, choices=['instancedata', 'forensics', 'containment'], action='store')
    my_parser.add_argument('--ssh_public_ip', required=False, dest='ssh_public_ip', action='store_true')
    my_parser.add_argument('--use_this_ip', required=False, dest='use_this_ip', type=str, action='store')

    args = my_parser.parse_args()

    argsh = { 
        'instance_id': args.instance_id,
        'todo_param': args.todo_param,
        'ssh_public_ip': args.ssh_public_ip,
        'use_this_ip': args.use_this_ip
    } 

    main(argsh)
