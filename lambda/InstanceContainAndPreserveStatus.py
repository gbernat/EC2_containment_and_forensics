import argparse
import time
import boto3
import botocore.config
import os, shutil
import json

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
S3_bucket = None
S3_evidence_path = None
isolation_security_groups = None  # To drop established connections: apply First SG (inbound/outbound 0.0.0.0/0), wait, apply Second SG (restricted)
region = None

# Global variables
ec2_client = boto3.client('ec2', region_name=region)
s3_client = boto3.client('s3', region_name=region, config=botocore.config.Config(s3={'addressing_style':'path'}))


print("""
////////////////////////////////////////////////////////////////////////////////
| Script to preserve status of an EC2 vulnerated instance,                     |
| take AMI/EBS snapshot and executes EC2 instance containment                  |
|                                                                              |
| Author: Guido Bernat.                                                        |
///////////////////////////////////////////////////////////////////////////////

""")

def get_config_params():
    global S3_bucket
    global S3_evidence_path
    global isolation_security_groups
    global region
    print('Getting configuration parameters from S3: {}/{}\n'.format(S3_conf_bucket, S3_conf_params))
    try:
        confS3 = s3_client.get_object(Bucket= S3_conf_bucket, Key=S3_conf_params)
        conf = json.loads(confS3['Body'].read().decode("utf-8")) 

        S3_bucket = conf['S3_bucket']
        S3_evidence_path= conf['S3_evidence_path']
        isolation_security_groups = conf['isolation_security_groups']
        region = conf['region']

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
        print('-> Attaching SG {} (first step: change all connections to untracked)'.format(isolation_security_groups[0]))
        res = ec2_client.modify_instance_attribute(InstanceId=Iid, Groups=[isolation_security_groups[0]])
        time.sleep(2)   # just wait 2 seconds...
        print('-> Attaching SG {} (second step: dropping all connections with isolation SG)'.format(isolation_security_groups[1]))
        res = ec2_client.modify_instance_attribute(InstanceId=Iid, Groups=[isolation_security_groups[1]])
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



######################################################
# Main from command line Arguments or Lambda execution
######################################################


def main(params):

    print("I'm going to do this:\n"+str(params).replace('\'','').replace('{', '').replace('}','').replace(',','\n')+'\n')

    get_config_params()

    inst_id = params['instance_id']

    inst_data = get_instance_data(inst_id)
    #print(str(inst_data))
    if not inst_data:
        raise ValueError('Target instance Id does no exist.')

    preserve_status(inst_id, params['ami_snapshot'], inst_data['Reservations'][0]['Instances'][0]['BlockDeviceMappings'])

    ec2_containment(inst_id)

    print('\nDone!\n')




# From AWS lambda:    
def lambda_handler(event, context):
    """
    Example input lambda event:
    event = {
    "instance_id": "",
    "no_ami_snapshot": true/false,          --> default: false (make AMI snapshot. Otherwise only EBS snapshot will be taken)
    }
    """   
    print("Received event: {}".format(event))

    if not event['instance_id']:
        raise ValueError('Target instance Id is required.')

    argsh = { 
        'instance_id': event['instance_id'],
        'ami_snapshot': False if 'no_ami_snapshot' in event and event['no_ami_snapshot'] else True
    }

    print('Starting for instance: ' + event['instance_id'])

    main(argsh)




# From command line arguments (not useful from lambda. Only for stand-alone tests):
if __name__=='__main__':
    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-id', '--InstanceId', type=str, required=True, dest='instance_id', help='Instance id of the server to take forensics data from.')
    my_parser.add_argument('--no-ami-snapshot', required=False, dest='no_ami_snapshot', action='store_true', help='Do not snapshot entire AMI. --> default: false (make EBS snapshot. Otherwise only EBS snapshot will be taken)')
    args = my_parser.parse_args()

    argsh = { 
        'instance_id': args.instance_id,
        'ami_snapshot': not args.no_ami_snapshot
    } 

    main(argsh)