__author__ = 'dc'
####
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
####
import boto3
import sys
import argparse


# List every region you'd like to scan.  We'll need to update this if AWS adds a region
aws_regions = ['ca-central-1']

# Global variable for Keys and Values to be tagged to each instances
KEY_LOB = 'line_of_business' # Line Of Business
VAL_LOB = 'Cloud Infrastructure'
KEY_COST = 'cost_centre' # Cost Centre
VAL_COST = '123456' 
KEY_ITYPE = '' # Instance type 
VAL_ITYPE = ''
OWNER_ID = '123455678910' # AWS account number

Filters = ['terminated', 'terminating']

#############################
# Check instances with no tag
#############################

def tag_instance(ec2, aws_region):
    KEY_ITYPE = 'instancetype'
    try:
        reservations = ec2.describe_instances()['Reservations']
    except:
        # Don't fatal error on regions that we haven't activated/enabled
        if 'OptInRequired' in str(sys.exc_info()):
            return
        else:
            raise

    try:
        for reservation in reservations:
            for instance in reservation['Instances']:
                if instance['State']['Name'] not in Filters:
                    tags = {}
                    try:
                        for tag in instance['Tags']:
                            tags[tag['Key']] = tag['Value']
                    except Exception as e:
                        # If all tags are missing
                        print("Found instance without any " + str(e))
                        add_name_tag(instance['InstanceId'], instance['InstanceType'], KEY_ITYPE, ec2)
                        print("Tags were successfully added to {}".format(instance['InstanceId']))
                        if not ('Name' in tags):
                            print("Instance without key:Name and Value")
                            ec2.create_tags(Resources=[instance['InstanceId']],
                                            Tags=[{'Key': 'Name', 'Value': instance['InstanceId']}])
                            print("Key:Name added with Value: {}\n".format(instance['InstanceId']))
                        break
                    # Check for only key:Name, and tag it with InstanceId if missing
                    if not ('Name' in tags):
                        print("Instance without key:Name and Value")
                        ec2.create_tags(Resources=[instance['InstanceId']],
                                        Tags=[{'Key': 'Name', 'Value': instance['InstanceId']}])
                        print("Key:Name added with Value: {}\n".format(instance['InstanceId']))
                    # If all tags are found as per compliance
                    if ('line_of_business' in tags) and ('cost_centre' in tags) \
                            and ('instancetype' in tags):
                        print("InstanceId: {}; Region {}: properly tagged with line_of_business, cost_centre, "
                              "and instancetype".format(instance['InstanceId'], aws_region))
                    # If specific tags missing call function to add them
                    else:
                        print("InstanceId: {} not tagged as per standards".format(instance['InstanceId'], aws_region))
                        add_name_tag(instance['InstanceId'], instance['InstanceType'], KEY_ITYPE, ec2)
                        print("Tags were successfully added to {}\n".format(instance['InstanceId']))

    except Exception:
        print("Unexpected error:", sys.exc_info()[0])


#######################################
# Function to Tag Volumes
#######################################

def tag_vol(ec2, aws_region):
    KEY_ITYPE = 'volumetype'

    try:
        reservations = ec2.describe_volumes()['Volumes']
    except:
        # Don't fatal error on regions that we haven't activated/enabled
        if 'OptInRequired' in str(sys.exc_info()):
            return
        else:
            raise
    try:
        for volume in reservations:
            tags = {}
            try:
                for tag in volume['Tags']:
                    tags[tag['Key']] = tag['Value']
            except Exception as e:
                # If all tags are missing
                print("Found volume without any " + str(e))
                add_name_tag(volume['VolumeId'], volume['VolumeType'], KEY_ITYPE, ec2)
                print("Tags were successfully added to {}".format(volume['VolumeId']))
            for v in volume['Attachments']:
                if not ('Name' in tags):
                    print("Volume without key:Name and Value")
                    ec2.create_tags(Resources=[v['VolumeId']],
                                    Tags=[{'Key': 'Name', 'Value': v['InstanceId']}])
            # If all tags are found as per compliance
            if ('line_of_business' in tags) and ('cost_centre' in tags) \
                    and ('volumetype' in tags) and ('client' in tags):
                print("VolumeId: {}; Region {}: properly tagged with line_of_business, cost_centre, "
                      "client and volumetype".format(volume['VolumeId'], aws_region))
            else:
                print("VolumeId: {} not tagged as per standards".format(volume['VolumeId'], aws_region))
                add_name_tag(volume['VolumeId'], volume['VolumeType'], KEY_ITYPE, ec2)
                print("Tags were successfully added to {}\n".format(volume['VolumeId']))

    except Exception:
        print("Unexpected error:", sys.exc_info()[0])


#######################################
# Function to Tag Snapshots
#######################################

def tag_snapshots(ec2, aws_region):
    KEY_ITYPE = 'encrypted'

    try:
        reservations = ec2.describe_snapshots()['Snapshots']
    except:
        # Don't fatal error on regions that we haven't activated/enabled
        if 'OptInRequired' in str(sys.exc_info()):
            return
        else:
            raise
    try:
        for snapshot in reservations:
            tags = {}
            if snapshot['OwnerId'] == OWNER_ID:
                try:
                    for tag in snapshot['Tags']:
                        tags[tag['Key']] = tag['Value']
                except Exception as e:
                    # If all tags are missing
                    print("Found snapshots without any " + str(e))
                    # print(f"{snapshot['SnapshotId']}; {snapshot['Encrypted']}; {KEY_ITYPE}")
                    add_name_tag(snapshot['SnapshotId'], str(snapshot['Encrypted']), KEY_ITYPE, ec2)
                    print("Tags were successfully added to {}".format(snapshot['SnapshotId']))
                if not ('Name' in tags):
                    print("Snapshot without key:Name and Value")
                    ec2.create_tags(Resources=[snapshot['SnapshotId']],
                                    Tags=[{'Key': 'Name', 'Value': snapshot['VolumeId']}])
                # # If all tags are found as per compliance
                if ('line_of_business' in tags) and ('cost_centre' in tags) \
                        and ('encrypted' in tags) and ('client' in tags):
                    print("SnapshotId: {}; Region {}: properly tagged with line_of_business, cost_centre, "
                        "encrypted and client".format(volume['SnapshotId'], aws_region))
                else:
                    print("SnapshotId: {} not tagged as per standards".format(snapshot['SnapshotId'], aws_region))
                    add_name_tag(snapshot['SnapshotId'], str(snapshot['Encrypted']), KEY_ITYPE, ec2)
                    print("Tags were successfully added to {}\n".format(snapshot['SnapshotId']))
    except Exception:
        print("Unexpected error:", sys.exc_info()[0])


#######################################
# Function to Create Tags
#######################################

def add_name_tag(resource_id, resource_type, KEY_ITYPE, ec2):
    try:
        print(f'Adding necessary tags to {resource_id}')
        return ec2.create_tags(
            Resources=[resource_id],
            Tags=[{
                'Key': KEY_LOB,
                'Value': VAL_LOB
            }, {
                'Key': KEY_COST,
                'Value': VAL_COST
            }, {
                'Key': KEY_ITYPE,
                'Value': resource_type
            }]
        )
    except Exception:
        print("Unexpected error:", sys.exc_info()[0])
        raise


#####################
# Main Function
#####################

def main():
    try:
        # For each region we want to scan...
        parser = argparse.ArgumentParser()
        parser.add_argument('-p', '--profile', help="AWS profile name is required as an argument to run this command.")
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(0)
        args = parser.parse_args()

        session = boto3.session.Session(
            profile_name=args.profile
        )

        for aws_region in aws_regions:
            ec2 = session.client('ec2', region_name=aws_region)
            """ :type : pyboto3.ec2 """
            print("Scanning region: {}".format(aws_region))
            #
            # tag_instance(ec2, aws_region)
            # tag_vol(ec2,aws_region)
            tag_snapshots(ec2, aws_region)
    except Exception:
        print("Unexpected error:", sys.exc_info()[0])
        raise


if __name__ == "__main__":
    main()

