variable "forensics_S3_bucket_name" {
    default = "my-forensics"
    description = "Bucket for configuration, resources and evidence"
}

variable "ec2_key" {
    # Remove me!
    default = "/Users/guido/Documents/AWSCourse/EC2tutorial.pem"
    description = "Path to key.pem to access by ssh to vulnerated EC2" 
}

variable vpc_id {
    # Remove me!
    default = "vpc-3c47a55a"
    description = "VPC id for the creation of the Security Group"
}
