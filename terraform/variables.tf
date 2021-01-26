variable "forensics_S3_bucket_name" {
    default = "my-forensics"
    description = "Bucket for configuration, resources and evidence"
}

variable "ec2_key" {
    description = "Path to key.pem to access by ssh to vulnerated EC2" 
}

variable vpc_id {
    description = "VPC id for the creation of the Security Group"
}
