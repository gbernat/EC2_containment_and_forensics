variable "forensics_S3_bucket_name" {
    default = "my-forensics"
    description = "Bucket for configuration, resources and evidence"
}

variable "S3_evidence_path" {
    default = "forensics/evidence/"
    description = "Location in S3 bucket where evidence is copied"
}

variable "ec2_key" {
    description = "Path to key.pem to access by ssh to vulnerated EC2" 
}

variable "ec2_local_user" {
    default = "ec2-user" 
    description = "Local username of the vulnerated EC2 instance"
}

variable "vpc_id" {
    description = "VPC id"
}

variable "vpc_lambda_subnets" {
    type = string
    description = "List of subnets to be assigned to lambda ec2-forensics. i.e.: subnet-11111111,subnet-22222222"
}

variable "region" {
    default = "sa-east-1"
}
