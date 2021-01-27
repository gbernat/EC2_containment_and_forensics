resource "aws_lambda_function" "instance-containment" {
  function_name    = "instance-containment-2"
  description      = "Instance containment and preserve status"
  handler          = "InstanceContainAndPreserveStatus.lambda_handler"
  memory_size      = 1024
  timeout          = 30
  role             = aws_iam_role.containment_and_forensics_role.arn
  runtime          = "python3.7"
  filename         = data.archive_file.instance_containment_pkg.output_path
  source_code_hash = filebase64sha256(data.archive_file.instance_containment_pkg.output_path)

  environment {
    variables = {
      FORENSICS_BUCKET = var.forensics_S3_bucket_name
      FORENSICS_EVIDENCE_PATH = var.S3_evidence_path
      REGION = var.region
    }
  }
}

# First copy lambda/EC2ForensicsEvidence.py to lambda/packages/paramiko_src/ !!!
resource "aws_lambda_function" "ec2-forensics" {
  function_name    = "ec2-forensics-2"
  description      = "Get EC2 forensics files and memory dump"
  handler          = "EC2ForensicsEvidence.lambda_handler"
  memory_size      = 1024
  timeout          = 30
  role             = aws_iam_role.containment_and_forensics_role.arn
  runtime          = "python3.7"
  filename         = data.archive_file.forensics_evidence_pkg.output_path
  source_code_hash = filebase64sha256(data.archive_file.forensics_evidence_pkg.output_path)
  
  vpc_config {
    #subnet_ids = ["subnet-54294c0f"]
    subnet_ids = split(",", var.vpc_lambda_subnets) 
    security_group_ids= [aws_security_group.lambda_access_to_ec2.id]
  }

  environment {
    variables = {
      FORENSICS_BUCKET = var.forensics_S3_bucket_name
      FORENSICS_EVIDENCE_PATH = var.S3_evidence_path
      REGION = var.region
      EC2_LOCAL_USER = var.ec2_local_user 
    }
  }

}