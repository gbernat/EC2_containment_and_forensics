resource "aws_s3_bucket" "s3_containment_and_forensics" {
    bucket = var.forensics_S3_bucket_name
    acl = "private"
}

resource "aws_s3_bucket_public_access_block" "s3_containment_and_forensics" {
  bucket = var.forensics_S3_bucket_name
  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket_object" "resources_artifacts" {
  bucket = var.forensics_S3_bucket_name
  key    = "forensics/resources/artifacts.json"
  source = "../resources/artifacts.json"

  etag = filemd5("../resources/artifacts.json")
  depends_on = [aws_s3_bucket.s3_containment_and_forensics]
}

resource "aws_s3_bucket_object" "resources_collectLocalForensics" {
  bucket = var.forensics_S3_bucket_name
  key    = "forensics/resources/collectLocalForensics.py"
  source = "../resources/collectLocalForensics.py"

  etag = filemd5("../resources/collectLocalForensics.py")
  depends_on = [aws_s3_bucket.s3_containment_and_forensics]
}

resource "aws_s3_bucket_object" "config_ec2_key" {
  bucket = var.forensics_S3_bucket_name
  key    = "forensics/config/EC2-key.pem"
  source = var.ec2_key

  etag = filemd5(var.ec2_key)
  depends_on = [aws_s3_bucket.s3_containment_and_forensics]
}
