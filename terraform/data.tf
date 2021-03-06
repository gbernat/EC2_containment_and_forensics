data "aws_iam_policy_document" "containment_and_forensics_policy_document" {
    statement {
        sid = "tf1"
        effect = "Allow"

        actions = [
            "s3:GetObject",
            "s3:PutObject",
        ]

        resources = [
            "arn:aws:s3:::${var.forensics_S3_bucket_name}/*",
        ]
    }

    statement {
        sid = "tf2"
        effect = "Allow"

        actions =  [
            "ec2:CreateNetworkInterface",
            "ec2:DescribeInstances",
            "ec2:DescribeNetworkInterfaces",
            "ec2:CreateTags",
            "ec2:CreateSnapshot",
            "ec2:DeleteNetworkInterface",
            "ec2:CreateImage",
            "ec2:ModifyInstanceAttribute",
            "ec2:AssignPrivateIpAddresses",
            "ec2:UnassignPrivateIpAddresses",
            "ec2:DescribeSecurityGroups",
        ]

        resources = ["*"]
    }

    statement {
        sid = "tf3"
        effect = "Allow"

        actions = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
        ]

        resources = ["*"]
    }

}

data "aws_iam_policy_document" "containment_and_forensics_assume_policy_document" {
  statement {
    principals {
      identifiers = ["lambda.amazonaws.com"]
      type        = "Service"
    }

    actions = ["sts:AssumeRole"]
  }
}



data "archive_file" "instance_containment_pkg" {
    type = "zip"
    source_file = "../lambda/InstanceContainAndPreserveStatus.py"
    output_path = "../lambda/packages/InstanceContainAndPreserveStatus.zip"
}

data "archive_file" "forensics_evidence_pkg" {
    type = "zip"
    #source_dir = "../lambda/packages/paramiko_src/"
    source_file = "../lambda/EC2ForensicsEvidence.py"
    output_path = "../lambda/packages/EC2ForensicsEvidence.zip"
}

