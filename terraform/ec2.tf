data "http" "myip" {
  url = "http://ipv4.icanhazip.com"
}

resource "aws_security_group" "lambda_access_to_ec2" {
  name        = "lambda_access_to_ec2"
  description = "Lambda access to EC2 to run local triage tasks"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "isolation_step1" {
  name        = "isolation_step1"
  description = "Change all connections to untracked"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "isolation_step2" {
  name        = "isolation"
  description = "Drop all connections but explicitly allowed"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.myip.body)}/32"]
  }  
  
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    security_groups = [aws_security_group.lambda_access_to_ec2.id]
  }

  depends_on = [aws_security_group.lambda_access_to_ec2]
}