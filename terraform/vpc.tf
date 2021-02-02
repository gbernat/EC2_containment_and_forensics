# VPC Gateway endpoint for lambda access to S3 within VPC

data "aws_vpc_endpoint_service" "vpc_ep_lambda_s3" {
  service      = "s3"
  service_type = "Gateway"
}

# Create a VPC endpoint
resource "aws_vpc_endpoint" "ep" {
  vpc_id       = var.vpc_id
  service_name = data.aws_vpc_endpoint_service.vpc_ep_lambda_s3.service_name
}

# Associate Route table with VPC Gateway endpoint for S3
resource "aws_vpc_endpoint_route_table_association" "vpc_ep_route" {
  route_table_id  = var.vpc_lambda_route_table
  vpc_endpoint_id = aws_vpc_endpoint.ep.id
}
