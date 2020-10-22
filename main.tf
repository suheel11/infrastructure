provider "aws" {
  region = var.awsRegion
  access_key = var.accessKey
  secret_key = var.secretAccessKey
}

resource "aws_vpc" "csye6225_demo_vpc" {
  cidr_block = var.vpcCIDR
  enable_dns_hostnames = true
  enable_dns_support = true
  enable_classiclink_dns_support = true
  tags = {
    Name = var.vpcTagName
  }
}

resource "aws_subnet" "subnet1" {
  cidr_block = var.subnet1CIDR
  vpc_id = aws_vpc.csye6225_demo_vpc.id
  availability_zone = var.subnet1AZ
  map_public_ip_on_launch = true
  tags = {
    Name = var.subnet1TagName
  }
}

resource "aws_subnet" "subnet2" {
  cidr_block = var.subnet2CIDR
  vpc_id = aws_vpc.csye6225_demo_vpc.id
  availability_zone = var.subnet2AZ
  map_public_ip_on_launch = true
  tags = {
    Name = var.subnet2TagName
  }
}
resource "aws_subnet" "subnet3" {
  cidr_block = var.subnet3CIDR
  vpc_id = aws_vpc.csye6225_demo_vpc.id
  availability_zone = var.subnet3AZ
  map_public_ip_on_launch = true
  tags = {
    Name = var.subnet3TagName
  }
}

resource "aws_internet_gateway" "gateway_for_csye6225_demo_vpc" {
  vpc_id = aws_vpc.csye6225_demo_vpc.id

  tags = {
    Name = var.internetGatewayTagName
  }
}

resource "aws_route_table" "route_table_for_3_subnets" {
  vpc_id = aws_vpc.csye6225_demo_vpc.id

  route {
    cidr_block = var.routeTableCIDR
    gateway_id = aws_internet_gateway.gateway_for_csye6225_demo_vpc.id
  }

  tags = {
    Name = var.routeTableTagName
  }
}

resource "aws_route_table_association" "association_for_subnet1" {
  subnet_id      = aws_subnet.subnet1.id
  route_table_id = aws_route_table.route_table_for_3_subnets.id
}

resource "aws_route_table_association" "association_for_subnet2" {
  subnet_id      = aws_subnet.subnet2.id
  route_table_id = aws_route_table.route_table_for_3_subnets.id
}

resource "aws_route_table_association" "association_for_subnet3" {
  subnet_id      = aws_subnet.subnet3.id
  route_table_id = aws_route_table.route_table_for_3_subnets.id
}