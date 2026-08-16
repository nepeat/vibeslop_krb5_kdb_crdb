# Everything inside one region: VPC, subnets across up to 3 AZs, IGW,
# route table, SG, key pair, spot instances. The caller passes the
# regional provider.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "name_prefix" { type = string }
variable "region_name" { type = string }
variable "cidr" { type = string }
variable "nodes" { type = number }
variable "instance_type" { type = string }
variable "spot" { type = bool }
variable "ssh_public_key" { type = string }
variable "admin_cidrs" { type = list(string) }
variable "mesh_cidrs" { type = list(string) }
variable "root_volume_gb" { type = number }
variable "ebs_iops" { type = number }
variable "ebs_throughput" { type = number }
variable "user_data" { type = string }
variable "arch" { type = string }           # amd64 | arm64 (must match instance type)
variable "ubuntu_version" { type = string } # e.g. "26.04"

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # us-west-1 only exposes 2 AZs to most accounts; take what exists.
  azs = slice(
    data.aws_availability_zones.available.names,
    0,
    min(3, length(data.aws_availability_zones.available.names)),
  )
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name    = "${var.name_prefix}-${var.region_name}"
    project = var.name_prefix
  }
}

resource "aws_subnet" "this" {
  count                   = length(local.azs)
  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(var.cidr, 8, 16 + count.index)
  map_public_ip_on_launch = true
  tags = {
    Name    = "${var.name_prefix}-${var.region_name}-${local.azs[count.index]}"
    project = var.name_prefix
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name_prefix}-${var.region_name}", project = var.name_prefix }
}

resource "aws_route_table" "this" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "${var.name_prefix}-${var.region_name}", project = var.name_prefix }
}

resource "aws_route_table_association" "this" {
  count          = length(aws_subnet.this)
  subnet_id      = aws_subnet.this[count.index].id
  route_table_id = aws_route_table.this.id
}

resource "aws_security_group" "nodes" {
  name        = "${var.name_prefix}-nodes"
  description = "CRDB nodes"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }
  ingress {
    description = "CRDB SQL/RPC + admin UI, mesh-internal only"
    from_port   = 26257
    to_port     = 26257
    protocol    = "tcp"
    cidr_blocks = var.mesh_cidrs
  }
  ingress {
    description = "CRDB admin UI, mesh-internal only"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.mesh_cidrs
  }
  ingress {
    description = "KDC (krb5kdc on cluster nodes), mesh-internal only"
    from_port   = 8888
    to_port     = 8888
    protocol    = "tcp"
    cidr_blocks = var.mesh_cidrs
  }
  ingress {
    description = "KDC UDP, mesh-internal only"
    from_port   = 8888
    to_port     = 8888
    protocol    = "udp"
    cidr_blocks = var.mesh_cidrs
  }
  ingress {
    description = "ICMP inside mesh"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = var.mesh_cidrs
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { project = var.name_prefix }
}

resource "aws_key_pair" "admin" {
  key_name   = "${var.name_prefix}-admin"
  public_key = var.ssh_public_key
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name = "name"
    # codename-agnostic: matches gp3 image naming for any release
    values = ["ubuntu/images/hvm-ssd*/ubuntu-*-${var.ubuntu_version}-${var.arch}-server-*"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_instance" "node" {
  count                  = var.nodes
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.this[count.index % length(aws_subnet.this)].id
  vpc_security_group_ids = [aws_security_group.nodes.id]
  key_name               = aws_key_pair.admin.key_name
  user_data              = var.user_data

  dynamic "instance_market_options" {
    for_each = var.spot ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        spot_instance_type             = "one-time"
        instance_interruption_behavior = "terminate"
      }
    }
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    iops        = var.ebs_iops
    throughput  = var.ebs_throughput
  }

  tags = {
    Name        = "${var.name_prefix}-${var.region_name}-${count.index}"
    project     = var.name_prefix
    crdb_region = var.region_name
    crdb_index  = count.index
  }
}

output "vpc_id" { value = aws_vpc.this.id }
output "route_table_id" { value = aws_route_table.this.id }
output "cidr" { value = var.cidr }
output "nodes" {
  value = [
    for i, n in aws_instance.node : {
      name       = n.tags.Name
      public_ip  = n.public_ip
      private_ip = n.private_ip
      az         = n.availability_zone
      region     = var.region_name
    }
  ]
}
