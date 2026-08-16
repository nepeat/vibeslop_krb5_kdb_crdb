# Multi-region CRDB substrate on AWS spot: 3 VPCs, full peering mesh,
# 9 spot instances, generated Ansible inventory.
#
#   export AWS_PROFILE=...
#   terraform apply -var "ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"
#   cd ../../ansible && ansible-playbook -i inventory/aws/hosts.ini site.yml

locals {
  mesh_cidrs = [for r in var.regions : r.cidr]
  user_data  = file("${path.module}/templates/cloud-init.yaml")
}

module "use1" {
  source    = "./modules/region"
  providers = { aws = aws.use1 }

  name_prefix    = var.name_prefix
  region_name    = "us-east-1"
  cidr           = var.regions["us-east-1"].cidr
  nodes          = var.regions["us-east-1"].nodes
  instance_type  = lookup(var.instance_type_overrides, "us-east-1", var.instance_type)
  spot           = var.spot
  ssh_public_key = var.ssh_public_key
  admin_cidrs    = var.admin_cidrs
  mesh_cidrs     = local.mesh_cidrs
  root_volume_gb = var.root_volume_gb
  user_data      = local.user_data
  arch           = var.arch
  ubuntu_version = var.ubuntu_version
  ebs_iops       = var.ebs_iops
  ebs_throughput = var.ebs_throughput
}

module "use2" {
  source    = "./modules/region"
  providers = { aws = aws.use2 }

  name_prefix    = var.name_prefix
  region_name    = "us-east-2"
  cidr           = var.regions["us-east-2"].cidr
  nodes          = var.regions["us-east-2"].nodes
  instance_type  = lookup(var.instance_type_overrides, "us-east-2", var.instance_type)
  spot           = var.spot
  ssh_public_key = var.ssh_public_key
  admin_cidrs    = var.admin_cidrs
  mesh_cidrs     = local.mesh_cidrs
  root_volume_gb = var.root_volume_gb
  user_data      = local.user_data
  arch           = var.arch
  ubuntu_version = var.ubuntu_version
  ebs_iops       = var.ebs_iops
  ebs_throughput = var.ebs_throughput
}

module "usw2" {
  source    = "./modules/region"
  providers = { aws = aws.usw2 }

  name_prefix    = var.name_prefix
  region_name    = "us-west-2"
  cidr           = var.regions["us-west-2"].cidr
  nodes          = var.regions["us-west-2"].nodes
  instance_type  = lookup(var.instance_type_overrides, "us-west-2", var.instance_type)
  spot           = var.spot
  ssh_public_key = var.ssh_public_key
  admin_cidrs    = var.admin_cidrs
  mesh_cidrs     = local.mesh_cidrs
  root_volume_gb = var.root_volume_gb
  user_data      = local.user_data
  arch           = var.arch
  ubuntu_version = var.ubuntu_version
  ebs_iops       = var.ebs_iops
  ebs_throughput = var.ebs_throughput
}
