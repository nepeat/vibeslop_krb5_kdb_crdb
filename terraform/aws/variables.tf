variable "name_prefix" {
  type    = string
  default = "crdb-krb5"
}

variable "instance_type" {
  description = "Default instance type for all regions (c7a.xlarge = 4 vCPU / 8 GiB AMD; c8g.xlarge = Graviton4, cheaper — set arch=arm64 with it)"
  type        = string
  default     = "c7a.xlarge"
}

variable "arch" {
  description = "AMI architecture: amd64 (c7a/c8a...) or arm64 (c7g/c8g Graviton). Must match instance_type; also set crdb_arch=linux-arm64 in the generated group_vars via crdb_arch below."
  type        = string
  default     = "amd64"
  validation {
    condition     = contains(["amd64", "arm64"], var.arch)
    error_message = "arch must be amd64 or arm64"
  }
}

variable "crdb_arch" {
  description = "CockroachDB tarball arch written into the generated group_vars (linux-amd64 | linux-arm64)"
  type        = string
  default     = "linux-amd64"
}

variable "instance_type_overrides" {
  description = "Per-region instance type override (e.g. c8a where available — c8a IS available in us-west-2 (unlike us-west-1))"
  type        = map(string)
  default     = {}
}

variable "spot" {
  description = "Use spot instances (false = on-demand, for debugging)"
  type        = bool
  default     = true
}

variable "regions" {
  description = "Region -> {cidr, nodes}. Keys must match the provider aliases in versions.tf."
  type = map(object({
    cidr  = string
    nodes = number
  }))
  default = {
    us-east-1 = { cidr = "10.91.0.0/16", nodes = 3 }
    us-east-2 = { cidr = "10.92.0.0/16", nodes = 3 }
    us-west-2 = { cidr = "10.93.0.0/16", nodes = 3 }
  }
}

variable "ssh_public_key" {
  description = "SSH public key material for the ubuntu user on all nodes"
  type        = string
}

variable "admin_cidrs" {
  description = "CIDRs allowed to reach SSH"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "root_volume_gb" {
  type    = number
  default = 50
}

variable "ubuntu_version" {
  description = "Ubuntu release for node AMIs"
  type        = string
  default     = "26.04"
}

# gp3 baseline is free and sufficient: dataset is ~90MB/node at RF3 and
# the write burn peaks ~1-2k batched WAL writes/s/node; reads hit the
# pebble block cache. Bump these vars if a bigger burn ever saturates.
variable "ebs_iops" {
  type    = number
  default = 3000
}

variable "ebs_throughput" {
  type    = number
  default = 125
}
