# AWS spot substrate (Terraform) for the multi-region CRDB test bed

3 regions (us-east-1 / us-east-2 / us-west-2) x 3 spot instances, with:

- one **VPC per region** + a **full cross-region peering mesh** with
  routes both ways — CRDB inter-node and KDC->CRDB traffic stays on
  private IPs; security groups admit 26257/8080 only from the mesh
  CIDRs, SSH only from `admin_cidrs`
- **spot instances** (`instance_type` variable, per-region
  `instance_type_overrides` — note c8a IS available in us-west-2 (unlike us-west-1);
  `spot=false` for on-demand), subnets spread over up to 3 AZs and
  instances round-robin'd across them for spot-pool diversity
  (us-west-2 has 4 AZs; we use 3)
- Ubuntu 26.04 + cloud-init: chrony (site.yml asserts sync),
  containerd, python3, sysctls
- generated Ansible inventory at `ansible/inventory/aws/`

## Use (from this dev box)

```sh
export AWS_PROFILE=...      # or access keys
tofu init
tofu apply -var "ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"
# ~2-3 min, then:
cd ../../ansible
ansible-playbook -i inventory/aws/hosts.ini site.yml
```

Teardown (spot spend stops here):

```sh
tofu destroy -var "ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"
```

Cost at defaults (9x c7a.xlarge spot): ~$0.70/hour + $0.01-0.02/GB
cross-region transfer (irrelevant for chaos runs, measurable for
week-long benches).

## Notes

- **Spot reclaim = free chaos test** (the suite's "one node down"
  phase). `tofu apply` recreates terminated instances and refreshes the
  inventory (public IPs change); then run docs/runbooks.md runbook 3
  for the CRDB side (decommission the dead store id).
- Fresh accounts: check Service Quotas -> EC2 -> "All Standard Spot
  Instance Requests" (needs 12+ vCPU per region at defaults).
- Adding a region requires editing BOTH `var.regions` and the provider
  aliases in versions.tf + a module block + peering pairs — Terraform
  cannot loop providers. At 4+ regions the O(n^2) peering mesh is
  Transit Gateway territory.
- Region config (`--locality`, join seeds, multi-region DDL) is NOT
  here — the Ansible playbook derives all of it from the generated
  inventory. This module only owns cloud resources.
