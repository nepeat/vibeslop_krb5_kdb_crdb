# Full cross-region peering mesh (3 pairs) + routes both ways in every
# region's route table. CRDB inter-node traffic stays on private IPs.

# --- use1 <-> use2 -----------------------------------------------------
resource "aws_vpc_peering_connection" "use1_use2" {
  provider    = aws.use1
  vpc_id      = module.use1.vpc_id
  peer_vpc_id = module.use2.vpc_id
  peer_region = "us-east-2"
  tags        = { Name = "${var.name_prefix}-use1--use2", project = var.name_prefix }
}

resource "aws_vpc_peering_connection_accepter" "use1_use2" {
  provider                  = aws.use2
  vpc_peering_connection_id = aws_vpc_peering_connection.use1_use2.id
  auto_accept               = true
  tags                      = { Name = "${var.name_prefix}-use1--use2", project = var.name_prefix }
}

resource "aws_route" "use1_to_use2" {
  provider                  = aws.use1
  route_table_id            = module.use1.route_table_id
  destination_cidr_block    = module.use2.cidr
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.use1_use2.id
}

resource "aws_route" "use2_to_use1" {
  provider                  = aws.use2
  route_table_id            = module.use2.route_table_id
  destination_cidr_block    = module.use1.cidr
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.use1_use2.id
}

# --- use1 <-> usw2 -----------------------------------------------------
resource "aws_vpc_peering_connection" "use1_usw2" {
  provider    = aws.use1
  vpc_id      = module.use1.vpc_id
  peer_vpc_id = module.usw2.vpc_id
  peer_region = "us-west-2"
  tags        = { Name = "${var.name_prefix}-use1--usw2", project = var.name_prefix }
}

resource "aws_vpc_peering_connection_accepter" "use1_usw2" {
  provider                  = aws.usw2
  vpc_peering_connection_id = aws_vpc_peering_connection.use1_usw2.id
  auto_accept               = true
  tags                      = { Name = "${var.name_prefix}-use1--usw2", project = var.name_prefix }
}

resource "aws_route" "use1_to_usw2" {
  provider                  = aws.use1
  route_table_id            = module.use1.route_table_id
  destination_cidr_block    = module.usw2.cidr
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.use1_usw2.id
}

resource "aws_route" "usw2_to_use1" {
  provider                  = aws.usw2
  route_table_id            = module.usw2.route_table_id
  destination_cidr_block    = module.use1.cidr
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.use1_usw2.id
}

# --- use2 <-> usw2 -----------------------------------------------------
resource "aws_vpc_peering_connection" "use2_usw2" {
  provider    = aws.use2
  vpc_id      = module.use2.vpc_id
  peer_vpc_id = module.usw2.vpc_id
  peer_region = "us-west-2"
  tags        = { Name = "${var.name_prefix}-use2--usw2", project = var.name_prefix }
}

resource "aws_vpc_peering_connection_accepter" "use2_usw2" {
  provider                  = aws.usw2
  vpc_peering_connection_id = aws_vpc_peering_connection.use2_usw2.id
  auto_accept               = true
  tags                      = { Name = "${var.name_prefix}-use2--usw2", project = var.name_prefix }
}

resource "aws_route" "use2_to_usw2" {
  provider                  = aws.use2
  route_table_id            = module.use2.route_table_id
  destination_cidr_block    = module.usw2.cidr
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.use2_usw2.id
}

resource "aws_route" "usw2_to_use2" {
  provider                  = aws.usw2
  route_table_id            = module.usw2.route_table_id
  destination_cidr_block    = module.use2.cidr
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.use2_usw2.id
}
