# Source of truth for the blocklist. One row per CIDR with the reason and
# expiry; see bin/blocklist for the write path and the README for the schema.
# The stream drives the reconciler; its contents are not read, so keys only.
resource "aws_dynamodb_table" "this" {
  name                        = var.name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "cidr"
  deletion_protection_enabled = var.deletion_protection_enabled
  stream_enabled              = true
  stream_view_type            = "KEYS_ONLY"
  tags                        = local.tags

  attribute {
    name = "cidr"
    type = "S"
  }

  point_in_time_recovery {
    enabled = var.point_in_time_recovery_enabled
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }
}
