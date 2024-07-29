locals {
  dev_rules = csvdecode(file(data.external.rules.result.rules_dev_formated_file))
  indexed_dev_rules = {
    for idx, rule in zipmap(range(length(local.dev_rules)), local.dev_rules) :
    idx + 1 => rule
  }

  ip_set   = csvdecode(file(data.external.rules.result.ip_sets_formated_file))
  port_set = csvdecode(file(data.external.rules.result.port_sets_formated_file))
}

data "external" "rules" {
  program = ["python3", "${path.module}/python/script.py"]

  query = {
    path_to_csv_files_folder = "${path.module}/rule_files"
  }
}


resource "aws_networkfirewall_rule_group" "example" {
  capacity = 10
  name     = "dev"
  type     = "STATEFUL"
  rule_group {
    rule_variables {
      dynamic "ip_sets" {
        for_each = local.ip_set
        content {
          key = ip_sets.value.key
          ip_set {
            definition = jsondecode(ip_sets.value.cidr)
          }
        }
      }
      dynamic "port_sets" {
        for_each = local.port_set
        content {
          key = port_sets.value.key
          port_set {
            definition = jsondecode(port_sets.value.port)
          }
        }
      }
    }
    rules_source {
      dynamic "stateful_rule" {
        for_each = local.indexed_dev_rules
        content {
          action = "PASS"
          header {
            destination      = stateful_rule.value.destination
            destination_port = stateful_rule.value.destination_port
            direction        = "ANY"
            protocol         = stateful_rule.value.protocol
            source_port      = "ANY"
            source           = stateful_rule.value.source
          }
          rule_option {
            keyword  = "sid"
            settings = [stateful_rule.key]
          }
        }
      }
    }
  }
}

