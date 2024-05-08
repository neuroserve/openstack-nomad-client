data_dir           = "/opt/nomad"                                                                                                                                                                                   
enable_syslog      = true
region             = "${os_region}"
datacenter         = "${datacenter_name}"
name               = "${node_name}"
client {
  enabled          = true
  cni_path         = "/opt/cni/bin"
  cni_config_dir   = "/opt/cni/config"
  server_join {
    retry_join     = [ "provider=os tag_key=nomad-role tag_value=server auth_url=${auth_url} user_name=${user_name} domain_name=${os_domain_name} password=\"${password}\" region=${os_region}" ] 
    retry_interval = "15s"
  }
}

tls {
  http = true
  rpc  = true
  ca_file   = "/etc/nomad/certificates/ca.pem"
  cert_file = "/etc/nomad/certificates/cert.pem"
  key_file  = "/etc/nomad/certificates/private_key.pem"

  verify_server_hostname = false
  verify_https_client    = false
}

consul {
  grpc_ca_file = "/etc/consul/certificates/ca.pem"
  grpc_address = "127.0.0.1:8503"
  ca_file      = "/etc/consul/certificates/ca.pem"
  cert_file    = "/etc/consul/certificates/cert.pem"
  key_file     = "/etc/consul/certificates/private_key.pem"
  ssl          = true
  auto_advertise = true
  address      = "127.0.0.1:8501"
  client_service_name = "${node_name}"
  token = "" # nomad-client token here
}

telemetry {
  collection_interval = "1s"
  disable_hostname = true
  prometheus_metrics = true
  publish_allocation_metrics = true
  publish_node_metrics = true
}

