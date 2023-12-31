datacenter = "${datacenter_name}"
data_dir   =  "/opt/consul"
log_level  =  "INFO"
node_name  =  "${node_name}"
server     =  false
leave_on_terminate = true

retry_join = ["provider=os tag_key=consul-role tag_value=server auth_url=${auth_url} user_name=${user_name} domain_name=${os_domain_name} password=\"${password}\" region=${os_region}"]
encrypt    = "${encryption_key}"

ca_file    = "/etc/consul/certificates/ca.pem"
cert_file  = "/etc/consul/certificates/cert.pem"
key_file   = "/etc/consul/certificates/private_key.pem"

bind_addr  = "0.0.0.0"
client_addr = "0.0.0.0"
advertise_addr = "{{ GetInterfaceIP \"ens3\" }}"

recursors = ["62.138.222.111","62.138.222.222"]
