# =================================================================
# Licensed Materials - Property of IBM
# 5737-E67
# @ Copyright IBM Corporation 2016, 2017 All Rights Reserved
# US Government Users Restricted Rights - Use, duplication or disclosure
# restricted by GSA ADP Schedule Contract with IBM Corp.
# =================================================================

# This is a terraform generated template generated from apache_http_v24_standalone_full

##############################################################
# Keys - CAMC (public/private) & optional User Key (public)
##############################################################
variable "ibm_pm_public_ssh_key_name" {
  description = "Public CAMC SSH key name used to connect to the virtual guest."
}

variable "ibm_pm_private_ssh_key" {
  description = "Private CAMC SSH key (base64 encoded) used to connect to the virtual guest."
}

variable "user_public_ssh_key" {
  type        = "string"
  description = "User defined public SSH key used to connect to the virtual machine. The format must be in openSSH."
  default     = "None"
}

##############################################################
# Define the ibm provider
##############################################################
#define the ibm provider
provider "ibm" {
  version = "~> 0.5"
}

provider "camc" {
  version = "~> 0.1"
}

provider "random" {
  version = "~> 1.0"
}

##############################################################
# Reference public key in Devices>Manage>SSH Keys in SL console)
##############################################################
data "ibm_compute_ssh_key" "ibm_pm_public_key" {
  label       = "${var.ibm_pm_public_ssh_key_name}"
  most_recent = "true"
}

resource "random_id" "stack_id" {
  byte_length = "16"
}

##############################################################
# Define pattern variables
##############################################################
##### unique stack name #####
variable "ibm_stack_name" {
  description = "A unique stack name."
}

#### Default OS Admin User Map ####
variable "default_os_admin_user" {
  type        = "map"
  description = "look up os_admin_user using resource image"

  default = {
    UBUNTU_16_64 = "root"
    REDHAT_7_64  = "root"
  }
}

##### Environment variables #####
#Variable : ibm_pm_access_token
variable "ibm_pm_access_token" {
  type        = "string"
  description = "IBM Pattern Manager Access Token"
}

#Variable : ibm_pm_service
variable "ibm_pm_service" {
  type        = "string"
  description = "IBM Pattern Manager Service"
}

#Variable : ibm_sw_repo
variable "ibm_sw_repo" {
  type        = "string"
  description = "IBM Software Repo Root (https://<hostname>:<port>)"
}

#Variable : ibm_sw_repo_password
variable "ibm_sw_repo_password" {
  type        = "string"
  description = "IBM Software Repo Password"
}

#Variable : ibm_sw_repo_user
variable "ibm_sw_repo_user" {
  type        = "string"
  description = "IBM Software Repo Username"
  default     = "repouser"
}

##### HttpdNode01 variables #####
#Variable : HttpdNode01-image
variable "HttpdNode01-image" {
  type        = "string"
  description = "Operating system image id / template that should be used when creating the virtual image"
  default     = "REDHAT_7_64"
}

#Variable : HttpdNode01-mgmt-network-public
variable "HttpdNode01-mgmt-network-public" {
  type        = "string"
  description = "Expose and use public IP of virtual machine for internal communication"
  default     = "true"
}

#Variable : HttpdNode01-name
variable "HttpdNode01-name" {
  type        = "string"
  description = "Short hostname of virtual machine"
}

#Variable : HttpdNode01-os_admin_user
variable "HttpdNode01-os_admin_user" {
  type        = "string"
  description = "Name of the admin user account in the virtual machine that will be accessed via SSH"
}

#Variable : HttpdNode01_httpd_data_dir_mode
variable "HttpdNode01_httpd_data_dir_mode" {
  type        = "string"
  description = "OS Permisssions of data folders"
  default     = "0755"
}

#Variable : HttpdNode01_httpd_document_root
variable "HttpdNode01_httpd_document_root" {
  type        = "string"
  description = "File System Location of the Document Root"
  default     = "/var/www/html5"
}

#Variable : HttpdNode01_httpd_listen
variable "HttpdNode01_httpd_listen" {
  type        = "string"
  description = "Listening port to be configured in HTTP server"
  default     = "8080"
}

#Variable : HttpdNode01_httpd_log_dir
variable "HttpdNode01_httpd_log_dir" {
  type        = "string"
  description = "Directory where HTTP Server logs will be sent"
  default     = "/var/log/httpd"
}

#Variable : HttpdNode01_httpd_log_level
variable "HttpdNode01_httpd_log_level" {
  type        = "string"
  description = "Log levels of the http process"
  default     = "info"
}

#Variable : HttpdNode01_httpd_os_users_web_content_owner_gid
variable "HttpdNode01_httpd_os_users_web_content_owner_gid" {
  type        = "string"
  description = "Group ID of web content owner to be configured in HTTP server"
  default     = "webmaster"
}

#Variable : HttpdNode01_httpd_os_users_web_content_owner_home
variable "HttpdNode01_httpd_os_users_web_content_owner_home" {
  type        = "string"
  description = "Home directory of web content owner to be configured in HTTP server"
  default     = "/home/webmaster"
}

#Variable : HttpdNode01_httpd_os_users_web_content_owner_ldap_user
variable "HttpdNode01_httpd_os_users_web_content_owner_ldap_user" {
  type        = "string"
  description = "Use LDAP to authenticate Web Content Owner account on Linux HTTP server as well as web site logins"
  default     = "false"
}

#Variable : HttpdNode01_httpd_os_users_web_content_owner_name
variable "HttpdNode01_httpd_os_users_web_content_owner_name" {
  type        = "string"
  description = "User ID of web content owner to be configured in HTTP server"
  default     = "webmaster"
}

#Variable : HttpdNode01_httpd_os_users_web_content_owner_shell
variable "HttpdNode01_httpd_os_users_web_content_owner_shell" {
  type        = "string"
  description = "Default shell configured on Linux server"
  default     = "/bin/bash"
}

#Variable : HttpdNode01_httpd_php_mod_enabled
variable "HttpdNode01_httpd_php_mod_enabled" {
  type        = "string"
  description = "Enable PHP in Apache on Linux by Loading the Module"
  default     = "true"
}

#Variable : HttpdNode01_httpd_proxy_ProxyPreserveHost
variable "HttpdNode01_httpd_proxy_ProxyPreserveHost" {
  type        = "string"
  description = "Instruct the reverse proxy to preserve original host header from the client browser"
  default     = "On"
}

#Variable : HttpdNode01_httpd_server_admin
variable "HttpdNode01_httpd_server_admin" {
  type        = "string"
  description = "Email Address of the Webmaster"
  default     = "webmaster@orpheus.ibm.com"
}

#Variable : HttpdNode01_httpd_server_name
variable "HttpdNode01_httpd_server_name" {
  type        = "string"
  description = "The Name of the HTTP Server, normally the FQDN of server."
  default     = "orpheus.ibm.com"
}

#Variable : HttpdNode01_httpd_ssl_sslcompression
variable "HttpdNode01_httpd_ssl_sslcompression" {
  type        = "string"
  description = "Enable SSL compression within HTTP Server Configuration"
  default = "Off"
}

#Variable : HttpdNode01_httpd_ssl_sslproxycacertificatefile
variable "HttpdNode01_httpd_ssl_sslproxycacertificatefile" {
  type        = "string"
  description = "SSL proxy Certificate file name"
  default = "PleaseProvide"
}

#Variable : HttpdNode01_httpd_ssl_sslproxycacertificatepath
variable "HttpdNode01_httpd_ssl_sslproxycacertificatepath" {
  type        = "string"
  description = "SSL proxy Certificate file path"
  default = "PleaseProvide"
}

#Variable : HttpdNode01_httpd_ssl_sslproxycarevocationcheck
variable "HttpdNode01_httpd_ssl_sslproxycarevocationcheck" {
  type        = "string"
  description = "SSL proxy CA revocation check"
  default = "PleaseProvide"
}

#Variable : HttpdNode01_httpd_ssl_sslproxycarevocationfile
variable "HttpdNode01_httpd_ssl_sslproxycarevocationfile" {
  type        = "string"
  description = "SSL proxy CA revocation file"
  default = "PleaseProvide"
}

#Variable : HttpdNode01_httpd_version
variable "HttpdNode01_httpd_version" {
  type        = "string"
  description = "Version of HTTP Server to be installed."
  default     = "2.4"
}

#Variable : HttpdNode01_httpd_vhosts_enabled
variable "HttpdNode01_httpd_vhosts_enabled" {
  type        = "string"
  description = "Allow to configure virtual hosts to run multiple websites on the same HTTP server"
  default     = "false"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_custom_log
variable "HttpdNode01_httpd_virtualhosts_default_http_server_custom_log" {
  type        = "string"
  description = "Location of the HTTP Server Custom Log"
  default     = "default_http_server_custom_log"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_custom_log_format
variable "HttpdNode01_httpd_virtualhosts_default_http_server_custom_log_format" {
  type        = "string"
  description = "Log Format of the Custom Log"
  default     = "combined"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_document_root
variable "HttpdNode01_httpd_virtualhosts_default_http_server_document_root" {
  type        = "string"
  description = "Location of the Default Docuement Root"
  default     = "/var/www/default_http_server"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_error_log
variable "HttpdNode01_httpd_virtualhosts_default_http_server_error_log" {
  type        = "string"
  description = "Location of the HTTP Server Error Log"
  default     = "default_http_server_error_log"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_global_ssl_config
variable "HttpdNode01_httpd_virtualhosts_default_http_server_global_ssl_config" {
  type        = "string"
  description = "Use default global configuration for HTTPS communication in HTTP server"
  default     = "true"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_server_admin
variable "HttpdNode01_httpd_virtualhosts_default_http_server_server_admin" {
  type        = "string"
  description = "Email address of the Server Admin"
  default     = "webmaster"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_server_name
variable "HttpdNode01_httpd_virtualhosts_default_http_server_server_name" {
  type        = "string"
  description = "Vhost server name for directing requests"
  default     = "default_http_server"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_ssl_enabled
variable "HttpdNode01_httpd_virtualhosts_default_http_server_ssl_enabled" {
  type        = "string"
  description = "Enable SSL for virtual host for HTTP communication in HTTP server"
  default     = "false"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_vhost_listen
variable "HttpdNode01_httpd_virtualhosts_default_http_server_vhost_listen" {
  type        = "string"
  description = "Listening port configured in virtual host for HTTP communication in HTTP server"
  default     = "80"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_http_server_vhost_type
variable "HttpdNode01_httpd_virtualhosts_default_http_server_vhost_type" {
  type        = "string"
  description = "Allow to configure virtual hosts to run multiple websites on the same HTTP server"
  default     = "name_based"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_custom_log
variable "HttpdNode01_httpd_virtualhosts_default_https_server_custom_log" {
  type        = "string"
  description = "Vhost custom log dir"
  default     = "default_https_server_custom_log"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_custom_log_format
variable "HttpdNode01_httpd_virtualhosts_default_https_server_custom_log_format" {
  type        = "string"
  description = "Vhost custom log format"
  default     = "combined"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_document_root
variable "HttpdNode01_httpd_virtualhosts_default_https_server_document_root" {
  type        = "string"
  description = "Vhost document root"
  default     = "/var/www/default_https_server"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_error_log
variable "HttpdNode01_httpd_virtualhosts_default_https_server_error_log" {
  type        = "string"
  description = "Vhost error log dir"
  default     = "default_https_server_error_log"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_global_ssl_config
variable "HttpdNode01_httpd_virtualhosts_default_https_server_global_ssl_config" {
  type        = "string"
  description = "Use default global configuration for HTTPS communication in HTTP server"
  default     = "true"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_log_dir
variable "HttpdNode01_httpd_virtualhosts_default_https_server_log_dir" {
  type        = "string"
  description = "Vhost log dir"
  default     = "/var/log/httpd"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_proxy_enabled
variable "HttpdNode01_httpd_virtualhosts_default_https_server_proxy_enabled" {
  type        = "string"
  description = "Enable proxy configuration"
  default     = "true"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_server_admin
variable "HttpdNode01_httpd_virtualhosts_default_https_server_server_admin" {
  type        = "string"
  description = "Vhost Server admin"
  default     = "webmaster"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_server_name
variable "HttpdNode01_httpd_virtualhosts_default_https_server_server_name" {
  type        = "string"
  description = "Vhost server name for directing requests"
  default     = "default_https_server"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_ssl_enabled
variable "HttpdNode01_httpd_virtualhosts_default_https_server_ssl_enabled" {
  type        = "string"
  description = "Enable SSL for virtual host for HTTP communication in HTTP server"
  default     = "true"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_vhost_listen
variable "HttpdNode01_httpd_virtualhosts_default_https_server_vhost_listen" {
  type        = "string"
  description = "Listening port configured in virtual host for HTTPS communication in HTTP server"
  default     = "443"
}

#Variable : HttpdNode01_httpd_virtualhosts_default_https_server_vhost_type
variable "HttpdNode01_httpd_virtualhosts_default_https_server_vhost_type" {
  type        = "string"
  description = "Specify type of virtual host for HTTP communication in HTTP server"
  default     = "name_based"
}

##### ungrouped variables #####
##### domain name #####
variable "runtime_domain" {
  description = "domain name"
  default     = "cam.ibm.com"
}

#########################################################
##### Resource : HttpdNode01
#########################################################

#Parameter : HttpdNode01_datacenter
variable "HttpdNode01_datacenter" {
  type        = "string"
  description = "IBMCloud datacenter where infrastructure resources will be deployed"
  default     = "dal05"
}

#Parameter : HttpdNode01_private_network_only
variable "HttpdNode01_private_network_only" {
  type        = "string"
  description = "Provision the virtual machine with only private IP"
  default     = "false"
}

#Parameter : HttpdNode01_number_of_cores
variable "HttpdNode01_number_of_cores" {
  type        = "string"
  description = "Number of CPU cores, which is required to be a positive Integer"
  default     = "2"
}

#Parameter : HttpdNode01_memory
variable "HttpdNode01_memory" {
  type        = "string"
  description = "Amount of Memory (MBs), which is required to be one or more times of 1024"
  default     = "2048"
}

#Parameter : HttpdNode01_network_speed
variable "HttpdNode01_network_speed" {
  type        = "string"
  description = "Bandwidth of network communication applied to the virtual machine"
  default     = "10"
}

#Parameter : HttpdNode01_hourly_billing
variable "HttpdNode01_hourly_billing" {
  type        = "string"
  description = "Billing cycle: hourly billed or monthly billed"
  default     = "true"
}

#Parameter : HttpdNode01_dedicated_acct_host_only
variable "HttpdNode01_dedicated_acct_host_only" {
  type        = "string"
  description = "Shared or dedicated host, where dedicated host usually means higher performance and cost"
  default     = "false"
}

#Parameter : HttpdNode01_local_disk
variable "HttpdNode01_local_disk" {
  type        = "string"
  description = "User local disk or SAN disk"
  default     = "false"
}

variable "HttpdNode01_root_disk_size" {
  type        = "string"
  description = "Root Disk Size - HttpdNode01"
  default     = "25"
}

resource "ibm_compute_vm_instance" "HttpdNode01" {
  hostname                 = "${var.HttpdNode01-name}"
  os_reference_code        = "${var.HttpdNode01-image}"
  domain                   = "${var.runtime_domain}"
  datacenter               = "${var.HttpdNode01_datacenter}"
  network_speed            = "${var.HttpdNode01_network_speed}"
  hourly_billing           = "${var.HttpdNode01_hourly_billing}"
  private_network_only     = "${var.HttpdNode01_private_network_only}"
  cores                    = "${var.HttpdNode01_number_of_cores}"
  memory                   = "${var.HttpdNode01_memory}"
  disks                    = ["${var.HttpdNode01_root_disk_size}"]
  dedicated_acct_host_only = "${var.HttpdNode01_dedicated_acct_host_only}"
  local_disk               = "${var.HttpdNode01_local_disk}"
  ssh_key_ids              = ["${data.ibm_compute_ssh_key.ibm_pm_public_key.id}"]

  # Specify the ssh connection
  connection {
    user        = "${var.HttpdNode01-os_admin_user == "" ? lookup(var.default_os_admin_user, var.HttpdNode01-image) : var.HttpdNode01-os_admin_user}"
    private_key = "${base64decode(var.ibm_pm_private_ssh_key)}"
  }

  provisioner "file" {
    destination = "HttpdNode01_add_ssh_key.sh"
    content     = <<EOF
# =================================================================
# Licensed Materials - Property of IBM
# 5737-E67
# @ Copyright IBM Corporation 2016, 2017 All Rights Reserved
# US Government Users Restricted Rights - Use, duplication or disclosure
# restricted by GSA ADP Schedule Contract with IBM Corp.
# =================================================================
#!/bin/bash

if (( $# != 2 )); then
    echo "usage: arg 1 is user, arg 2 is public key"
    exit -1
fi

userid=$1
ssh_key=$2

if [[ $ssh_key = 'None' ]]; then
  echo "skipping add, 'None' specified"
  exit 0
fi

user_home=$(eval echo "~$userid")
user_auth_key_file=$user_home/.ssh/authorized_keys
if ! [ -f $user_auth_key_file ]; then
  echo "$user_auth_key_file does not exist on this system"
  exit -1
else
  echo "user_home --> $user_home"
fi

echo $ssh_key >> $user_auth_key_file
if [ $? -ne 0 ]; then
  echo "failed to add to $user_auth_key_file"
  exit -1
else
  echo "updated $user_auth_key_file"
fi

EOF
  }

  # Execute the script remotely
  provisioner "remote-exec" {
    inline = [
      "bash -c 'chmod +x HttpdNode01_add_ssh_key.sh'",
      "bash -c './HttpdNode01_add_ssh_key.sh  \"${var.HttpdNode01-os_admin_user}\" \"${var.user_public_ssh_key}\">> HttpdNode01_add_ssh_key.log 2>&1'",
    ]
  }
}

#########################################################
##### Resource : HttpdNode01_chef_bootstrap_comp
#########################################################

resource "camc_bootstrap" "HttpdNode01_chef_bootstrap_comp" {
  depends_on      = ["camc_vaultitem.VaultItem", "ibm_compute_vm_instance.HttpdNode01"]
  name            = "HttpdNode01_chef_bootstrap_comp"
  camc_endpoint   = "${var.ibm_pm_service}/v1/bootstrap/chef"
  access_token    = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace           = true

  data = <<EOT
{
  "os_admin_user": "${var.HttpdNode01-os_admin_user == "default"? lookup(var.default_os_admin_user, var.HttpdNode01-image) : var.HttpdNode01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${var.HttpdNode01-mgmt-network-public == "false" ? ibm_compute_vm_instance.HttpdNode01.ipv4_address_private : ibm_compute_vm_instance.HttpdNode01.ipv4_address}",
  "node_name": "${var.HttpdNode01-name}",
  "node_attributes": {
    "ibm_internal": {
      "stack_id": "${random_id.stack_id.hex}",
      "stack_name": "${var.ibm_stack_name}",
      "vault": {
        "item": "secrets",
        "name": "${random_id.stack_id.hex}"
      }
    }
  }
}
EOT
}

#########################################################
##### Resource : HttpdNode01_httpd24-base-install
#########################################################

resource "camc_softwaredeploy" "HttpdNode01_httpd24-base-install" {
  depends_on      = ["camc_bootstrap.HttpdNode01_chef_bootstrap_comp"]
  name            = "HttpdNode01_httpd24-base-install"
  camc_endpoint   = "${var.ibm_pm_service}/v1/software_deployment/chef"
  access_token    = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace           = true

  data = <<EOT
{
  "os_admin_user": "${var.HttpdNode01-os_admin_user == "default"? lookup(var.default_os_admin_user, var.HttpdNode01-image) : var.HttpdNode01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${var.HttpdNode01-mgmt-network-public == "false" ? ibm_compute_vm_instance.HttpdNode01.ipv4_address_private : ibm_compute_vm_instance.HttpdNode01.ipv4_address}",
  "node_name": "${var.HttpdNode01-name}",
  "runlist": "role[httpd24-base-install]",
  "node_attributes": {
    "httpd": {
      "data_dir_mode": "${var.HttpdNode01_httpd_data_dir_mode}",
      "document_root": "${var.HttpdNode01_httpd_document_root}",
      "listen": "${var.HttpdNode01_httpd_listen}",
      "log_dir": "${var.HttpdNode01_httpd_log_dir}",
      "log_level": "${var.HttpdNode01_httpd_log_level}",
      "os_users": {
        "web_content_owner": {
          "gid": "${var.HttpdNode01_httpd_os_users_web_content_owner_gid}",
          "home": "${var.HttpdNode01_httpd_os_users_web_content_owner_home}",
          "ldap_user": "${var.HttpdNode01_httpd_os_users_web_content_owner_ldap_user}",
          "name": "${var.HttpdNode01_httpd_os_users_web_content_owner_name}",
          "shell": "${var.HttpdNode01_httpd_os_users_web_content_owner_shell}"
        }
      },
      "php_mod_enabled": "${var.HttpdNode01_httpd_php_mod_enabled}",
      "server_admin": "${var.HttpdNode01_httpd_server_admin}",
      "server_name": "${var.HttpdNode01_httpd_server_name}",
      "version": "${var.HttpdNode01_httpd_version}",
      "vhosts_enabled": "${var.HttpdNode01_httpd_vhosts_enabled}"
    },
    "ibm": {
      "sw_repo": "${var.ibm_sw_repo}",
      "sw_repo_user": "${var.ibm_sw_repo_user}"
    },
    "ibm_internal": {
      "roles": "[httpd24-base-install]"
    }
  },
  "vault_content": {
    "item": "secrets",
    "values": {
      "ibm": {
        "sw_repo_password": "${var.ibm_sw_repo_password}"
      }
    },
    "vault": "${random_id.stack_id.hex}"
  }
}
EOT
}

#########################################################
##### Resource : HttpdNode01_httpd24-ssl-vhosts
#########################################################

resource "camc_softwaredeploy" "HttpdNode01_httpd24-ssl-vhosts" {
  depends_on      = ["camc_softwaredeploy.HttpdNode01_httpd24-base-install"]
  name            = "HttpdNode01_httpd24-ssl-vhosts"
  camc_endpoint   = "${var.ibm_pm_service}/v1/software_deployment/chef"
  access_token    = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace           = true

  data = <<EOT
{
  "os_admin_user": "${var.HttpdNode01-os_admin_user == "default"? lookup(var.default_os_admin_user, var.HttpdNode01-image) : var.HttpdNode01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${var.HttpdNode01-mgmt-network-public == "false" ? ibm_compute_vm_instance.HttpdNode01.ipv4_address_private : ibm_compute_vm_instance.HttpdNode01.ipv4_address}",
  "node_name": "${var.HttpdNode01-name}",
  "runlist": "role[httpd24-ssl-vhosts]",
  "node_attributes": {
    "httpd": {
      "document_root": "${var.HttpdNode01_httpd_document_root}",
      "log_dir": "${var.HttpdNode01_httpd_log_dir}",
      "log_level": "${var.HttpdNode01_httpd_log_level}",
      "os_users": {
        "web_content_owner": {
          "gid": "${var.HttpdNode01_httpd_os_users_web_content_owner_gid}",
          "ldap_user": "${var.HttpdNode01_httpd_os_users_web_content_owner_ldap_user}",
          "name": "${var.HttpdNode01_httpd_os_users_web_content_owner_name}"
        }
      },
      "proxy": {
        "ProxyPreserveHost": "${var.HttpdNode01_httpd_proxy_ProxyPreserveHost}"
      },
      "server_admin": "${var.HttpdNode01_httpd_server_admin}",
      "ssl": {
        "sslcompression": "${var.HttpdNode01_httpd_ssl_sslcompression}",
        "sslproxycacertificatefile": "${var.HttpdNode01_httpd_ssl_sslproxycacertificatefile}",
        "sslproxycacertificatepath": "${var.HttpdNode01_httpd_ssl_sslproxycacertificatepath}",
        "sslproxycarevocationcheck": "${var.HttpdNode01_httpd_ssl_sslproxycarevocationcheck}",
        "sslproxycarevocationfile": "${var.HttpdNode01_httpd_ssl_sslproxycarevocationfile}"
      },
      "version": "${var.HttpdNode01_httpd_version}",
      "vhosts_enabled": "${var.HttpdNode01_httpd_vhosts_enabled}",
      "virtualhosts": {
        "default_http_server": {
          "custom_log": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_custom_log}",
          "custom_log_format": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_custom_log_format}",
          "document_root": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_document_root}",
          "error_log": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_error_log}",
          "global_ssl_config": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_global_ssl_config}",
          "server_admin": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_server_admin}",
          "server_name": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_server_name}",
          "ssl_enabled": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_ssl_enabled}",
          "vhost_listen": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_vhost_listen}",
          "vhost_type": "${var.HttpdNode01_httpd_virtualhosts_default_http_server_vhost_type}"
        },
        "default_https_server": {
          "custom_log": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_custom_log}",
          "custom_log_format": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_custom_log_format}",
          "document_root": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_document_root}",
          "error_log": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_error_log}",
          "global_ssl_config": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_global_ssl_config}",
          "log_dir": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_log_dir}",
          "proxy_enabled": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_proxy_enabled}",
          "server_admin": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_server_admin}",
          "server_name": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_server_name}",
          "ssl_enabled": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_ssl_enabled}",
          "vhost_listen": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_vhost_listen}",
          "vhost_type": "${var.HttpdNode01_httpd_virtualhosts_default_https_server_vhost_type}"
        }
      }
    },
    "ibm": {
      "sw_repo": "${var.ibm_sw_repo}",
      "sw_repo_user": "${var.ibm_sw_repo_user}"
    },
    "ibm_internal": {
      "roles": "[httpd24-ssl-vhosts]"
    }
  },
  "vault_content": {
    "item": "secrets",
    "values": {
      "ibm": {
        "sw_repo_password": "${var.ibm_sw_repo_password}"
      }
    },
    "vault": "${random_id.stack_id.hex}"
  }
}
EOT
}

#########################################################
##### Resource : VaultItem
#########################################################

resource "camc_vaultitem" "VaultItem" {
  camc_endpoint   = "${var.ibm_pm_service}/v1/vault_item/chef"
  access_token    = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace           = true

  data = <<EOT
{
  "vault_content": {
    "item": "secrets",
    "values": {},
    "vault": "${random_id.stack_id.hex}"
  }
}
EOT
}

output "HttpdNode01_ip" {
  value = "Private : ${ibm_compute_vm_instance.HttpdNode01.ipv4_address_private} & Public : ${ibm_compute_vm_instance.HttpdNode01.ipv4_address}"
}

output "HttpdNode01_name" {
  value = "${var.HttpdNode01-name}"
}

output "HttpdNode01_roles" {
  value = "httpd24-base-install,httpd24-ssl-vhosts"
}

output "stack_id" {
  value = "${random_id.stack_id.hex}"
}
