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
variable "user_public_ssh_key" {
  type        = "string"
  description = "User defined public SSH key used to connect to the virtual machine. The format must be in openSSH."
  default     = "None"
}

variable "ibm_pm_public_ssh_key" {
  description = "Public CAMC SSH key value which is used to connect to a guest, used on VMware only."
}

variable "ibm_pm_private_ssh_key" {
  description = "Private CAMC SSH key (base64 encoded) used to connect to the virtual guest."
}

variable "allow_unverified_ssl" {
  description = "Communication with vsphere server with self signed certificate"
  default     = "true"
}

##############################################################
# Define the vsphere provider
##############################################################
provider "vsphere" {
  allow_unverified_ssl = "${var.allow_unverified_ssl}"
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
}

#Variable : HttpdNode01_httpd_ssl_sslproxycacertificatefile
variable "HttpdNode01_httpd_ssl_sslproxycacertificatefile" {
  type        = "string"
  description = "SSL proxy Certificate file name"
}

#Variable : HttpdNode01_httpd_ssl_sslproxycacertificatepath
variable "HttpdNode01_httpd_ssl_sslproxycacertificatepath" {
  type        = "string"
  description = "SSL proxy Certificate file path"
  default     = "/etc/httpd/ssl"
}

#Variable : HttpdNode01_httpd_ssl_sslproxycarevocationcheck
variable "HttpdNode01_httpd_ssl_sslproxycarevocationcheck" {
  type        = "string"
  description = "SSL proxy CA revocation check"
}

#Variable : HttpdNode01_httpd_ssl_sslproxycarevocationfile
variable "HttpdNode01_httpd_ssl_sslproxycarevocationfile" {
  type        = "string"
  description = "SSL proxy CA revocation file"
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

#########################################################
##### Resource : HttpdNode01
#########################################################

variable "HttpdNode01_domain" {
  type = "string"
  description = "Domain Name of virtual machine"
}

variable "HttpdNode01-os_password" {
  type        = "string"
  description = "Operating System Password for the Operating System User to access virtual machine"
}

variable "HttpdNode01_folder" {
  description = "Target vSphere folder for virtual machine"
}

variable "HttpdNode01_datacenter" {
  description = "Target vSphere datacenter for virtual machine creation"
}

variable "HttpdNode01_number_of_vcpu" {
  description = "Number of virtual CPU for the virtual machine, which is required to be a positive Integer"
  default     = "2"
}

variable "HttpdNode01_memory" {
  description = "Memory assigned to the virtual machine in megabytes. This value is required to be an increment of 1024"
  default     = "2048"
}

variable "HttpdNode01_cluster" {
  description = "Target vSphere cluster to host the virtual machine"
}

variable "HttpdNode01_dns_suffixes" {
  type        = "list"
  description = "Name resolution suffixes for the virtual network adapter"
}

variable "HttpdNode01_dns_servers" {
  type        = "list"
  description = "DNS servers for the virtual network adapter"
}

variable "HttpdNode01_network_interface_label" {
  description = "vSphere port group or network label for virtual machine's vNIC"
}

variable "HttpdNode01_ipv4_gateway" {
  description = "IPv4 gateway for vNIC configuration"
}

variable "HttpdNode01_ipv4_address" {
  description = "IPv4 address for vNIC configuration"
}

variable "HttpdNode01_ipv4_prefix_length" {
  description = "IPv4 prefix length for vNIC configuration. The value must be a number between 8 and 32"
}

variable "HttpdNode01_root_disk_datastore" {
  description = "Data store or storage cluster name for target virtual machine's disks"
}

variable "HttpdNode01_root_disk_type" {
  type        = "string"
  description = "Type of template disk volume"
  default     = "eager_zeroed"
}

variable "HttpdNode01_root_disk_controller_type" {
  type        = "string"
  description = "Type of template disk controller"
  default     = "scsi"
}

variable "HttpdNode01_root_disk_keep_on_remove" {
  type        = "string"
  description = "Delete template disk volume when the virtual machine is deleted"
  default     = "false"
}

# vsphere vm
resource "vsphere_virtual_machine" "HttpdNode01" {
  name         = "${var.HttpdNode01-name}"
  folder       = "${var.HttpdNode01_folder}"
  datacenter   = "${var.HttpdNode01_datacenter}"
  vcpu         = "${var.HttpdNode01_number_of_vcpu}"
  memory       = "${var.HttpdNode01_memory}"
  cluster      = "${var.HttpdNode01_cluster}"
  dns_suffixes = "${var.HttpdNode01_dns_suffixes}"
  dns_servers  = "${var.HttpdNode01_dns_servers}"

  network_interface {
    label              = "${var.HttpdNode01_network_interface_label}"
    ipv4_gateway       = "${var.HttpdNode01_ipv4_gateway}"
    ipv4_address       = "${var.HttpdNode01_ipv4_address}"
    ipv4_prefix_length = "${var.HttpdNode01_ipv4_prefix_length}"
  }

  disk {
    type            = "${var.HttpdNode01_root_disk_type}"
    template        = "${var.HttpdNode01-image}"
    datastore       = "${var.HttpdNode01_root_disk_datastore}"
    keep_on_remove  = "${var.HttpdNode01_root_disk_keep_on_remove}"
    controller_type = "${var.HttpdNode01_root_disk_controller_type}"
  }

  # Specify the connection
  connection {
    type     = "ssh"
    user     = "${var.HttpdNode01-os_admin_user}"
    password = "${var.HttpdNode01-os_password}"
  }

  provisioner "file" {
    destination = "HttpdNode01_add_ssh_key.sh"

    content = <<EOF
##############################################################
# Licensed Materials - Property of IBM
#
# For use by authorized subscribers only.
#
# Refer to Service Description and SLA available here:
# http://www-03.ibm.com/software/sla/sladb.nsf/sla/saas
#
# D0021ZX IBM Cloud Automation Library, Enterprise Middleware
# © Copyright IBM Corp. 2017
##############################################################
#!/bin/bash

if (( $# != 3 )); then
echo "usage: arg 1 is user, arg 2 is public key, arg3 is CAMC Public Key"
exit -1
fi

userid="$1"
ssh_key="$2"
camc_ssh_key="$3"

user_home=$(eval echo "~$userid")
user_auth_key_file=$user_home/.ssh/authorized_keys
echo "$user_auth_key_file"
if ! [ -f $user_auth_key_file ]; then
echo "$user_auth_key_file does not exist on this system, creating."
mkdir $user_home/.ssh
chmod 600 $user_home/.ssh
echo "" > $user_home/.ssh/authorized_keys
chmod 600 $user_home/.ssh/authorized_keys
else
echo "user_home : $user_home"
fi

if [[ $ssh_key = 'None' ]]; then
echo "skipping user key add, 'None' specified"
else
echo "$user_auth_key_file"
echo "$ssh_key" >> "$user_auth_key_file"
if [ $? -ne 0 ]; then
echo "failed to add to $user_auth_key_file"
exit -1
else
echo "updated $user_auth_key_file"
fi
fi

echo "$camc_ssh_key" >> "$user_auth_key_file"
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
      "sudo bash -c 'chmod +x HttpdNode01_add_ssh_key.sh'",
      "sudo bash -c './HttpdNode01_add_ssh_key.sh  \"${var.HttpdNode01-os_admin_user}\" \"${var.user_public_ssh_key}\" \"${var.ibm_pm_public_ssh_key}\">> HttpdNode01_add_ssh_key.log 2>&1'",
    ]
  }
}

#########################################################
##### Resource : HttpdNode01_chef_bootstrap_comp
#########################################################

resource "camc_bootstrap" "HttpdNode01_chef_bootstrap_comp" {
  depends_on      = ["camc_vaultitem.VaultItem", "vsphere_virtual_machine.HttpdNode01"]
  name            = "HttpdNode01_chef_bootstrap_comp"
  camc_endpoint   = "${var.ibm_pm_service}/v1/bootstrap/chef"
  access_token    = "${var.ibm_pm_access_token}"
  skip_ssl_verify = true
  trace           = true

  data = <<EOT
{
  "os_admin_user": "${var.HttpdNode01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${vsphere_virtual_machine.HttpdNode01.network_interface.0.ipv4_address}",
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
  "os_admin_user": "${var.HttpdNode01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${vsphere_virtual_machine.HttpdNode01.network_interface.0.ipv4_address}",
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
  "os_admin_user": "${var.HttpdNode01-os_admin_user}",
  "stack_id": "${random_id.stack_id.hex}",
  "environment_name": "_default",
  "host_ip": "${vsphere_virtual_machine.HttpdNode01.network_interface.0.ipv4_address}",
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
  value = "VM IP Address : ${vsphere_virtual_machine.HttpdNode01.network_interface.0.ipv4_address}"
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
