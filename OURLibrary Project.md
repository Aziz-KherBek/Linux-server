# Project Overview
This project involves setting up a comprehensive Linux-based infrastructure for a local library that aims to minimize costs by utilizing open-source software. The setup consists of a server and a workstation, both configured to support the library's daily operations with essential services and applications.
### **Objectives**

The primary objectives of this project are:

- **Set up a Linux-based server** to run essential network services: DHCP, DNS, and Nginx web server.
- **Configure the server** to handle dynamic IP assignment for internal devices, resolve domain names for internal resources, and host a local webpage.
- **Automate backup processes** using `cron` to ensure regular and secure backups of key service configurations.
- **Enable remote management** of the server through SSH, allowing for easy troubleshooting and configuration updates.
- **Provide a workstation** with the necessary applications for daily tasks, such as LibreOffice, Gimp, and Mullvad browser, all configured with automatic IP addressing from the server’s DHCP service.
### Software and hardware used
In this project, the following components were used to set up the library’s IT infrastructure:

1. **Virtualization Platform**:
    
    - **VirtualBox**: Used to create and manage virtual machines (VMs) that simulate the library’s server and workstation environment.
2. **Server VM**:
    
    - **VM1: Library Server (Ubuntu Server)**: A virtual machine running **Ubuntu Server**, configured with the required services (DHCP, DNS, and Nginx web server).
3. **Workstation VM**:
    
    - **VM2: Library Workstation (Ubuntu Desktop)**: A virtual machine running **Ubuntu Desktop**, equipped with essential applications such as **LibreOffice**, **Gimp**, and **Mullvad Browser**.
4. **Services and Software**:
    
    - **ISC DHCP Server**: Used for providing dynamic IP addressing to the internal network.
    - **BIND DNS Server**: Used for resolving internal network resources and forwarding external DNS queries.
    - **Nginx**: Configured as a web server to host a local webpage for the library.
    - **Cron**: Used for scheduling weekly backups of configuration files.
    - **SSH**: For remote management of the server. 
5. **Backup System**:
    
    - **rsync** (Optional): For placing backups on a separate partition, mounted only during the backup process.


---
# Configurations
## Server Configuration

---
### DHCP Server Configuration

- **Objective**: Provide dynamic IP addressing for the internal network.
- **Package Installed**: `isc-dhcp-server`
```
sudo apt-get install isc-dhcp-server // Install `isc-dhcp-server`
```
Configure the `/etc/dhcp/dhcpd.conf` file.
This file defines how the DHCP server will allocate IP addresses and configure other network settings (like DNS and default gateway) to clients on the network.
```
sudo vim  /etc/dhcp/dhcpd.conf
```
our configuration:
```
subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.100 192.168.1.200; # Define the range of IP addresses to be assigned
  option routers 192.168.1.1; # Default gateway (router)
 option subnet-mask 255.255.255.0; 
  option domain-name "example.com"; # Domain name for clients
  option domain-name-servers 192.168.1.1;
}

```

Configure the `/etc/default/isc-dhcp-server` file:
 This tells the ISC DHCP server to listen for **IPv4 DHCP requests** on the `enp0s3` interface (which is typically the interface connected to your internal network or LAN).
 ```
 sudo nano /etc/default/isc-dhcp-server
```
The configuration:
```
INTERFACESv4="enp0s3"
```
Restart the DHCP service:
```
sudo systemctl restart isc-dhcp-server
```

**Testing**: Show how you verified that DHCP was assigning IP addresses to the workstation
```
 sudo systemctl status isc-dhcp-server
```
Normally you should see everything is activated

In addition to configuring the **`/etc/dhcp/dhcpd.conf`** file for the DHCP server, you'll also need to configure **Netplan** (for modern versions of Ubuntu) and the network interfaces to ensure proper network connectivity for your system.

#### **Configuring Netplan:**

Netplan is the default network configuration tool for Ubuntu 18.04 and later. Netplan uses YAML files to define network settings, and you typically find these configuration files in `/etc/netplan/`.
```
sudo nano /etc/netplan/50-cloud-init.yaml
```
Our configuration:
```
network: 
	version: 2 
	ethernets: 
		enp0s3: //this is for our internal network connected to the worksation
			dhcp4: false // this is false so we assign static ip to the server
			addresses: 
			  - 192.168.1.1/24 // our static ip (DHCP & DNS )
			  - 192.168.1.2/24 // static ip for WEB SERVER 
		enp0s8 : //this is connected to the internet so the worksation has internet
			dhcp4 :true //this is true so we can get an ip to the internet
```
**Apply the configuration**: to apply the new configuration
```
   sudo netplan apply
```



----
### DNS Server Configuration

- **Objective**: Resolve internal resources and redirect external traffic.
- **Package Installed**: `bind9`
```
sudo apt-get install bind9
```
 ### Modify configuration files to add the internal domain and configure forwarding:
 
 ### Update `/etc/bind/named.conf.local` for the Internal Domain
```
sudo nano /etc/bind/named.conf.local
``` 
Our configuration:
```
zone "ourlibrary.com" IN {
      type master;
      file "/etc/bind/forward.ourlibrary.com.db"; // Path to the zone file
      allow-update { none; }; 
};

zone "1.168.192.in-addr.arpa" IN {
     type master; 
     file "/etc/bind/reverse.ourlibrary.com.db";
     allow-update { none; }; 
}; 

```
Explanation :
- **zone "ourlibrary.com" IN { ... }**
    - Defines a **zone** for the domain `ourlibrary.com`, which is your internal domain.
    - **IN** indicates the Internet class of the DNS, which is standard for most DNS configurations.
- **type master;**
    - Specifies that this server is the **master** (primary) DNS server for the `ourlibrary.com` domain.
    - As the master, this server has the authoritative zone file for `ourlibrary.com`.
- **file "/etc/bind/forward.ourlibrary.com.db";**
    - This is the path to the **zone file** for `ourlibrary.com`, where the forward (normal) DNS records for your domain are defined.
    - This file contains mappings of domain names (like `www.ourlibrary.com`) to IP addresses.
- **allow-update { none; };**
    - Restricts dynamic DNS updates to this zone, meaning no clients can modify the DNS records in `ourlibrary.com`.
    - `none` is specified here to enhance security by ensuring no unauthorized changes to DNS records.
- **zone "1.168.192.in-addr.arpa" IN { ... }**
    
    - Defines a **reverse DNS zone** for the IP address range `192.168.1.x`.
    - `in-addr.arpa` is the domain used for **reverse DNS lookup** zones. Here, `1.168.192` is the reverse format of `192.168.1`.
    - This setup allows reverse lookups, meaning you can resolve IP addresses in the `192.168.1.x` range to hostnames.
- **file "/etc/bind/reverse.ourlibrary.com.db";**
    
    - Specifies the path to the **reverse zone file** for this IP range.
    - This file will contain mappings of IP addresses (like `192.168.1.1`) to hostnames (like `ourlibrary.com`).
- **allow-update { none; };**
    
    - Similarly to the forward zone, this setting prevents dynamic DNS updates to the reverse zone, enhancing security.
#### Create the Zone File for the Internal Domain
##### **Create the Forward Zone File** (`/etc/bind/forward.ourlibrary.com.db`)
This file will map domain names like `www.ourlibrary.com` to IP addresses.
Open the forward zone file for editing:
```
sudo nano /etc/bind/forward.ourlibrary.com.db
```
Add the following content to the file:
```
;
; BIND data file 
;
$TTL	604800
@	IN	SOA	ns1.ourlibrary.com. root.ns1.ourlibrary.com. (
			      3		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL

; Nameserver
@      IN      NS       ns1.ourlibrary.com.

; IP address of Name Server

ns1    IN      A        192.168.1.1


; A Records  Hostnales to IP address
#@	IN	A	192.168.1.2
www	IN	A	192.168.1.2


```
- **`@ IN SOA ns1.ourlibrary.com. root.ns1.ourlibrary.com.`**:
    
    - This line specifies the **Start of Authority (SOA)** record, which is required in every zone file. It indicates that `ns1.ourlibrary.com` is the authoritative DNS server for this zone.
    - The contact email is `root@ns1.ourlibrary.com`, where the first `.` separates the username and domain (replacing the `@` symbol).
- **NS Record**: Defines `ns1.ourlibrary.com` as the **nameserver** for the `ourlibrary.com` zone.
- The `@` symbol represents the root of the domain (in this case, `ourlibrary.com`), so this line essentially says "ourlibrary.com’s nameserver is `ns1.ourlibrary.com`."
- **A Record for `ns1`**: Maps the hostname `ns1` to the IP address `192.168.1.1`.
- This tells DNS clients that `ns1.ourlibrary.com` can be reached at `192.168.1.1`.
- **Commented Line**: The line `#@ IN A 192.168.1.2` is commented out (indicated by `#`), so it is ignored by the server.
- **A Record for `www`**: Maps the hostname `www.ourlibrary.com` to `192.168.1.2`.
    - This allows users to access `www.ourlibrary.com` using the IP address `192.168.1.2`.
##### **Create the Reverse Zone File** (`/etc/bind/reverse.ourlibrary.com.db`)
This file will map IP addresses in the `192.168.1.x` range to hostnames.
Open the reverse zone file for editing:
```
sudo nano /etc/bind/reverse.ourlibrary.com.db
```
Our configuration:
```
;
; BIND reverse data file
;
$TTL	604800
@	IN	SOA	ourlibrary.com. root.ourlibrary.com. (
			      3		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL

; Name server information
@	IN	NS	ns1.ourlibrary.com.
ns1	IN	A	192.168.1.1

; Reverse lookup for Name Server

1       IN      PTR     ns1.ourlibrary.com.


; PTR Record IP address to Hostname

2      IN        PTR    www.ourlibrary.com.

```
**`@ IN SOA ns1.ourlibrary.com. root.ns1.ourlibrary.com.`**:

- This line specifies the **Start of Authority (SOA)** record, which is required in every zone file. It indicates that `ns1.ourlibrary.com` is the authoritative DNS server for this zone.
- The contact email is `root@ns1.ourlibrary.com`, where the first `.` separates the username and domain (replacing the `@` symbol).

-**NS Record**: Defines `ns1.ourlibrary.com` as the **nameserver** for the `ourlibrary.com` zone.
The `@` symbol represents the root of the domain (in this case, `ourlibrary.com`), so this line essentially says "ourlibrary.com’s nameserver is `ns1.ourlibrary.com`."
 **A Record for `ns1`**: Maps the hostname `ns1` to the IP address `192.168.1.1`.
 This tells DNS clients that `ns1.ourlibrary.com` can be reached at `192.168.1.1`.
 - **A Record for `www`**: Maps the hostname `www.ourlibrary.com` to `192.168.1.2`.
    - This allows users to access `www.ourlibrary.com` using the IP address `192.168.1.2`.

#### Configure Forwarding for External Domains
To configure DNS forwarding, open `/etc/bind/named.conf.options` and add your forwarders. Forwarders are external DNS servers (like Quad9 or Google DNS) that will resolve any domain that is not part of `ourlibrary.com`.
```
sudo nano /etc/bind/named.conf.options
```
Inside the `options` block, add the following:
```
options {
 forwarders { 9.9.9.9; // primary
              149.112.112.112; //secondary
              
	 };
	 dnssec-validation auto;

	listen-on-v6 { any; };
	 };

```
- **`forwarders { 9.9.9.9; 149.112.112.112; };`**:
    
    - **Forwarders**: Specifies upstream DNS servers to which queries should be forwarded if they can't be resolved locally. In this case:
        - **`9.9.9.9`** is the **primary** forwarder (Quad9 DNS).
        - **`149.112.112.112`** is the **secondary** forwarder (also a Quad9 DNS server).
    - Forwarding improves response times by relying on external servers (often faster and more secure) to handle requests for domains not in the local zone files.
- **`dnssec-validation auto;`**:
    
    - **DNSSEC (DNS Security Extensions)**: `auto` enables DNSSEC validation if the upstream server supports it. DNSSEC adds security by ensuring the DNS responses have not been tampered with in transit.
    - Setting this to `auto` lets BIND validate responses with DNSSEC if available, enhancing security without requiring manual setup.
- **`listen-on-v6 { any; };`**:
    
    - **IPv6 Listening**: Configures BIND to listen on all available IPv6 interfaces.
    - `any` allows BIND to handle queries over IPv6, which is essential for compatibility with IPv6 networks.
#### Restart BIND
After making these changes, restart the BIND service to apply the configuration:
```
sudo systemctl restart bind9
```

#### Web Server Configuration
- **Objective**: Host a simple webpage for the library.
- **Package Installed**: `nginx`
Install Nginx:
```
sudo apt-get install nginx
```
Configure the server block in `/etc/nginx/sites-available/default`.
```
sudo nano /etc/nginx/sites-available/default
```
Our configuration:
```
server {
 listen 192.168.1.2:80;
 server_name ourlibrary.com;

 root /var/www/ourlibrary.com;
 index index.html; 
 
 location / {
   try_files $uri $uri/ =404;
 }
} 
```
**`listen 192.168.1.2:80;`**
- This tells Nginx to listen on the specific IP address `192.168.1.2` and port `80` (the standard HTTP port). It ensures that the server only responds to requests sent to this IP address on port 80.

If you want the server to respond on all interfaces (not just `192.168.1.2`), you can simply use `listen 80;` or `listen [::]:80;` for IPv6 compatibility.

 **`server_name ourlibrary.com;`**
- This directive specifies the domain name for which this server block is responsible. It will respond to requests for `ourlibrary.com` but will not handle requests for other domains unless specified in other server blocks.

3. **`root /var/www/ourlibrary.com;`**
- Defines the document root (the directory where the website files are stored). Nginx will look for files to serve in this directory when handling requests.

Make sure that `/var/www/ourlibrary.com` exists and contains your website files (e.g., `index.html`).

 4. **`index index.html;`**
- Specifies the default file that Nginx should serve when a request is made to the root directory `/`. If the user accesses `http://ourlibrary.com/`, Nginx will serve the `index.html` file from the root directory.

 5. **`location / { try_files $uri $uri/ =404; }`**
- This block handles requests to the root directory and subdirectories.
    - `try_files $uri $uri/ =404;`: This tells Nginx to check if the requested URI corresponds to an actual file or directory. If it does, Nginx will serve the file. If not, it will return a `404 Not Found` error.
##### Final Check & Activation

1. Ensure the directory `/var/www/ourlibrary.com` exists and contains the necessary website files (like `index.html`).
    
2. Save the configuration file.
    
3. Test the configuration:
```
sudo nginx -t
```
4. If the test is successful, restart Nginx to apply the changes:
```
sudo systemctl restart nginx
```

**Testing**: Open the server IP or internal domain on the workstation browser to ensure the webpage loads.


---
### Enabling IP Forwarding for Internet Access on the Workstation via Server
##### Enable IP Forwarding on the Server

**Edit the sysctl configuration** to enable IP forwarding:
    
    Open the sysctl configuration file:
 ```
sudo nano /etc/sysctl.conf
```
Find and uncomment (or add) the following line to enable IP forwarding:
```
net.ipv4.ip_forward = 1
```
Apply the changes:
```
sudo sysctl -p
```
This will enable IP forwarding, allowing your server to forward traffic between its internal network (workstation) and the external network (internet).

##### Configure NAT (Network Address Translation):
Since your server is acting as a gateway, you need to set up NAT to forward traffic from the internal network (workstation) to the external network (internet). Here's how:

Use **iptables** to enable NAT. Run the following command on the server:
```
sudo iptables -t nat -A POSTROUTING -o <NAT interface> -j MASQUERADE
```
Replace the NAT interface with the name of Your NAT adapter (you should activated on VM box before starting the server)

Allowing forwarding from internal network to the NAT network :
```
sudo iptables -A FORWARD -i <internal interface> - o <NAT interface> -j ACCEPT
```
##### Explanation of the Command:

- **`-A FORWARD`**: This adds a rule to the `FORWARD` chain in `iptables`. The `FORWARD` chain is responsible for controlling how packets are forwarded between different network interfaces.
    
- **`-i <internal interface>`**: Specifies the input interface for the packets (traffic coming from the internal network). Replace `<internal interface>` with the name of the internal network interface on your server, such as `enp0s3`.
    
- **`-o <NAT interface>`**: Specifies the output interface for the packets (traffic going out to the internet). Replace `<NAT interface>` with the name of your external network interface on the server, such as `enp0s8`.
    
- **`-j ACCEPT`**: This tells `iptables` to **accept** the packets matching this rule. Essentially, this means the server will allow traffic to flow from the internal network to the external interface.

```
sudo iptables -A FORWARD -i <NAT interface> -o <internal interface> -m state --state RELATED, ESTABLISHED -j ACCEPT
```
##### Explanation of the Command:

- **`-A FORWARD`**: This adds a rule to the `FORWARD` chain, which is used for packets that are being routed through the server (from one network interface to another).
    
- **`-i <NAT interface>
- `**: Specifies the input interface (traffic coming from the **external** network). Replace `NAT interface with your external network interface

- **`-o` internal interface ** :  Specifies the output interface (traffic going to the **internal** network). Replace internal interface with your internal network interface>
    
- **`-m state` --state RELATED,ESTABLISHED**: This condition ensures that only packets from **established connections** or **related connections** (such as replies to outgoing traffic) are forwarded. The `RELATED` state refers to packets that are part of a new connection, but related to an existing one (e.g., FTP data transfer after an FTP connection is established), while the `ESTABLISHED` state refers to packets that are part of an already-established connection (e.g., the reply to an HTTP request).
    
- **`-j ACCEPT`**: This tells `iptables` to **accept** packets matching the rule, allowing them to be forwarded.



To make the changes persistent after a reboot, save the iptables configuration:
```
sudo apt install iptables-persistent
sudo netfilter-persistent save

```


---
### Install SSH Server
#### Configure
We install `openssh-server` package on our server and then edit its configuration file located on `/etc/ssh/sshd_config`.
There, we implement severals option to enhance security : 
 - `Port 1337`:
    Changing the default SSH port reduce the amount of attacks ; they often occurs using automated port scan but mostly scan for common ports. 
    Another benefit being that it makes malicious attempts to connect on default SSH port more obvious on logs, therefore easier to detect. 
    **Configure firewall according to the defined port.** 
- `AllowUsers becode`:
    Restrict which users can access to the server using SSH, reducing the surface of attack. 
- `LogInGraceTime 2m` : 
    Amount of time to authenticate after initiating an SSH connection before it close.
- `PermitRootLogin no`: 
    Deactivate root access throught SSH connection. With proper configuration of `sudo`rights, reduce surface of attacks. 
-  `StrictModes yes`:
    Deny access of the user if files permissions on certain sensitives files  (SSH related on user's home directory) are too open - which could potentially made them accessible by others users on the server. 
- `MaxAuthTries 3`:
    Set a limit of failed authentification before the connection get closed. Serve as a small protection again brute force attacks. 
-  `PubkeyAuthentication yes`:
    Enable use of public key for authentification. 
- `PasswordAuthentication no`: 
    Disable use of password. Combine with `PubkeyAuthentication`, its eliminate the risks of brute force attacks since only ssh keys are used to login. 

When modification are made, we can save the file and restart the service using :
     `sudo systemctl restart ssh`

#### Set up SSH key based authentication

We need - on **CLIENT** machine, **NOT the server** - to generate a ssh key pair :
     `ssh-keygen -t rsa -b 4096 -C "your_email@example.com"`
 Then we can copy the public key on the server : 
     `ssh-copy-id -i ~/.ssh/id_rsa.pub yourusername@server_ip`


---

---
### Automation 

We implement a weekly backup for the server configuration files. They will be gathered into one single archive file, which is then saved on a separate disk. 
Theses scripts will be placed in `/usr/local/sbin` directory regarding the Unix systems convention : /sbin directory being for "system" binaries, backup scripts fits perfectly this purpose. 

#### Scripts

In the first place, we need to mount the partition it will be saved on :

```
#!/bin/bash

# Define the device and mount point
DEVICE="/dev/sdb1"
MOUNT_POINT="/mnt"

# Check if the device is already mounted at the specified mount point
if mountpoint -q "$MOUNT_POINT"; then
    echo "$DEVICE is already mounted at $MOUNT_POINT."
else
    echo "Mounting $DEVICE to $MOUNT_POINT..."
    sudo mount "$DEVICE" "$MOUNT_POINT"
    
    # Check if the mount was successful
    if [ $? -eq 0 ]; then
        echo "$DEVICE successfully mounted to $MOUNT_POINT."
    else
        echo "Failed to mount $DEVICE to $MOUNT_POINT."
    fi
fi
```
 
Then, we gathered all files and compress them in one single archive file : 

```

#!/bin/bash

# Define backup directory
BACKUP_DIR="/var/backups"
TIMESTAMP=$(date +'%Y-%m-%d')
BACKUP_PATH="$BACKUP_DIR/backup_$TIMESTAMP"

# Define the backup archive filename
BACKUP_ARCHIVE="$BACKUP_PATH.tar.gz"

# Define directories and files to back up
DHCP_CONFIG_DIR="/etc/dhcp"
DHCP_CONFIG="/etc/dhcp/dhcpd.conf"
DHCP_ISC_CONFIG="/etc/default/isc-dhcp-server"
NETPLAN_CONFIG="/etc/netplan/50-cloud-init.yaml"
NETPLAN_CONFIG_DIR="/etc/netplan"
SYSCTL_CONFIG="/etc/sysctl.conf"
IPTABLES_CONFIG="/etc/iptables/rules.v4"
IPTABLES_CONFIG_DIR="/etc/iptables"
DNS_CONFIG_DIR="/etc/bind"
NGINX_CONFIG_DIR="/etc/nginx"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"

# Check if backup directory exists; if not, create it
if [ ! -d "$BACKUP_DIR" ]; then
    echo "Backup directory does not exist. Creating it..."
    mkdir -p "$BACKUP_DIR"
fi

# Create a timestamped backup directory (temporarily used for organizing files)
mkdir -p "$BACKUP_PATH"

# Backup DHCP config
if [ -d "$DHCP_CONFIG_DIR" ]; then
    echo "Backing up DHCP configuration..."
    mkdir -p "$BACKUP_PATH/dhcp"
    cp "$DHCP_CONFIG" "$BACKUP_PATH/dhcp/dhcpd.conf"
    cp "$DHCP_ISC_CONFIG" "$BACKUP_PATH/dhcp/isc-dhcp-server"
else
    echo "DHCP configuration file not found!"
fi

# Backup netplan
if [ -d "$NETPLAN_CONFIG_DIR" ]; then
    echo "Backing up netplan..."
    mkdir -p "$BACKUP_PATH/netplan"
    cp "$NETPLAN_CONFIG" "$BACKUP_PATH/netplan/50-cloud-init.yaml"
else
    echo "Netplan not found!"
fi

# Backup iptables
if [ -d "$IPTABLES_CONFIG_DIR" ]; then
    echo "Backing up iptables..."
    mkdir -p "$BACKUP_PATH/iptables"
    cp "$IPTABLES_CONFIG" "$BACKUP_PATH/iptables/rules.v4"
else
    echo "Iptables not found!"
fi

# Backup systctl
if [ -f "$SYSCTL_CONFIG" ]; then
    echo "Backing up sysctl..."
    cp "$SYSCTL_CONFIG" "$BACKUP_PATH/sysctl.conf"
else
    echo "sysctl not found!"
fi

# Backup DNS config (for BIND)
if [ -d "$DNS_CONFIG_DIR" ]; then
    echo "Backing up DNS configuration..."
    cp -r "$DNS_CONFIG_DIR" "$BACKUP_PATH/bind"
else
    echo "DNS configuration file not found!"
fi
# Backup Nginx config
if [ -d "$NGINX_CONFIG_DIR" ]; then
    echo "Backing up Nginx configuration..."
    cp -r "$NGINX_CONFIG_DIR" "$BACKUP_PATH/nginx"
    
    if [ -d "$NGINX_SITES_AVAILABLE" ]; then
        cp -r "$NGINX_SITES_AVAILABLE" "$BACKUP_PATH/nginx/sites-available"
    fi
    if [ -d "$NGINX_SITES_ENABLED" ]; then
        cp -r "$NGINX_SITES_ENABLED" "$BACKUP_PATH/nginx/sites-enabled"
    fi
else
    echo "Nginx configuration directory not found!"
fi

# Create a compressed tarball (gzip) of the backup directory
echo "Compressing backup into a single archive..."
tar -czf "$BACKUP_ARCHIVE" -C "$BACKUP_DIR" "backup_$TIMESTAMP"

# Print success message
echo "Backup completed successfully. Archive stored at $BACKUP_ARCHIVE."

# Clean up the temporary backup directory after creating the archive
rm -rf "$BACKUP_PATH"
```

Once the archive created, we copy it on a separate partition, located on a separate disk. 

```
#!/bin/bash

# Define source and destination directories
SOURCE="/var/backups"
DESTINATION="/mnt"

# Define log file for output
LOG_FILE="/var/log/backup_rsync.log"

# Timestamp for log entries
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Ensure that the source and destination directories exist
if [ ! -d "$SOURCE" ]; then
  echo "$TIMESTAMP: ERROR - Source directory $SOURCE does not exist." >> "$LOG_FILE"
  exit 1
fi

if [ ! -d "$DESTINATION" ]; then
  echo "$TIMESTAMP: ERROR - Destination directory $DESTINATION does not exist." >> "$LOG_FILE"
  exit 1
fi

# Perform rsync from source to destination
echo "$TIMESTAMP: Starting backup from $SOURCE to $DESTINATION..." >> "$LOG_FILE"
rsync -av --delete "$SOURCE/" "$DESTINATION/" >> "$LOG_FILE" 2>&1

# Check if the rsync command was successful
if [ $? -eq 0 ]; then
  echo "$TIMESTAMP: Backup completed successfully." >> "$LOG_FILE"
else
  echo "$TIMESTAMP: ERROR - Backup failed." >> "$LOG_FILE"
fi
```
Then we can unmount the partition:

```
#!/bin/bash

# Define the device and mount point
DEVICE="/dev/sdb1"
MOUNT_POINT="/mnt"

# Check if the device is mounted at the specified mount point
if mountpoint -q "$MOUNT_POINT"; then
    echo "Unmounting $DEVICE from $MOUNT_POINT..."
    sudo umount "$DEVICE"
    
    # Check if the unmount was successful
    if [ $? -eq 0 ]; then
        echo "$DEVICE successfully unmounted from $MOUNT_POINT."
    else
        echo "Failed to unmount $DEVICE from $MOUNT_POINT."
    fi
else
    echo "$DEVICE is not mounted at $MOUNT_POINT."
fi

```

#### Cron
To schedule weekly those scripts, we set up cronjobs for the system to automate the execution of theses scripts.
Using `crontab -e`we schedule them to execute every friday at 8PM : 
```
# Run the first job at 8:00 PM every Friday
0 20 * * 5 /usr/local/bin/mount_sdb1.sh

# Run the second job at 8:01 PM every Friday
1 20 * * 5 /usr/local/bin/weekly_backup.sh

# Run the third job at 8:02 PM every Friday
2 20 * * 5 /usr/local/bin/rsync.sh

# Run the third job at 8:03 PM every Friday
3 20 * * 5 /usr/local/bin/unmount_sdb1.sh
```