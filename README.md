# WireGuard Management Script

This script automates the setup and management of WireGuard VPN configurations.

## Features

- Installs WireGuard if not already installed
- Generates server and client configuration files
- Manages user IP address assignments

## Background

Initially, I used [angristan/wireguard-install](https://github.com/angristan/wireguard-install) for installing WireGuard. To manage users, I created my own script to modify a text file and deploy from Git. Later, I decided to integrate WireGuard installation into my script for a more seamless, all-in-one solution. This script now provides a complete solution for WireGuard setup and user management.

## Prerequisites

- Python 3.x
- Install `apt install python3-pip`
- `requests` library: Install via `pip install requests`
- `netifaces` library: Install via `pip install netifaces`
- Ensure you have sudo or root privileges

## Usage

1. **Download the Script**:
- Download the script directly from the repository using the following command: `wget https://raw.githubusercontent.com/egubaidullin/wireguard_managing/main/wireguard_config_script.py`

2. **Configure the Script**:
The `SCRIPT_DIR` variable is crucial as it defines the directory where the script is located. This directory will also contain all related data, including:

- **User Configuration Files**: Where individual user settings are stored.
- **Auxiliary Script Files**: Any additional files the script requires to function properly.

Set this variable to the path where you wish to store these items: `SCRIPT_DIR = '/path/to/script'`

3. **Add Users**:
   - Add users to the `user_list.txt` file located in the `SCRIPT_DIR` directory. Each user should be on a new line.

4. **Make the Script Executable**:
   - Ensure the script is executable by running: `chmod +x wireguard_config_script.py`

5. **Run the Script**:
   After adding/removing users, run the script to generate their configurations and apply the changes.
   - Execute the script: `sudo ./wireguard_config_script.py`

## Configuration

- Configuration files and user details are stored as specified in the variables `USER_LIST`, `CONFIG_DIR`, and `IPADDR_MAP`.
- The main WireGuard configuration file is located at `/etc/wireguard/wg0.conf`.
- Parameters for the server setup are stored in `/etc/wireguard/params`.
- User configurations are saved in the directory specified by `CONFIG_DIR`.

### Default Parameters

The script uses default parameters for the WireGuard setup. These include:

- `SERVER_WG_NIC`: Network interface for the WireGuard server (default: `wg0`)
- `SERVER_WG_IPV4`: IPv4 address for the WireGuard server (default: `10.66.66.1`)
- `SERVER_WG_IPV4_MASK`: Subnet mask for the IPv4 address (default: `24`)
- `SERVER_WG_IPV6`: IPv6 address for the WireGuard server (default: `fd42:42:42::1`)
- `SERVER_WG_IPV6_MASK`: Subnet mask for the IPv6 address (default: `64`)
- `SERVER_PORT`: Port for the WireGuard server (default: `51820`)
- `CLIENT_DNS_1` and `CLIENT_DNS_2`: DNS servers for clients (default: `1.1.1.1` and `1.0.0.1`)

example:
```
[params]
SERVER_PUB_IP=xx.xx.xx.xx
SERVER_PUB_NIC=eth0
SERVER_WG_NIC=wg0
SERVER_WG_IPV4=10.66.66.1
SERVER_WG_IPV6=fd42:42:42::1
SERVER_WG_IPV4_MASK=24
SERVER_WG_IPV6_MASK=64 
SERVER_PORT=51559
SERVER_PRIV_KEY=46TRObSvKZgABPzjGSj2467+emPP1KsY/lOorBoFJ1I=
SERVER_PUB_KEY=TGt/uperjsvvuP43ZVB7q44pl4sPxNnjOqnom1zFMzHE=
CLIENT_DNS_1=1.1.1.1
CLIENT_DNS_2=1.0.0.1
ALLOWED_IPS=0.0.0.0/0,::/0
```

### Customizing Parameters

If you wish to change any of the default parameters, you can do so by editing the `/etc/wireguard/params` file. This file uses INI format, and you can modify the values under the `[params]` section.

## Notes

- Ensure you have sudo privileges to run the script and manage system configurations.
- The script assumes a Debian-based system for package management. Adjustments may be needed for other distributions.
