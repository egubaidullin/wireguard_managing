# WireGuard Managing Script

This script automates the setup and management of WireGuard VPN configurations.

## Features

- Installs WireGuard if not already installed
- Generates server and client configuration files
- Manages user IP address assignments

## Background

Initially, I used [angristan/wireguard-install](https://github.com/angristan/wireguard-install) for installing WireGuard. To manage users, I created my own script to modify a text file and deploy from Git. Later, I decided to integrate WireGuard installation into my script for a more seamless, all-in-one solution. This script now provides a complete solution for WireGuard setup and user management.

## Prerequisites

- Python 3.x
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
   - Add users to the user_list.txt file must be located in the `SCRIPT_DIR` directory. Each user should be on a new line.
   - 
4.  **Make the Script Executable**:
   - Ensure the script is executable by running: `chmod +x wireguard_config_script.py`

5.  **Run the Script**:
   After adding/removing users, run the script to generate their configurations and apply the changes.
   - Execute the script: `sudo ./wireguard_config_script.py`

## Configuration

- Configuration files and user details are stored as specified in the variables `USER_LIST`, `CONFIG_DIR`, and `IPADDR_MAP`.
- The main WireGuard configuration file is located at `/etc/wireguard/wg0.conf`.
- Parameters for the server setup are stored in `/etc/wireguard/params`.
- User configurations are saved in the directory specified by `CONFIG_DIR`.

## Notes

- Ensure you have sudo privileges to run the script and manage system configurations.
- The script assumes a Debian-based system for package management. Adjustments may be needed for other distributions.
