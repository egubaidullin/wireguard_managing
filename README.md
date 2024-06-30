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
   - Download directly: [wireguard_config_script.py](https://github.com/egubaidullin/wireguard_managing/blob/main/wireguard_config_script.py)

2. **Configure the Script**:
   - Open the script and set the following variables to appropriate values:
     - `USER_LIST`: Path to the file where user details are stored.
     - `CONFIG_DIR`: Directory where configuration files will be generated and stored.
     - `IPADDR_MAP`: Path to the file mapping user IP addresses.

   Example:
   ```python
   USER_LIST = '/path/to/user_list.txt'
   CONFIG_DIR = '/path/to/config_dir'
   IPADDR_MAP = '/path/to/ipaddr_map.txt'
   ```

3. **Run the Script**:
   - Make the script executable: `chmod +x wireguard_config_script.py`
   - Execute the script: `sudo ./wireguard_config_script.py`

## Configuration

- Configuration files and user details are stored as specified in the variables `USER_LIST`, `CONFIG_DIR`, and `IPADDR_MAP`.
- The main WireGuard configuration file is located at `/etc/wireguard/wg0.conf`.
- Parameters for the server setup are stored in `/etc/wireguard/params`.
- User configurations are saved in the directory specified by `CONFIG_DIR`.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
