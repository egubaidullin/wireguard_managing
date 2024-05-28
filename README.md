# WireGuard Configuration Script

This script automates the process of setting up and managing WireGuard VPN users.

## Configuration

The script uses the following configuration variables:

- `WG_CONF`: Path to the WireGuard configuration file.
- `USER_LIST`: Path to the text file containing the list of users.
- `CONFIG_DIR`: Directory where user configurations will be stored.
- `IPADDR_MAP`: JSON file mapping usernames to IP addresses and keys.
- `SERVER_PUBLIC_KEY`: Public key of the WireGuard server.
- `ENDPOINT`: Endpoint of the WireGuard server (IP and port).
- `DNS`: DNS servers to be used by the VPN clients.
- `SUBNET`: Subnet used for the VPN network.
- `CLIENT_ADDRESS_START`: Starting IP address for clients.

## Usage

To use the script, ensure that the `USER_LIST` file contains the list of users you want to configure. The script will:

- Create a backup of the original `wg0.conf` if it doesn't exist.
- Generate private and public keys for new users.
- Create individual WireGuard configuration files for each user.
- Update the `wg0.conf` with the new user configurations.
- Apply the changes to the WireGuard interface.

## Requirements

- WireGuard must be installed on the system.
- The script must be run with root privileges.

## Running the Script

To run the script, simply execute the Python file:

```bash
sudo ./wireguard_config_script.py
