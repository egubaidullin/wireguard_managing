# WireGuard Configuration Script

This script automates the process of setting up and managing WireGuard VPN users. It simplifies the configuration and deployment of WireGuard for your organization.

## Configuration

The script uses the following configuration variables:

- `WG_CONF`: Path to the WireGuard configuration file (`wg0.conf`).
- `USER_LIST`: Path to the text file containing the list of users.
- `CONFIG_DIR`: Directory where user configurations will be stored (individual files for each user).
- `IPADDR_MAP`: JSON file mapping usernames to IP addresses and keys.
- `SERVER_PUBLIC_KEY`: Public key of the WireGuard server (replace with your actual server's public key).
- `ENDPOINT`: Endpoint of the WireGuard server (IP and port).
- `DNS`: DNS servers to be used by the VPN clients.
- `SUBNET`: Subnet used for the VPN network.
- `CLIENT_ADDRESS_START`: Starting IP address for clients.

## Usage

1. **Prerequisites:**
   - Ensure that WireGuard is installed on your system.
   - Run the script with root privileges (`sudo`).

2. **User List:**
   - Edit the `USER_LIST` file to include the usernames you want to configure.

3. **Running the Script:**
   - Execute the Python script:
     ```bash
     sudo ./wireguard_config_script.py
     ```

## How the Script Works

1. **Backup:**
   - The script creates a backup of the original `wg0.conf` if it doesn't exist.

2. **User Configuration:**
   - For each user in the `USER_LIST`:
     - Generates private and public keys.
     - Creates individual WireGuard configuration files.
     - Updates the `wg0.conf` with new user configurations.

3. **WireGuard Interface:**
   - The script applies the changes to the WireGuard interface.

## Generating Client Configurations

- After running the script, individual configuration files for each user will be created in the `CONFIG_DIR` directory.
- These files contain the necessary settings for each client, including private keys, IP addresses, and server details.

## Creating QR Codes

- If you want to generate QR codes for easy client setup, follow these steps:
  1. Install `qrencode` on your system (if not already installed).
     ```bash
     sudo apt-get install qrencode
     ```
  2. Generate a QR code for a specific user's configuration file (e.g., `alice.conf`):
     ```bash
     qrencode -t ansiutf8 < /path_to_CONFIG_DIR/alice.conf
     ```
     This command will display the QR code in the terminal. Users can scan this code with their mobile devices to import the WireGuard configuration.

## Example Configuration

Below is an example of a client configuration file named `alice.conf` that would be generated for a user named Alice. This file includes all the necessary details that Alice would need to connect to the WireGuard VPN.

```ini
[Interface]
PrivateKey = <Alice's Private Key>
Address = 10.66.66.2/32
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = <Server's Public Key>
PresharedKey = <Alice's Preshared Key>
Endpoint = <Server's Endpoint IP>:<Server's Endpoint Port>
AllowedIPs = 0.0.0.0/0, ::/0
```

## Running the Script

Keep the private key secure and do not share it.
Customize the script according to your organization’s needs.
