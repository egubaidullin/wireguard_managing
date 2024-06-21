# WireGuard User Management Script

This Python script automates the configuration and management of WireGuard VPN servers and clients. It dynamically reads parameters from a configuration file, generates client configurations, and updates the server configuration accordingly.

## Features

- **Dynamic Parameter Loading**: Reads server parameters from `/etc/wireguard/params` to configure the WireGuard server and clients.
- **Client Configuration Generation**: Automatically generates configuration files for each client listed in `user_list.txt`.
- **IP Address Management**: Manages IP address assignments for clients, ensuring unique and sequential allocations.
- **Key Generation**: Generates private, public, and preshared keys for each client.
- **Configuration Updates**: Updates the WireGuard server configuration file (`wg0.conf`) with the latest parameters and peer configurations.
- **Backup and Restore**: Backs up the original `wg0.conf` file before making changes and restores it if needed.

## Prerequisites

Before using this script, ensure you have installed WireGuard on your server using the following script:

- [WireGuard Install Script by angristan](https://github.com/angristan/wireguard-install)

This script provides a quick and easy way to set up a WireGuard server, which is a prerequisite for using the `wireguard_config_script.py` script.

## Quick Start

To quickly get started with the script, you can download and run it directly from GitHub using `curl`:

```bash
curl -O https://raw.githubusercontent.com/egubaidullin/wireguard_managing/main/wireguard_config_script.py
python3 wireguard_config_script.py
```

## Usage

1. **Configure Parameters**: Update the `/etc/wireguard/params` file with your server details.
2. **List Users**: Add user names to `user_list.txt` to generate their WireGuard configurations.
3. **Run the Script**: Execute `wireguard_config_script.py` to generate and update configurations.

## Requirements

- Python 3.x
- WireGuard tools (`wg`, `wg-quick`)
- iptables and ip6tables for firewall rules

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)

---

This updated description includes a quick start guide using `curl` to download the script directly from GitHub, making it easier for users to get started without cloning the repository.
