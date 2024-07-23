#!/usr/bin/env python3
import configparser
import json
import os
import subprocess
import sys
from pathlib import Path
import ipaddress
import requests
import netifaces

# Configuration
WG_CONF = "/etc/wireguard/wg0.conf"
PARAMS_FILE = "/etc/wireguard/params"
SCRIPT_DIR = "/root/script"
USER_LIST = f"{SCRIPT_DIR}/user_list.txt"
CONFIG_DIR = f"{SCRIPT_DIR}/users"
IPADDR_MAP = f"{SCRIPT_DIR}/ipaddr-map.json"

# Default configuration
DEFAULT_CONFIG = {
    'SERVER_WG_NIC': 'wg0',
    'SERVER_WG_IPV4': '10.66.66.1',
    'SERVER_WG_IPV4_MASK': '24',
    'SERVER_PORT': '51820',
    'CLIENT_DNS_1': '1.1.1.1',
    'CLIENT_DNS_2': '1.0.0.1'
}

def ensure_directory(path):
    """Ensure that a directory exists, creating it if necessary."""
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except PermissionError:
        print(f"Error: Permission denied when creating directory {path}")
        return False

def get_external_ip():
    try:
        response = requests.get('https://api.ipify.org')
        return response.text
    except requests.RequestException:
        print("Unable to get external IP. Please check your internet connection.")
        return None

def get_default_interface():
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        return default_gateway[1]
    except:
        print("Unable to determine default network interface. Using 'eth0' as fallback.")
        return 'eth0'

def install_wireguard():
    try:
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "-y", "wireguard"], check=True)
        print("WireGuard installed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing WireGuard: {e}")
        return False

def generate_wireguard_keys():
    private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    public_key = subprocess.check_output(["wg", "pubkey"], input=private_key.encode()).decode().strip()
    preshared_key = subprocess.check_output(["wg", "genpsk"]).decode().strip()
    return private_key, public_key, preshared_key

def create_params_file(server_pub_ip, server_pub_nic):
    config = configparser.ConfigParser()

    if os.path.exists(PARAMS_FILE):
        config.read(PARAMS_FILE)
        print("Existing params file found. Using its values and updating if necessary.")

    if 'params' not in config:
        config['params'] = {}

    for key, value in DEFAULT_CONFIG.items():
        if key not in config['params']:
            config['params'][key] = value

    if server_pub_ip:
        config['params']['SERVER_PUB_IP'] = server_pub_ip
    if server_pub_nic:
        config['params']['SERVER_PUB_NIC'] = server_pub_nic

    if 'SERVER_PRIV_KEY' not in config['params'] or 'SERVER_PUB_KEY' not in config['params']:
        private_key, public_key, _ = generate_wireguard_keys()
        config['params']['SERVER_PRIV_KEY'] = private_key
        config['params']['SERVER_PUB_KEY'] = public_key

    params_dir = os.path.dirname(PARAMS_FILE)
    if not ensure_directory(params_dir):
        return False

    try:
        with open(PARAMS_FILE, 'w') as configfile:
            config.write(configfile)
        print(f"Params file updated: {PARAMS_FILE}")
        return True
    except IOError as e:
        print(f"Error updating params file: {e}")
        return False

def create_wg0_conf():
    wg_dir = os.path.dirname(WG_CONF)
    if not ensure_directory(wg_dir):
        return False

    if not os.path.exists(WG_CONF):
        try:
            with open(WG_CONF, 'w') as f:
                f.write("# WireGuard configuration file\n")
            print(f"Created empty {WG_CONF}")
            return True
        except IOError as e:
            print(f"Error creating {WG_CONF}: {e}")
            return False
    return True

def ensure_script_dir():
    if not ensure_directory(SCRIPT_DIR):
        return False

    if not os.path.exists(USER_LIST):
        try:
            with open(USER_LIST, 'w') as f:
                f.write("# Add usernames here, one per line\n")
            print(f"Created empty {USER_LIST}")
        except IOError as e:
            print(f"Error creating {USER_LIST}: {e}")
            return False
    return True

def set_wg_conf_permissions():
    try:
        os.chmod(WG_CONF, 0o600)
        print(f"Permissions for {WG_CONF} set to 600 (read/write for owner only).")
    except OSError as e:
        print(f"Error setting permissions for {WG_CONF}: {e}")

def create_wg_interface():
    try:
        subprocess.run(["ip", "link", "add", "dev", "wg0", "type", "wireguard"], check=True)
        print("WireGuard interface 'wg0' created successfully.")
    except subprocess.CalledProcessError as e:
        if e.returncode == 2:
            print("WireGuard interface 'wg0' already exists.")
        else:
            print(f"Error creating WireGuard interface: {e}")
            return False
    return True

def apply_wg_config():
    try:
        create_wg_interface()
        subprocess.run(["wg-quick", "down", "wg0"], check=False)
        subprocess.run(["wg-quick", "up", "wg0"], check=True)
        print("WireGuard configuration applied successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error applying WireGuard configuration: {e}")
        return False

def create_user_config(username, private_key, address, preshared_key, server_public_key, endpoint, dns):
    config_path = Path(CONFIG_DIR) / f"{username}.conf"
    config_content = f"""\
[Interface]
PrivateKey = {private_key}
Address = {address}/32
DNS = {dns}

[Peer]
PublicKey = {server_public_key}
PresharedKey = {preshared_key}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0
"""
    try:
        config_path.write_text(config_content)
    except IOError as e:
        print(f"Error creating user config for {username}: {e}")

def check_and_enable_ip_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
        ip_forward = f.read().strip()

    if ip_forward != '1':
        print("IP forwarding is not enabled. Enabling it now...")
        subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
        with open('/etc/sysctl.conf', 'a') as f:
            f.write('\n# Enable IP forwarding\nnet.ipv4.ip_forward = 1\n')
        print("IP forwarding has been enabled and set to persist across reboots.")
    else:
        print("IP forwarding is already enabled.")

def main():
    if not ensure_script_dir():
        print("Failed to create necessary directories. Please check permissions.")
        sys.exit(1)

    if not os.path.exists(PARAMS_FILE):
        print("Params file not found. Installing WireGuard and creating params file.")
        server_pub_ip = get_external_ip()
        if not server_pub_ip:
            sys.exit(1)
        server_pub_nic = get_default_interface()
        if not install_wireguard():
            sys.exit(1)
        if not create_params_file(server_pub_ip, server_pub_nic):
            print("Failed to create params file. Please check permissions and try again.")
            sys.exit(1)
    else:
        print("Params file found. Skipping WireGuard installation.")

    check_and_enable_ip_forwarding()

    if not create_wg0_conf():
        print("Failed to create WireGuard configuration file. Please check permissions and try again.")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(PARAMS_FILE)

    SERVER_PUBLIC_KEY = config.get("params", "SERVER_PUB_KEY")
    ENDPOINT = f"{config.get('params', 'SERVER_PUB_IP')}:{config.get('params', 'SERVER_PORT')}"
    DNS = f"{config.get('params', 'CLIENT_DNS_1')},{config.get('params', 'CLIENT_DNS_2')}"
    SERVER_PORT = config.getint("params", "SERVER_PORT")
    SERVER_PUB_NIC = config.get("params", "SERVER_PUB_NIC")
    SERVER_WG_NIC = config.get("params", "SERVER_WG_NIC")
    SUBNET = config.get("params", "SERVER_WG_IPV4").rsplit('.', 1)[0]
    CLIENT_ADDRESS_START = 2

    if not ensure_directory(CONFIG_DIR):
        print("Failed to create config directory. Please check permissions.")
        sys.exit(1)

    if not os.path.exists(f"{WG_CONF}.bak"):
        try:
            os.system(f"cp {WG_CONF} {WG_CONF}.bak")
        except Exception as e:
            print(f"Failed to create backup of {WG_CONF}: {e}")

    ipaddr_map_path = Path(IPADDR_MAP)
    if ipaddr_map_path.exists():
        try:
            with open(ipaddr_map_path, "r") as f:
                ipaddr_map = json.load(f)
        except json.JSONDecodeError:
            print(f"Error reading {IPADDR_MAP}. Initializing empty map.")
            ipaddr_map = {}
    else:
        ipaddr_map = {}

    try:
        with open(USER_LIST, "r") as f:
            users = set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except IOError as e:
        print(f"Error reading {USER_LIST}: {e}")
        users = set()

    if not users:
        print(f"Warning: No users found in {USER_LIST}. Please add users and run the script again.")
        sys.exit(0)

    ipaddr_map = {user: data for user, data in ipaddr_map.items() if user in users}

    network = ipaddress.ip_network(f"{SUBNET}.0/24", strict=False)
    used_ips = set(data['address'] for data in ipaddr_map.values())
    available_ips = (str(ip) for ip in network.hosts() if str(ip) not in used_ips and ip.packed[-1] >= CLIENT_ADDRESS_START)

    for user in users:
        username = user.replace("@", "_")
        if user not in ipaddr_map:
            try:
                client_ipaddr = next(available_ips)
            except StopIteration:
                print("Error: Address space exhausted")
                sys.exit(1)

            private_key, public_key, preshared_key = generate_wireguard_keys()

            ipaddr_map[user] = {
                "privateKey": private_key,
                "publicKey": public_key,
                "presharedKey": preshared_key,
                "address": client_ipaddr
            }

            create_user_config(username, private_key, client_ipaddr, preshared_key, SERVER_PUBLIC_KEY, ENDPOINT, DNS)

    try:
        with open(WG_CONF, "w") as f:
            f.write("[Interface]\n")
            f.write(f"Address = {config.get('params', 'SERVER_WG_IPV4')}/{config.get('params', 'SERVER_WG_IPV4_MASK')}\n")
            f.write(f"ListenPort = {SERVER_PORT}\n")
            f.write(f"PrivateKey = {config.get('params', 'SERVER_PRIV_KEY')}\n")

            post_up_rules = [
                f"iptables -I INPUT -p udp --dport {SERVER_PORT} -j ACCEPT",
                f"iptables -I FORWARD -i {SERVER_PUB_NIC} -o {SERVER_WG_NIC} -j ACCEPT",
                f"iptables -I FORWARD -i {SERVER_WG_NIC} -j ACCEPT",
                f"iptables -t nat -A POSTROUTING -o {SERVER_PUB_NIC} -j MASQUERADE"
            ]

            post_down_rules = [rule.replace("-I", "-D").replace("-A", "-D") for rule in post_up_rules]

            for rule in post_up_rules:
                f.write(f"PostUp = {rule}\n")

            for rule in post_down_rules:
                f.write(f"PostDown = {rule}\n")

            for user, data in ipaddr_map.items():
                f.write(f"\n### Client {user}\n")
                f.write("[Peer]\n")
                f.write(f"PublicKey = {data['publicKey']}\n")
                f.write(f"PresharedKey = {data['presharedKey']}\n")
                f.write(f"AllowedIPs = {data['address']}/32\n")

        print(f"WireGuard configuration written to {WG_CONF}")
    except IOError as e:
        print(f"Error writing to {WG_CONF}: {e}")
        sys.exit(1)

    try:
        with open(ipaddr_map_path, "w") as f:
            json.dump(ipaddr_map, f, indent=4)
        print(f"IP address map saved to {IPADDR_MAP}")
    except IOError as e:
        print(f"Error saving IP address map: {e}")

    set_wg_conf_permissions()

    if not apply_wg_config():
        print("Failed to apply WireGuard configuration. Please check your system configuration and try again.")
        sys.exit(1)

    print("\nSetup complete!")
    if not users:
        print(f"Remember to add users to {USER_LIST} and run the script again to configure clients.")

if __name__ == "__main__":
    main()
