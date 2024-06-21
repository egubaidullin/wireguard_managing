#!/usr/bin/env python3
# please install https://github.com/angristan/wireguard-install
# curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
# chmod +x wireguard-install.sh
# ./wireguard-install.sh


import configparser
import json
import os
import subprocess
from pathlib import Path

# Configuration
WG_CONF = "/etc/wireguard/wg0.conf"
USER_LIST = "/root/script/user_list.txt"
CONFIG_DIR = "/root/script/users"
IPADDR_MAP = "/root/script/ipaddr-map.json"

# Read parameters from file
config = configparser.ConfigParser()
config.read("/etc/wireguard/params")

# Set parameters
SERVER_PUBLIC_KEY = config.get("params", "SERVER_PUB_KEY")
ENDPOINT = f"{config.get('params', 'SERVER_PUB_IP')}:{config.get('params', 'SERVER_PORT')}"
DNS = f"{config.get('params', 'CLIENT_DNS_1')},{config.get('params', 'CLIENT_DNS_2')}"
SERVER_PORT = config.getint("params", "SERVER_PORT")
SERVER_PUB_NIC = config.get("params", "SERVER_PUB_NIC")
SERVER_WG_NIC = config.get("params", "SERVER_WG_NIC")

# Ensure config directory exists
os.makedirs(CONFIG_DIR, exist_ok=True)

# Backup the original wg0.conf if it doesn't exist
if not os.path.exists(f"{WG_CONF}.bak"):
    os.system(f"cp {WG_CONF} {WG_CONF}.bak")

def create_user_config(username, private_key, address, preshared_key):
    """Creates a client configuration file."""
    config_path = Path(CONFIG_DIR) / f"{username}.conf"
    config_content = f"""\
[Interface]
PrivateKey = {private_key}
Address = {address}/32
DNS = {DNS}

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
PresharedKey = {preshared_key}
Endpoint = {ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
"""
    config_path.write_text(config_content)

# Load or initialize IP address map
ipaddr_map_path = Path(IPADDR_MAP)
if ipaddr_map_path.exists():
    with open(ipaddr_map_path, "r") as f:
        ipaddr_map = json.load(f)
else:
    ipaddr_map = {}

# Read user list into a set
with open(USER_LIST, "r") as f:
    users = set(line.strip() for line in f if line.strip())

# Remove users not in user_list.txt from ipaddr_map
ipaddr_map = {user: data for user, data in ipaddr_map.items() if user in users}

# Assign IP addresses and generate keys for new users
next_available_ip = CLIENT_ADDRESS_START
for user in users:
    username = user.replace("@", "_")
    if user not in ipaddr_map:
        # Find the next available IP address
        while f"{SUBNET}.{next_available_ip}" in [u['address'] for u in ipaddr_map.values()]:
            next_available_ip += 1
        if next_available_ip > 254:
            raise Exception("Address space exhausted")
        client_ipaddr = f"{SUBNET}.{next_available_ip}"

        # Generate client keys
        private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
        public_key = (
            subprocess.check_output(["wg", "pubkey"], input=private_key.encode())
            .decode()
            .strip()
        )
        preshared_key = subprocess.check_output(["wg", "genpsk"]).decode().strip()

        # Update the ipaddr_map
        ipaddr_map[user] = {
            "privateKey": private_key,
            "publicKey": public_key,
            "presharedKey": preshared_key,
            "address": client_ipaddr
        }

        # Create user configuration file
        create_user_config(username, private_key, client_ipaddr, preshared_key)

        next_available_ip += 1

# Write the new wg0.conf file
with open(WG_CONF, "w") as f:
    f.write("[Interface]\n")
    f.write(f"Address = {config.get('params', 'SERVER_WG_IPV4')}/{config.get('params', 'SERVER_WG_IPV4_MASK')},"
            f"{config.get('params', 'SERVER_WG_IPV6')}/{config.get('params', 'SERVER_WG_IPV6_MASK')}\n")
    f.write(f"ListenPort = {SERVER_PORT}\n")
    f.write(f"PrivateKey = {config.get('params', 'SERVER_PRIV_KEY')}\n")
    f.write(f"PostUp = iptables -I INPUT -p udp --dport {SERVER_PORT} -j ACCEPT\n")
    f.write(f"PostUp = iptables -I FORWARD -i {SERVER_PUB_NIC} -o {SERVER_WG_NIC} -j ACCEPT\n")
    f.write(f"PostUp = iptables -I FORWARD -i {SERVER_WG_NIC} -j ACCEPT\n")
    f.write(f"PostUp = iptables -t nat -A POSTROUTING -o {SERVER_PUB_NIC} -j MASQUERADE\n")
    f.write(f"PostUp = ip6tables -I FORWARD -i {SERVER_WG_NIC} -j ACCEPT\n")
    f.write(f"PostUp = ip6tables -t nat -A POSTROUTING -o {SERVER_PUB_NIC} -j MASQUERADE\n")
    f.write(f"PostDown = iptables -D INPUT -p udp --dport {SERVER_PORT} -j ACCEPT\n")
    f.write(f"PostDown = iptables -D FORWARD -i {SERVER_PUB_NIC} -o {SERVER_WG_NIC} -j ACCEPT\n")
    f.write(f"PostDown = iptables -D FORWARD -i {SERVER_WG_NIC} -j ACCEPT\n")
    f.write(f"PostDown = iptables -t nat -D POSTROUTING -o {SERVER_PUB_NIC} -j MASQUERADE\n")
    f.write(f"PostDown = ip6tables -D FORWARD -i {SERVER_WG_NIC} -j ACCEPT\n")
    f.write(f"PostDown = ip6tables -t nat -D POSTROUTING -o {SERVER_PUB_NIC} -j MASQUERADE\n")
    for user, data in ipaddr_map.items():
        f.write(f"\n### Client {user}\n")
        f.write("[Peer]\n")
        f.write(f"PublicKey = {data['publicKey']}\n")
        f.write(f"PresharedKey = {data['presharedKey']}\n")
        f.write(f"AllowedIPs = {data['address']}/32\n")

# Save the updated ipaddr_map
with open(ipaddr_map_path, "w") as f:
    json.dump(ipaddr_map, f, indent=4)

# Apply the WireGuard configuration changes
try:
    subprocess.run(
        ["wg", "syncconf", "wg0", "<(wg-quick strip wg0)"], shell=True, check=True
    )
    print("WireGuard configuration applied successfully.")
except subprocess.CalledProcessError as e:
    print(f"Error applying WireGuard configuration: {e}")
