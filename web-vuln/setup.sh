#!/bin/bash

# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
NC="\033[0m" # No Color

echo -e "${GREEN}[+] Starting setup...${NC}"

# Update package list
echo -e "${YELLOW}[+] Updating package list...${NC}"
sudo apt update -y

# Install required packages
echo -e "${YELLOW}[+] Installing required packages: python3, pip, proxychains4, sqlmap, gau, waybackurls, xsstrik${NC}"
sudo apt install -y python3 python3-pip proxychains4 sqlmap curl

# Install gau and waybackurls
if ! command -v gau &> /dev/null; then
    echo -e "${YELLOW}[+] Installing gau...${NC}"
    GO111MODULE=on go install github.com/lc/gau/v2/cmd/gau@latest
    sudo ln -s ~/go/bin/gau /usr/local/bin/gau
fi

if ! command -v waybackurls &> /dev/null; then
    echo -e "${YELLOW}[+] Installing waybackurls...${NC}"
    GO111MODULE=on go install github.com/tomnomnom/waybackurls@latest
    sudo ln -s ~/go/bin/waybackurls /usr/local/bin/waybackurls
fi

# Install xsstrik
if ! command -v xsstrik &> /dev/null; then
    echo -e "${YELLOW}[+] Installing xsstrik...${NC}"
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike || exit
    sudo pip install -r requirements.txt
    sudo python3 setup.py install
    sudo ln -s $(pwd)/xsstrike /usr/local/bin/xsstrik
    cd ..
    rm -rf XSStrike
fi

# Install Python packages
echo -e "${YELLOW}[+] Installing Python packages: colorama${NC}"
pip3 install colorama

# Proxychains configuration
echo -e "${YELLOW}[+] Configuring proxychains4...${NC}"
sudo cp /etc/proxychains4.conf /etc/proxychains4.conf.bak  # Backup existing config
sudo bash -c 'cat > /etc/proxychains4.conf' <<EOL
strict_chain
proxy_dns
remote_dns_subnet 224
[ProxyList]
socks5 127.0.0.1 9050
EOL
echo -e "${GREEN}[✓] Proxychains configuration updated.${NC}"

# Final message
echo -e "${GREEN}[✓] Setup completed successfully!${NC}"
