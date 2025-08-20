# DHCPv6 Vendor Client - Docker Test Environment
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    tcpdump \
    net-tools \
    vim \
    curl \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies for fake server
RUN pip3 install scapy

# Create application directory
WORKDIR /app

# Copy source code and build artifacts
COPY . /app/

# Create necessary directories
RUN mkdir -p /etc/vendor/keys /etc/vendor/certs /var/lib/vendor-dhcp6 /var/log

# Set up permissions
RUN chmod +x /app/vendor-dhclient \
    && chmod +x /app/scripts/*.sh \
    && chmod +x /app/test_integration.sh \
    && chmod +x /app/tests/it/fake_dhcp6_server.py

# Generate test keys and certificates
RUN openssl genrsa -out /etc/vendor/keys/client.key 2048 \
    && chmod 600 /etc/vendor/keys/client.key \
    && openssl req -new -x509 -key /etc/vendor/keys/client.key \
       -out /etc/vendor/certs/request.pem -days 365 \
       -subj "/C=US/ST=Test/L=Test/O=Test/CN=test.example.com" \
    && chmod 644 /etc/vendor/certs/request.pem

# Copy configuration
RUN cp /app/conf/vendor-dhcp6.toml /etc/vendor/dhcp6-vendor.conf

# Create environment file
RUN echo "SN_NUMBER=DOCKER_TEST_123456789" > /etc/vendor/environment

# Expose DHCPv6 ports
EXPOSE 546/udp 547/udp

# Default command
CMD ["/bin/bash"]