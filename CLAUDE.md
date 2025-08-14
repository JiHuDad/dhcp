# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the ISC DHCP Distribution version 4.4.3-P1, a mature C implementation of DHCP protocol components. **Important**: This software is End-of-Life as of 4.4.3 - no further releases are planned.

### Core Components

- **dhcpd** - DHCP server (main component still maintained)
- **dhclient** - DHCP client (EOL, no longer maintained)
- **dhcrelay** - DHCP relay agent (EOL, no longer maintained)  
- **dhcpctl** - DHCP control library for OMAPI
- **omapip** - Object Management API for runtime configuration
- **keama** - KEA Migration Assistant (converts ISC DHCP configs to KEA format)

### Architecture

The codebase follows a modular C architecture:

- `server/` - DHCP server implementation with lease management, packet processing, and configuration parsing
- `client/` - DHCP client with platform-specific network interface handling
- `relay/` - DHCP relay agent for forwarding between networks
- `common/` - Shared utilities (packet handling, memory management, option parsing, DNS updates)
- `omapip/` - Object Management API for runtime control
- `dhcpctl/` - Control interface library
- `includes/` - Header files and platform abstractions
- `bind/` - Embedded BIND libraries for DNS operations

## Build Commands

### Basic Build
```bash
./configure
make
```

### Build with Testing Support
```bash
./configure --with-atf
make
make check
```

### Development Build Options
```bash
./configure --help                    # See all configuration options
./configure --enable-debug           # Debug build
./configure --enable-dhcpv6          # DHCPv6 support (default: yes)
./configure --with-randomdev=PATH    # Specify random device
```

### Installation
```bash
make install
```

### Testing
```bash
make check          # Run unit tests (requires ATF)
make distcheck      # Test distribution packaging
```

## Testing Framework

The project uses ATF (Automated Testing Framework) for unit tests:
- Install ATF and configure with `--with-atf`
- Unit tests are in `*/tests/` subdirectories
- Test files: `*_unittest.c`, `Atffile`, `Kyuafile`
- Run with `make check` after building

## Key Configuration Files

- `dhcpd.conf` - Server configuration
- `dhclient.conf` - Client configuration  
- `dhcpd.leases` - Server lease database
- `dhclient.leases` - Client lease database

## Development Notes

- Code follows BIND 9 coding standards
- Platform-specific code in `common/` (bpf.c, lpf.c, dlpi.c, etc.)
- Network interface detection varies by OS (Linux Packet Filter, BSD BPF, Solaris DLPI)
- Supports IPv4 and IPv6 protocols
- Uses autotools build system (autoconf/automake)

## Important Paths

Configuration and lease files are typically in:
- `/etc/dhcpd.conf` (server config)
- `/var/db/dhcpd.leases` or `/var/lib/dhcp/dhcpd.leases` (server leases)
- `/var/run/dhcpd.pid` (process ID files)

## End-of-Life Notice

The client and relay components reached EOL in January 2022. Only the server component continues to receive maintenance updates. When working on this codebase, focus primarily on server-related functionality.