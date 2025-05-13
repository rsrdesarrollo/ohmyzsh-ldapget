# Oh My Zsh LDAP Search Plugin

A plugin for Oh My Zsh that simplifies LDAP search operations and provides LDIF conversion utilities.

## Features

- Simplified LDAP search commands
- LDIF to CSV conversion
- LDIF to JSON conversion
- Configurable LDAP settings

## Requirements

- Python 3.x (required for LDIF conversion utilities)
- Oh My Zsh
- LDAP utils (ldapsearch command)

## Installation

1. Clone this repository into your Oh My Zsh custom plugins directory:

```bash
git clone https://github.com/rsrdesarrollo/ohmyzsh-ldapget.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/ldapget
```

2. Add `ldapget` to your plugins array in `~/.zshrc`:

```bash
plugins=(... ldapget)
```

3. Create your configuration file by copying the sample:

```bash
cp ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/ldapget/config/default.conf.sample ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/ldapget/config/default.conf
```

## Configuration

The plugin is configured through `config/default.conf`. Here are the available configuration options:

### Authentication

```bash
# GSSAPI (Kerberos) authentication
LDAPSEARCH_OPTIONS="-Y GSSAPI"
```

### Output Format

```bash
# Set the default output format
DEFAULT_FORMAT="clean"  # Clean formatted output
```

### LDAP Servers

Configure your primary LDAP server:

```bash
# Primary LDAP server configuration
DEFAULT_LDAP_SERVER="hostname"
DEFAULT_BASE_DN='DC=acme,DC=local'
```

You can also configure multiple LDAP servers for different environments. Access them using the `@<name>` syntax:

```bash
# Development LDAP server
DEVELOP_LDAP_SERVER="dev_host"
DEVELOP_BASE_DN='DC=acme,DC=dev'
```

Example using a secondary server:

```bash
ldapget user -f "samAccountName=test" @develop  # Searches in the development LDAP server
```

All configuration options should be defined in your `config/default.conf` file. Create this file by copying the sample configuration:

```bash
cp ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/ldapsearch/config/default.conf.sample ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/ldapsearch/config/default.conf
```

## Usage

### LDAP Search

```bash
# Basic LDAP search
ldapget <objectclass> [-f <ldap_filter> | -z N | -H ldap_host | -b base_dn | --format <clean|bof|raw>] [<attrs>*] [@server]

# Advanced search with custom filter
ldapget computer -f "operatingSystem=*Server*" operatingSystem -E pr=1000/noprompt
```

### LDIF Conversion

```bash
# Convert LDIF to CSV
ldapget computer | ldap2csv

# Convert LDIF to JSON
ldapget computer | ldap2json
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
