# netspray

Shout out to NetExec & CrackMapExec crew.

## Purpose

"If only you tried *that*..."

## Overview

Based on the information you provide, it'll construct and execute all of the different ways that you could authenticate to each nxc/cme compatible service.

Anytime a new username, hash, password or possible word is discovered, this is an easy way to run the gaunlet instead of checking each service with the different auth variations.

Do not use if stealth is a priority. 

## Installation & Dependencies

Clone or paste the code into a file.

```bash
git clone https://github.com/itsnotgunnar/netspray
sudo apt install nxc
```

## Usage

Run directly from the command line.

### Command-Line Arguments

```bash
usage: netspray.py [-h] (-i IP | -t TARGETS_FILE) [-u USERNAME] [-p PASSWORD]
                   [-H HASHES_FILE] [-k CCACHE_FILE] [--kdcHost KDCHOST]
                   [--domain DOMAIN] [--dc-ip DC_IP] [--wicked]
                   [-o OUTPUT_DIR]

Enhance Active Directory security by testing multiple protocols and services with various authentication methods.

optional arguments:
  -h, --help            show this help message and exit

Target Specification:
  -i IP, --ip IP        Direct IP address or FQDN to test
  -t TARGETS_FILE, --targets-file TARGETS_FILE
                        File containing list of IP addresses or FQDNs

Authentication:
  -u USERNAME, --username USERNAME
                        Username or file containing usernames to test
  -p PASSWORD, --password PASSWORD
                        Password or file containing passwords to test
  -H HASHES_FILE, --hashes-file HASHES_FILE
                        (Optional) File containing list of NTLM hashes
  -k CCACHE_FILE, --ccache-file CCACHE_FILE
                        (Optional) Specify Kerberos credential cache file for authentication

Domain Settings:
  --kdcHost KDCHOST, -dc KDCHOST
                        (Optional) Specify the KDC host for Kerberos authentication
  --domain DOMAIN, -d DOMAIN
                        (Optional) Specify the domain name
  --dc-ip DC_IP         (Optional) Specify the Domain Controller IP if KDC host cannot be resolved

Options:
  --wicked              (Optional) Run additional commands for services
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        (Optional) Specify output directory (default: ./output)
```

## Examples.

Basic Usage with Single User and Password.

```bash
python netspray.py -i $ip -u $user -p $pass
```

Using Files for Users and Passwords.

```bash
python netspray.py -i targets.txt -u users.txt -p passwords.txt
```

With --wicked Option.

```bash
python netspray.py -i targets.txt -u users.txt -p passwords.txt --wicked
```

Specifying Domain and KDC Host.

```bash
python netspray.py -i target.domain.com -u $user -p $pass -d $dom --kdcHost $dc
```

Using NTLM Hashes.

```bash
python netspray.py -i target.domain.com -u $user -H hashes.txt
```

Using Kerberos Credential Cache.

```bash
python netspray.py -i target.domain.com -k /tmp/krb5cc_1000 -d $dom -dc $dc
```

## Output

```bash
Authentication Summary:

User: alice
  Service: smb with password 'password123' -> user_pass
  Service: ldap with password 'password123' -> user_pass

User: bob
  Service: rdp with password 'BobPassword!' -> user_pass

Note: Only users with successful authentications are shown.
```

### Command Logging

All executed commands are logged in nxc_commands.txt within the specified output directory. This file contains a list of commands run during the script execution, which is useful for auditing and review purposes.

