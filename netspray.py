#!/usr/bin/env python3

import argparse
import os
import subprocess
import threading
import signal
import sys
from multiprocessing import cpu_count
from concurrent.futures import ThreadPoolExecutor, as_completed

'''
TODO:
- have 3 tiers of this commands
    - default -> run through all of the different variations of authentication given the args (for each service)
    - initial enum -> enumeration whereas you wouldn't gain additional information from doing it again
    - aggressive -> actually doing stuff like reading dacl, kerberoasting, ...  (scared of auto-exploit)
- if pwn3d, provide commands to get a shell or dump creds (not important)

structure:
    results = {
        'target': {
            'user': {
                'service': {
                    'auth_method': {
                        'success': True,
                        'pwned': False,
                        'output': '...'
                    },
                },
            },
        },
    }
'''

# Define services to test - variables for thread control and synchronization
SERVICES = ["smb", "winrm", "ssh", "ftp", "rdp", "wmi", "ldap", "mssql", "vnc"]
stop_threads = False  # Flag to stop threads gracefully
lock = threading.Lock()  # Lock for synchronizing access to shared resources
command_lock = threading.Lock()  # Lock for writing commands to file

def signal_handler(sig, frame):
    global stop_threads
    print("\nTermination signal received. Stopping all threads...")
    stop_threads = True
    sys.exit(0)

# Register the signal handler for SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, signal_handler)

def parse_arguments():
    """
    Parse command-line arguments provided by the user.
    Returns an argparse.Namespace object containing the arguments.
    """
    parser = argparse.ArgumentParser(description="Enhance Active Directory security by testing multiple protocols and services with various authentication methods.")

    # Mutually exclusive group for target specification
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', help='Direct IP address or FQDN to test')
    group.add_argument('-t', '--targets-file', help='File containing list of IP addresses or FQDNs')

    # Authentication arguments
    parser.add_argument('-u', '--username', help='Username or file containing usernames to test')
    parser.add_argument('-p', '--password', help='Password or file containing passwords to test')
    parser.add_argument('-H', '--hashes-file', help='(Optional) File containing list of NTLM hashes')

    # Optional arguments for Kerberos and domain settings
    parser.add_argument('-k', '--ccache-file', help='(Optional) Specify Kerberos credential cache file for authentication')
    parser.add_argument('--kdcHost', '-dc', help='(Optional) Specify the KDC host for Kerberos authentication')
    parser.add_argument('--domain', '-d', help='(Optional) Specify the domain name')
    parser.add_argument('--dc-ip', help='(Optional) Specify the Domain Controller IP if KDC host cannot be resolved')
    parser.add_argument('--wicked', action='store_true', help='(Optional) Run additional commands for services')
    parser.add_argument('-o', '--output-dir', default='./output', help='(Optional) Specify output directory (default: ./output)')
    args = parser.parse_args()

    # Fix this. If there are no possible authentication methods possible given the arguments, try to authenticate as guest or anonymously. "If you want to test past guest and anonymous access, these are the possible auth methods that we can run. {...}. This will automatically test every method possible, given the arguments.""
    if not any([args.username, args.hashes_file, args.ccache_file]):
        parser.error('At least one of --username, --hashes-file, or --ccache-file must be provided.')

    return args

def read_targets(args):
    """
    Read the list of targets (IP addresses or FQDNs) from the provided arguments.
    Returns a list of targets.
    """
    if args.targets_file:
        if not os.path.isfile(args.targets_file):
            print(f"Targets file '{args.targets_file}' not found.")
            exit(1)
        with open(args.targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [args.ip]
    return targets

def read_users(args):
    """
    Read the list of usernames from the provided arguments.
    Returns a tuple containing the list of users and a boolean indicating if usernames are from a file.
    """
    usernames_from_file = False
    if args.username:
        if os.path.isfile(args.username):
            usernames_from_file = True
            with open(args.username, 'r') as f:
                users = [line.strip() for line in f if line.strip()]
        else:
            users = [args.username]
    else:
        users = []
    return users, usernames_from_file

def read_passwords(args):
    """
    Read the list of passwords from the provided arguments.
    Returns a list of passwords.
    """
    if args.password:
        if os.path.isfile(args.password):
            with open(args.password, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            passwords = [args.password]
    else:
        passwords = []
    return passwords

def construct_auth_methods(args, user, password, usernames_from_file):
    """
    Construct the list of authentication methods to be used based on the provided arguments and user/password.
    Returns a list of authentication methods.
    """
    auth_methods = []
    if args.ccache_file and not usernames_from_file:
        auth_methods.append("use_kcache")
    if user and password:
        auth_methods.append("user_pass")
        if (args.kdcHost or args.ccache_file) and not usernames_from_file:
            auth_methods.append("user_pass_kerberos")
    if args.hashes_file and user:
        auth_methods.append("user_hash")
    return auth_methods

    
# May need to adjust for services. --windows-auth for mssql, i assume ftp doesn't take in dc info
def construct_command(ip, service, auth_method, args, user=None, password=None, local_auth=False):
    """
    Construct the command to be executed for a given service, authentication method, and user/password.
    Returns a list representing the command and its arguments.
    """
    cmd = ["nxc", service, ip]
    # Authentication options
    if auth_method == "use_kcache":
        cmd.append("--use-kcache")
    elif auth_method == "user_pass_kerberos":
        cmd.extend(["-u", user, "-p", password, "-k"])
    elif auth_method == "user_pass":
        cmd.extend(["-u", user, "-p", password])
    elif auth_method == "user_hash":
        cmd.extend(["-u", user, "-H", args.hashes_file])
    # Additional arguments
    if args.kdcHost:
        cmd.extend(["--kdcHost", args.kdcHost])
    if args.domain:
        cmd.extend(["-d", args.domain])
    if args.dc_ip:
        cmd.extend(["--dc-ip", args.dc_ip])
    if service == "mssql" and local_auth:
        cmd.append("--local-auth")
    return cmd

def execute_command(cmd, env):
    """
    Execute the given command using subprocess and capture its output.
    Returns a dictionary containing success status, pwned status, and command output.
    """
    try:
        # Run the command and capture stdout and stderr
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, timeout=60)
        output = result.stdout + result.stderr
        # Determine if the command was successful based on output content
        success = '[+]' in output or 'PWN3D' in output
        pwned = 'PWN3D' in output
        return {'success': success, 'pwned': pwned, 'output': output}
    except subprocess.TimeoutExpired:
        return {'success': False, 'pwned': False, 'output': 'Command timed out.'}
    except Exception as e:
        return {'success': False, 'pwned': False, 'output': str(e)}


def process_services(ip, services, auth_methods, args):
    results = {}
    env = os.environ.copy()
    if args.ccache_file:
        env['KRB5CCNAME'] = args.ccache_file

    username = args.username if args.username else 'unknown_user'
    results[username] = {}

    for service in services:
        print(f"Processing {service} on {ip} using auth methods: {', '.join(auth_methods)}\n")
        results[username][service] = {}
        commands = construct_commands(ip, service, auth_methods, args)
        for cmd_info in commands:
            auth_method = cmd_info['auth_method']
            cmd = cmd_info['cmd']
            exec_result = execute_command(cmd, env)
            results[username][service][auth_method] = exec_result
    return results

def choose_best_auth_method(auth_methods):
    """
    Didn't want extra commands to be run for each success auth method.
    This chooses the authentication method from a list based on a (arbitrary) predefined priority.
    Returns the authentication method with the highest priority (lowest value).
    """
    auth_priority = {
        'use_kcache': 1,
        'user_pass_kerberos': 2,
        'user_pass': 3,
        'user_hash': 4,
    }
    # Remove '_local' or '_windows' suffixes for comparison
    def auth_key(auth):
        base_auth = auth.replace('_local', '').replace('_windows', '')
        return auth_priority.get(base_auth, 100)
    return min(auth_methods, key=auth_key)


def run_additional_commands(ip, service, auth_method, args, env, nxc_commands_file, user=None, password=None, local_auth=False):
    """
    Run additional commands for a service after successful authentication.
    Writes commands to nxc_commands_file and executes them.
    """
    base_cmd = ["nxc", service, ip]

    # Build base command with auth options
    if auth_method == "use_kcache":
        base_cmd.append("--use-kcache")
    elif auth_method == "user_pass_kerberos":
        base_cmd.extend(["-u", user, "-p", password, "-k"])
    elif auth_method == "user_pass":
        base_cmd.extend(["-u", user, "-p", password])
    elif auth_method == "user_hash":
        base_cmd.extend(["-u", user, "-H", args.hashes_file])

    # Add additional arguments if provided
    if args.kdcHost:
        base_cmd.extend(["--kdcHost", args.kdcHost])
    if args.domain:
        base_cmd.extend(["-d", args.domain])
    if args.dc_ip:
        base_cmd.extend(["--dc-ip", args.dc_ip])
    if service == "mssql" and local_auth:
        base_cmd.append("--local-auth")

    # Define additional commands per service
    additional_commands = []
    if service == "smb":
        additional_commands = [
            # "--disks",
            # "--groups",
            # "--interfaces",
            # "--laps",
            # "--local-group",
            # "--local-groups",
            "--loggedon-users",
            # "--lsa",
            "--pass-pol",
            # "--rid-brute",
            # "--sam",
            # "--sessions",
            # "--sccm",
            # "--sccm disk",
            # "--sccm wmi",
            "--shares",
            # "--users",
            "-M enum_av",
            "-M enum_ca",
            "-M enum_dns",
            # "-M gpp_password",
            # "-M gpp_autologin",
            # "-M lsassy",
            # "-M mremoteng",
            # "-M msol",
            # "-M nanodump",
            # "-M nopac",
            # "-M ntdsutil",
            # "-M petitpotam",
            # "-M procdump",
            # "-M rdcman",
            # "-M security-questions",
            # "-M spider_plus",
            # "-M spooler",
            # "-M smbghost",
            # "-M teams_localdb",
            # "-M veeam",
            # "-M vnc",
            # "-M webdav",
            # "-M winscp",
            # "-M zerologon",
            "-x whoami",
            "-X whoami"
        ]
    elif service == "ldap":
        additional_commands = [
            "--active-users",
            # "--asreproast ${user}-asreproast.txt",
            "--groups",
            # "--kerberoasting ${user}-kerberoast.txt",
            "--trusted-for-delegation",
            "--users",
            # "--user-count",
            "-M adcs",
            # "-M daclread -o TARGET=$ip ACTION=read",
            "-M enum_trusts",
            # "-M get-network -o ALL=true",
            # "-M laps",
            # "-M ldap-checker",
            "-M user-desc"
        ]
    elif service in ["winrm", "ssh", "wmi"]:
        additional_commands = ["-x whoami"]
    elif service == "mssql":
        additional_commands = [
            "-M mssql_priv",
            "-q SELECT name FROM master.dbo.sysdatabases;",
            "-x whoami"
        ]

    # Execute additional commands
    for option in additional_commands:
        cmd = base_cmd + option.split()
        with command_lock:
            with open("nxc_commands.txt", "a") as cmd_file:
                cmd_file.write(' '.join(cmd) + '\n')
        result = execute_command(cmd, env)
        # Handle or log the result as needed
        if result['output']:
            print(f"Executing nxc {service} {ip} {' '.join(option.split())}")
            print(result['output'])

def execute_and_record(cmd, env, ip, user, password, service, auth_method_label, results, nxc_commands_file):
    """
    Execute a command and record its result in the shared results dictionary.
    Also writes the command to nxc_commands.txt.
    """
    # Write the command to nxc_commands.txt
    with command_lock:
        with open(nxc_commands_file, "a") as cmd_file:
            cmd_file.write(' '.join(cmd) + '\n')
    
    # Execute the command
    exec_result = execute_command(cmd, env)

    # Store result in results
    with lock:
        if user not in results[ip]:
            results[ip][user] = {}
        if password not in results[ip][user]:
            results[ip][user][password] = {}
        if service not in results[ip][user][password]:
            results[ip][user][password][service] = {}
        results[ip][user][password][service][auth_method_label] = exec_result

    # If successful, print output
    if exec_result['success']:
        print(f"Success: {user}@{ip} via {service} using {auth_method_label}")
        # Optionally print the output
        # print(exec_result['output'])

def get_all_auth_methods(args, usernames_from_file):
    """
    Determine all possible authentication methods based on the provided arguments.
    Returns a set of authentication methods.
    """
    auth_methods = set()
    if args.ccache_file and not usernames_from_file:
        auth_methods.add("use_kcache")
    if args.username and args.password:
        auth_methods.add("user_pass")
        if args.kdcHost and args.ccache_file and not usernames_from_file:
            auth_methods.add("user_pass_kerberos")
    if args.hashes_file and args.username:
        auth_methods.add("user_hash")
    return auth_methods


def process_targets(args, nxc_commands_file):
    """
    Main function to process all targets, users, and passwords.
    Executes commands for each combination and collects results.
    """
    # Read targets, users, and passwords from the provided arguments
    targets = read_targets(args)
    users, usernames_from_file = read_users(args)
    passwords = read_passwords(args)

    # Prepare the environment variables. This can be be removed.
    env = os.environ.copy()
    if args.ccache_file:
        env['KRB5CCNAME'] = args.ccache_file

    results = {}  # To store results per target

    # Determine all possible authentication methods
    all_auth_methods = get_all_auth_methods(args, usernames_from_file)
    user_list = ', '.join(users)
    print(f"Processing services for users: {user_list} using auth methods: {', '.join(all_auth_methods)}\n")

    # Use ThreadPoolExecutor for concurrent execution
    with ThreadPoolExecutor(max_workers=cpu_count()) as executor:
        futures = []
        for ip in targets:
            results[ip] = {}
            for user in users:
                for password in passwords:
                    # Get authentication methods for the current user/password
                    auth_methods = construct_auth_methods(args, user, password, usernames_from_file)
                    for service in SERVICES:
                        for auth_method in auth_methods:
                            if service == "mssql":
                                # For MSSQL, test both local and Windows authentication
                                for local_auth in [False, True]:
                                    cmd = construct_command(ip, service, auth_method, args, user, password, local_auth)
                                    auth_method_label = auth_method + ("_local" if local_auth else "_windows")
                                    # Submit the command execution to the thread pool
                                    future = executor.submit(execute_and_record, cmd, env, ip, user, password, service, auth_method_label, results, nxc_commands_file)
                                    futures.append(future)
                            else:
                                # Construct and execute command for other services
                                cmd = construct_command(ip, service, auth_method, args, user, password)
                                future = executor.submit(execute_and_record, cmd, env, ip, user, password, service, auth_method, results, nxc_commands_file)
                                futures.append(future)
        
        # Wait for all tasks to complete
        for future in as_completed(futures):
            pass

        # Run additional commands for successful authentications if --wicked is specified
        if args.wicked:
            for ip in results:
                for user in results[ip]:
                    for password in results[ip][user]:
                        for service in results[ip][user][password]:
                            # Get successful authentication methods for the service
                            successful_auths = [auth for auth, res in results[ip][user][password][service].items() if res['success']]
                            if successful_auths:
                                # Choose the best authentication method
                                best_auth = choose_best_auth_method(successful_auths)
                                if service == "mssql":
                                    # Determine if local authentication was used
                                    local_auth_best = '_local' in best_auth
                                    base_auth_method = best_auth.replace('_local', '').replace('_windows', '')
                                    # Run additional commands
                                    run_additional_commands(ip, service, base_auth_method, args, env, nxc_commands_file, user, password, local_auth_best)
                                else:
                                    run_additional_commands(ip, service, best_auth, args, env, nxc_commands_file, user, password)

    # Generate and print authentication summary
    print("\nAuthentication Summary:\n")
    for ip in results:
        for user in results[ip]:
            user_has_success = False  # Flag to check if user had any successful authentications
            service_lines = {}  # Dictionary to store service lines for the user
            for password in results[ip][user]:
                for service in results[ip][user][password]:
                    successful_auths = []
                    pwned = False
                    # Collect successful authentications and pwned status
                    for auth_method, res in results[ip][user][password][service].items():
                        if res['success']:
                            successful_auths.append(auth_method)
                            if res['pwned']:
                                pwned = True
                    if successful_auths:
                        user_has_success = True
                        pwned_text = " (PWN3D)" if pwned else ""
                        auth_methods_str = ', '.join(successful_auths)
                        if service not in service_lines:
                            service_lines[service] = []
                        # Store the service line with password and authentication methods
                        service_lines[service].append((password, auth_methods_str, pwned_text))
            if user_has_success:
                # Print the user's successful authentications
                print(f"User: {user}")
                for service, entries in service_lines.items():
                    for entry in entries:
                        password, auth_methods_str, pwned_text = entry
                        print(f"  Service: {service} with password '{password}' -> {auth_methods_str}{pwned_text}")
                print()  # Add an empty line between users
    print("Note: Only users with successful authentications are shown.\n")

def main():

    args = parse_arguments()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize nxc_commands.txt
    nxc_commands_file = os.path.join(args.output_dir, "nxc_commands.txt")
    with open(nxc_commands_file, "w") as cmd_file:
        cmd_file.write("Commands executed:\n")

    # Do tha thing
    process_targets(args, nxc_commands_file)

    # Optionally, write results to files or process them further
    print(f"All tasks completed. Results are stored in the '{args.output_dir}' directory.")

if __name__ == "__main__":
    main()
