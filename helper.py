import os
import stat
import subprocess
import pwd
import grp
import yaml
import json


# --------------------------------------------------------- Worker Node rules ------------------------------------------------------------------------------------------

def get_process_argument(process_name, argument):
    """
    Get a specific argument from a running process.
    Returns the process line containing the argument or None if not found.
    """
    result = subprocess.run(['ps', '-ef'], stdout=subprocess.PIPE, text=True)
    for line in result.stdout.splitlines():
        if process_name in line and argument in line:
            return line
    return None

def check_process_argument_set(process_name, argument, expected_value=None):
    """
    Check if a process argument is set with optional expected value.
    Returns status dict with PASS/FAIL and details.
    """
    line = get_process_argument(process_name, argument)
    
    if not line:
        return {"status": "FAIL", "reason": f"{argument} not found in {process_name} process"}
    
    if expected_value:
        if f"{argument}={expected_value}" in line:
            return {"status": "PASS", "value": expected_value}
        else:
            return {"status": "FAIL", "reason": f"{argument} is not set to {expected_value}"}
    else:
        if f"{argument}=" in line:
            return {"status": "PASS", "reason": f"{argument} is set"}
        else:
            return {"status": "FAIL", "reason": f"{argument} is not set"}

def check_process_feature_gate(process_name, feature_gate, expected_value="true"):
    """
    Check if a feature gate is enabled in a process.
    Returns status dict with PASS/FAIL and details.
    """
    line = get_process_argument(process_name, "--feature-gates")
    
    if not line:
        return {"status": "FAIL", "reason": "--feature-gates not found in process"}
    
    if f"{feature_gate}={expected_value}" in line:
        return {"status": "PASS", "value": f"{feature_gate}={expected_value}"}
    else:
        return {"status": "FAIL", "reason": f"{feature_gate} is not set to {expected_value}"}

def check_kubelet_feature_gate(feature_gate, expected_value="true"):
    """
    Check if a feature gate is enabled in kubelet (either via command line or config file).
    Returns status dict with PASS/FAIL and details.
    """
    # First check command line arguments
    line = get_process_argument("kubelet", "--feature-gates")
    if line and f"{feature_gate}={expected_value}" in line:
        return {"status": "PASS", "value": f"{feature_gate}={expected_value} (command line)"}
    
    # If not found in command line, check config file
    config_path = get_kubelet_config_file_path()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Check for feature gates in config
            if 'featureGates' in config and feature_gate in config['featureGates']:
                if config['featureGates'][feature_gate] == (expected_value.lower() == 'true'):
                    return {"status": "PASS", "value": f"{feature_gate}={expected_value} (config file)"}
                else:
                    return {"status": "FAIL", "reason": f"{feature_gate} is set to {config['featureGates'][feature_gate]} in config file, expected {expected_value}"}
            
            # Check for rotateCertificates (special case for RotateKubeletServerCertificate)
            if feature_gate == "RotateKubeletServerCertificate" and 'rotateCertificates' in config:
                if config['rotateCertificates'] == (expected_value.lower() == 'true'):
                    return {"status": "PASS", "value": f"{feature_gate}={expected_value} (config file as rotateCertificates)"}
                else:
                    return {"status": "FAIL", "reason": f"rotateCertificates is set to {config['rotateCertificates']} in config file, expected {expected_value}"}
            
            return {"status": "FAIL", "reason": f"{feature_gate} not found in kubelet config file"}
            
        except Exception as e:
            return {"status": "FAIL", "reason": f"Error reading kubelet config file: {str(e)}"}
    
    return {"status": "FAIL", "reason": f"{feature_gate} not found in command line or config file"}

def check_file_permissions(file_path, expected_permission="600"):
    """
    Check if file permissions are 600 or more restrictive.
    Returns status dict with PASS/FAIL and details.
    """
    if not os.path.exists(file_path):
        return {"status": "FAIL", "reason": f"{file_path} not found"}
    
    st = os.stat(file_path)
    file_mode = stat.S_IMODE(st.st_mode)
    
    if file_mode <= int(expected_permission, 8) and (file_mode & 0o077) == 0:
        return {"status": "PASS", "mode": oct(file_mode)}
    return {"status": "FAIL", "mode": oct(file_mode), "reason": "Permissions too open"}

def check_file_ownership(file_path, expected_owner="root:root"):
    """
    Check if file is owned by expected user:group.
    Returns status dict with PASS/FAIL and details.
    """
    if not os.path.exists(file_path):
        return {"status": "FAIL", "reason": f"{file_path} not found"}
    
    st = os.stat(file_path)
    uid = st.st_uid
    gid = st.st_gid
    user = pwd.getpwuid(uid).pw_name
    group = grp.getgrgid(gid).gr_name
    actual_owner = f"{user}:{group}"
    
    if actual_owner == expected_owner:
        return {"status": "PASS", "owner": actual_owner}
    return {"status": "FAIL", "owner": actual_owner, "reason": f"Ownership is not {expected_owner}"}

def check_kubelet_tls_cipher_suites():
    """
    Check if kubelet uses strong cryptographic ciphers for --tls-cipher-suites.
    Returns status dict with PASS/FAIL and details.
    """
    line = get_process_argument("kubelet", "--tls-cipher-suites")
    
    if not line:
        return {"status": "FAIL", "reason": "--tls-cipher-suites not found in kubelet process"}
    
    strong_ciphers = [
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
    ]
    
    if all(cipher in line for cipher in strong_ciphers):
        return {"status": "PASS", "reason": "Strong ciphers are configured"}
    else:
        return {"status": "FAIL", "reason": "Weak or missing cipher suites"}

def get_kubelet_config_file_path():
    """
    Get the kubelet config file path from the --config argument.
    Returns the file path or None if not found.
    """
    line = get_process_argument("kubelet", "--config")
    if line and "--config=" in line:
        # Extract the path after --config=
        parts = line.split("--config=")
        if len(parts) > 1:
            config_path = parts[1].split()[0]  # Get first word after --config=
            return config_path
    return None

def get_kubelet_kubeconfig_path():
    """
    Get the kubelet kubeconfig file path from the --kubeconfig argument.
    Returns the file path or None if not found.
    """
    line = get_process_argument("kubelet", "--kubeconfig")
    if line and "--kubeconfig=" in line:
        # Extract the path after --kubeconfig=
        parts = line.split("--kubeconfig=")
        if len(parts) > 1:
            kubeconfig_path = parts[1].split()[0]  # Get first word after --kubeconfig=
            return kubeconfig_path
    return None

def get_kubelet_client_ca_file_path():
    """
    Get the kubelet client CA file path from the --client-ca-file argument.
    Returns the file path or None if not found.
    """
    line = get_process_argument("kubelet", "--client-ca-file")
    if line and "--client-ca-file=" in line:
        # Extract the path after --client-ca-file=
        parts = line.split("--client-ca-file=")
        if len(parts) > 1:
            ca_file_path = parts[1].split()[0]  # Get first word after --client-ca-file=
            return ca_file_path
    return None

def check_proxy_kubeconfig_permissions():
    """
    Check if proxy kubeconfig file exists and has proper permissions (600 or more restrictive).
    Returns status dict with PASS/FAIL and details.
    """
    # Common proxy kubeconfig locations
    proxy_kubeconfig_paths = [
        "/var/lib/kube-proxy/kubeconfig",
        "/etc/kubernetes/kube-proxy.kubeconfig",
        "/var/lib/kube-proxy/kube-proxy.kubeconfig"
    ]
    
    for path in proxy_kubeconfig_paths:
        if os.path.exists(path):
            return check_file_permissions(path, "600")
    
    return {"status": "PASS", "reason": "Proxy kubeconfig file not found (not required)"}

def check_proxy_kubeconfig_ownership():
    """
    Check if proxy kubeconfig file exists and has proper ownership (root:root).
    Returns status dict with PASS/FAIL and details.
    """
    # Common proxy kubeconfig locations
    proxy_kubeconfig_paths = [
        "/var/lib/kube-proxy/kubeconfig",
        "/etc/kubernetes/kube-proxy.kubeconfig",
        "/var/lib/kube-proxy/kube-proxy.kubeconfig"
    ]
    
    for path in proxy_kubeconfig_paths:
        if os.path.exists(path):
            return check_file_ownership(path, "root:root")
    
    return {"status": "PASS", "reason": "Proxy kubeconfig file not found (not required)"}

def check_kubelet_kubeconfig_permissions():
    """
    Check if kubelet kubeconfig file has proper permissions (600 or more restrictive).
    Returns status dict with PASS/FAIL and details.
    """
    kubeconfig_path = get_kubelet_kubeconfig_path()
    if not kubeconfig_path:
        return {"status": "FAIL", "reason": "Kubelet kubeconfig file path not found"}
    
    return check_file_permissions(kubeconfig_path, "600")

def check_kubelet_kubeconfig_ownership():
    """
    Check if kubelet kubeconfig file has proper ownership (root:root).
    Returns status dict with PASS/FAIL and details.
    """
    kubeconfig_path = get_kubelet_kubeconfig_path()
    if not kubeconfig_path:
        return {"status": "FAIL", "reason": "Kubelet kubeconfig file path not found"}
    
    return check_file_ownership(kubeconfig_path, "root:root")

def check_kubelet_ca_file_permissions():
    """
    Check if kubelet client CA file has proper permissions (600 or more restrictive).
    Returns status dict with PASS/FAIL and details.
    """
    ca_file_path = get_kubelet_client_ca_file_path()
    if not ca_file_path:
        return {"status": "FAIL", "reason": "Kubelet client CA file path not found"}
    
    return check_file_permissions(ca_file_path, "600")

def check_kubelet_ca_file_ownership():
    """
    Check if kubelet client CA file has proper ownership (root:root).
    Returns status dict with PASS/FAIL and details.
    """
    ca_file_path = get_kubelet_client_ca_file_path()
    if not ca_file_path:
        return {"status": "FAIL", "reason": "Kubelet client CA file path not found"}
    
    return check_file_ownership(ca_file_path, "root:root")

def check_kubelet_config_file_permissions():
    """
    Check if kubelet config.yaml file has proper permissions (600 or more restrictive).
    Returns status dict with PASS/FAIL and details.
    """
    config_path = get_kubelet_config_file_path()
    if not config_path:
        return {"status": "PASS", "reason": "Kubelet config file not being used (using command line arguments)"}
    
    return check_file_permissions(config_path, "600")

def check_kubelet_config_file_ownership():
    """
    Check if kubelet config.yaml file has proper ownership (root:root).
    Returns status dict with PASS/FAIL and details.
    """
    config_path = get_kubelet_config_file_path()
    if not config_path:
        return {"status": "PASS", "reason": "Kubelet config file not being used (using command line arguments)"}
    
    return check_file_ownership(config_path, "root:root")

def check_kubelet_event_record_qps():
    """
    Check if kubelet eventRecordQPS is set to an appropriate level (not 0, but reasonable value).
    Returns status dict with PASS/FAIL and details.
    """
    # First check command line arguments
    line = get_process_argument("kubelet", "--eventRecordQPS")
    if line and "--eventRecordQPS=" in line:
        # Extract the value after --eventRecordQPS=
        parts = line.split("--eventRecordQPS=")
        if len(parts) > 1:
            value_str = parts[1].split()[0]  # Get first word after --eventRecordQPS=
            try:
                value = int(value_str)
                if value == 0:
                    return {"status": "FAIL", "reason": "eventRecordQPS is set to 0, which could cause DoS due to excessive events"}
                elif value > 0:
                    return {"status": "PASS", "value": f"eventRecordQPS={value}", "reason": "eventRecordQPS is set to an appropriate level"}
                else:
                    return {"status": "FAIL", "reason": f"eventRecordQPS has invalid value: {value}"}
            except ValueError:
                return {"status": "FAIL", "reason": f"eventRecordQPS has non-numeric value: {value_str}"}
    
    # If not found in command line, check config file
    config_path = get_kubelet_config_file_path()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if 'eventRecordQPS' in config:
                value = config['eventRecordQPS']
                if value == 0:
                    return {"status": "FAIL", "reason": "eventRecordQPS is set to 0 in config file, which could cause DoS due to excessive events"}
                elif value > 0:
                    return {"status": "PASS", "value": f"eventRecordQPS={value}", "reason": "eventRecordQPS is set to an appropriate level in config file"}
                else:
                    return {"status": "FAIL", "reason": f"eventRecordQPS has invalid value in config file: {value}"}
            else:
                return {"status": "FAIL", "reason": "eventRecordQPS not found in kubelet config file"}
                
        except Exception as e:
            return {"status": "FAIL", "reason": f"Error reading kubelet config file: {str(e)}"}
    
    return {"status": "FAIL", "reason": "eventRecordQPS not found in command line or config file"}

def check_kubelet_setting_generic(
    cmd_arg, 
    config_key, 
    expected_value=None, 
    nested_path=None,
    default_behavior="fail",
    default_reason="Setting not found"
):
    """
    Generic function to check kubelet settings in both command line and config file.
    
    Args:
        cmd_arg: Command line argument (e.g., "--client-ca-file")
        config_key: Config file key (e.g., "clientCAFile")
        expected_value: Expected value (None means any value is acceptable)
        nested_path: Nested path in config (e.g., ["authentication", "x509"])
        default_behavior: What to do if not found ("pass", "fail", "warn")
        default_reason: Reason when using default behavior
    
    Returns:
        dict: Status with PASS/FAIL and details
    """
    # First check command line arguments
    line = get_process_argument("kubelet", cmd_arg)
    if line and f"{cmd_arg}=" in line:
        # Extract the value after the argument
        parts = line.split(f"{cmd_arg}=")
        if len(parts) > 1:
            value_str = parts[1].split()[0]  # Get first word after the argument
            
            # Validate based on expected value
            if expected_value is not None:
                if value_str == str(expected_value):
                    return {"status": "PASS", "value": f"{cmd_arg}={value_str}", "reason": f"{cmd_arg} is set correctly (command line)"}
                else:
                    return {"status": "FAIL", "reason": f"{cmd_arg} is set to {value_str} in command line, expected {expected_value}"}
            else:
                return {"status": "PASS", "value": f"{cmd_arg}={value_str}", "reason": f"{cmd_arg} is set (command line)"}
    
    # If not found in command line, check config file
    config_path = get_kubelet_config_file_path()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Navigate to nested path if specified
            current_config = config
            if nested_path:
                for key in nested_path:
                    if key in current_config:
                        current_config = current_config[key]
                    else:
                        return {"status": "FAIL", "reason": f"Nested path {' -> '.join(nested_path)} not found in config file"}
            
            if config_key in current_config:
                value = str(current_config[config_key])  # Convert to string for consistent comparison
                
                # Validate based on expected value
                if expected_value is not None:
                    if value == str(expected_value):
                        return {"status": "PASS", "value": f"{config_key}={value}", "reason": f"{config_key} is set correctly (config file)"}
                    else:
                        return {"status": "FAIL", "reason": f"{config_key} is set to {value} in config file, expected {expected_value}"}
                else:
                    return {"status": "PASS", "value": f"{config_key}={value}", "reason": f"{config_key} is set (config file)"}
            else:
                # Handle default behavior when setting is not found
                if default_behavior == "pass":
                    return {"status": "PASS", "reason": f"{config_key} not found in config file ({default_reason})"}
                elif default_behavior == "warn":
                    return {"status": "WARN", "reason": f"{config_key} not found in config file ({default_reason})"}
                else:  # fail
                    return {"status": "FAIL", "reason": f"{config_key} not found in config file ({default_reason})"}
                
        except Exception as e:
            return {"status": "FAIL", "reason": f"Error reading kubelet config file: {str(e)}"}
    
    # If no config file, handle default behavior
    if default_behavior == "pass":
        return {"status": "PASS", "reason": f"{cmd_arg} not found in command line ({default_reason})"}
    elif default_behavior == "warn":
        return {"status": "WARN", "reason": f"{cmd_arg} not found in command line ({default_reason})"}
    else:  # fail
        return {"status": "FAIL", "reason": f"{cmd_arg} not found in command line or config file ({default_reason})"}

def check_kubelet_read_only_port():
    """
    Check if kubelet read-only-port is set to 0 (either via command line or config file).
    Returns status dict with PASS/FAIL and details.
    """
    return check_kubelet_setting_generic(
        cmd_arg="--read-only-port",
        config_key="readOnlyPort",
        expected_value="0",
        default_behavior="pass",
        default_reason="defaults to 0"
    )

def check_kubelet_client_ca_file():
    """
    Check if kubelet client-ca-file is set (either via command line or config file).
    Returns status dict with PASS/FAIL and details.
    """
    return check_kubelet_setting_generic(
        cmd_arg="--client-ca-file",
        config_key="clientCAFile",
        expected_value=None,  # Any value is acceptable
        nested_path=["authentication", "x509"],
        default_behavior="fail",
        default_reason="client CA file must be specified"
    )

def check_kubelet_streaming_connection_idle_timeout():
    """
    Check if kubelet streaming-connection-idle-timeout is not set to 0.
    Returns status dict with PASS/FAIL and details.
    """
    # First check command line
    line = get_process_argument("kubelet", "--streaming-connection-idle-timeout")
    if line and "--streaming-connection-idle-timeout=" in line:
        parts = line.split("--streaming-connection-idle-timeout=")
        if len(parts) > 1:
            value_str = parts[1].split()[0]
            try:
                value = int(value_str)
                if value == 0:
                    return {"status": "FAIL", "reason": "streaming-connection-idle-timeout is set to 0 in command line"}
                else:
                    return {"status": "PASS", "value": f"streaming-connection-idle-timeout={value}", "reason": "streaming-connection-idle-timeout is not 0 (command line)"}
            except ValueError:
                return {"status": "FAIL", "reason": f"streaming-connection-idle-timeout has non-numeric value: {value_str}"}
    
    # Check config file
    config_path = get_kubelet_config_file_path()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if 'streamingConnectionIdleTimeout' in config:
                value = config['streamingConnectionIdleTimeout']
                # Handle duration strings like "0s", "30s", etc.
                if isinstance(value, str) and value.endswith('s'):
                    try:
                        numeric_value = int(value[:-1])
                        if numeric_value == 0:
                            return {"status": "FAIL", "reason": "streamingConnectionIdleTimeout is set to 0 in config file"}
                        else:
                            return {"status": "PASS", "value": f"streamingConnectionIdleTimeout={value}", "reason": "streamingConnectionIdleTimeout is not 0 (config file)"}
                    except ValueError:
                        return {"status": "FAIL", "reason": f"streamingConnectionIdleTimeout has invalid duration format: {value}"}
                elif value == 0:
                    return {"status": "FAIL", "reason": "streamingConnectionIdleTimeout is set to 0 in config file"}
                else:
                    return {"status": "PASS", "value": f"streamingConnectionIdleTimeout={value}", "reason": "streamingConnectionIdleTimeout is not 0 (config file)"}
            else:
                return {"status": "PASS", "reason": "streamingConnectionIdleTimeout not found in config file (defaults to non-zero)"}
        except Exception as e:
            return {"status": "FAIL", "reason": f"Error reading kubelet config file: {str(e)}"}
    
    return {"status": "PASS", "reason": "streaming-connection-idle-timeout not found in command line (defaults to non-zero)"}

def check_kubelet_make_iptables_util_chains():
    """
    Check if kubelet make-iptables-util-chains is set to true.
    Returns status dict with PASS/FAIL and details.
    """
    return check_kubelet_setting_generic(
        cmd_arg="--make-iptables-util-chains",
        config_key="makeIPTablesUtilChains",
        expected_value="true",
        default_behavior="fail",
        default_reason="make iptables util chains must be enabled"
    )

def check_kubelet_tls_cert_and_key():
    """
    Check if kubelet TLS cert and key files are set.
    Returns status dict with PASS/FAIL and details.
    """
    # Check command line arguments
    cert_line = get_process_argument("kubelet", "--tls-cert-file")
    key_line = get_process_argument("kubelet", "--tls-private-key-file")
    
    if cert_line and key_line and "--tls-cert-file=" in cert_line and "--tls-private-key-file=" in key_line:
        return {"status": "PASS", "reason": "TLS cert and key files are set (command line)"}
    
    # Check config file
    config_path = get_kubelet_config_file_path()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if 'tlsCertFile' in config and 'tlsPrivateKeyFile' in config:
                return {"status": "PASS", "reason": "TLS cert and key files are set (config file)"}
            else:
                return {"status": "FAIL", "reason": "TLS cert and key files not found in config file"}
        except Exception as e:
            return {"status": "FAIL", "reason": f"Error reading kubelet config file: {str(e)}"}
    
    return {"status": "FAIL", "reason": "TLS cert and key files not found in command line or config file"}

def check_kubelet_rotate_certificates():
    """
    Check if kubelet rotate-certificates is not set to false.
    Returns status dict with PASS/FAIL and details.
    """
    # Check command line
    line = get_process_argument("kubelet", "--rotate-certificates")
    if line and "--rotate-certificates=" in line:
        parts = line.split("--rotate-certificates=")
        if len(parts) > 1:
            value_str = parts[1].split()[0]
            if value_str == "false":
                return {"status": "FAIL", "reason": "rotate-certificates is set to false in command line"}
            else:
                return {"status": "PASS", "value": f"rotate-certificates={value_str}", "reason": "rotate-certificates is not false (command line)"}
    
    # Check config file
    config_path = get_kubelet_config_file_path()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if 'rotateCertificates' in config:
                value = config['rotateCertificates']
                if value == False:
                    return {"status": "FAIL", "reason": "rotateCertificates is set to false in config file"}
                else:
                    return {"status": "PASS", "value": f"rotateCertificates={value}", "reason": "rotateCertificates is not false (config file)"}
            else:
                return {"status": "PASS", "reason": "rotateCertificates not found in config file (defaults to true)"}
        except Exception as e:
            return {"status": "FAIL", "reason": f"Error reading kubelet config file: {str(e)}"}
    
    return {"status": "PASS", "reason": "rotate-certificates not found in command line (defaults to true)"}

def check_kubelet_tls_cipher_suites_config():
    """
    Check if kubelet TLS cipher suites are set to strong values in config file.
    Returns status dict with PASS/FAIL and details.
    """
    # Check command line first
    line = get_process_argument("kubelet", "--tls-cipher-suites")
    if line and "--tls-cipher-suites=" in line:
        return check_kubelet_tls_cipher_suites()  # Use existing function
    
    # Check config file
    config_path = get_kubelet_config_file_path()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if 'tlsCipherSuites' in config:
                ciphers = config['tlsCipherSuites']
                if isinstance(ciphers, list):
                    strong_ciphers = [
                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                        "TLS_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    ]
                    if all(cipher in ciphers for cipher in strong_ciphers):
                        return {"status": "PASS", "value": f"tlsCipherSuites={ciphers}", "reason": "Strong ciphers are configured (config file)"}
                    else:
                        return {"status": "FAIL", "reason": "Weak or missing cipher suites in config file"}
                else:
                    return {"status": "FAIL", "reason": "tlsCipherSuites is not a list in config file"}
            else:
                return {"status": "FAIL", "reason": "tlsCipherSuites not found in config file"}
        except Exception as e:
            return {"status": "FAIL", "reason": f"Error reading kubelet config file: {str(e)}"}
    
    return {"status": "FAIL", "reason": "tls-cipher-suites not found in command line or config file"}

def check_kubelet_pod_max_pids():
    """
    Check if kubelet pod-max-pids is set (either via command line or config file).
    Returns status dict with PASS/FAIL and details.
    """
    return check_kubelet_setting_generic(
        cmd_arg="--pod-max-pids",
        config_key="podPidsLimit",
        expected_value=None,  # Any value is acceptable
        default_behavior="warn",
        default_reason="no limit in place"
    )

def check_kubelet_authorization_mode():
    """
    Check if kubelet authorization-mode is not set to AlwaysAllow.
    Returns status dict with PASS/FAIL and details.
    """
    # First check command line arguments
    line = get_process_argument("kubelet", "--authorization-mode")
    if line and "--authorization-mode=" in line:
        # Extract the value after --authorization-mode=
        parts = line.split("--authorization-mode=")
        if len(parts) > 1:
            value_str = parts[1].split()[0]  # Get first word after the argument
            if value_str == "AlwaysAllow":
                return {"status": "FAIL", "reason": "authorization-mode is set to AlwaysAllow in command line"}
            else:
                return {"status": "PASS", "value": f"authorization-mode={value_str}", "reason": "authorization-mode is not AlwaysAllow (command line)"}
    
    # If not found in command line, check config file
    config_path = get_kubelet_config_file_path()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Check for authorization.mode in config
            if 'authorization' in config and 'mode' in config['authorization']:
                value = str(config['authorization']['mode'])
                if value == "AlwaysAllow":
                    return {"status": "FAIL", "reason": "authorization.mode is set to AlwaysAllow in config file"}
                else:
                    return {"status": "PASS", "value": f"authorization.mode={value}", "reason": "authorization.mode is not AlwaysAllow (config file)"}
            else:
                return {"status": "PASS", "reason": "authorization.mode not found in config file (defaults to non-AlwaysAllow)"}
                
        except Exception as e:
            return {"status": "FAIL", "reason": f"Error reading kubelet config file: {str(e)}"}
    
    return {"status": "PASS", "reason": "authorization-mode not found in command line (defaults to non-AlwaysAllow)"}

def check_kubelet_seccomp_default():
    """
    Check if kubelet seccomp-default is set to true.
    Returns status dict with PASS/FAIL and details.
    """
    return check_kubelet_setting_generic(
        cmd_arg="--seccomp-default",
        config_key="seccompDefault",
        expected_value="true",
        default_behavior="fail",
        default_reason="seccomp profile is not enabled"
    )

def check_kubelet_ip_address_deny():
    """
    Check if kubelet IPAddressDeny is set to any.
    Returns status dict with PASS/FAIL and details.
    """
    return check_kubelet_setting_generic(
        cmd_arg="--IPAddressDeny",
        config_key="IPAddressDeny",
        expected_value="any",
        default_behavior="fail",
        default_reason="IP address restrictions are not enabled"
    )

def check_kube_proxy_metrics_bind_address():
    """
    Check if kube-proxy metrics-bind-address is set to 127.0.0.1.
    Returns status dict with PASS/FAIL and details.
    """
    # First check command line arguments
    line = get_process_argument("kube-proxy", "--metrics-bind-address")
    if line and "--metrics-bind-address=" in line:
        # Extract the value after --metrics-bind-address=
        parts = line.split("--metrics-bind-address=")
        if len(parts) > 1:
            value_str = parts[1].split()[0]  # Get first word after the argument
            if value_str == "127.0.0.1":
                return {"status": "PASS", "value": f"metrics-bind-address={value_str}", "reason": "metrics-bind-address is set to localhost (command line)"}
            else:
                return {"status": "FAIL", "reason": f"metrics-bind-address is set to {value_str} in command line, expected 127.0.0.1"}
    
    # If not found in command line, check config file
    config_path = get_kube_proxy_config_file_path()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if 'metricsBindAddress' in config:
                value = str(config['metricsBindAddress'])
                if value == "127.0.0.1":
                    return {"status": "PASS", "value": f"metricsBindAddress={value}", "reason": "metricsBindAddress is set to localhost (config file)"}
                else:
                    return {"status": "FAIL", "reason": f"metricsBindAddress is set to {value} in config file, expected 127.0.0.1"}
            else:
                return {"status": "PASS", "reason": "metricsBindAddress not found in config file (defaults to 127.0.0.1)"}
                
        except Exception as e:
            return {"status": "FAIL", "reason": f"Error reading kube-proxy config file: {str(e)}"}
    
    return {"status": "PASS", "reason": "metrics-bind-address not found in command line (defaults to 127.0.0.1)"}

def get_kube_proxy_config_file_path():
    """
    Get the kube-proxy config file path from the --config argument.
    Returns the file path or None if not found.
    """
    line = get_process_argument("kube-proxy", "--config")
    if line and "--config=" in line:
        # Extract the path after --config=
        parts = line.split("--config=")
        if len(parts) > 1:
            config_path = parts[1].split()[0]  # Get first word after --config=
            return config_path
    return None

def check_cluster_admin_role_usage():
    """
    Check if cluster-admin role is only used where required.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        # Get clusterrolebindings
        result = subprocess.run([
            'kubectl', 'get', 'clusterrolebindings', 
            '-o=custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name',
            '--no-headers'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        violations = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 3:
                role_name = parts[0]
                role_binding = parts[1]
                subject = ' '.join(parts[2:]) if len(parts) > 2 else ''
                
                # Check if role_name is not cluster-admin but role_binding is cluster-admin
                if role_name != "cluster-admin" and role_binding == "cluster-admin":
                    violations.append(f"Role {role_name} bound to cluster-admin role")
        
        if violations:
            return {
                "status": "FAIL", 
                "reason": f"Found {len(violations)} violations: {'; '.join(violations)}"
            }
        else:
            return {"status": "PASS", "reason": "No inappropriate cluster-admin role bindings found"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}

def check_secrets_access():
    """
    Check if system:authenticated can get, list, watch secrets.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        result = subprocess.run([
            'kubectl', 'auth', 'can-i', 'get,list,watch', 'secrets', 
            '--all-namespaces', '--as=system:authenticated'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        can_access = result.stdout.strip().lower()
        if can_access == "no":
            return {"status": "PASS", "reason": "system:authenticated cannot access secrets"}
        else:
            return {"status": "FAIL", "reason": f"system:authenticated can access secrets: {can_access}"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}

def check_roles_wildcard_usage():
    """
    Check for wildcard usage in Roles and ClusterRoles.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        violations = []
        
        # Check Roles
        result = subprocess.run([
            'kubectl', 'get', 'roles', '--all-namespaces',
            '-o', 'custom-columns=ROLE_NAMESPACE:.metadata.namespace,ROLE_NAME:.metadata.name',
            '--no-headers'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                role_namespace = parts[0]
                role_name = parts[1]
                
                # Get role rules
                role_result = subprocess.run([
                    'kubectl', 'get', 'role', '-n', role_namespace, role_name, '-o=json'
                ], stdout=subprocess.PIPE, text=True, check=True)
                
                role_data = json.loads(role_result.stdout)
                rules = role_data.get('rules', [])
                
                for rule in rules:
                    for key, values in rule.items():
                        if isinstance(values, list) and '["*"]' in str(values):
                            violations.append(f"Role {role_name} in namespace {role_namespace} has wildcard in {key}")
        
        # Check ClusterRoles
        result = subprocess.run([
            'kubectl', 'get', 'clusterroles',
            '-o', 'custom-columns=CLUSTERROLE_NAME:.metadata.name',
            '--no-headers'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            clusterrole_name = line.strip()
            
            # Get clusterrole rules
            role_result = subprocess.run([
                'kubectl', 'get', 'clusterrole', clusterrole_name, '-o=json'
            ], stdout=subprocess.PIPE, text=True, check=True)
            
            role_data = json.loads(role_result.stdout)
            rules = role_data.get('rules', [])
            
            for rule in rules:
                for key, values in rule.items():
                    if isinstance(values, list) and '["*"]' in str(values):
                        violations.append(f"ClusterRole {clusterrole_name} has wildcard in {key}")
        
        if violations:
            return {
                "status": "FAIL", 
                "reason": f"Found {len(violations)} wildcard violations: {'; '.join(violations)}"
            }
        else:
            return {"status": "PASS", "reason": "No wildcard usage found in Roles and ClusterRoles"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}

def check_pods_create_access():
    """
    Check if system:authenticated can create pods.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        result = subprocess.run([
            'kubectl', 'auth', 'can-i', 'create', 'pods', 
            '--all-namespaces', '--as=system:authenticated'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        can_create = result.stdout.strip().lower()
        if can_create == "no":
            return {"status": "PASS", "reason": "system:authenticated cannot create pods"}
        else:
            return {"status": "FAIL", "reason": f"system:authenticated can create pods: {can_create}"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}

def check_default_service_accounts():
    """
    Check if default service accounts are not actively used (automountServiceAccountToken: false).
    Returns status dict with PASS/FAIL and details.
    """
    try:
        result = subprocess.run([
            'kubectl', 'get', 'serviceaccount', '--all-namespaces',
            '--field-selector', 'metadata.name=default', '-o=json'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        data = json.loads(result.stdout)
        items = data.get('items', [])
        
        violations = []
        for item in items:
            namespace = item['metadata']['namespace']
            automount_token = item.get('automountServiceAccountToken')
            
            # If automountServiceAccountToken is not explicitly set to false, it's a violation
            if automount_token is not False:
                violations.append(f"Default service account in namespace {namespace} has automountServiceAccountToken: {automount_token}")
        
        if violations:
            return {
                "status": "FAIL", 
                "reason": f"Found {len(violations)} violations: {'; '.join(violations)}"
            }
        else:
            return {"status": "PASS", "reason": "All default service accounts have automountServiceAccountToken: false"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


# ------------------------------------------------------ API Server rules --------------------------------------------------------------------------------------

def check_apiserver_anonymous_auth_false():
    """
    CIS 1.2.1: Ensure that the --anonymous-auth argument is set to false (Manual)
    Checks the running kube-apiserver process for --anonymous-auth=false.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        # Get process arguments of kube-apiserver
        result = subprocess.run(
            ["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True
        )
        found = False
        for line in result.stdout.splitlines():
            if "kube-apiserver" in line and "--anonymous-auth" in line:
                found = True
                if "--anonymous-auth=false" in line:
                    return {
                        "status": "PASS",
                        "reason": "--anonymous-auth is explicitly set to false"
                    }
                else:
                    return {
                        "status": "FAIL",
                        "reason": "--anonymous-auth is not set to false"
                    }

        if not found:
            return {
                "status": "FAIL",
                "reason": "--anonymous-auth argument not found in kube-apiserver process"
            }

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


def check_apiserver_token_auth_file_not_set():
    """
    CIS 1.2.2: Ensure that the --token-auth-file parameter is NOT set (Automated)
    Verifies that kube-apiserver does not use static token auth.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        result = subprocess.run(
            ["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if "kube-apiserver" in line:
                # Handle both common spellings seen in CIS docs/flags
                if ("--token-auth-file" in line) or ("--token-authfile" in line):
                    # Try to surface the exact token flag usage for clarity
                    match_snippet = []
                    for flag in ["--token-auth-file", "--token-authfile"]:
                        if flag in line:
                            # Extract the flag+value snippet if present
                            part = line.split(flag, 1)[1].strip()
                            value = part.split()[0] if part else ""
                            match_snippet.append(flag + (value and value[0] == "=" and value or ""))

                    reason = "Static token auth flag present"
                    if match_snippet:
                        reason += f" ({', '.join(match_snippet)})"
                    return {"status": "FAIL", "reason": reason}

        return {"status": "PASS", "reason": "--token-auth-file not set on kube-apiserver"}

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


def check_apiserver_deny_service_external_ips():
    """
    CIS 1.2.3: Ensure that the DenyServiceExternalIPs admission controller is set (Manual)
    Checks if --enable-admission-plugins includes DenyServiceExternalIPs for kube-apiserver.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        result = subprocess.run(
            ["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True
        )

        for line in result.stdout.splitlines():
            if "kube-apiserver" in line and "--enable-admission-plugins" in line:
                if "DenyServiceExternalIPs" in line:
                    return {
                        "status": "PASS",
                        "reason": "DenyServiceExternalIPs is enabled in --enable-admission-plugins"
                    }
                else:
                    return {
                        "status": "FAIL",
                        "reason": "DenyServiceExternalIPs not found in --enable-admission-plugins"
                    }

        return {
            "status": "FAIL",
            "reason": "--enable-admission-plugins not found in kube-apiserver process"
        }

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


def check_apiserver_kubelet_client_cert_and_key_set():
    """
    CIS 1.2.4: Ensure that --kubelet-client-certificate and --kubelet-client-key are set (Automated)
    Primary: scan running kube-apiserver process flags.
    Fallback: inspect kube-apiserver pod command via kubectl.
    Returns status dict with PASS/FAIL and details.
    """
    cert_flag = "--kubelet-client-certificate"
    key_flag = "--kubelet-client-key"

    try:
        # --- Primary: process list check ---
        ps = subprocess.run(["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True)

        cert_found, key_found = False, False
        cert_val, key_val = None, None

        for line in ps.stdout.splitlines():
            if "kube-apiserver" in line:
                if cert_flag in line:
                    cert_found = True
                    if cert_flag + "=" in line:
                        cert_val = line.split(cert_flag + "=", 1)[1].split()[0]
                if key_flag in line:
                    key_found = True
                    if key_flag + "=" in line:
                        key_val = line.split(key_flag + "=", 1)[1].split()[0]

        if cert_found or key_found:
            if cert_found and key_found:
                return {
                    "status": "PASS",
                    "reason": "Both kubelet client cert and key flags are set on kube-apiserver",
                    "values": {"certificate": cert_val, "key": key_val}
                }
            else:
                missing = []
                if not cert_found: missing.append(cert_flag)
                if not key_found:  missing.append(key_flag)
                return {"status": "FAIL", "reason": f"Missing flag(s): {', '.join(missing)}"}

        # --- Fallback: static pod deployments via kubectl ---
        try:
            k = subprocess.run(
                [
                    "kubectl", "get", "pod", "-n", "kube-system",
                    "-l", "component=kube-apiserver",
                    "-o", "jsonpath={range .items[*]}{.spec.containers[*].command}{\"\\n\"}{end}"
                ],
                stdout=subprocess.PIPE, text=True, check=True
            )
            cmd = k.stdout or ""
            cert_found = cert_flag in cmd
            key_found = key_flag in cmd

            if cert_found and key_found:
                # Try to capture values if provided with '='
                def extract(flag, s):
                    if flag + "=" in s:
                        return s.split(flag + "=", 1)[1].split()[0]
                    return None
                return {
                    "status": "PASS",
                    "reason": "Both kubelet client cert and key flags are set on kube-apiserver (pod)",
                    "values": {
                        "certificate": extract(cert_flag, cmd),
                        "key": extract(key_flag, cmd)
                    }
                }
            missing = []
            if not cert_found: missing.append(cert_flag)
            if not key_found:  missing.append(key_flag)
            return {"status": "FAIL", "reason": f"Missing flag(s): {', '.join(missing)} (pod)"}

        except subprocess.CalledProcessError as e:
            return {"status": "FAIL", "reason": f"kubectl error during fallback: {str(e)}"}

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


def check_apiserver_kubelet_ca_set():
    """
    CIS 1.2.5: Ensure that the --kubelet-certificate-authority argument is set (Automated)
    Primary: scan kube-apiserver process args.
    Fallback: inspect kube-apiserver pod command via kubectl.
    Returns status dict with PASS/FAIL and details.
    """
    flag = "--kubelet-certificate-authority"

    try:
        # --- Primary: process list check ---
        ps = subprocess.run(["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True)

        apiserver_seen = False
        for line in ps.stdout.splitlines():
            if "kube-apiserver" in line:
                apiserver_seen = True
                if flag in line:
                    value = None
                    if f"{flag}=" in line:
                        value = line.split(f"{flag}=", 1)[1].split()[0]
                    return {
                        "status": "PASS",
                        "reason": f"{flag} is set on kube-apiserver",
                        "value": value
                    }

        if apiserver_seen:
            return {
                "status": "FAIL",
                "reason": f"{flag} not found in kube-apiserver process"
            }

        # --- Fallback: static pod check via kubectl ---
        try:
            k = subprocess.run(
                [
                    "kubectl", "get", "pod", "-n", "kube-system",
                    "-l", "component=kube-apiserver",
                    "-o", "jsonpath={range .items[*]}{.spec.containers[*].command}{\"\\n\"}{end}"
                ],
                stdout=subprocess.PIPE, text=True, check=True
            )
            cmd = k.stdout or ""
            if flag in cmd:
                # Try to extract the value if provided with '='
                value = None
                if f"{flag}=" in cmd:
                    value = cmd.split(f"{flag}=", 1)[1].split()[0]
                return {
                    "status": "PASS",
                    "reason": f"{flag} is set on kube-apiserver (pod)",
                    "value": value
                }
            return {
                "status": "FAIL",
                "reason": f"{flag} not found in kube-apiserver (pod)"
            }

        except subprocess.CalledProcessError as e:
            return {"status": "FAIL", "reason": f"kubectl error during fallback: {str(e)}"}

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


def check_apiserver_authorization_mode_not_always_allow():
    """
    CIS 1.2.6: Ensure that --authorization-mode is NOT set to AlwaysAllow (Automated)
    Scans kube-apiserver args; passes if AlwaysAllow is absent from the mode list.
    If the flag is missing, returns PASS (modern defaults are non-AlwaysAllow).
    """
    try:
        ps = subprocess.run(["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True)

        apiserver_seen = False
        for line in ps.stdout.splitlines():
            if "kube-apiserver" in line:
                apiserver_seen = True
                if "--authorization-mode=" in line:
                    value = line.split("--authorization-mode=", 1)[1].split()[0]
                    # value may be comma-separated, e.g., "Node,RBAC"
                    modes = [m.strip() for m in value.split(",") if m.strip()]
                    if any(m.lower() == "alwaysallow" for m in modes):
                        return {"status": "FAIL", "reason": f"authorization-mode includes AlwaysAllow ({value})"}
                    return {"status": "PASS", "value": value, "reason": "authorization-mode does not include AlwaysAllow"}

        if apiserver_seen:
            # Flag not present; modern default modes are non-AlwaysAllow
            return {"status": "PASS", "reason": "authorization-mode flag not set (defaults to non-AlwaysAllow)"}

        return {"status": "FAIL", "reason": "kube-apiserver process not found"}

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}



def check_apiserver_authorization_mode_includes_node():
    """
    CIS 1.2.7: Ensure that --authorization-mode includes Node (Automated)
    Scans kube-apiserver args for --authorization-mode and verifies 'Node' is present.
    Returns PASS if Node is included, FAIL otherwise.
    """
    try:
        ps = subprocess.run(["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True)

        for line in ps.stdout.splitlines():
            if "kube-apiserver" in line and "--authorization-mode=" in line:
                value = line.split("--authorization-mode=", 1)[1].split()[0]
                modes = [m.strip() for m in value.split(",") if m.strip()]
                if any(m.lower() == "node" for m in modes):
                    return {"status": "PASS", "value": value, "reason": "authorization-mode includes Node"}
                else:
                    return {"status": "FAIL", "reason": f"authorization-mode does not include Node ({value})"}

        # If the flag not present, defaults don’t include Node → FAIL
        return {"status": "FAIL", "reason": "authorization-mode not set (defaults exclude Node)"}

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


def check_apiserver_authorization_mode_includes_rbac():
    """
    CIS 1.2.8: Ensure that --authorization-mode includes RBAC (Automated)
    Scans kube-apiserver args for --authorization-mode and verifies 'RBAC' is present.
    Returns PASS if RBAC is included, FAIL otherwise.
    """
    try:
        ps = subprocess.run(["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True)

        for line in ps.stdout.splitlines():
            if "kube-apiserver" in line and "--authorization-mode=" in line:
                value = line.split("--authorization-mode=", 1)[1].split()[0]
                modes = [m.strip() for m in value.split(",") if m.strip()]
                if any(m.lower() == "rbac" for m in modes):
                    return {"status": "PASS", "value": value, "reason": "authorization-mode includes RBAC"}
                else:
                    return {"status": "FAIL", "reason": f"authorization-mode does not include RBAC ({value})"}

        # If the flag is not present, defaults don’t include RBAC → FAIL
        return {"status": "FAIL", "reason": "authorization-mode not set (defaults exclude RBAC)"}

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


def check_apiserver_eventratelimit_enabled():
    """
    CIS 1.2.9: Ensure that the EventRateLimit admission control plugin is set (Manual)
    Verifies that --enable-admission-plugins on kube-apiserver includes 'EventRateLimit'.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        result = subprocess.run(
            ["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True
        )

        for line in result.stdout.splitlines():
            if "kube-apiserver" in line and "--enable-admission-plugins" in line:
                # Extract the value after the flag, if present as --enable-admission-plugins=...
                if "EventRateLimit" in line:
                    return {
                        "status": "PASS",
                        "reason": "EventRateLimit is enabled in --enable-admission-plugins"
                    }
                else:
                    return {
                        "status": "FAIL",
                        "reason": "EventRateLimit not found in --enable-admission-plugins"
                    }

        return {
            "status": "FAIL",
            "reason": "--enable-admission-plugins not found in kube-apiserver process"
        }

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


def check_apiserver_no_always_admit():
    """
    CIS 1.2.10: Ensure that the AlwaysAdmit admission control plugin is NOT set (Automated)
    Verifies that --enable-admission-plugins, if present, does not include 'AlwaysAdmit'.
    If the flag is absent, returns PASS (defaults exclude AlwaysAdmit).
    """
    try:
        ps = subprocess.run(["ps", "-ef"], stdout=subprocess.PIPE, text=True, check=True)

        apiserver_seen = False
        for line in ps.stdout.splitlines():
            if "kube-apiserver" in line:
                apiserver_seen = True
                if "--enable-admission-plugins" in line:
                    if "AlwaysAdmit" in line:
                        return {
                            "status": "FAIL",
                            "reason": "AlwaysAdmit is included in --enable-admission-plugins"
                        }
                    else:
                        return {
                            "status": "PASS",
                            "reason": "AlwaysAdmit not present in --enable-admission-plugins"
                        }

        if apiserver_seen:
            # Flag not present; defaults do NOT include AlwaysAdmit
            return {"status": "PASS", "reason": "--enable-admission-plugins not set (defaults exclude AlwaysAdmit)"}

        return {"status": "FAIL", "reason": "kube-apiserver process not found"}

    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running ps command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}


# --------------------------------------------------------- Policies rules ------------------------------------------------------------------------------------------

def check_cluster_admin_role_usage():
    """
    Check if cluster-admin role is only used where required.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        # Get clusterrolebindings
        result = subprocess.run([
            'kubectl', 'get', 'clusterrolebindings', 
            '-o=custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name',
            '--no-headers'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        violations = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 3:
                role_name = parts[0]
                role_binding = parts[1]
                subject = ' '.join(parts[2:]) if len(parts) > 2 else ''
                
                # Check if role_name is not cluster-admin but role_binding is cluster-admin
                if role_name != "cluster-admin" and role_binding == "cluster-admin":
                    violations.append(f"Role {role_name} bound to cluster-admin role")
        
        if violations:
            return {
                "status": "FAIL", 
                "reason": f"Found {len(violations)} violations: {'; '.join(violations)}"
            }
        else:
            return {"status": "PASS", "reason": "No inappropriate cluster-admin role bindings found"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}

def check_secrets_access():
    """
    Check if system:authenticated can get, list, watch secrets.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        result = subprocess.run([
            'kubectl', 'auth', 'can-i', 'get,list,watch', 'secrets', 
            '--all-namespaces', '--as=system:authenticated'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        can_access = result.stdout.strip().lower()
        if can_access == "no":
            return {"status": "PASS", "reason": "system:authenticated cannot access secrets"}
        else:
            return {"status": "FAIL", "reason": f"system:authenticated can access secrets: {can_access}"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}

def check_roles_wildcard_usage():
    """
    Check for wildcard usage in Roles and ClusterRoles.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        violations = []
        
        # Check Roles
        result = subprocess.run([
            'kubectl', 'get', 'roles', '--all-namespaces',
            '-o', 'custom-columns=ROLE_NAMESPACE:.metadata.namespace,ROLE_NAME:.metadata.name',
            '--no-headers'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                role_namespace = parts[0]
                role_name = parts[1]
                
                # Get role rules
                role_result = subprocess.run([
                    'kubectl', 'get', 'role', '-n', role_namespace, role_name, '-o=json'
                ], stdout=subprocess.PIPE, text=True, check=True)
                
                role_data = json.loads(role_result.stdout)
                rules = role_data.get('rules', [])
                
                for rule in rules:
                    for key, values in rule.items():
                        if isinstance(values, list) and '["*"]' in str(values):
                            violations.append(f"Role {role_name} in namespace {role_namespace} has wildcard in {key}")
        
        # Check ClusterRoles
        result = subprocess.run([
            'kubectl', 'get', 'clusterroles',
            '-o', 'custom-columns=CLUSTERROLE_NAME:.metadata.name',
            '--no-headers'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            clusterrole_name = line.strip()
            
            # Get clusterrole rules
            role_result = subprocess.run([
                'kubectl', 'get', 'clusterrole', clusterrole_name, '-o=json'
            ], stdout=subprocess.PIPE, text=True, check=True)
            
            role_data = json.loads(role_result.stdout)
            rules = role_data.get('rules', [])
            
            for rule in rules:
                for key, values in rule.items():
                    if isinstance(values, list) and '["*"]' in str(values):
                        violations.append(f"ClusterRole {clusterrole_name} has wildcard in {key}")
        
        if violations:
            return {
                "status": "FAIL", 
                "reason": f"Found {len(violations)} wildcard violations: {'; '.join(violations)}"
            }
        else:
            return {"status": "PASS", "reason": "No wildcard usage found in Roles and ClusterRoles"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}

def check_pods_create_access():
    """
    Check if system:authenticated can create pods.
    Returns status dict with PASS/FAIL and details.
    """
    try:
        result = subprocess.run([
            'kubectl', 'auth', 'can-i', 'create', 'pods', 
            '--all-namespaces', '--as=system:authenticated'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        can_create = result.stdout.strip().lower()
        if can_create == "no":
            return {"status": "PASS", "reason": "system:authenticated cannot create pods"}
        else:
            return {"status": "FAIL", "reason": f"system:authenticated can create pods: {can_create}"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}

def check_default_service_accounts():
    """
    Check if default service accounts are not actively used (automountServiceAccountToken: false).
    Returns status dict with PASS/FAIL and details.
    """
    try:
        result = subprocess.run([
            'kubectl', 'get', 'serviceaccount', '--all-namespaces',
            '--field-selector', 'metadata.name=default', '-o=json'
        ], stdout=subprocess.PIPE, text=True, check=True)
        
        data = json.loads(result.stdout)
        items = data.get('items', [])
        
        violations = []
        for item in items:
            namespace = item['metadata']['namespace']
            automount_token = item.get('automountServiceAccountToken')
            
            # If automountServiceAccountToken is not explicitly set to false, it's a violation
            if automount_token is not False:
                violations.append(f"Default service account in namespace {namespace} has automountServiceAccountToken: {automount_token}")
        
        if violations:
            return {
                "status": "FAIL", 
                "reason": f"Found {len(violations)} violations: {'; '.join(violations)}"
            }
        else:
            return {"status": "PASS", "reason": "All default service accounts have automountServiceAccountToken: false"}
            
    except subprocess.CalledProcessError as e:
        return {"status": "FAIL", "reason": f"Error running kubectl command: {str(e)}"}
    except Exception as e:
        return {"status": "FAIL", "reason": f"Unexpected error: {str(e)}"}
