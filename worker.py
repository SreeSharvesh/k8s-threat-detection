import json
from helper import (
    get_process_argument,
    check_process_argument_set,
    check_process_feature_gate,
    check_kubelet_feature_gate,
    check_file_permissions,
    check_file_ownership,
    check_kubelet_tls_cipher_suites,
    check_proxy_kubeconfig_permissions,
    check_proxy_kubeconfig_ownership,
    check_kubelet_kubeconfig_permissions,
    check_kubelet_kubeconfig_ownership,
    check_kubelet_ca_file_permissions,
    check_kubelet_ca_file_ownership,
    check_kubelet_config_file_permissions,
    check_kubelet_config_file_ownership,
    check_kubelet_event_record_qps,
    check_kubelet_read_only_port,
    check_kubelet_client_ca_file,
    check_kubelet_streaming_connection_idle_timeout,
    check_kubelet_make_iptables_util_chains,
    check_kubelet_tls_cert_and_key,
    check_kubelet_rotate_certificates,
    check_kubelet_tls_cipher_suites_config,
    check_kubelet_pod_max_pids,
    check_kubelet_authorization_mode,
    check_kubelet_seccomp_default,
    check_kubelet_ip_address_deny,
    check_kube_proxy_metrics_bind_address
)

RULES = [
    # 4.1 Kubelet Service File Checks
    ("4.1.1", "Ensure that the kubelet service file permissions are set to 600 or more restrictive (Automated)",
        lambda: check_file_permissions("/etc/systemd/system/kubelet.service.d/kubeadm.conf", "600")),
    
    ("4.1.2", "Ensure that the kubelet service file ownership is set to root:root (Automated)",
        lambda: check_file_ownership("/etc/systemd/system/kubelet.service.d/kubeadm.conf", "root:root")),
    
    ("4.1.3", "If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive (Manual)",
        lambda: check_proxy_kubeconfig_permissions()),
    
    ("4.1.4", "If proxy kubeconfig file exists ensure ownership is set to root:root (Manual)",
        lambda: check_proxy_kubeconfig_ownership()),
    
    ("4.1.5", "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive (Automated)",
        lambda: check_kubelet_kubeconfig_permissions()),
    
    ("4.1.6", "Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root (Automated)",
        lambda: check_kubelet_kubeconfig_ownership()),
    
    ("4.1.7", "Ensure that the certificate authorities file permissions are set to 600 or more restrictive (Manual)",
        lambda: check_kubelet_ca_file_permissions()),
    
    ("4.1.8", "Ensure that the client certificate authorities file ownership is set to root:root (Manual)",
        lambda: check_kubelet_ca_file_ownership()),
    
    ("4.1.9", "If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive (Automated)",
        lambda: check_kubelet_config_file_permissions()),
    
    ("4.1.10", "If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root (Automated)",
        lambda: check_kubelet_config_file_ownership()),
    
    # 4.2 Kubelet Configuration Checks
    ("4.2.1", "Ensure that the --anonymous-auth argument is set to false (Automated)",
        lambda: check_process_argument_set("kubelet", "--anonymous-auth", "false")),
    
    ("4.2.2", "Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)",
        lambda: check_kubelet_authorization_mode()),
    
    ("4.2.3", "Ensure that the --client-ca-file argument is set as appropriate (Automated)",
        lambda: check_kubelet_client_ca_file()),
    
    ("4.2.4", "Ensure that the --read-only-port argument is set to 0 (Automated)",
        lambda: check_kubelet_read_only_port()),
    
    ("4.2.5", "Ensure that the --streaming-connection-idle-timeout argument is not set to 0 (Automated)",
        lambda: check_kubelet_streaming_connection_idle_timeout()),
    
    ("4.2.6", "Ensure that the --make-iptables-util-chains argument is set to true (Automated)",
        lambda: check_kubelet_make_iptables_util_chains()),
    
    ("4.2.7", "Ensure that the --hostname-override argument is not set (Manual)",
        lambda: {"status": "PASS", "reason": "--hostname-override is not set"} if not get_process_argument("kubelet", "--hostname-override") else {"status": "FAIL", "reason": "--hostname-override should not be set"}),
    
    ("4.2.8", "Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture (Manual)",
        lambda: check_kubelet_event_record_qps()),
    
    ("4.2.9", "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Manual)",
        lambda: check_kubelet_tls_cert_and_key()),
    
    ("4.2.10", "Ensure that the --rotate-certificates argument is not set to false (Automated)",
        lambda: check_kubelet_rotate_certificates()),
    
    ("4.2.11", "Ensure that the RotateKubeletServerCertificate argument is set to true (Automated)",
        lambda: check_kubelet_feature_gate("RotateKubeletServerCertificate", "true")),
    
    ("4.2.12", "Ensure that the --tls-cipher-suites argument is set to strong cryptographic ciphers (Manual)",
        lambda: check_kubelet_tls_cipher_suites_config()),
    
    ("4.2.13", "Ensure that the --pod-max-pids argument is set to an appropriate value (Manual)",
        lambda: check_kubelet_pod_max_pids()),
    
    ("4.2.14", "Ensure that the --seccomp-default parameter is set to true (Manual)",
        lambda: check_kubelet_seccomp_default()),
    
    ("4.2.15", "Ensure that the --IPAddressDeny is set to any (Manual)",
        lambda: check_kubelet_ip_address_deny()),
    
    ("4.3.1", "Ensure that the kube-proxy metrics service is bound to localhost (Manual)",
        lambda: check_kube_proxy_metrics_bind_address())
]

def main():
    """Main function to run all kubelet security checks and output results in JSON format."""
    results = []
    for rule, description, check_fn in RULES:
        result = check_fn()
        results.append({
            "rule": rule,
            "description": description,
            "result": result
        })

    # Print clean JSON output
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
