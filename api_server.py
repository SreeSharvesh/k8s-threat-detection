import json

from helper import (
    check_apiserver_anonymous_auth_false,                 # 1.2.1
    check_apiserver_token_auth_file_not_set,              # 1.2.2
    check_apiserver_deny_service_external_ips,            # 1.2.3
    check_apiserver_kubelet_client_cert_and_key_set,      # 1.2.4
    check_apiserver_kubelet_ca_set,                       # 1.2.5
    check_apiserver_authorization_mode_not_always_allow,  # 1.2.6
    check_apiserver_authorization_mode_includes_node,     # 1.2.7
    check_apiserver_authorization_mode_includes_rbac,     # 1.2.8
    check_apiserver_eventratelimit_enabled,               # 1.2.9
    check_apiserver_no_always_admit                       # 1.2.10
)

RULES = [
    ("1.2.1", "Ensure that the --anonymous-auth argument is set to false (Manual)",
        lambda: check_apiserver_anonymous_auth_false()),
    ("1.2.2", "Ensure that the --token-auth-file parameter is not set (Automated)",
        lambda: check_apiserver_token_auth_file_not_set()),
    ("1.2.3", "Ensure that the DenyServiceExternalIPs admission controller is set (Manual)",
        lambda: check_apiserver_deny_service_external_ips()),
    ("1.2.4", "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate (Automated)",
        lambda: check_apiserver_kubelet_client_cert_and_key_set()),
    ("1.2.5", "Ensure that the --kubelet-certificate-authority argument is set as appropriate (Automated)",
        lambda: check_apiserver_kubelet_ca_set()),
    ("1.2.6", "Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)",
        lambda: check_apiserver_authorization_mode_not_always_allow()),
    ("1.2.7", "Ensure that the --authorization-mode argument includes Node (Automated)",
        lambda: check_apiserver_authorization_mode_includes_node()),
    ("1.2.8", "Ensure that the --authorization-mode argument includes RBAC (Automated)",
        lambda: check_apiserver_authorization_mode_includes_rbac()),
    ("1.2.9", "Ensure that the EventRateLimit admission control plugin is set (Manual)",
        lambda: check_apiserver_eventratelimit_enabled()),
    ("1.2.10", "Ensure that the AlwaysAdmit admission control plugin is not set (Automated)",
        lambda: check_apiserver_no_always_admit()),
]
def main():
    results = []
    for rule, description, check_fn in RULES:
        try:
            result = check_fn()
        except Exception as e:
            result = {"status": "FAIL", "reason": f"Unhandled error: {e}"}

        results.append({
            "rule": rule,
            "description": description,
            "result": result
        })

    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
