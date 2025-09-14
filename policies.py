import json
from helper import (
    check_cluster_admin_role_usage,
    check_secrets_access,
    check_roles_wildcard_usage,
    check_pods_create_access,
    check_default_service_accounts
)

RULES = [
    ("5.1.1", "Ensure that the cluster-admin role is only used where required (Manual)",
        lambda: check_cluster_admin_role_usage()),
    
    ("5.1.2", "Minimize access to secrets (Manual)",
        lambda: check_secrets_access()),
    
    ("5.1.3", "Minimize wildcard use in Roles and ClusterRoles (Manual)",
        lambda: check_roles_wildcard_usage()),
    
    ("5.1.4", "Minimize access to create pods (Manual)",
        lambda: check_pods_create_access()),
    
    ("5.1.5", "Ensure that default service accounts are not actively used (Manual)",
        lambda: check_default_service_accounts())
]

def main():
    """Main function to run all RBAC and service account security checks and output results in JSON format."""
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

if _name_ == "_main_":
    main()
