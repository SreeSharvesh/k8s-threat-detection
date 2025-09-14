import json
from helper import (
    check_process_argument_set,
    check_process_feature_gate
)

RULES = [
    ("1.3.1", "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Manual)",
        lambda: check_process_argument_set("kube-controller-manager", "--terminated-pod-gc-threshold")),
    
    ("1.3.2", "Ensure that the --profiling argument is set to false (Automated)",
        lambda: check_process_argument_set("kube-controller-manager", "--profiling", "false")),
    
    ("1.3.3", "Ensure that the --use-service-account-credentials argument is set to true (Automated)",
        lambda: check_process_argument_set("kube-controller-manager", "--use-service-account-credentials", "true")),
    
    ("1.3.4", "Ensure that the --service-account-private-key-file argument is set as appropriate (Manual)",
        lambda: check_process_argument_set("kube-controller-manager", "--service-account-private-key-file")),
    
    ("1.3.5", "Ensure that the --root-ca-file argument is set as appropriate (Manual)",
        lambda: check_process_argument_set("kube-controller-manager", "--root-ca-file")),
    
    ("1.3.6", "Ensure that the RotateKubeletServerCertificate argument is set to true (Automated)",
        lambda: check_process_feature_gate("kube-controller-manager", "RotateKubeletServerCertificate", "true")),
    
    ("1.3.7", "Ensure that the --bind-address argument is set to 127.0.0.1 (Automated)",
        lambda: check_process_argument_set("kube-controller-manager", "--bind-address", "127.0.0.1")),
    
    # 1.4 Scheduler Checks
    ("1.4.1", "Ensure that the --profiling argument is set to false (Automated)",
        lambda: check_process_argument_set("kube-scheduler", "--profiling", "false")),
    
    ("1.4.2", "Ensure that the --bind-address argument is set to 127.0.0.1 (Automated)",
        lambda: check_process_argument_set("kube-scheduler", "--bind-address", "127.0.0.1"))
]

def main():
    """Main function to run all controller manager and scheduler security checks and output results in JSON format."""
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
