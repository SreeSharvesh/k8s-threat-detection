import os
import re
import grp
import pwd
import stat
import json
import subprocess

from helper import *

# ---- Rule Checks ----
RULES = [
    ("1.1.1", "Ensure that the API server pod specification file permissions are set to 600 or more restrictive (Automated)",
        lambda: check_permissions("/etc/kubernetes/manifests/kube-apiserver.yaml")),
    ("1.1.2", "Ensure that the API server pod specification file ownership is set to root:root (Automated)",
        lambda: check_ownership("/etc/kubernetes/manifests/kube-apiserver.yaml")),
    ("1.1.3", "Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive (Automated)",
        lambda: check_permissions("/etc/kubernetes/manifests/kube-controller-manager.yaml")),
    ("1.1.4", "Ensure that the controller manager pod specification file ownership is set to root:root (Automated)",
        lambda: check_ownership("/etc/kubernetes/manifests/kube-controller-manager.yaml")),
    ("1.1.5", "Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive (Automated)",
        lambda: check_permissions("/etc/kubernetes/manifests/kube-scheduler.yaml")),
    ("1.1.6", "Ensure that the scheduler pod specification file ownership is set to root:root (Automated)",
        lambda: check_ownership("/etc/kubernetes/manifests/kube-scheduler.yaml")),
    ("1.1.7", "Ensure that the etcd pod specification file permissions are set to 600 or more restrictive (Automated)",
        lambda: check_permissions("/etc/kubernetes/manifests/etcd.yaml")),
    ("1.1.8", "Ensure that the etcd pod specification file ownership is set to root:root (Automated)",
        lambda: check_ownership("/etc/kubernetes/manifests/etcd.yaml")),
    ("1.1.9", "Ensure that the Container Network Interface file permissions are set to 600 or more restrictive (Manual)",
        lambda: check_cni_file_permissions()),
    ("1.1.10", "Ensure that the Container Network Interface file ownership is set to root:root (Manual)",
        lambda: check_cni_file_ownership()),
    ("1.1.11", "Ensure that the etcd data directory permissions are set to 700 or more restrictive (Automated)",
        lambda: check_etcd_data_directory_permissions()),
    ("1.1.12", "Ensure that the etcd data directory ownership is set to etcd:etcd (Automated)",
        lambda: check_etcd_data_directory_ownership())
]

def main():
    results = []
    for rule, description, check_fn in RULES:
        result = check_fn()
        results.append({
            "rule": rule,
            "description": description,
            "result": result
        })
        
    os.makedirs("/output", exist_ok=True)
    with open("/output/results.json", "w") as f:
        json.dump(results, f, indent=4)
        
    # Print clean JSON output
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()