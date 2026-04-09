## Terraform Tool Comparison

| Metric              | tfsec | Checkov | Terrascan |
|---------------------|-------|---------|-----------|
| **Total findings**  | 53    | 78      | 22        |
| **CRITICAL**        | 9     | -       | 0         |
| **HIGH**            | 25    | -       | 14        |
| **MEDIUM**          | 11    | -       | 8         |
| **LOW**             | 8     | -       | 0         |
| **Speed**           | 2 sec | 8 sec   | 4 sec     |
| **False positives** | Low   | Medium  | Low       |

### Key differences

- **tfsec**: Detected 9 CRITICAL vulnerabilities, primarily hardcoded AWS keys,
passwords in code, and public access to S3 and RDS. It's good at detecting encryption issues and
network vulnerabilities.
- **Checkov**: The most comprehensive coverage. Detects not only security issues but also governance/compliance issues.
Unique checks: CKV_AWS_144 (cross-region replication), CKV_AWS_145 (S3 SSE with KMS), CKV_AWS_211 (RDS CaCert).
- **Terrascan**: Focus on compliance frameworks. Fewest findings, but all are assigned to specific categories.
Uniquely maps rules to PCI-DSS and HIPAA standards.

## Pulumi Security Analysis

**Results KICS for Pulumi:**
- Total findings: **6**
- CRITICAL: 1, HIGH: 2, MEDIUM: 1, INFO: 2

| # | Vulnerability                                  | Severity | CWE     | Category                |
|---|------------------------------------------------|----------|---------|-------------------------|
| 1 | RDS DB Instance Publicly Accessible            | CRITICAL | CWE-284 | Insecure Configurations |
| 2 | DynamoDB Table Not Encrypted                   | HIGH     | CWE-311 | Encryption              |
| 3 | Passwords And Secrets - Generic Password       | HIGH     | CWE-798 | Secret Management       |
| 4 | EC2 Instance Monitoring Disabled               | MEDIUM   | CWE-778 | Observability           |
| 5 | DynamoDB Table Point In Time Recovery Disabled | INFO     | CWE-459 | Best Practices          |
| 6 | EC2 Not EBS Optimized                          | INFO     | CWE-459 | Best Practices          |

**Analysis:** KICS identified the most critical issues in Pulumi code: publicly accessible RDS, unencrypted DynamoDB, and hardcoded secrets. However, KICS did not detect a number of vulnerabilities clearly present in the code (public S3 bucket with `acl: public-read`, security groups with `0.0.0.0/0`, wildcard IAM policies), indicating less comprehensive coverage of Pulumi requests compared to Terraform scanners.

## Terraform vs. Pulumi
| Aspect                                | Terraform                                                              | Pulumi (KICS)                                                            |
|---------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------|
| **Number of vulnerabilities in code** | 30                                                                     | 20                                                                       |
| **Total number of findings**          | 153                                                                    | 6                                                                        |
| **Vulnerability coverage**            | 90%                                                                    | 30% (6 out of 20 vulnerabilities)                                        |
| **Tool maturity**                     | High - tfsec, Checkov, Terrascan have thousands of rules for Terraform | Medium - KICS supports Pulumi since v1.6.x, the query catalog is growing |
| **Report detail**                     | tfsec/Checkov provide code, remediation, and links                     | KICS provides links to the Pulumi Registry and description               |

**Conclusion:** Terraform is significantly better covered by security tools. 
For Pulumi, the only mature open-source scanner is KICS, and its query catalog for Pulumi is still limited compared 
to Terraform.

## KICS Pulumi Support

KICS (Checkmarx) v2.1.20 provides first-class support for Pulumi:

- **Supported format:** Pulumi YAML manifests
- **Total number of requests:** 21
- **Cloud providers:** AWS, Azure, GCP, Kubernetes
- **Check categories:** Encryption, Insecure Configurations, Secret Management, Observability, Best Practices
- **Scan speed:** <1 second for 280 lines

**KICS strengths for Pulumi:**
1. The only open-source scanner with native Pulumi YAML support
2. CWE mapping and risk score for each finding
3. Multiple output formats: JSON, HTML, SARIF, console
4. A unified tool for Pulumi + Ansible + Terraform

**Limitations:**
1. Not all Terraform-equivalent checks are ported to Pulumi
2. Doesn't detect public S3 bucket ACLs, wildcard IAM policies, or open security groups in Pulumi YAML
3. Works only with YAML manifests

---

## Critical Findings

### Hardcoded AWS-keys
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```
**Found by:** tfsec (AVD-AWS-0017), Checkov (CKV_AWS_41)
**Risks:** Complete unauthorized access to an AWS account

### Publicly accessible RDS with a hardcoded password

```hcl
username = "admin"
password = "SuperSecretPassword123!"  # SECURITY ISSUE #9 - Hardcoded password!
```
**Found:** tfsec, Checkov, Terrascan, KICS Pulumi
**Risk:** The database is accessible from the internet without encryption, data leak


### Security Group with access 0.0.0.0/0 to all ports

```hcl
ingress {
  description = "Allow all traffic"
  from_port   = 0
  to_port     = 65535
  protocol    = "-1"  # All protocols
  cidr_blocks = ["0.0.0.0/0"]  # From anywhere!
}
```
**Обнаружено:** tfsec, Checkov, Terrascan
**Risk:** All ports and protocols are open to the entire internet. An attacker can connect to any service.

### Wildcard IAM Policy (HIGH)

```hcl
policy = jsonencode({
  Statement = [{
    Effect   = "Allow"
    Action   = "*"
    Resource = "*"
  }]
})
```
**Обнаружено:** tfsec, Checkov, Terrascan
**Risk:** Privilege escalation - anyone with this policy gets full admin access to the entire AWS account.

### 5. Hardcoded secrets in Ansible Playbook

```yaml
vars:
  db_password: "SuperSecret123!"
  api_key: "sk_live_1234567890abcdef"
  db_connection: "postgresql://admin:password123@db.example.com:5432/myapp"
```
**Обнаружено:** KICS
**Risk:** Cleartext secrets end up in Git, logs, and CI/CD artifacts.

## Tool Strengths
| Tool          | Pros                                                                                                                                                                   |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **tfsec**     | Fast, low false positive rate, precise severity ratings, excellent links to documentation and remediation, Terraform-specific                                          |
| **Checkov**   | Maximum coverage, >1000 built-in policies, Terraform + CloudFormation + K8s + Docker support, governance/compliance checks                                             |
| **Terrascan** | Compliance-oriented, OPA-based, clear categorization                                                                                                                   |
| **KICS**      | The only open-source scanner with native support for Pulumi YAML and Ansible, CWE mapping, risk scoring, multiple output formats, one tool for multiple IaC frameworks |

## Ansible Security Issues

KICS v2.1.20 scanned 3 Ansible files and found **10 hits** (9 HIGH, 1 LOW) across 287 queries.

| # | Issue Type                               | Severity | Files                                         | Number of Instances |
|---|------------------------------------------|----------|-----------------------------------------------|---------------------|
| 1 | Passwords And Secrets - Generic Password | HIGH     | `inventory.ini, `configure.yml`, `deploy.yml` | 7                   |
| 2 | Passwords And Secrets - Generic Secret   | HIGH     | `inventory.ini`                               | 1                   |
| 3 | Passwords And Secrets - Password in URL  | HIGH     | `deploy.yml`                                  | 2                   |
| 4 | Unpinned Package Version                 | LOW      | `deploy.yml`                                  | 1                   |

**Major issues:**
1. **Hard-coded passwords** - found in all 3 files: database passwords, API keys, private SSH keys, connection strings with credentials
2. **Passwords in URLs**
3. **Unpinned package versions** - `state: latest` instead of a fixed version, which creates a supply-chain risk

## Best Practice Violations
### Missing `no_log: true` for tasks with secrets

**Problem:** In `deploy.yml`, a command is executed with a password without `no_log`:
```yaml
- name: Set database password
  command: mysql -u root -p{{ db_password }} -e "CREATE DATABASE myapp;"
```
**Impact:** Passwords are visible in Ansible stdout, CI/CD logs, and can be accessed through monitoring systems.
**Fix:**
```yaml
- name: Set database password
  command: mysql -u root -p{{ db_password }} -e "CREATE DATABASE myapp;"
  no_log: true
```

### Storing secrets in plaintext instead of Ansible Vault

**Problem:** In `configure.yml`, the private SSL key is stored directly in the playbook:
```yaml
  vars:
    # SECURITY ISSUE #20 - Plaintext secrets
    ssl_private_key: |
      -----BEGIN PRIVATE KEY-----
      MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt...
      -----END PRIVATE KEY-----
    
    admin_password: "Admin123!"
```
**Impact:** Secrets are written to the Git history, accessible to anyone with access to the repository.
**Fix:**
``bash
ansible-vault encrypt_string 'Admin123!' --name 'admin_password' > vars/vault.yml
```yaml
vars_files:
  - vars/vault.yml
```

### 3. Files with permissions 0777 and SSH keys with 0644 (CWE-732)

**Problem:** In `deploy.yml` (lines 31-38 and 41-47):
```yaml
# SECURITY ISSUE #6 - File with overly permissive permissions
- name: Create config file
  copy:
    content: |
      DB_PASSWORD={{ db_password }}
      API_KEY={{ api_key }}
    dest: /etc/myapp/config.env
    mode: '0777'  # World readable/writable!
    owner: root
    group: root

# SECURITY ISSUE #7 - SSH key with wrong permissions
- name: Deploy SSH key
  copy:
    src: files/id_rsa
    dest: /root/.ssh/id_rsa
    mode: '0644'  # Should be 0600!
    owner: root
    group: root
```
**Impact:** Sensitive files are accessible to all users of the system.
**Fix:**
```yaml
- name: Create config file
  copy:
  dest: /etc/myapp/config.env
  mode: '0640'
  owner: appuser
  group: appgroup

- name: Deploy SSH key
  copy:
  dest: /root/.ssh/id_rsa
  mode: '0600'
  owner: root
  group: root
```
---

## KICS Ansible Queries

| Request                                  | Category          | CWE     | Risk Score |
|------------------------------------------|-------------------|---------|------------|
| Passwords And Secrets - Generic Password | Secret Management | CWE-798 | 7.8        |
| Passwords And Secrets - Generic Secret   | Secret Management | CWE-798 | 7.8        |
| Passwords And Secrets - Password in URL  | Secret Management | CWE-798 | 7.8        |
| Unpinned Package Version                 | Supply Chain      | CWE-706 | 4.1        |

**KICS Score for Ansible:**
- **Strengths:** Excellent secret detection
- **Limitations:** No issues were found that are clearly visible in the code:
- `shell` instead of `apt` module
- Disabled firewall
- Disabled SELinux
- Permissive sudo NOPASSWD
- Insecure SSH configuration: `PermitRootLogin yes`, `PermitEmptyPasswords yes`
- File permissions `0777`


## Remediation Steps

### Terraform
| Problem                   | Fix                                                              |
|---------------------------|------------------------------------------------------------------|
| Hardcoded AWS credentials | Remove `access_key`/`secret_key`, use IAM roles or env vars      |
| Public S3 bucket          | Set `acl = "private"`, enable `block_public_acls = true`         |
| Unencrypted S3            | Add `server_side_encryption_configuration` with AES256 or KMS    |
| Open Security Groups      | Restrict CIDR to corporate VPN/internal network                  |
| Public RDS                | `publicly_accessible = false`, `storage_encrypted = true`        |
| Hardcoded DB password     | Use `aws_secretsmanager_secret`                                  |
| Wildcard IAM              | Apply least-privilege: specify specific Action and Resource      |
| Weak default vars         | Add `sensitive = true`, remove password defaults, add validation |

### Ansible
| Problem                  | Fix                                                                          |
|--------------------------|------------------------------------------------------------------------------|
| Plaintext passwords      | Use Ansible Vault: `ansible-vault encrypt vars.yml`                          |
| Missing no_log           | Add `no_log: true` to tasks with secrets                                     |
| File permissions 0777    | Set `mode: '0640'` or stronger                                               |
| SSH key permissions 0644 | Set `mode: '0600'`                                                           |
| shell instead of modules | Replace `shell: apt-get install` with the `apt:` module                      |
| Disabled firewall        | Don't disable UFW, but configure rules                                       |
| Permissive SSH config    | `PermitRootLogin no`, `PasswordAuthentication no`, `PermitEmptyPasswords no` |
| Plaintext inventory      | Use `ansible-vault encrypt inventory.ini` or SSH keys                        |
| Unpinned packages        | `state: present` with a specific version                                     |
### Pulumi
| Problem                      | Fix                                                                   |
|------------------------------|-----------------------------------------------------------------------|
| Hardcoded AWS credentials    | Remove `access_key`/`secret_key`, use `aws.Provider` with a profile   |
| Hardcoded secrets            | Use `config.require_secret("db_password")`                            |
| Public S3 bucket             | Set `acl="private"`, add `BucketPublicAccessBlock`                    |
| Open Security Groups         | Restrict `cidr_blocks` to specific subnets                            |
| Unencrypted RDS/DynamoDB/EBS | Enable encryption: `storage_encrypted=True`, `server_side_encryption` |
| Public RDS                   | `publicly_accessible=False`                                           |
| Wildcard IAM                 | Replace `"Action": "*"` with specific actions                         |
| Secrets in outputs           | Use `pulumi.export("password", pulumi.Output.secret(password))`       |

## Tool Effectiveness Matrix
| Criteria | tfsec | Checkov | Terrascan | KICS                                  |
|---------------------------|----------------------------------|-------------------------|---------|---------------------------------------|
| **Total Finds** | 53 | 78 | 22 | 6 (Pulumi) + 10 (Ansible) = 16        |
| **Scan Speed** | Fast (~2 sec) | Medium (~8 sec) | Medium (~4 sec) | Fast (<1 sec)                         |
| **False Positives** | Low | Medium | Low | Low                                   |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐                                  |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐                                  |
| **Documentation** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐                                  |
| **Platform Support** | Terraform Only | TF, CFN, K8s, Docker, ARM | TF, CFN, K8s, Docker, Helm | TF, Pulumi, Ansible, CFN, Docker, K8s |
| **Output Formats** | JSON, text, SARIF, CSV | JSON, CLI, SARIF, JUnit | JSON, YAML, human | JSON, HTML, SARIF, console            |
| **CI/CD Integration** | Easy | Easy | Medium | Easy                                  |
| **Unique Power** | Terraform Accuracy, Severity | Maximum Coverage, 1000+ Rules | Compliance Mapping (PCI-DSS, HIPAA) | Pulumi + Ansible Support, CWE Mapping |
## Vulnerability Category Analysis
| Security Category             | tfsec | Checkov | Terrascan | KICS | KICS | Best Tool   |
|-------------------------------|-------|---------|-----------|------|------|-------------|
| **Encryption**                | 12    | 18      | 5         | 1    | N/A  | Checkov     |
| **Network Security**          | 15    | 20      | 8         | 0    | 0    | Checkov     |
| **Secret Management**         | 9     | 6       | 0         | 1    | 9    | tfsec, KICS |
| **IAM/Privileges**            | 8     | 16      | 4         | 0    | 0    | Checkov     |
| **Access Control**            | 5     | 10      | 3         | 1    | 0    | Checkov     |
| **Compliance/Best Practices** | 4     | 8       | 2         | 3    | 1    | Checkov     |


## Tool Selection Guide
| Scenario                              | Recommended Tool      | Rationale                                                            |
|---------------------------------------|-----------------------|----------------------------------------------------------------------|
| **Fast scan in the pre-commit hook**  | tfsec                 | Fastest, least false positives                                       |
| **Full Terraform audit**              | Checkov               | Maximum coverage, 78 detections vs. 53 for tfsec                     |
| **Compliance audit (PCI-DSS, HIPAA)** | Terrascan             | Built-in mapping to compliance frameworks                            |
| **Pulumi scanning**                   | KICS                  | The only open-source scanner with native Pulumi YAML support         |
| **Ansible scanning**                  | KICS                  | Comprehensive secrets discovery, supply-chain checks                 |
| **Multi-framework project**           | KICS + Checkov        | KICS for Pulumi/Ansible, Checkov for Terraform/K8s/Docker            |
| **CI/CD gate (blocking)**             | tfsec (CRITICAL/HIGH) | Fast, accurate, minimal false positives - doesn't delay the pipeline |
| **CI/CD reporting (informational)**   | Checkov               | Full report for the security team                                    |

---

## Lessons Learned
- One tool isn't enough to guarantee security.
- You need to balance speed and analysis quality.


## CI/CD Integration Strategy
1. Stage 1: Pre-commit
   - Tool: tfsec
   - Result: BLOCK on CRITICAL, WARN on HIGH
   - Goal: quick developer feedback

2. Stage 2: PR Check
   - Tools: Checkov, KICS scan
   - Result: BLOCK on HIGH+, report in PR comment
   - Goal: full coverage before merge

3. Stage 3: Nightly Scan
   - Tools: Terrascan, Checkov
   - Result: SARIF, Security Dashboard
   - Goal: compliance reporting, trend tracking

4. **Stage 4: Release Gate**
   - Tools: all scanners with `--severity HIGH`
   - Result: BLOCK deployment to any HIGH+
   - Goal: final check before production

## Justification
1. **Complementarity:** Each tool finds unique issues that others miss. tfsec found 9 CRITICAL issues, Checkov found an additional 25 governance issues, and Terrascan found compliance mapping.

2. **Platform Coverage:** No single tool covers all IaC frameworks. The combination of Checkov + KICS provides the full spectrum.

3. **Different Pipeline Stages:** Pre-commit requires speed, PR-check requires comprehensiveness, and release gate requires rigor.

4. **Defense in Depth:** Using multiple tools reduces the risk of missing critical vulnerabilities. In our experiment, no single tool found all 30 Terraform vulnerabilities on its own.

5. **Cost-effectiveness:** All four tools are open-source. The cost of integration is minimal compared to the potential damage from missed vulnerabilities.