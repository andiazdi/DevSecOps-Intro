## Threat Modeling with Threagile


### 1.2 Risk Ranking Methodology

**Using Composite Score:**

```
Composite Score = Severity * 100 + Likelihood * 10 + Impact
```

| Parameter      | Value                                                     |
|----------------|-----------------------------------------------------------|
| **Severity**   | critical (5), elevated (4), high (3), medium (2), low (1) |
| **Likelihood** | very-likely (4), likely (3), possible (2), unlikely (1)   |
| **Impact**     | high (3), medium (2), low (1)                             |


| Rank | Risk Category                               |   Severity   |   Likelihood    |   Impact   | Composite Score | Affected Asset             |
|:----:|---------------------------------------------|:------------:|:---------------:|:----------:|:---------------:|----------------------------|
|  1   | **Unencrypted Communication** (credentials) | elevated (4) |   likely (3)    |  high (3)  |     **433**     | User Browser → Juice Shop  |
|  2   | **Unencrypted Communication** (proxy)       | elevated (4) |   likely (3)    | medium (2) |     **432**     | Reverse Proxy → Juice Shop |
|  3   | **Cross-Site Scripting (XSS)**              | elevated (4) |   likely (3)    | medium (2) |     **432**     | Juice Shop Application     |
|  4   | **Missing Authentication**                  | elevated (4) |   likely (3)    | medium (2) |     **432**     | Reverse Proxy → Juice Shop |
|  5   | **CSRF**                                    |  medium (2)  | very-likely (4) |  low (1)   |     **241**     | Juice Shop Application     |

#### Unencrypted Communication

Transmission of authentication credentials over unencrypted HTTP protocol between User Browser and Juice Shop. Could lead to:
   - MITM attack
   - Account takeover
   - Steal of private data
#### XSS
Service is vulnerable to XSS attacks. Could lead to:
   - Running malicious scripts in user browsers
   - Session stealing и account takeover
#### Missing Authentication
Missing authentication on the communication link between Reverse Proxy and Juice Shop Application. Could lead to:
   - Bypassing Reverse Proxy
   - Direct access to backend without authentication
   - Unauthorized access to internal APIs
#### CSRF
Very high likelihood of CSRF exploitation due to lack of protection. Could lead to:
   - Unauthorized actions on behalf of users
   - Data manipulation without user consent
   - Social engineering attacks leveraging CSRF
#### Unencrypted Assets
Persistent Storage and Juice Shop Application do not use encryption-at-rest. Could lead to:
   - Data breach if storage media is stolen
   - Access to sensitive data if host is compromised
   - Lack of protection for sensitive data

**Baseline Data Flow Diagram:**
![data-flow-diagram.png](lab2/baseline/data-flow-diagram.png)

**Baseline Data Asset Diagram:**  
![data-flow-diagram.png](lab2/baseline/data-flow-diagram.png)

## HTTPS Variant & Risk Comparison
**Secure Data Flow Diagram:**
![data-flow-diagram.png](lab2/secure/data-flow-diagram.png)

**Secure Data Asset Diagram:**
![data-asset-diagram.png](lab2/secure/data-asset-diagram.png)

| Category                             | Baseline | Secure |  Δ |
|--------------------------------------|---------:|-------:|---:|
| container-baseimage-backdooring      |        1 |      1 |  0 |
| cross-site-request-forgery           |        2 |      2 |  0 |
| cross-site-scripting                 |        1 |      1 |  0 |
| missing-authentication               |        1 |      1 |  0 |
| missing-authentication-second-factor |        2 |      2 |  0 |
| missing-build-infrastructure         |        1 |      1 |  0 |
| missing-hardening                    |        2 |      2 |  0 |
| missing-identity-store               |        1 |      1 |  0 |
| missing-vault                        |        1 |      1 |  0 |
| missing-waf                          |        1 |      1 |  0 |
| server-side-request-forgery          |        2 |      2 |  0 |
| unencrypted-asset                    |        2 |      1 | -1 |
| unencrypted-communication            |        2 |      0 | -2 |
| unnecessary-data-transfer            |        2 |      2 |  0 |
| unnecessary-technical-asset          |        2 |      2 |  0 |

### Changes made to the model
1. **HTTPS for User Browser → Reverse Proxy:**
   - Changed: `protocol: http` → `protocol: https`
2. **HTTPS for Reverse Proxy → Juice Shop:**
   - Changed: `protocol: http` → `protocol: https`
3. **Encryption transparent for Persistent Storage:**
   - Changed: `encryption: none` → `encryption: transparent`

### Analysis of Changes

#### Fixed:

**1. Unencrypted Communication**

Using HTTPS secures application because it eliminates the risk of unencrypted communication for credentials and sensitive data in transit.

**2. Unencrypted Asset**

Using transparent encryption for Persistent Storage reduces the risk of data breach if storage media is stolen or host is compromised, as data at rest will be encrypted.

Some risks remain unchanged because they are not directly related to the changes made and require additional mitigations to be addressed.

### 2.5 Security Posture Improvement

| Metrics                     | Baseline | Secure | Improvement |
|-----------------------------|----------|--------|-------------|
| **Elevated Severity Risks** | 4        | 2      | **-50%**    |
| **Total Risks**             | 23       | 20     | **-13.0%**  |
| **Data Breach (Possible)**  | 7        | 5      | **-28.6%**  |

## Diagrams Comparison
- Color of Reverse Proxy in data asset diagram changed from orange to more dark orange (color is the same as for Persistent Storage)
- Text on the arrows in data flow diagram changed from "http" to "https" for both User Browser → Reverse Proxy and Reverse Proxy → Juice Shop