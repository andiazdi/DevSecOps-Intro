###  Critical/High Vulnerabilities


**Docker Scout summary:** `11 Critical | 65 High | 30 Medium | 5 Low` across 1004 packages.

| # | CVE / ID                | Package              | Severity           | CVSS                                                                                                 | Impact |
|---|-------------------------|----------------------|--------------------|------------------------------------------------------------------------------------------------------|--------|
| 1 | CVE-2023-37466          | `vm2@3.9.17`         | **Critical** (9.8) | Code Injection - sandbox escape via async stack overflow allows arbitrary code execution on the host |
| 2 | CVE-2023-37903          | `vm2@3.9.17`         | **Critical** (9.8) | OS Command Injection - attacker can run arbitrary OS commands by escaping the VM2 sandbox            |
| 3 | CVE-2025-55130          | `node@22.18.0`       | **Critical**       | Race Condition in Node.js allows remote attackers to crash the process or execute code               |
| 4 | SNYK-JS-MULTER-10299078 | `multer@1.4.5-lts.2` | **Critical**       | Uncaught Exception - malformed multipart request causes unhandled exception and DoS                  |
| 5 | SNYK-JS-MARSDB-480405   | `marsdb@0.6.11`      | **Critical**       | Arbitrary Code Injection - no sanitization of user-provided query strings leads to RCE               |

**Additional notable high-severity findings from Snyk:**

- `express-jwt@0.1.3` - Authorization Bypass (token forging possible with empty/null algorithm)
- `socket.io@3.1.2` - Denial of Service via crafted WebSocket frames
- `sequelize@6.37.7` - SQL Injection via unsanitized user input
- `sanitize-html@1.4.2` → `lodash@2.4.2` - Prototype Pollution (×5)
- `openssl/libssl3@3.0.17` - High severity CVE-2025-69421, fixed in 3.0.18


###  Dockle Configuration Findings


| Level | ID          | Finding                                                                                        | Security Concern                                                                                                                    |
|-------|-------------|------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| INFO  | CIS-DI-0005 | Content trust for Docker not enabled (`DOCKER_CONTENT_TRUST=1` not set)                        | Without content trust, Docker does not verify image signatures - a compromised registry could serve a malicious image               |
| INFO  | CIS-DI-0006 | No `HEALTHCHECK` instruction in the image                                                      | Without a health check, the orchestrator cannot detect that the container is unhealthy and should be restarted, reducing resilience |
| INFO  | DKL-LI-0003 | Unnecessary files present: `.DS_Store` in `node_modules/micromatch` and `node_modules/extglob` | macOS metadata files leaked into the image - indicates poor build hygiene and increases attack surface                              |
| SKIP  | DKL-LI-0001 | Could not detect `/etc/shadow` or `/etc/master.passwd`                                         | Distroless image - no password files accessible; this is actually a security improvement                                            |

**No FATAL or WARN issues were found** - the image passes the critical Dockle checks.


### 1.3 Security Posture Assessment

**Does the image run as root?**

Yes. The `bkimminich/juice-shop:v19.0.0` image runs as `root` by default. Docker Scout and Dockle confirm no 
`USER` directive is set in the Dockerfile to drop privileges before starting the application.

**Security improvements recommended:**

1. **Add a non-root user** - Add `USER node` or a dedicated `appuser` in the Dockerfile to prevent privilege escalation if the app is compromised.
2. **Update `vm2`** - This package has multiple Critical sandbox bypass CVEs. Either upgrade to `≥3.10.2` or replace it with a safer sandboxing alternative like `isolated-vm`.
3. **Update `node` runtime** - Upgrade from `22.18.0` to `≥22.22.0` to fix 1 Critical and 4 High CVEs.
4. **Upgrade `express-jwt`** from `0.1.3` to `≥6.0.0` - the old version allows algorithm confusion attacks (empty algorithm bypass).
5. **Add `HEALTHCHECK`** instruction to the Dockerfile.
6. **Enable `DOCKER_CONTENT_TRUST=1`** in the CI/CD pipeline to verify image signatures before deploying.


## Docker Host Security Benchmarking

### Summary Statistics

| Result           | Count |
|------------------|-------|
| **PASS**         | 19    |
| **WARN**         | 11    |
| **NOTE**         | 6     |
| **INFO**         | 38    |
| **Total checks** | 74    |
| **Score**        | 7     |

### Analysis of Warnings

| Check | Description                                                         | Security Impact                                                                                             | Remediation                                                                                   |
|-------|---------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| 1.1   | No separate partition for containers (`/var/lib/docker`)            | If containers fill the disk, the host OS can be disrupted - classic DoS via disk exhaustion                 | Create a dedicated LVM partition or volume for `/var/lib/docker`                              |
| 1.5   | No auditing configured for Docker daemon                            | Without audit logs, it is impossible to detect unauthorized actions or reconstruct incidents                | Add Docker daemon to `auditd` rules: `auditctl -w /usr/bin/dockerd -k docker`                 |
| 2.1   | Network traffic not restricted between containers on default bridge | Containers on the default bridge can communicate freely - lateral movement is trivial if one is compromised | Set `"icc": false` in `/etc/docker/daemon.json` or use user-defined networks                  |
| 2.6   | Docker daemon listening on TCP without TLS                          | Unauthenticated access to the Docker API means full host compromise for anyone on the network               | Either remove TCP socket or configure TLS: `--tlsverify --tlscacert --tlscert --tlskey`       |
| 2.8   | User namespace support not enabled                                  | Container processes run with the same UIDs as the host - a container root is host root if breakout occurs   | Enable in `daemon.json`: `"userns-remap": "default"`                                          |
| 2.11  | No authorization plugin for Docker client                           | Any user in the `docker` group has unrestricted API access - equivalent to root                             | Install and configure an authorization plugin (e.g., `open-policy-agent/opa-docker-authz`)    |
| 2.12  | No centralized/remote logging                                       | Container logs are stored locally and can be lost or tampered with                                          | Configure `log-driver` in `daemon.json` (e.g., `"log-driver": "syslog"` or use a log shipper) |
| 2.14  | Live restore not enabled                                            | Containers stop when the Docker daemon restarts, causing downtime                                           | Add `"live-restore": true` to `daemon.json`                                                   |
| 2.15  | Userland proxy not disabled                                         | The userland proxy adds unnecessary attack surface and reduces performance                                  | Set `"userland-proxy": false` in `daemon.json`                                                |
| 2.18  | Containers not restricted from acquiring new privileges             | Processes inside containers can gain additional OS capabilities via `setuid` binaries                       | Set `"no-new-privileges": true` in `daemon.json` as a daemon-wide default                     |
| 4.5   | Docker Content Trust not enabled                                    | Images are pulled without signature verification                                                            | Export `DOCKER_CONTENT_TRUST=1` in the shell profile and CI environment                       |


### Configuration Comparison Table


| Parameter          | Default       | Hardened          | Production        |
|--------------------|---------------|-------------------|-------------------|
| **Port**           | 3001          | 3002              | 3003              |
| **HTTP Response**  | 200 OK        | 200 OK            | 200 OK            |
| **CapDrop**        | *(none)*      | ALL               | ALL               |
| **CapAdd**         | *(none)*      | *(none)*          | NET_BIND_SERVICE  |
| **SecurityOpt**    | *(none)*      | no-new-privileges | no-new-privileges |
| **Memory limit**   | *(unlimited)* | 512 MiB           | 512 MiB           |
| **Memory swap**    | *(unlimited)* | *(unlimited)*     | 512 MiB (swap=0)  |
| **CPU limit**      | *(unlimited)* | 1.0 vCPU          | 1.0 vCPU          |
| **PID limit**      | *(unlimited)* | *(none)*          | 100               |
| **Restart policy** | no            | no                | on-failure:3      |
| **Seccomp**        | default       | default           | default           |

**Memory usage observed:**

| Container        | CPU % | Memory Used | Limit     |
|------------------|-------|-------------|-----------|
| juice-default    | 0.42% | 113 MiB     | 15.57 GiB |
| juice-hardened   | 0.40% | 95.2 MiB    | 512 MiB   |
| juice-production | 1.38% | 95.03 MiB   | 512 MiB   |


### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**Linux capabilities** are fine-grained permissions that divide the traditional `root` superuser into distinct units.
Instead of "root can do everything," each capability grants a specific right: 
`NET_BIND_SERVICE` lets a process bind to ports < 1024, `SYS_PTRACE` lets it trace other processes, etc.

**`--cap-drop=ALL`** removes every capability from the container - the process cannot change file ownership, 
load kernel modules, mount filesystems, or perform any privileged OS operation.
This eliminates most privilege-escalation attack paths: even if an attacker achieves RCE inside the container, 
they cannot perform actions that require elevated capabilities.

**`--cap-add=NET_BIND_SERVICE`** is added back so the Node.js server can listen on port 3000.

**Trade-off:** Some legitimate application features may break if they require capabilities.
Each required capability must be evaluated and added back intentionally.

#### b) `--security-opt=no-new-privileges`

This flag sets the `PR_SET_NO_NEW_PRIVS` bit on the container's init process. 
Once set, neither the process nor any of its children can gain new privileges through `setuid`/`setgid` 
binaries or file capabilities, even if such binaries exist in the image.

**Attack prevented:** Without this flag, an attacker who gains code execution can run a `setuid` 
binary to escalate to root. With `no-new-privileges`, that escalation path is closed.

**Downside:** Applications that intentionally use `setuid` mechanisms will break.

#### c) `--memory=512m` and `--cpus=1.0`

Without resource limits, a single compromised or misbehaving container can consume all host memory or all CPU.

**Memory limiting prevents DoS** via memory exhaustion - a classic attack against web servers is to send many large 
requests to consume RAM. With `--memory=512m`, the container is killed instead of taking down the host.

**Risk of limits too low:** If the application legitimately needs more than 512 MiB, it will be OOM-killed. 
The limit must be set based on profiling, with a reasonable safety margin.

#### d) `--pids-limit=100`

A **fork bomb** is an attack where a process recursively forks itself until it exhausts the system's process table, making the host unusable: `: () { : | : & }; :`.

**`--pids-limit=100`** prevents any process inside the container from creating more than 100 total PIDs. 
A fork bomb hits the limit and fails instead of affecting the host.

**How to determine the right limit:** Profile the application under peak load using `docker stats` or 
`/proc/<pid>/status` and add a 2x safety margin. For Juice Shop, a single Node.js worker 
with ~20 threads comfortably stays under 100.

#### e) `--restart=on-failure:3`

This policy tells Docker to restart the container if it exits with a non-zero exit code, 
up to a maximum of 3 attempts. After 3 failures, Docker stops retrying.

**Benefits:** Provides automatic recovery from transient crashes without operator intervention.

**Risk:** If the container is crashing because of an ongoing attack or misconfiguration, 
auto-restart can mask the problem and delay incident response. 
An attacker exploiting a crash-and-restart loop could also use it for timing attacks.

**`on-failure` vs `always`:** `always` restarts even after a clean `exit 0` 
but also restarts after `docker stop`. `on-failure` is safer - 
it only triggers on abnormal exits and respects intentional stops.


### 3.3 Critical Thinking Questions

**1. Which profile for DEVELOPMENT? Why?**

**Default** profile is appropriate for development. Developers need flexibility - debugging tools, ability to attach to processes,
write to the filesystem, use higher ports, etc. Security restrictions in Hardened/Production can interfere with 
debugging. Developer machines are also not exposed to the internet, reducing risk.

**2. Which profile for PRODUCTION? Why?**

**Production** profile. It provides defense-in-depth: capability dropping limits what a compromised container can do on the OS, 
`no-new-privileges` closes setuid escalation paths, memory/CPU/PID limits prevent resource exhaustion attacks, and `restart=on-failure:3` 
ensures availability. All three profiles served identical HTTP responses, so hardening did not affect functionality.

**3. What real-world problem do resource limits solve?**

Resource limits prevent **noisy neighbour** and **DoS amplification** problems. In a multi-tenant environment, 
one container with a memory leak or under attack can exhaust shared host resources, cascading into failures of unrelated services.
Limits provide isolation at the infrastructure level, independent of application code.

**4. If an attacker exploits Default vs Production, what actions are blocked in Production?**

In **Default**, an attacker with RCE can: change file ownership, kill arbitrary processes, load kernel modules, mount filesystems, use raw sockets for network scanning, bypass DAC permissions, and escalate via setuid binaries.

In **Production**, all of the above are blocked by `--cap-drop=ALL`. Additionally, `no-new-privileges` prevents setuid escalation, the 512 MiB memory cap prevents exhaustion attacks from inside, and the 100-PID limit stops fork bombs.

**5. What additional hardening would you add?**

- **Run as non-root user** - most impactful single change
- **Read-only root filesystem** with tmpfs mounts for writable paths
- **Custom seccomp profile** - restrict to only the ~50 syscalls Node.js actually needs
- **AppArmor or SELinux profile** for mandatory access control
- **Network isolation** - attach to a user-defined bridge instead of the default bridge, disable inter-container communication
- **Image pinning** - use a digest instead of a mutable tag to prevent supply-chain attacks
- **Regular base image rebuilds** - automate weekly rebuilds to pick up OS patches
