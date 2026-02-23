### Benefits of Signing Commits for Security

- **Author verification** - proof that the commit was made by a specific developer.
- **Integrity guarantee** - a signed commit cannot be altered after the fact without invalidating the signature
- **Supply-chain protection** - prevents malicious actors from injecting unauthorized commits into a repository
![lab3_ssh_key_gen.png](screenshots%2Flab3_ssh_key_gen.png)
![lab3_ssh_setup.png](screenshots%2Flab3_ssh_setup.png)
![lab3_verification_badge.png](screenshots%2Flab3_verification_badge.png)

### Why Is Commit Signing Critical in DevSecOps Workflows?

A malicious insider or a compromised CI token can push code under any developer's name, 
making attribution impossible during an incident. 
Also CI pipelines can be configured to reject unverified commits.

### Pre-commit Setup
I added pre-commit to `.git/hooks/pre-commit`
I fixed it to be runnable on the Windows
Example of blocked commit:
![lab_3_commit_blocked.png](screenshots%2Flab_3_commit_blocked.png)

After removing fake AWS_KEY:
![lab_3_commit_accepted.png](screenshots%2Flab_3_commit_accepted.png)

Programs like `TruffleHog` scans repos detects some leaks of sensitive data before commit.
It helps developers to not lose their data and reduces manual verification.