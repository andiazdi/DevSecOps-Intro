### Benefits of Signing Commits for Security

- **Author verification** - proof that the commit was made by a specific developer.
- **Integrity guarantee** - a signed commit cannot be altered after the fact without invalidating the signature
- **Supply-chain protection** - prevents malicious actors from injecting unauthorized commits into a repository

![lab3_ssh_setup.png](screenshots/lab3_ssh_setup.png)

### Why Is Commit Signing Critical in DevSecOps Workflows?

A malicious insider or a compromised CI token can push code under any developer's name, 
making attribution impossible during an incident. 
Also CI pipelines can be configured to reject unverified commits.
