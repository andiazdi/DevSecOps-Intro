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


AWS_KEY = 1234abcd-12ab-34cd-56ef-1234567890ab