# DAMP
The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.

This project contains several files that implement host-based security descriptor "backdoors" that facilitate the abuse of various remotely accessible services for arbitrary trustees/security principals.

__tl;dr__ - this grants users/groups (local, domain, or 'well-known' like 'Everyone') of an attacker's choosing the ability to perform specific administrative actions on a modified host without needing membership in the local administrators group.

__Note:__ to implement these backdoors, you need the right to change the security descriptor information for the targeted service, which in stock configurations nearly always means membership in the local administrators group.

More information:

* [An ACE in the Hole - Stealthy Host Persistence via Security Descriptors](https://www.slideshare.net/harmj0y/an-ace-in-the-hole-stealthy-host-persistence-via-security-descriptors)
* [The Unintended Risks of Trusting Active Directory ](https://www.slideshare.net/harmj0y/the-unintended-risks-of-trusting-active-directory)

__Authors:__ [@tifkin_](https://twitter.com/tifkin\_), [@enigma0x3](https://twitter.com/enigma0x3), and [@harmj0y](https://twitter.com/harmj0y).

__License:__ BSD 3-Clause

## Remote Registry

### Add-RemoteRegBackdoor.ps1

#### Add-RemoteRegBackdoor

Implements a new remote registry backdoor that allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.

### RemoteHashRetrieval.ps1

#### Get-RemoteMachineAccountHash

Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.

#### Get-RemoteLocalAccountHash

Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.

#### Get-RemoteCachedCredential

Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
