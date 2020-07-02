# This project has now been deprecated. Its functionality has been incorporated into [Rubeus](https://github.com/GhostPack/Rubeus) via the "asreproast" action, which utilizes a more minimal ASN.1 parsing library.

# ASREPRoast

Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled.

More information is available [here](http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/) and in [ExumbraOps' post](http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws).

## ASREPRoast.ps1

### Get-ASREPHash

Returns a crackable hash for users withouth kerberos preauthentication enabled.

### Invoke-ASREPRoast

Enumerates any users in the current (or specified) domain without kerberos preauthentication enabled and requests crackable AS-REP responses.

## krb5_asrep_fmt_plug.c

A customized version of the [krb5_tgs_fmt_plug.c](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/krb5_tgs_fmt_plug.c) plugin from [magnumripper version of John The Ripper](https://github.com/magnumripper/JohnTheRipper). Drop into ./src/ and compile as normal. The new hash tag is krb5asrep.

## tgscrack.go

A customized version of [@tifkin_](https://twitter.com/tifkin_)'s [tgscrack project](https://github.com/leechristensen/tgscrack/blob/master/tgscrack.go). The hash format needed is salt:hash:description.
