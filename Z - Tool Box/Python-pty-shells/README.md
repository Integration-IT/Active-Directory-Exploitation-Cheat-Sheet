python-pty-shells
=================

Python PTY backdoors - full PTY or nothing!

Insecurety Research (2013)

The following is a collection of bind and reverse shells which give you a fully working PTY.

This is far superior to a normal bind or reverse shell, as you have job control and an interactive PTY and can do such things as use nano/vi to write files, su to elevate privs/change user, and ssh onward. You can also CTRL+C  and suchlike. 

I have implemented the bind and backconnect shells using the TCP protocol, the SCTP protocol, and the UDP protocol.

A demonstration video and blog post explaining the advantages/disadvantages of each technique is on the way, I just need to get around to it. 

For the SCTP shell, you will need the PySCTP module and the host will need to support the SCTP protocol. Most modern Linux boxes do, however you may need to install lksctp and lksctp-dev to build the python extensions. I am unsure if pyinstaller or similar can get around this.

Released under the WTFPL - wtfpl.net

Project by Insecurety Research - insecurety.net

Author: Darren 'infodox' Martyn.
