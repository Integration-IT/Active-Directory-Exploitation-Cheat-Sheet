Invoke-CradleCrafter v1.1
===============

![Invoke-CradleCrafter Screenshot](https://github.com/danielbohannon/danielbohannon.github.io/blob/master/Invoke-CradleCrafter%20Screenshot.png)

Introduction
------------
Invoke-CradleCrafter is a PowerShell v2.0+ compatible PowerShell remote
download cradle generator and obfuscator.

Background
----------
In the Fall of 2016 after releasing Invoke-Obfuscation, I continued updating
my spreadsheet of PowerShell remote download cradles thinking that one day I
might add a "cradle selector" menu into Invoke-Obfuscation. This list 
consisted of cradles that were obscure to me, and many of which were not 
prevelently (or at all) being observed in the wild.

However, since Invoke-Obfuscation was designed to obfuscate any arbitrary 
PowerShell command or script, there are certain obfuscation techniques that 
I knew I needed to include with regards to building customized cradles that 
were not feasible to include in Invoke-Obfuscation.

This was the point that led me to shift this cradle research into a separate
project altogether, though you can always take output from Invoke-
CradleCrafter and intput it into Invoke-Obfuscation and continue the fun.
Since Invoke-CradleCrafter is much more tightly controlled, it has enabled 
me to include obfuscation techniques that are completely unlike any 
technique found in Invoke-Obfuscation.

Some of the new obfuscation techniques in this tool include token 
obfuscation through data type enumeration and wildcard matching, and the 
reordering of command structure by introducing additional variables and 
variable syntaxes.

Lastly, the tool supports 10+ invocation syntaxes that extend beyond the 
most prevalent Invoke-Expression and IEX.

Purpose
-------
Invoke-CradleCrafter exists to aid Blue Teams and Red Teams in easily 
exploring, generating and obfuscating PowerShell remote download cradles.
In addition, it helps Blue Teams test the effectiveness of detections that 
may work for output produced by Invoke-Obfuscation but may fall short when
dealing with Invoke-CradleCrafter since it does not contain any string
concatenations, encodings, tick marks, type casting, etc.

Another important component of this research and tool development was to 
effectively highlight the high-level behavior and artifacts left behind 
when each cradle is executed. I have tried to highlight this information 
when you first enter a new cradle type in the interactive menus of the tool.

Ultimately, knowing more about each cradle's behavior and artifacts will 
help the Blue Team better detect these cradles. This knowledge should also
benefit the Red Teamer in making more informed selections of which cradle 
to use in a given scenario.

Usage
-----
While all of the cradles can be produced by directly calling the Out-Cradle
function, the complexity of the moving pieces for all of the stacked 
obfuscated components makes using the Invoke-CradleCrafter function the 
easiest way to explorer and visualize the cradle syntaxes and obfuscation 
techniques that this framework currently supports.

Installation
------------
The source code for Invoke-CradleCrafter is hosted at Github, and you may
download, fork and review it from this repository
(https://github.com/danielbohannon/Invoke-CradleCrafter). Please report issues
or feature requests through Github's bug tracker associated with this project.

To install:

	Import-Module ./Invoke-CradleCrafter.psd1
	Invoke-CradleCrafter

License
-------
Invoke-CradleCrafter is released under the Apache 2.0 license.

Release Notes
-------------
v1.0 - 2017-04-28 x33fcon (Gdynia, Poland): PUBLIC Release of Invoke-CradleCrafter.

v1.1 - 2017-05-11 NOPcon (Istanbul, Turkey):
Added 3 new memory-based cradles:
- PsComMsXml
- PsInlineCSharp
- PsCompiledCSharp
Added 2 disk-based cradles:
- PsBits
- BITSAdmin

v1.1.1 - 2018-01-08:
Added 1 new memory-based cradle:
- Certutil -ping
Added 1 new disk-based cradle:
- Certutil -urlcache

v1.1.2 - 2018-02-05:
Added User-Agent strings to cradle info
- Thanks for the PR, @mgreen27!
