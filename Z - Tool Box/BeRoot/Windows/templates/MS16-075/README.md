# MS16-075

*MS16-075 checks has been removed from the BeRoot project. However, I let the poc here.*

For French user, I recommend the article written on the MISC 90 which explain in details how it works. 

This vulnerability has been corrected by Microsoft with MS16-075, however many servers are still vulnerable to this kind of attack. 
I have been inspired from the C++ POC available [here](https://github.com/secruul/SysExec)

Here are some explaination (not in details):

1. Start Webclient service (used to connect to some shares) using some magic tricks (using its UUID)
2. Start an HTTP server locally
3. Find a service which will be used to trigger a _SYSTEM NTLM hash_. 
4. Enable file tracing on this service modifying its registry key to point to our webserver (_\\\\127.0.0.1@port\\tracing_)
5. Start this service
6. Our HTTP Server start a negotiation to get the _SYSTEM NTLM hash_
7. Use of this hash with SMB to execute our custom payload ([SMBrelayx](https://github.com/CoreSecurity/impacket/blob/master/examples/smbrelayx.py) has been modify to realize this action)
8. Clean everything (stop the service, clean the regritry, etc.).


__How to exploit__:

Lots of code uses beroot package, so some actions are needed: 
* Move webclient directory into [beroot\modules\checks](https://github.com/AlessandroZ/BeRoot/tree/master/Windows/BeRoot/beroot/modules/checks)
* Move poc.py on the [Beroot](https://github.com/AlessandroZ/BeRoot/tree/master/Windows/BeRoot) directory. 
* Install impacket (`pip install impacket`)
* Change on [poc.py](https://github.com/AlessandroZ/BeRoot/blob/master/Windows/templates/MS16-075/poc.py#L29) file the command line you want to execute. 
* Run it: `python poc.py`


Special thanks
----
* C++ POC: https://github.com/secruul/SysExec
* Impacket as always, awesome work: https://github.com/CoreSecurity/impacket/
