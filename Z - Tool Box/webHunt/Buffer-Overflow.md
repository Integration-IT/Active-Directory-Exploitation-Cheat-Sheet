# Buffer Overflow
Users have to know that detecting a buffer overflow vulnerability will be only possible if the server is configured to return errors, and the application is developed in cgi-c or some other language that allows the programmer to do their own memory management.

#TODO: if lengths = ```[ 65 , 257 , 513 , 1025, 2049, 4097, 8000 ]``` then I get a BadStatusLine exception from urllib2, is seems to be an internal error. Tested against tomcat 5.5.7

### Payload
Build Payloads
Example: ```['A' * payload_len for payload_len in [65, 257, 513, 1025, 2049]]```

### Errors
##### Regexp:
```
stack smashing detected |Backtrace|Memory map
```

```
# Note that the lack of commas after the strings is intentional
        <html><head>
        <title>500 Internal Server Error</title>
        </head><body>
        <h1>Internal Server Error</h1>
```        
### Some notes:
On Apache, when an overflow happends on a cgic script, this is written to the log
```
                       *** stack smashing detected ***

                /var/www/.../buffer_overflow.cgi terminated,
                referer: http://localhost/w3af/buffer_overflow.cgi
 
                Premature end of script headers: buffer_overflow.cgi,
                referer: ...
    
On Apache, when an overflow happens on a cgic script, this is returned to the user:

                <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
                <html><head>
                <title>500 Internal Server Error</title>
                </head><body>
                <h1>Internal Server Error</h1>
                <p>The server encountered an internal error or
                misconfiguration and was unable to complete
                your request.</p>
                <p>Please contact the server administrator,
                 webmaster@localhost and inform them of the time the error
                 occurred,
                and anything you might have done that may have
                caused the error.</p>
                <p>More information about this error may be available
                in the server error log.</p>
                <hr>
                <address>Apache/2.0.55 (Ubuntu) mod_python/3.2.8 Python/2.4.4c1
                PHP/5.1.6 Server at localhost Port 80</address>
                </body></html>
                
Note that this is an Apache error 500, not the more common PHP error 500
