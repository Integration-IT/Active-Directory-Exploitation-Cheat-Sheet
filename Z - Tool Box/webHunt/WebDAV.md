# WebDAV 

Verify if the WebDAV module is properly configured.

```
CONTENT_TYPE = Headers([('content-type', 'application/xml; charset="utf-8"')])
```

### Test SEARCH method

```
<?xml version='1.0'?>
  <g:searchrequest xmlns:g='DAV:'>
  <g:sql>Select 'DAV:displayname' from scope()</g:sql>
</g:searchrequest>
```

#### Detect
```
xmlns:a="DAV:"

```


If response  is 200, 300 with directory name and path Directory listing with HTTP SEARCH method was found



### Test PROPFIND method

```
<?xml version='1.0'?>
  <a:propfind xmlns:a='DAV:'>
  <a:prop>
  <a:displayname:/>
  </a:prop>
"</a:propfind>
```

###  Tests PUT method.


```
headers = Headers([('content-type', 'text/plain')])

```

File upload with HTTP PUT method was found at resource if file is uploaded

DAV seems to be incorrectly configured. The web server answered with a 500 error code. 
In most cases, this means that the DAV extension failed in some way. 

if 403 DAV seems to be correctly configured and allowing you to use the PUT method but 
the directory does not have the right permissions that would allow the web server to write to it

This technique finds WebDAV configuration errors. These errors are generally server configuration 
errors rather than a web application errors. To check for vulnerabilities of this kind, try to PUT 
a file on a directory that has WebDAV enabled, if the file is uploaded successfully, then we have found a bug
