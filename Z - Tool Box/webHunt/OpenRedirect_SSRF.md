### Open Redirect|SSRF

Possible Open Redirect | SSRF detection Regexp

```
(=|%3D|%253D|%25253D)(http(s)?(%3A%2F%2F|%253A%252F%252F|%25253A%25252F%25252F|:\/\/)|aHR0c)|PWh0dH
```

### Detect Open Redirect in response

```
.*?; *?URL *?= *?(.*)|window\.location(\s=\s|\.href|\.replace)?(\(|\s=\s)?(https\:\/\/www\.)?google\.com(\))|Location:\shttps:\/\/www\.google\.com
```
#### Payloads:
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect/Intruder
