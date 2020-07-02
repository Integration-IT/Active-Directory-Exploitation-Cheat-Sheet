# xpath injection

### Detection method
To find this vulnerabilities sends the string "d'z'0" to every injection point, and searches the response for XPATH errors

### Basic Payloads
```
d'z"0
<!--"
```
 ##### Regexp for error
 ```
 System\.Xml\.XPath\.XPathException|MS\.Internal\.Xml|Unknown error in XPath|org\.apache\.xpath\.XPath|A closing bracket expected in|An operand in Union Expression does not produce a node-set|Cannot convert expression to a number|Document Axis does not allow any context Location Steps|Empty Path Expression|DOMXPath|Empty Relative Location Path|Empty Union Expression|Expected \'\)\' in|Expected node test or name specification after axis operator|Incompatible XPath key|Incorrect Variable Binding|libxml2 library function failed|libxml2|Invalid predicate|Invalid expression|xmlsec library function|xmlsec|error \'80004005\'|A document must contain exactly one root element|<font face="Arial" size=2>Expression must evaluate to a node-set|Expected token ']'|<p>msxml4\.dll<\/font>|<p>msxml3\.dll<\/font>|4005 Notes error: Query is not understandable|SimpleXMLElement::xpath|xmlXPathEval:
 ```
