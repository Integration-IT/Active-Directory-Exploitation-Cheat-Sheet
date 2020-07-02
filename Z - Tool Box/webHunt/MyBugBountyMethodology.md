# 1. Recon
## 1.1 Collect Subdomains

Change "domain.com" with your domain

### ~ crt.sh 
```$ curl -s https://crt.sh/?q=%25.domain.com\&output=json | jq '.[].name_value' | sort -u | sed 's/"//g' | sed '/^*/d'```

### ~ certspotter
```$ curl -s https://certspotter.com/api/v0/certs\?domain\=domain.com | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep domain.com```

### ~ Virustotal
```https://www.virustotal.com/gui/domain/domain.com/relations```

### ~ SecurityTrails
```https://securitytrails.com/list/apex_domain/domain.com```

### ~ Github
```https://github.com/search?q="domain.com"```

### ~ Censys
```443.https.tls.certificate.parsed.names: domain.com```

### ~ bgp
```https://bgp.he.net/```

### ~ Findomain
```https://github.com/Edu4rdSHL/findomain```

```findomain -t domain.com```

### ~ Amass
```https://github.com/OWASP/Amass```

```$ amass enum -d domain.com```

### ~ Subfinder 
```https://github.com/subfinder/subfinder```

```$ ./subfinder -d domain.com -b -w jhaddix_all.txt -t 100```

```jhaddix all.txt: https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056```

### Unique subdomains list
```$ cat file1 file2 file3 | sort -u | tee uniqSubdomains```





## 1.2 Burp Suite
* 1.2.1 [Export unique subdomains to Burp Suite](https://github.com/ghsec/webHunt/blob/master/SubdomainsToBurp.md)
                         
* 1.2.2 [Recon with Burp](https://github.com/ghsec/webHunt/blob/master/ReconWithBurp_Suite.md)

     [Demo Videos:](https://www.youtube.com/watch?v=-6ck9WhdtPk&list=PLq8PHzHe7znWfoKfi2ieVVC42_11u4t_C)
    
   


