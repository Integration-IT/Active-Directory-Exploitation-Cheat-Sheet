# Recon:

### OS: Ubuntu
..................................................

## საჭირო ხელსაწყოები.
 1.[Golang ინსტალაცია](https://golang.org/doc/install)
 
 2.[OwaspAmass](https://github.com/OWASP/Amass)
 
 3.[Subfinder](https://github.com/projectdiscovery/subfinder)
 
 4.[Findomain](https://github.com/Edu4rdSHL/findomain)
 
 5.[Assetfinder](https://github.com/tomnomnom/assetfinder)
 
 6.[Github-Search](https://github.com/gwen001/github-search)
 
 7.[GoAltdns](https://github.com/subfinder/goaltdns)
 
 8.[MassDns](https://github.com/blechschmidt/massdns)
 
 9.[gau](https://github.com/lc/gau)
 
10.[GoSpider](https://github.com/jaeles-project/gospider)

11.[Jaeles](https://github.com/jaeles-project/jaeles)

12.[Ffuf](https://github.com/ffuf/ffuf)

13.[DirSearch](https://github.com/maurosoria/dirsearch)

14.[Httprobe](https://github.com/tomnomnom/httprobe)


## Wordlists: 
* [RobotsDisallowed](https://github.com/danielmiessler/RobotsDisallowed)
* [SecLists Web Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)
* [content_discovery_nullenc0de](https://gist.github.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7)
* [content_discovery_all](https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10)
* [commonspeak2](https://github.com/assetnote/commonspeak2-wordlists)
* [all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)


## Recon Subdomains

- Owasp Amass : ```amass enum -d DOMAIN -o amass```

- Subfinder: ```subfinder -d DOMAIN -o subfinder```

- Findomain: ```findomain -t DOMAIN -o```

- Assetfinder: ```assetfinder DOMAIN | tee assetfinder```

- Gobuster: ```gobuster dns -d DOMAIN -w ~/PATH/all.txt -t 250 -o gobuste```

- github-search/github-subdomains.py: ```python3 github-subdomains.py -d DOMAIN -t <Personal access tokens>```

- https://securitytrails.com/list/apex_domain/DOMAIN ```GREP ან ვიყენებთ API-ს```

- https://subdomainfinder.c99.nl/

### ამოვიღოთ უნიკალური subdomain-ები და შევინახოთ uniq ფაილში.
```cat * | sort -u | tee uniq```

```rm <files>  # ვშლით ყველა ფაილს რომელიც აღარ გვჭირდება, ვტოვებთ მხოლოდ uniq ფაილს```


### დავაგენერიროთ სავარაუდო საბდომენების საბდომენები და დავარეზოლვოთ.
``` goaltdns -l uniq -w all.txt -o generated```

```massdns generated -r /massdns/lists/resolvers.txt -t A -o S -w results.txt```

```sed 's/A.*//' result.txt | sed 's/CN.*//' | sed 's/\..$//' > massdns```

```cat uniq massdns | sort -u | tee uniq.txt```

შესაძლებელი კიდე იგივე ოპერაცია გავიმეოროთ goaltdns-თან ერთად ოღონდ word.txt ფაილით.


### HttpProbe Live
```cat uniq.txt | httprobe | tee hosts```

