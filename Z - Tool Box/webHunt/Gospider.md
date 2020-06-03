# Spidering with Gospider
[Gospider](https://github.com/jaeles-project/gospider)

### Collect Endpoints

```
gospider -s https://domain.com -d 10 -a -w --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|woff2|svg|js)" | grep -oP "(http[s]?:\/\/)?((-)?[\w+\.]){1,}domain\.com.*"
```
