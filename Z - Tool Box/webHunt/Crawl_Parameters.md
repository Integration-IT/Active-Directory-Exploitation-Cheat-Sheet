# Crawl parameters with getallurls

- Download gau | link: https://github.com/lc/gau
- Compile
```go build gau.go```

- Move ```gau``` to /usr/bin
```sudo mv gau /usr/bin```

### Usage:
```gau -subs domain.com | grep -oP "(\?|\&)\w+" | tr -d "?|&" | sort -u | tee domain```
