# Api Key
Detect Api key in request | response body

How to use api key: https://github.com/streaak/keyhacks


### Keys:
ATOMIST_API_KEY : ```\b[A-F0-9]{64}\b/```

TWITTER_ACCESS_TOKEN : ```[1-9][0-9]+-[0-9a-zA-Z]{40}```

FACEBOOK_ACCESS_TOKEN : ```EAACEdEose0cBA[0-9A-Za-z]+```

GOOGLE_API_KEY: ```AIza[0-9A-Za-z\-_]{35}```

GOOGLE_OAUTH_ID : ```[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/```

PICATIC_API_KEY : ```sk_live_[0-9a-z]{32}```

STRIPE_REGULAR_API_KEY : ```sk_live_[0-9a-zA-Z]{24}```

STRIPE_RESTRICTED_API_KEY: ```rk_live_[0-9a-zA-Z]{24}```

SQUARE_OAUTH_TOKEN: ```sq0atp-[0-9A-Za-z\-_]{22}```

SQUARE_OAUTH_SECRET: ```sq0csp-[0-9A-Za-z\-_]{43}```

BRAINTREE_ACCESS_TOKEN: ```access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}```

AMAZON_AUTH_TOKEN: ```amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}```

TWILLIO_API_KEY: ```SK[0-9a-fA-F]{32}```

MAILGUN_KEY: ```key-[0-9a-zA-Z]{32}```

MAILCHIMP_API_KEY: ```[0-9a-f]{32}-us[0-9]{1,2}```

AMAZON_ACCESS_KEY: ```\bAK[0-9A-Z]{18}\b```

GITHUB_TOKEN: ```(https?:\/\/)(?:v1\.)?[a-f0-9]{40}((?::x-oauth-basic)?@)```

URL_PASSWORD: ```((?:ht|f|sm)tps?:\/\/[^:/?#\[\]@""<>{}|\\^``\s]+:)[^:/?#\[\]@""<>{}|\\^``\s]+@```

slack_token: ```(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})```

slack_webhook: ```https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}```

facebook_oauth: ```[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\s][0-9a-f]{32}['\"\s]```

twitter_oauth: ```[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\s][0-9a-zA-Z]{35,44}['\"\s]```

heroku_api: ```[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}```

google_captcha: ```6L[0-9A-Za-z-_]{38}```

google_oauth: ```ya29\.[0-9A-Za-z\-_]+```




#### Burp regexp

```
[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com|[0-9a-f]{32}-us[0-9]{1,2}|[1-9][0-9]+-[0-9a-zA-Z]{40}|6L[0-9A-Za-z-_]{38}|AC[a-zA-Z0-9_\-]{32}|access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}|AIza[0-9A-Za-z-_]{35}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|AP[a-zA-Z0-9_\-]{32}|api[key|\s*]+[a-zA-Z0-9_\-]+|[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*|\b[A-F0-9]{64}\b|\bAK[0-9A-Z]{18}\b|basic [a-zA-Z0-9_\-:\.]+|bearer [a-zA-Z0-9_\-\.]+|-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\S]{100,}-----END PRIVATE KEY-----|-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\S]{100,}-----END RSA PRIVATE KEY-----|EAACEdEose0cBA[0-9A-Za-z]+|eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]{10,}|[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\s][0-9a-f]{32}['\"\s]|[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}|((?:ht|f|sm)tps?:\/\/[^:/?#\[\]@""<>{}|\\^``\s]+:)[^:/?#\[\]@""<>{}|\\^``\s]+@|https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}|(https?:\/\/)(?:v1\.)?[a-f0-9]{40}((?::x-oauth-basic)?@)|key-[0-9a-zA-Z]{32}|rk_live_[0-9a-zA-Z]{24}|s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com|SK[0-9a-fA-F]{32}|sk_live_[0-9a-z]{32}|sk_live_[0-9a-zA-Z]{24}|sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[ 0-9A-Za-z\-_]{43}|sq0csp-[0-9A-Za-z\-_]{43}|sqOatp-[0-9A-Za-z\-_]{22}|[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\s][0-9a-zA-Z]{35,44}['\"\s]|(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})|ya29\.[0-9A-Za-z\-_]+
```
