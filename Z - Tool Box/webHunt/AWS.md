# AWS
Search AWS urls,keys in response body
### Regex

AMAZON_URL: ```https?://[^\"\\'> ]```

AMAZON_URL_1: ```[a-z0-9.-]+\.s3-[a-z0-9-]\\.amazonaws\.com```

AMAZON_URL_2: ```[a-z0-9.-]+\.s3-website[.-](eu|ap|us|ca|sa|cn)```

AMAZON_URL_3: ```s3\\.amazonaws\.com/[a-z0-9._-]```

AMAZON_URL_4: ```s3-[a-z0-9-]+\.amazonaws\\.com/[a-z0-9._-]```

URLS: ```https?://[^\"\\'> ]```

AMAZON_KEY: ```([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}```

UPLOAD_FIELDS: ```<input[^>]\stype=[\"']?file[\"']?```
