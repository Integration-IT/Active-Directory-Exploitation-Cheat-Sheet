### file_upload

Uploads a file and then searches for the file inside all known directories.

#### Common Upload Path
```
uploads
upload
up
files
file
user
content
images
documents
docs
downloads
download
down
public
pub
private
```
Analyze results of the _send_mutant method.
In this case, check if the file was uploaded to any of the known directories, or one of the "default" ones like "upload" or "files"


Parse the HTTP response and find our file.
Take into account that the file name might have been changed (we do not care) if the extension remains the same then we're happy.

Use the framework's knowledge to find the file in all possible locations
