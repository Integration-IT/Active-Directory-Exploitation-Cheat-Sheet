#!/usr/bin/env python
import os
import json
import yaml  # install pyyaml if needed

"""
Get a dictionary from yaml files
- cd /tmp/
- git clone https://github.com/GTFOBins/GTFOBins.github.io/
- ./parse_yaml.py

This script should help me to update easily my binary list here: 
- https://github.com/AlessandroZ/BeRoot/blob/master/Linux/beroot/analyse/binaries.py
"""

results = {}
root = '/tmp/GTFOBins.github.io/_gtfobins'
for file in os.listdir(root):
    if file.endswith('.md'):
        with open(os.path.join(root, file), 'r') as stream:
            binary = os.path.splitext(file)[0]
            results[binary] = {}
            gtfo_bins = yaml.load_all(stream, Loader=yaml.SafeLoader)
            for gtfo_bin in gtfo_bins:
                if gtfo_bin:
                    functions = gtfo_bin['functions']
                    # Sorted by priority
                    for func in ['sudo', 'command', 'file-write', 'file-read',
                                 'shell', 'file-download', 'file-upload']:
                        if func in functions:
                            sep = '----' if len(functions[func]) > 1 else ''
                            c = ''
                            for code in functions[func]:
                                c += code['code'] + '\n' + sep
                            results[binary] = c
                            break

json_parsed = json.dumps(results, indent=4, sort_keys=True)
print(json_parsed)
