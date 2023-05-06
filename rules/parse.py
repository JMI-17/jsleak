import yaml
import sys
import re
import glob

output = {}

for yml in glob.glob('*.yml'):
    with open(yml, 'r') as stream:
        y = yaml.safe_load(stream)

    for i in y["patterns"]:
        r = i["pattern"]["regex"]
        name = i["pattern"]["name"].replace(' ', '_').lower()
        output[name] = r

for line in output:
    print(f'"{line}" : `{output[line]}`,')