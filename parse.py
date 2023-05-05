import yaml
import sys
import re

if len(sys.argv) < 2:
    print(f"\nUsage:\n\t{sys.argv[0]} [regex-db.yml]")
    exit(1)

with open(sys.argv[1], 'r') as stream:
    y = yaml.safe_load(stream)

for i in y["patterns"]:
    r = i["pattern"]["regex"]
    name = i["pattern"]["name"]
    print(f'"{name}" : `{r}`,')