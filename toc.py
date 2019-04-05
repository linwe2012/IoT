# Generate github supported TOC for md file
from pathlib import Path
import os
import string
import re
urlprefix = 'https://github.com'
username = 'linwe2012'
repository = ''
branch = 'master'
target = 'paper.md'
output = 'toc.md'
list_dialect = '-' # or '*'
punctuation_except = '-'

if len(repository) == 0:
    repository = Path(os.getcwd()).name

baseurl = '/'.join([urlprefix, username, repository, 'blob', branch, target]) + '#'
print(baseurl)


TOC = '# TOC\n\n'

# strip all punctuations, exempting '-' [punctuation_except]
strip_punc = str.maketrans({key: None for key in string.punctuation if key not in punctuation_except})
with open(target, 'r', encoding = 'utf-8') as f:
    while 1:
        line = f.readline()
        if line == '':
            break
        if line[0] == '#':
            end = len(line)
            level = len(line.split()[0])
            stripped = line[level+1:].translate(strip_punc).lower()
            anchor = baseurl + '-'.join(stripped.split())
            for id in range(level):
                TOC += '  '
            
            TOC += list_dialect + ' [' + line[level+1:].rstrip('\n\r') + ']('  + anchor + ')\n'
            print(level, anchor)
            
with open(output, 'w', encoding = 'utf-8') as f:
    f.write(TOC)

            
        
        
            
