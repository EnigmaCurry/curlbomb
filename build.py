import pypandoc
import os
import codecs
import sys
from curlbomb import argparser
from build_manpage import build_manpage
import re

with open('README.txt','w+') as rst_file:
    with codecs.open('README.md', mode='r', encoding='utf-8') as markdown_file:
        readme = markdown_file.read()
        
    rst_file.write(pypandoc.convert(readme,'rst', format='markdown'))

### Build manpage
parts = re.split("^##?.*", readme, flags=re.MULTILINE)
long_description = parts[1]
example_use = parts[2]
arg_help = parts[3]

appname = os.popen("python setup.py --name").read().strip()
short_description = os.popen("python setup.py --description").read().strip()
homepage = os.popen("python setup.py --url").read().strip()
authors = "{} <{}>".format(os.popen("python setup.py --author").read().strip(), os.popen("python setup.py --author-email").read().strip())

build_manpage(argparser, 'curlbomb.1', appname, short_description, long_description, authors, homepage, pre_sections=[('examples',example_use)])

if sys.argv[-1] == "upload":
    os.system("python setup.py sdist upload")
else:
    os.system("python setup.py sdist")
os.remove('README.txt')
os.remove('curlbomb.1')
