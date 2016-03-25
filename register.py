import pypandoc
import os

with open('README.txt','w+') as rst_file:
    with open('README.md') as markdown_file:
        # Read the first line and throw it away, as it's the same description as in setup.py
        markdown_file.readline()
        readme = markdown_file.read()
    
    rst_file.write(pypandoc.convert(readme,'rst', format='markdown'))

os.system("python setup.py sdist upload")
os.remove('README.txt')
