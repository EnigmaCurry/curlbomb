#!/usr/bin/env python

from setuptools import setup
import os

from curlbomb import __version__

long_description = description = "A personal HTTP server for serving one-time-use shell scripts"
if os.path.exists('README.txt'):
    with open('README.txt') as f:
        long_description=f.read()

setup(name='curlbomb',
      version=__version__,
      description=description,
      long_description=long_description,
      license="MIT",
      classifiers=[
          "Development Status :: 4 - Beta",
          "Topic :: Utilities",
          "License :: OSI Approved :: MIT License",
      ],
      author='Ryan McGuire',
      author_email='ryan@enigmacurry.com',
      url='https://github.com/EnigmaCurry/curlbomb',
      py_modules=['curlbomb'],
      include_package_data = True,
      entry_points={
          'console_scripts': ['curlbomb = curlbomb:main']},
)
