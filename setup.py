#!/usr/bin/env python

from setuptools import setup
import os

long_description = description = "A personal HTTP server for serving one-time-use bash scripts"
if os.path.exists('README.txt'):
    long_description=open('README.txt').read()

setup(name='curlbomb',
      version='1.0.6',
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
      entry_points={
          'console_scripts': ['curlbomb = curlbomb:main']},
)

