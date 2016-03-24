#!/usr/bin/env python

from distutils.core import setup

setup(name='curlbomb',
      version='1.0',
      description='',
      author='Ryan McGuire',
      author_email='ryan@enigmacurry.com',
      url='https://github.com/EnigmaCurry/curlbomb',
      py_modules=['curlbomb'],
      entry_points={
          'console_scripts': ['curlbomb = curlbomb:main']}
      )

