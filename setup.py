# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='doc_gen',
    version='1.0',
    description='SPDX Document generator for projects using SPDXIDs',
    long_description=readme,
    author='Ekong Obie Philip',
    author_email='ekongobiephilip@gmail.com',
    url='',
    license=license,
    packages=find_packages(exclude=('tests')),
    entry_points={
        'console_scripts': [
            'spdxgen = doc_gen.main:entry_point',
        ],
    }
)
