#!/usr/bin/env python3

import os
from setuptools import setup, find_packages
from subprocess import *

# 1.2.0.dev1  # Development release
# 1.2.0a1     # Alpha Release
# 1.2.0b1     # Beta Release
# 1.2.0rc1    # Release Candidate
# 1.2.0       # Final Release

VER_MAJOR = 0
VER_MINOR = 0
VER_MAINT = 1
VER_PREREL = "azdev1"

if call(["git", "branch"], stderr=STDOUT, stdout=open(os.devnull, 'w')) == 0:
    p = Popen("git log -1 --format=%cd --date=format:%Y%m%d.%H%M%S", shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
    (outstr, errstr) = p.communicate()
    (VER_CDATE,VER_CTIME) = outstr.strip().decode("utf-8").split('.')

    p = Popen("git rev-parse --short HEAD", shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
    (outstr, errstr) = p.communicate()
    VER_CHASH = outstr.strip().decode("utf-8")

    VER_LOCAL = "+{}.{}.{}".format(VER_CDATE, VER_CTIME, VER_CHASH)

else:
    VER_LOCAL = ""

setup(name='cmx',
    version = "{}.{}.{}.{}{}".format(VER_MAJOR,VER_MINOR,VER_MAINT,VER_PREREL,VER_LOCAL),
    description='Network pentesting tool for on-prem, cloud, and hybrid AD environments.',
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security',
    ],
    keywords='pentesting security windows active-directory networks azure azureAD',
    url='http://github.com/awsmhacks/CrackMapExtreme',
    author='awsmhacks',
    author_email='dontemailmebruh',
    license='BSD',
    packages=find_packages(),
    install_requires=[
    ],
    entry_points={
        'console_scripts': [ 'cmx = cmx.crackmapextreme:main', 'cmxdb = cmx.CMXDB2.cmxdb:main'],
    },
    include_package_data=True,
    zip_safe=False)