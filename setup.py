#!/usr/bin/env python3

from setuptools import setup, find_packages


setup(name='crackmapextreme',
    version='0.1.0',
    description='rekd',
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security',
    ],
    keywords='pentesting security windows active-directory networks',
    url='http://github.com/awsmhacks/CrackMapExtreme',
    author='awsmhacks',
    author_email='dontemailmebruh',
    license='BSD',
    packages=find_packages(),
    install_requires=[
    ],
    entry_points={
        'console_scripts': [ 'cme = cmx.crackmapextreme:main','cmx = cmx.crackmapextreme:main', 'cmxdb = cmx.cmxdb:main', 'cmxdb2 = cmx.CMXDB2.cmxdb:main'],
    },
    include_package_data=True,
    zip_safe=False)