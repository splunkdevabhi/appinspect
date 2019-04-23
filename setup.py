# Copyright 2016 Splunk Inc. All rights reserved.

"""A setup tools configuration to be used for building and distribution."""

import setuptools
import os

# Information Configuration Goes Here
author = "Splunk"
author_email = "appinspect@splunk.com"
classifiers = ["Development Status :: 5 - Production/Stable",
               "Environment :: Console",
               "Intended Audience :: Developers",
               "Intended Audience :: End Users/Desktop",
               "License :: Other/Proprietary License",
               "Natural Language :: English",
               "Operating System :: MacOS",
               "Operating System :: Microsoft",
               "Operating System :: Unix",
               "Programming Language :: Python :: 2.7",
               "Programming Language :: Python :: 2 :: Only",
               "Programming Language :: Python :: Implementation :: CPython",
               "Topic :: Software Development :: Testing",
               "Topic :: Utilities"]
description = "Automatic validation checks for Splunk Apps"
download_url = "http://dev.splunk.com/goto/appinspectdownload"
home_page_url = "https://splunk.com"
# Specifies installation library dependencies
install_requirements = [
    "beautifulsoup4==4.5.1",
    "chardet==3.0.4",
    "click==6.6",
    "dimensions==0.0.2",
    "futures==3.0.5",
    "futures-then==0.1.1",
    "humanfriendly==1.44.7",
    "jinja2==2.10",
    "langdetect==1.0.6",
    "lxml>=3.6.4",  # ACD-1330 windows install issue
    "Markdown==2.6.6",
    "painter==0.3.1",
    "py==1.6.0",
    "pytest==3.8.2",
    "regex>=2017.6.23",  # Python re module does not support PCRE, so use another one
    "six==1.10.0",  # Python 2.7.13 setuptools no longer includes six
    "python-magic>=0.4.15",
    "ipaddress==1.0.22",
    "jsoncomment==0.3.0",
]
if os.name == 'nt':
    windows_install_requirements = [
        "pywin32==224",
    ]
    install_requirements += windows_install_requirements
keywords = ["AppInspect",
            "Certification",
            "Splunk",
            "Splunk AppInspect",
            "Testing"]
license = "Other/Proprietary License"
long_description = ("AppInspect is a tool for assessing a Splunk App's"
                    " compliance with Splunk recommended development practices,"
                    " by using static analysis. AppInspect is open for"
                    " extension, allowing other teams to compose checks that"
                    " meet their domain specific needs for semi- or"
                    " fully-automated analysis and validation of Splunk Apps.")
name = "splunk-appinspect"
package_data = {
    "splunk_appinspect": [
        "*.txt",             # Includes the banned_wordslist.txt
        "version/VERSION.txt",           # Includes the VERSION file
        "checks/**",         # Includes the checks directory
        "templates/*.html",  # Includes the templates for documentation generation
    ]
}
platforms = ["MacOS",
             "Microsoft",
             "Unix"]
scripts = ["scripts/splunk-appinspect"]

execfile("splunk_appinspect/version/version.py")
__version__ = get_version(os.path.join(os.path.dirname(os.path.realpath(__file__)), 
    'splunk_appinspect', 'version'))

# now we have an `__version__` variable

# Setup tools configuration goes here
setuptools.setup(
    author=author,
    author_email=author_email,
    classifiers=classifiers,
    description=description,
    download_url=download_url,
    install_requires=install_requirements,
    keywords=keywords,
    license=license,
    long_description=long_description,
    name=name,
    packages=setuptools.find_packages(),
    package_data=package_data,
    platforms=platforms,
    url=home_page_url,
    entry_points={
        'console_scripts': [
            'splunk-appinspect=splunk_appinspect:main.execute',
        ],
    },
    version=__version__
)
