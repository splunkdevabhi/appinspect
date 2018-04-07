# AppInspect
Services Fork of App Inspect release

# Splunk AppInspect
## Overview

AppInspect is a tool for assessing a Splunk App's compliance with Splunk recommended development practices, by using static analysis. AppInspect is open for extension, allowing other teams to compose checks that meet their domain specific needs for semi- or fully-automated analysis and validation of Splunk Apps. 

## Documentation

You can find the documentation for Splunk AppInspect at http://dev.splunk.com/goto/appinspectdocs.

## Builds

| Branch     | Status    | 
| --------|---------|
| master  | [![Build Status](http://re-jenkins03.sv.splunk.com:8080/buildStatus/icon?job=AppInspect_Toolkit/CLI_package_from_master)](http://re-jenkins03.sv.splunk.com:8080/job/AppInspect_Toolkit/job/CLI_package_from_master/)   | 
| development | [![Build Status](http://re-jenkins03.sv.splunk.com:8080/buildStatus/icon?job=AppInspect_Toolkit/CLI_package_from_development)](http://re-jenkins03.sv.splunk.com:8080/job/AppInspect_Toolkit/job/CLI_package_from_development/) | 

## Local Development

Use the following steps to setup AppInspect for local development.
### Install from source
* Checkout the `development` branch
* Create and activate a [virtual env](http://docs.python-guide.org/en/latest/dev/virtualenvs)
* Build and install from source
	- `python setup.py install`
	- That's it. The `splunk-appinspect` tool is installed into your virtualenv. You can verify this by running the following commands:
   		- `splunk-appinspect`
    	- `splunk-appinspect list version`

### Run CLI directly from codebase
* Install all dependencies, `pip install -r requirements.txt`
* Add current folder into PYTHONPATH, `export PYTHONPATH=$PYTHONPATH:.`
* Run the CLI, `script/splunk-appinspect list version`

### Build the distribution package
* Create a distribution of AppInspect
    - `python setup.py sdist`
    - after running the above command, an installation package with name like `splunk-appinspect-<version>.tar.gz` is created under the `dist` folder
* Install the distro previously created
    - `pip install dist/splunk-appinspect-<version>.tar.gz`

    
### Run tests
Once you have the `splunk-appinspect` tool installed, you can run tests by following the steps below.

* Install the Unit & Integration Test Requirements
    - `pip install -r test/requirements.txt`
* Ensure the Unit tests pass
    - `pytest -v test/unit/`
* Ensure the Integration tests pass
	- `pytest -v test/integration/test_cli.py`
	- network access is needed because some testing apps will be downloaded online, and this may take some time
	- `splunk-appinspect` CLI is needed in `PATH` so that integration tests can be run correctly
   
    
### Install without building
* Install the latest AppInspect CLI from the development branch.
    - `wget -r -l1 --no-parent --no-directories -A 'splunk-appinspect-*.tar.gz' https://repo.splunk.com/artifactory/Solutions/AppInspect/CLI/develop/builds/latest/ && pip install splunk-appinspect-*.tar.gz`



# Copyright

Copyright 2017 Splunk Inc. All rights reserved.
