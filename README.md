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
	- `pip install -r (windows|darwin|linux).txt`, it depends on your system platform
	- `python setup.py install`
	- That's it. The `splunk-appinspect` tool is installed into your virtualenv. You can verify this by running the following commands:
   		- `splunk-appinspect`
    	- `splunk-appinspect list version`

### Run CLI directly from codebase
* Install all dependencies, `pip install -r (windows|darwin|linux).txt`, it depends on your system platform
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
    - `pip install -r test/(windows|darwin|linux).txt`, it depends on your system platform
* Ensure the Unit tests pass
    - `pytest -v test/unit/`
* Ensure the Integration tests pass
    - Integration tests uses a library called `mule` to download packages from AWS S3 for testing
        - Export `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables, you can find the credentials in secret.splunk.com
	- `pytest -v test/integration/test_cli.py`
	- network access is needed because some testing apps will be downloaded online, and this may take some time
	- `splunk-appinspect` CLI is needed in `PATH` so that integration tests can be run correctly

### Speed up integration test
* When running integration tests, splunk mule library will automatically download testing app packages from S3,
which could be very slow depending on the network. If you download all the packages once,
you can set environment variable `APPINSPECT_DOWNLOAD_TEST_DATA` to `false` to avoid downloading them every time. For example:
`APPINSPECT_DOWNLOAD_TEST_DATA=false pytest -v --junitxml=test_cli_results.xml ./test/integration -k test_splunk_appinspect_list_works_with_included_and_excluded_tags_filter`   

### Speed up single unit test in a test scenario
Running single test case is time consuming since pytest will collect all tests even if you only plan to run single test case, which is too slow for fast feedback development cycle.
To make it faster, when you run pytest, either in CLI or IDE, you can specify the test scenario name prefix using an env var called `APPINSPECT_TEST`, so that only this test scenario csv will be handled and this makes running single test faster. For example, you can try:
```
APPINSPECT_TEST=test_check_server_configuration_file python -m pytest -v ./test/unit -k check_server_conf
```
You can use the `APPINSPECT_TEST` to fasten test scenario collection and use -k to focus on a specific check in the test scenario.

### Install without building
* Install the latest AppInspect CLI from the development branch.
    - `wget -r -l1 --no-parent --no-directories -A 'splunk-appinspect-*.tar.gz' https://repo.splunk.com/artifactory/Solutions/AppInspect/CLI/develop/builds/latest/ && pip install splunk-appinspect-*.tar.gz`

### `VERSION.txt` naming convention
Each update in `VERSION.txt` should correspond to a package release:

1. If we aim for a major release, we should name the version referring [semver](https://semver.org/) as is, example: `1.6.0`.
2. If we aim for a hotfix release, we should append hotfix version to current version(`{appinspect version}+b{hotfix version}`), example: `1.6.0+b1`.
    - Note: if there is a second hotfix after the first hotfix, the version should be updated to `1.6.0+b2`, and so on.
1. If we aim for a rc build in `release-candidate` phase, we should append rc version(`{appinspect version}rc{hotfix version}`), example: `1.6.0rc2`.

## Release strategy
Referring [Gitflow Workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow),
now the release strategy of appinspect can be descripted as following:
1. All `feature/` and `bugfix/` branches should be checked out from `development` branch, and merged back to `development` branch.
2. All `hotfix/` branches should be checked out directly from `master` branch, and merged back to `master` and `development` branch.
    - Notes:
        - Each PR from `hotfix/` to `master` branch should contain a updated version, reflected in `VERSION.txt`, as mentioned in naming convention.
3. Once `development` branch has acquired enough features for a release, a `release/` branch should be checked out from `development` branch.
    - Notes:
        - Bugfix in `release candidate` phase should be merged to `/release` branch.
        - Each `release/` branch should be merged back into `development` branch **after** `master` release, since it may have separately progressed from `development` branch since the release was initiated.
4. Jenkins builds for all `feature/` and `bugfix/` branches will generate a stub package naming `splunk-appinspect-1.0.1.prtest.tar.gz` as well, it's just for checking whether the _publish stage_ in Jenkins build can be finished successfully.

## Release version convention

|Branch name | Generate built package | Release to outside world | Package filename example| `requirements.txt` entry example | Notes |
|:---:|:---:|:---:|:---:|:---:|:---:|
| `development` | No | / |   /  | / | only accept PR from `feature/` and normal `bugfix/` branches|
| `master`(normal) |  Yes | Yes | `splunk-appinspect-1.6.0.tar.gz` | `splunk-appinspect==1.6.0` | only accept PR from `release/` branches |
| `master`(hotfix) | Yes | Yes | `splunk-appinspect-1.6.0+b1.tar.gz` | `splunk-appinspect==1.6.0+b1` | only accept PR from `hotfix/` branches |
| `release/{version_number}` | Yes | No | `splunk-appinspect-1.6.0rc2+4ae00b.tar.gz` | `splunk-appinspect==1.6.0rc2+4ae00b` | only for e2e test in `release-candidate` phase |

* To guarantee the PRs' quality, please execute the following steps for once:
    - `chmod +x ./scripts/hooks/install-hooks.sh ./scripts/hooks/pre-commit.sh ./scripts/hooks/pre-push.sh`
    - `./scripts/hooks/install-hooks.sh`

## Release testing
Before releasing a new version, we need to do some final verification. 
* Run all the unit/integration tests on macOS/Linux/Windows
    * Linux can be easily verified by viewing the built result in Jenkins since we run all our tests on Linux.
    * macOS:
        * Clone the repo
        * Create a fresh virtualenv
        * Install dependencies
        * Run unit test and integration test
    * Windows:
        * Install VirtualBox and Vagrant on your Mac
        * Clone the repo under Mac
        * Launch the Windows system with Python and all necessary dependencies installed
            * `cd test_environment`
            * `vagrant up`
            * You should be able to run any command like this:
                * `vagrant winrm --command Test-WSMan`
        * Run tests
            * Log in to Windows box using `vagrant/vagrant`
            * Clone the repo under Windows
                * Instead of using Vagrant's shared folder, an additional clone is needed because we have some permission related tests that don't work with shared folder under Windows
            * Set AWS access key id and access secret in PowerShell
                * `setx AWS_ACCESS_KEY_ID {your_aws_access_key_id}`
                * `setx AWS_SECRET_ACCESS_KEY {your_aws_secret_access_key}`
            * Run `make unit_test` in PowerShell
            * Run `make integration_test` in PowerShell
* Verify the installation package on macOS/Linux/Windows
    1. Create a new virtualenv
    1. Install the package 
        ```
        # where 1.6.1+c901a8 is the version you can find verify and you can find it in repo.splunk.com via "simple search", each commit on release/* branch will be built and published to repo.splunk.com
        pip install splunk-appinspect==1.6.1+c901a8 --extra-index-url https://repo.splunk.com/artifactory/api/pypi/pypi-virtual/simple
        ```
    1. Run some simple commands to verify the installed package for the following cases, including:
        * `splunk-appinspect list version`
        * `splunk-appinspect list checks`
        * `splunk-appinspect inspect /path/to/some/app`
        * `splunk-appinspect inspect /path/to/some/app --mode precert`

# Copyright

Copyright 2017 Splunk Inc. All rights reserved.
