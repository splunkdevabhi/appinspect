# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Directory Structure Standards

Ensure that the directories and files that exist adhere to desired hierarchy
standards.
"""

# Python Standard Libraries
import logging
import os
import re
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "self-service")
@splunk_appinspect.cert_version(min="1.0.0")
@splunk_appinspect.display(report_display_order=1)
def check_that_local_does_not_exist(app, reporter):
    """Check that the 'local' directory does not exist.  All configuration
    should be in the 'default' directory.
    """
    if app.directory_exists("local"):
        reporter_output = "A 'local' directory exists in the app."
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud", "self-service")
@splunk_appinspect.cert_version(min="1.1.9")
def check_for_local_meta(app, reporter):
    """Check that the file 'local.meta' does not exist.  All metadata
    permissions should be set in 'default.meta'.
    """
    if app.file_exists("metadata", "local.meta"):
        reporter_output = ("Do not supply a local.meta file- put all settings"
                           " in default.meta")
        reporter.fail(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.1.16")
def check_that_local_passwords_conf_does_not_exist(app, reporter):
    """Check that `local/passwords.conf` does not exist.  Password files are not
    transferable between instances.
    """
    if app.directory_exists("local"):
        if app.file_exists("local", "passwords.conf"):
            reporter_output = ("A 'passwords.conf' file exists in the 'local'"
                               " directory of the app.")
            reporter.fail(reporter_output)
        else:
            pass  # No passwords.conf so it passes
    else:
        reporter_output = "The local directory does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud")
@splunk_appinspect.cert_version(min="1.3.2")
def check_that_directory_name_matches_package_id(app, reporter):
    """Check that when decompressed the Splunk App directory name matches the
    app.conf [package] stanza's `id` property.
    """
    if app.file_exists("default", "app.conf"):
        uncompressed_directory_name = app.name
        app_configuration_file = app.get_config('app.conf')
        if app_configuration_file.has_section("package"):
            package_configuration_section = app_configuration_file.get_section("package")
            if package_configuration_section.has_option("id"):
                package_stanza_id_property = package_configuration_section.get_option("id").value
                if package_stanza_id_property != uncompressed_directory_name:
                    reporter_output = ("The `app.conf` [package] stanza has an"
                                       " `id` property that does not match the"
                                       " uncompressed directory's name."
                                       " `app.conf` [package] id: {}"
                                       " uncompressed directory name: {}"
                                       ).format(package_stanza_id_property,
                                                uncompressed_directory_name)
                    reporter.fail(reporter_output)
                else:
                    # Success, uncompressed package name matches the app.conf
                    # [package] - id name
                    pass
            else:
                reporter_output = ("`app.conf` has the [package] stanza that"
                                   " does not have  the `id` property. Please"
                                   " add that property.")
                reporter.fail(reporter_output)
        else:
            reporter_output = ("The `app.conf` [package] stanza was not"
                               " detected. Please add this stanza.")
            reporter.fail(reporter_output)
    else:
        reporter_output = ("No app.conf file was detected.")
        reporter.fail(reporter_output)

@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_filenames_for_spaces(app, reporter):
    """Check that app has no .conf or dashboard filenames that contain spaces. 
    Splunk software does not support such files.
    """
    for directory, file, ext in app.iterate_files(types=['.xml', '.conf']):
        if re.search(r"\s", file):
            reporter_output = ("A conf or dashboard file was detected that contains space in filename. File: {}"
                               .format(os.path.join(directory, file)))
            reporter.fail(reporter_output)
