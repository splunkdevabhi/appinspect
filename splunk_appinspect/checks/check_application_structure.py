# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Directory structure standards

Ensure that the directories and files in the app adhere to hierarchy standards.
"""

# Python Standard Libraries
import logging
import os
import re
import string
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.splunk import normalizeBoolean

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
        file_path = os.path.join("metadata", "local.meta")
        reporter_output = ("Do not supply a local.meta file- put all settings"
                           " in default.meta. File: {}"
                           ).format(file_path)
        reporter.fail(reporter_output, file_path)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.1.16")
def check_that_local_passwords_conf_does_not_exist(app, reporter):
    """Check that `local/passwords.conf` does not exist.  Password files are not
    transferable between instances.
    """
    if app.directory_exists("local"):
        if app.file_exists("local", "passwords.conf"):
            file_path = os.path.join("local", "passwords.conf")
            reporter_output = ("A 'passwords.conf' file exists in the 'local'"
                               " directory of the app. File: {}"
                               ).format(file_path)
            reporter.fail(reporter_output, file_path)
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
        filename = os.path.join("default", "app.conf")
        uncompressed_directory_name = app.name
        app_configuration_file = app.get_config('app.conf')
        if app_configuration_file.has_section("package"):
            package_configuration_section = app_configuration_file.get_section("package")
            if package_configuration_section.has_option("id"):
                package_stanza_id_property = package_configuration_section.get_option("id").value
                if package_stanza_id_property != uncompressed_directory_name:
                    # Fail, app id is present but id does not match directory name
                    lineno = package_configuration_section.get_option('id').lineno
                    reporter_output = ("The `app.conf` [package] stanza has an"
                                       " `id` property that does not match the"
                                       " uncompressed directory's name."
                                       " `app.conf` [package] id: {}"
                                       " uncompressed directory name: {}."
                                       " File: {}, Line: {}."
                                       ).format(package_stanza_id_property,
                                                uncompressed_directory_name,
                                                filename,
                                                lineno)
                    reporter.fail(reporter_output, filename, lineno)
            elif not package_configuration_section.has_option("check_for_updates") \
                    or _is_update_enabled(package_configuration_section.get_option("check_for_updates").value):
                # Fail, app id isn't present but updates are enabled
                lineno = package_configuration_section.get_option('check_for_updates').lineno \
                    if package_configuration_section.has_option('check_for_updates') \
                    else package_configuration_section.lineno
                reporter_output = ("The `check_for_updates` property is enabled, "
                                   "but no `id` property is defined. Please disable "
                                   "`check_for_updates` or set the `id` property "
                                   "to the uncompressed directory name of the app. "
                                   "File: {}, Line: {}."
                                   ).format(filename, lineno)
                reporter.fail(reporter_output, filename, lineno)
        else:
            # Fail, the package stanza doesn't exist
            reporter_output = ("The `app.conf` [package] stanza does not "
                               "exist. Please disable `check_for_updates` "
                               "or set the `id` property in the [package] "
                               "stanza. File: {}"
                               ).format(filename)
            reporter.fail(reporter_output, filename)
    else:
        reporter_output = ("No app.conf file was detected.")
        reporter.fail(reporter_output)


def _is_update_enabled(check_for_updates_value):
    try:
        return normalizeBoolean(check_for_updates_value)
    except ValueError:
        return True


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_filenames_for_spaces(app, reporter):
    """Check that app has no .conf or dashboard filenames that contain spaces.
    Splunk software does not support such files.
    """
    # <app_dir>/default contains configuration required by your app and dashboard files, 
    # so set it as the base directory.
    for directory, file, ext in list(app.iterate_files(basedir='default', types=['.conf'])) + \
                                list(app.iterate_files(basedir='default/data', types=['.xml'])):
        if re.search(r"\s", file):
            filename = os.path.join(directory, file)
            # The regex that extracts the filename would extract wrong file name due to the space,
            # so here I use `Filename: {}`.
            reporter_output = ("A conf or dashboard file contains a space in the filename. Filename: {}"
                               .format(filename))
            reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.6.0")
def check_that_app_name_config_is_valid(app, reporter):
    """Check that the app name does not start with digits"""
    if app.package.app_cloud_name.startswith(tuple(string.digits)):
        reporter_output = "The app name (%s) cannot start with digits!" % app.name
        reporter.fail(reporter_output)
    else:
        pass