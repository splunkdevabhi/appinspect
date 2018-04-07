# Copyright 2017 Splunk Inc. All rights reserved.

"""
### Splunk App Packaging Standards

These checks validate that a Splunk App has been correctly packaged, and can be
provided safely for package validation.
"""

# Python Standard Library
import logging
import stat
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect

report_display_order = 1
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# ORIGIN ARTIFACT CHECKS
# ------------------------------------------------------------------------------
@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_splunk_app_package_has_read_permission(app, reporter):
    """Check that the Splunk app provided does not contain incorrect permissions.
    Packages must have have the owner's read permission set to r (400).
    """
    # TODO(PBL-5212): produce actionable app inspect output instead of 'Permission denied' error
    if not app.package.does_origin_artifact_have_read_permission():
        reporter_output = ("Splunk App package does not contain owner read"
                           " permission and cannot be extracted.")
        reporter.fail(reporter_output)

@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_splunk_app_package_valid_compressed_file(app, reporter):
    """Check that the Splunk app provided a valid compressed file.
    """
    if not app.package.is_origin_artifact_valid_compressed_file():
        reporter_output = ("Splunk App package is not a valid compressed file"
                           " and cannot be extracted."
                           " Origin artifact name: {}").format(app.package.origin_artifact_name)
        reporter.fail(reporter_output)

@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_splunk_app_package_name_does_not_start_with_period(app, reporter):
    """Check that the Splunk app provided does not start with a `.`
    character.
    """
    if app.package.does_origin_artifact_start_with_period():
        reporter_output = ("Splunk App packages cannot start with a `.` as its"
                           " name."
                           " Origin artifact name: {}").format(app.package.origin_artifact_name)
        reporter.fail(reporter_output)


# ------------------------------------------------------------------------------
# WORKING ARTIFACT CHECKS
# ------------------------------------------------------------------------------
@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_splunk_app_package_extracts_to_directory(app, reporter):
    """Check that the compressed Splunk App extracts to a directory."""
    if not app.package.is_working_artifact_a_directory():
        reporter_output = ("Splunk App packages must extract to a directory."
                           " The Splunk App package extracted to: {}"
                           ).format(app.package.working_artifact_name)

        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_splunk_app_package_extracts_to_visible_directory(app, reporter):
    """Check that the compressed artifact extracts to a directory that does not
    start with a `.` character.
    """
    if app.package.working_artifact_name.startswith("."):
        reporter_output = ("Splunk App packages must extract to a directory"
                           " that is not hidden. The Splunk App package"
                           " extracted to: {}"
                           ).format(app.package.working_artifact_name)

        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_does_not_contain_prohibited_directories_or_files(app, reporter):
    """Check that the extracted Splunk App does not contain any directories or
    files that start with a `.`, or directories that start with `__MACOSX`.
    """
    main_app_package = app.package
    prohibited_directories_and_files = main_app_package.find_prohibited_files(main_app_package.working_path,
                                                                              main_app_package.NOT_ALLOWED_PATTERN,
                                                                              directory_whitelist=[".dependencies"])
    for prohibited_directory_or_file in prohibited_directories_and_files:
        reporter_output = ("A prohibited file or directory was found in the"
                           " extracted Splunk App."
                           " Resource located: {}").format(prohibited_directory_or_file)
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_contains_default_app_conf_file(app, reporter):
    """Check that the extracted Splunk App contains a `default/app.conf`
    file.
    """
    if not app.package.does_working_artifact_contain_default_app_conf():
        reporter_output = ("Splunk App packages must contain a"
                           " `default/app.conf file."
                           " No `default/app.conf` was found in `{}`."
                           ).format(app.package.origin_artifact_name)
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_contains_default_app_conf_file_with_valid_version_number(app, reporter):
    """Check that the extracted Splunk App contains a `default/app.conf` file
    that contains an `[id]` or [launcher] stanza with a `version` property that
    is formatted as `Major.Minor.Revision`.
    """
    if not app.package.does_working_artifact_contain_default_app_conf_with_valid_version_number():
        reporter_output = ("Splunk App packages must contain a"
                           " `default/app.conf file with an `[id]` or"
                           " [launcher] stanza using the `version` property"
                           " formatted as"
                           " `Major.Minor.Revision`.")
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_does_not_contain_invalid_directories(app, reporter):
    """Check that the extracted Splunk App does not contain any directories
    with incorrect permissions. Directories and sub directories
    must have the owner's permissions set to r/w/x (700).
    """

    main_app_package = app.package
    invalid_directories = main_app_package.find_invalid_directories_with_wrong_permission(main_app_package.working_path,
                                                                                          stat.S_IRWXU)
    for invalid_directory in invalid_directories:
        reporter_output = ("An invalid directory was found in the"
                           " extracted Splunk App."
                           " Resource located: {}").format(invalid_directory)
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_does_not_contain_files_with_invalid_permissions(app, reporter):
    """Check that the extracted Splunk App does not contain any files
    with incorrect permissions. Files must have the owner's
    permissions include read and write (600).
    """

    main_app_package = app.package
    invalid_files = main_app_package.find_files_with_incorrect_permissions(main_app_package.working_path,
                                                                           stat.S_IRUSR | stat.S_IWUSR)
    for invalid_file in invalid_files:
        reporter_output = ("An invalid file was found in the"
                           " extracted Splunk App."
                           " Resource located: {}").format(invalid_file)
        reporter.fail(reporter_output)
