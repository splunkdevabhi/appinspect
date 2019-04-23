# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Splunk app packaging standards

These checks validate that a Splunk app has been correctly packaged, and can be provided safely for package validation.
"""

# Python Standard Library
import logging
import os
import stat
import json
# Third-Party Libraries
from jsoncomment import JsonComment
# N/A
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.app_util import AppVersionNumberMatcher


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
@splunk_appinspect.cert_version(min="1.5.3")
def check_that_splunk_app_package_does_not_contain_files_outside_of_app(app, reporter):
    """Check that the Splunk App package does not contain any non-app files.
    Files within a valid app folder or valid dependencies within a .dependencies
    folder are permitted, all other files are not.
    """
    # Files inside app package's working_artifact
    for file_or_folder_outside_app in app.package.find_files_not_part_of_valid_apps():
        # Relative path to the app_dir, since these are outside the app_dir they
        # will most likely be of the form "../myfile.txt"
        relative_loc = os.path.relpath(file_or_folder_outside_app, app.app_dir)
        reporter_output = ("A file or folder was found outside of the app"
                           " directory. Please remove this file or folder: {}"
                           .format(relative_loc))
        reporter.fail(reporter_output)

    # Special case: if an origin artifact has non-app files associated with it
    # those are passed to the app.package to be called out here
    # For example, a tarball of tarball apps mixed with non-app files.
    # The app.package would be the first valid app tarball, the paths to
    # the non-app files within the overall package are captured here.

    # Files inside the origin package's working_artifact
    for file_or_folder_outside_app in app.package.origin_package_non_app_files:
        # These paths are relative to the origin app package which may or may
        # not be relative to the app_dir.
        reporter_output = ("A file or folder was found outside of the app"
                           " within the overall package. Please remove this"
                           " file or folder: {}"
                           .format(file_or_folder_outside_app))
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.3")
def check_that_splunk_app_package_with_static_dependencies_has_exactly_one_app_folder(app, reporter):
    """Check that the Splunk App package with a .dependencies directory also
    contains exactly one valid app folder.
    """
    # If no .dependencies folder exists, return N/A
    if not app.package.does_package_contain_dependencies_folder():
        reporter_output = "No {} folder found. Please add a .dependencies directory"
        " with an valid app folder.".format(app.dependencies_directory_path)
        reporter.not_applicable(reporter_output)
        return

    # If .dependencies folder exists but more than one folder exists as
    # sibling directories, return FAIL (app of apps + .dependencies are not
    # supported, only one or the other)
    contents = os.listdir(app.package.working_artifact)
    all_contents_are_folders = all(
        [os.path.isdir(os.path.join(app.package.working_artifact, path))
         for path in contents]
    )
    relative_dependencies_path = app.package.DEPENDENCIES_LOCATION
    relative_working_app_path = os.path.relpath(app.package.working_app_path,
                                                app.package.working_artifact)
    if (len(contents) != 2 or
            not all_contents_are_folders or
            not relative_dependencies_path in contents or
            not relative_working_app_path in contents):
        reporter_output = ("Only a single app folder and a single {} folder"
                           " should be included for apps packaged with static"
                           " dependencies using the Splunk Packaging Toolkit."
                           .format(app.dependencies_directory_path))
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.3")
def check_that_splunk_app_package_with_static_dependencies_has_app_manifest(app, reporter):
    """Check that the Splunk App package with a .dependencies directory also
    contains an app folder with an app.manifest.
    """
    # If no .dependencies folder exists, return N/A
    if not app.package.does_package_contain_dependencies_folder():
        reporter_output = "No {} folder found. Please add a .dependencies directory"
        " that contains an app folder with an app.manifest.".format(app.dependencies_directory_path)
        reporter.not_applicable(reporter_output)
        return

    # If .dependencies folder exists and single sibling directory is a valid
    # app but contains no app.manifest, return FAIL (.dependecies is only
    # valid when packaged and specified with slim)
    if not app.package.does_working_artifact_contain_app_manifest():
        reporter_output = ("App folder associated with package does not contain"
                           " an app.manifest file but contains a {} directory."
                           " Apps packaged with static dependencies using the"
                           " Splunk Packaging Toolkit are required to have an"
                           " app.manifest file.".format(app.dependencies_directory_path))
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.3")
def check_that_splunk_app_package_has_valid_static_dependencies(app, reporter):
    """Check that the Splunk App package contains only valid dependencies.
    Dependencies are valid if a .dependencies directory contains only valid
    app packages inside.
    """
    # If no .dependencies folder exists, return N/A
    if not app.package.does_package_contain_dependencies_folder():
        reporter_output = "No {} folder found. Please check that the Splunk App"
        "package contains only valid dependencies.".format(app.dependencies_directory_path)
        reporter.not_applicable(reporter_output)
        return

    # At this point, we accept that the .dependencies folder is valid - now
    # let's validate the contents of it. It should contain only valid app
    # packages and nothing else
    dependencies_folder = app.package.dependencies_folder
    dependencies_contents = os.listdir(dependencies_folder)

    for dependency_resource in dependencies_contents:
        resource_path = os.path.join(app.package.dependencies_folder,
                                     dependency_resource)
        generated_app_package = app.package.generate_app_package_from_file_or_folder(resource_path)
        if generated_app_package is None:
            reporter_output = ("Resource within the .dependencies folder that"
                               " does not appear to be a valid app package."
                               " Please remove this file or folder: {}/{}"
                               .format(app.dependencies_directory_path, dependency_resource))
            reporter.fail(reporter_output)

    # TODO: we may want to do some sort of validation that the dependencies
    # listed in app.manifest match what we see in the .dependencies
    # directory at some point. SLIM is probably the best place to do this
    # validation, however it does not appear to be supported at this time.
    # (running `slim validate` on an app with extra apps in the
    # .dependencies folder not listed in the app.manifest does not raise any
    # errors) - see APPMAN-20.


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_does_not_contain_prohibited_directories_or_files(app, reporter):
    """Check that the extracted Splunk App does not contain any directories or
    files that start with a `.`, or directories that start with `__MACOSX`.
    """
    prohibited_directories_and_files = app.package.find_prohibited_files(
        app.package.working_artifact,
        [app.package.DEPENDENCIES_LOCATION]
    )
    for prohibited_directory_or_file in prohibited_directories_and_files:
        # Relative path to the app_dir
        relative_loc = os.path.relpath(prohibited_directory_or_file, app.app_dir)
        reporter_output = ("A prohibited file or directory was found in the"
                           " extracted Splunk App: {}").format(relative_loc)
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_contains_default_app_conf_file(app, reporter):
    """Check that the extracted Splunk App contains a `default/app.conf`
    file.
    """
    if not app.package.does_working_artifact_contain_default_app_conf():
        reporter_output = ("Splunk App packages must contain a"
                           " `default/app.conf file`."
                           " No `default/app.conf` was found in `{}`."
                           ).format(app.package.origin_artifact_name)
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service","prelease")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_contains_default_app_conf_file_with_valid_version_number(app, reporter):
    """Check that the extracted Splunk App contains a `default/app.conf` file
    that contains an `[id]` or `[launcher]` stanza with a `version` property that
    is formatted as `Major.Minor.Revision`.
    """

    if app.file_exists("default", "app.conf"):
        filename = os.path.join('default', 'app.conf')
        config = app.get_config('app.conf')

        if not (config.has_section('id') or config.has_section('launcher')):
            reporter_output = "No `[id]` or `[launcher]` section found in app.conf. "
            reporter.fail(reporter_output, file_name=filename)
            return

        elif not (config.has_option('id', 'version') or config.has_option('launcher', 'version')):
            reporter_output = ("No version option specified in `[id]` or `[launcher]` section"
                               "of app.conf. ")
            reporter.fail(reporter_output, file_name=filename)
            return
        else:
            # at least has one of id_version, launcher_version
            id_version = config.has_option('id', 'version') and config.get('id', 'version')
            launcher_version = config.has_option('launcher', 'version') and config.get('launcher', 'version')

            # raise a warning only when version exists and malformed
            matcher = AppVersionNumberMatcher()
            reporter_output = ("`Major.Minor.Revision` version numbering "
                               "is required. ")
            # [id] stanza with version property takes precedence
            for version_val in (id_version, launcher_version):
                if version_val:
                    if config.has_option('id', 'version'):
                        lineno = config.get_section('id').get_option('version').lineno
                    else:
                        lineno = config.get_section('launcher').get_option('version').lineno

                    # regex matching
                    if len(matcher.match(version_val)) == 0:
                        reporter.fail(reporter_output, file_name=filename, line_number=lineno)
                    elif len(matcher.match(version_val)) == 1:
                        reporter.warn(reporter_output, file_name=filename, line_number=lineno)
                    break
    else:
        reporter_output = ("Splunk App packages must contain a"
                           " `default/app.conf file`."
                           " No `default/app.conf` was found in `{}`."
                           ).format(app.package.origin_artifact_name)
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_does_not_contain_invalid_directories(app, reporter):
    """Check that the extracted Splunk App does not contain any directories
    with incorrect permissions. Directories and sub directories
    must have the owner's permissions set to r/w/x (700).
    """
    invalid_directories = app.package.find_invalid_directories_with_wrong_permission(app.package.working_artifact,
                                                                                     stat.S_IRWXU)
    for invalid_directory in invalid_directories:
        reporter_output = ("An invalid directory was found in the"
                           " extracted Splunk App: {}").format(invalid_directory)
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud", "packaging_standards", "self-service")
@splunk_appinspect.cert_version(min="1.5.0")
def check_that_extracted_splunk_app_does_not_contain_files_with_invalid_permissions(app, reporter):
    """Check that the extracted Splunk App does not contain any files
    with incorrect permissions. Files must have the owner's
    permissions include read and write (600).
    """
    invalid_files = app.package.find_files_with_incorrect_permissions(app.package.working_artifact,
                                                                      stat.S_IRUSR | stat.S_IWUSR)
    for invalid_file in invalid_files:
        reporter_output = ("An invalid file was found in the"
                           " extracted Splunk App: {}").format(invalid_file)
        reporter.fail(reporter_output)

@splunk_appinspect.tags("self-service")
@splunk_appinspect.cert_version(min="1.6.1")
def check_that_json_schema_is_applicable(app, reporter):
    """Check if json schema is 2.0.0 in app.manifest then fail it.
    Because schema version of 2.0.0 is not yet compatible with any versions
    of the Splunk Cloud. So far, all cloud stack are 7.0 and lower but
    Json Schema 2.0.0 is only compatible with Splunk 7.1+.
    """
    if app.package.does_working_artifact_contain_app_manifest():
        app_manifest_path = os.path.join(app.package.working_app_path, "app.manifest")
        parser = JsonComment(json)
        with open(app_manifest_path) as f:
            app_manifest_content = parser.loads(f.read())
            schemaVersion = app_manifest_content['schemaVersion']
        if schemaVersion != '1.0.0':
            reporter_output = ("Json Schema version of 2.0.0 is not yet compatible with any versions of the Splunk Cloud (7.0 and lower)"
                               " so the app can't be SSAI. http://dev.splunk.com/view/packaging-toolkit/SP-CAAAE96#older"
                               " File: app.manifest")
            reporter.fail(reporter_output)
        else:
            pass
    else:
        reporter.not_applicable("app.manifest does not exist.")
