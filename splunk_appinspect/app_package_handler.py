# Copyright 2016 Splunk Inc. All rights reserved.

"""
AppPackageHandler class handles app package input which is passed to CLI.
This class currently can handle these cases:

- Simple Splunk App
    - Contains ONLY Splunk App files and directories
        - appserver/
        - default/
        - local/
        - etc.
- Nested Splunk Apps
    - Directory of multiple directory/tar/zip Splunk App packages
    - tar/zip of multiple directory/tar/zip Splunk App packages

Not implemented
- Static dependency support (.dependencies)
- Dynamic dependency support (app.manifest)
"""

# Standard Python Libraries
import logging
import os
import stat
import re
import shutil
import tarfile
import tempfile
import zipfile
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect

logger = logging.getLogger(__name__)


class AppPackageHandler(object):
    """A class intended to serve as the management interface for packages that
    are provided for certification. Not all apps are Splunk Apps.

    Attributes:
        apps (Dict of String: String): A dictionary where the key is the
            directory name that the app is extracted to, and the value is the
            absolute path to the extracted app's location.
        app_packages (List of AppPackage Objects): These are the list of
            packages detected in the App provided. This includes the root level
            app and any nested Apps detected. Implicit is the understanding is
            that the 0 index App is the root level app.
    """

    def __init__(self, app_package):
        """__init__ constructor for AppPackageHandler.

        Returns:
            None

        Arguments:
            app_package (String): The absolute path to the App that should be
                handled. This should be either a directory, spl, or tgz file.
        """
        # TODO: Remove self.apps, it is redundant and can be replaced by calling
        #       the AppPackage.working_artifact_name and AppPackage.working_path
        self.apps = {}  # Dictionary of (app's folder name, app's path)
        self.app_packages = []  # Array of all packages object
        origin_package = AppPackage.factory(app_package)

        # Regular app
        if origin_package.is_app:
            # Found app in the root dir, this is a single app
            self._add_package(origin_package)
            logger.info("Found app in {}".format(origin_package.origin_path))

            # Short circuits if simple app package is detected
            return

        # Tar of tars, app of apps, etc.
        app_found = False
        if os.path.isdir(origin_package.working_path):
            for resource in os.listdir(origin_package.working_path):
                resource_path = os.path.join(origin_package.working_path, resource)

                # Only attempt package addition if the package is one our our
                # supported types (directory, tar, zip)
                # is_tarfile and is_zipfile need to guard against directories
                # being used as parameters otherwise an IOError will be
                # raised if a directory path is pass into those functions.
                # Python built-in library should really handle this better, but
                # not sure why it doesn't
                is_resource_a_directory = os.path.isdir(resource_path)
                is_resource_a_tar_file = (True
                                          if (not is_resource_a_directory and
                                              tarfile.is_tarfile(resource_path))
                                          else False)
                is_resource_a_zip_file = (True
                                          if (not is_resource_a_directory and
                                              zipfile.is_zipfile(resource_path))
                                          else False)

                if (is_resource_a_directory or
                        is_resource_a_tar_file or
                        is_resource_a_zip_file):
                    app_package_candidate = AppPackage.factory(resource_path)
                    if app_package_candidate.is_app:
                        app_found = True
                        self._add_package(app_package_candidate)
                        logger.info("Found app in {}".format(app_package_candidate.origin_path))

        if not app_found:
            logger.warning("No app(s) found. Apps must adhere to the checks"
                           " tagged with `packaging_standards`.")
            # Last ditch effort to support a package for review. Added as a
            # package so vetting can be performed using `packaging_standards`
            # tags to determine minimum package requirements needed in order
            # for full validation to be performed. Done so that validator.py
            # has a package to test with for validtor.validate_package()
            self._add_package(origin_package)

    def _add_package(self, package):
        """Adds package to the Package Handler for tracking.

        Returns:
            None

        Arguments:
            package (AppPackage object): The app package object to be tracked.
        """
        self.apps[package.working_artifact_name] = package.working_path
        self.app_packages.append(package)

    @property
    def main_app_package(self):
        """Returns an AppPackage derived object."""
        if len(self.app_packages) > 0:
            return self.app_packages[0]
        else:
            return None

    def cleanup(self):
        """Helper function to initiate the cleanup function of AppPackages that
        are being tracked.

        Returns:
            None
        """
        for package in self.app_packages:
            package.clean_up()


class AppPackage(object):
    """This is a class meant to control the logic for interacting with a
    potential Splunk App package provided. This is intended to control the
    initially provided application artifact and the extracted contents of the
    application artifact.

    Attributes:
        NOT_ALLOWED_PATTERN (Regex Object): A regex pattern used to identify
            invalid paths for directory names.
        origin_path (String): An absolute path to the initially provided Splunk
            Application. Typically this will be the compressed Splunk
            Application as a .tgz, .spl, etc. or a directory that is provided.
        working_path (String): An absolute path to the extracted directory of
            the Splunk App. This should always be a directory.
    """

    NOT_ALLOWED_PATTERN = re.compile(
        r"""
            (?P<nix>
                ^\.         # Hidden folder
            )
            | (?P<macosx>
                ^__MACOSX   # Mac OSX folder
            )
        """,
        re.VERBOSE
    )

    def __init__(self, app_package):
        """Constructor/Initialization function.

        Args:
            app_package (String): a absolute path to a potential Splunk App
                package

        Returns:
            None
        """
        self.origin_path = app_package
        self.working_path = None

    @staticmethod
    def factory(app_package=""):
        """A helper function to facilitate the creation of AppPackage objects.

        Attributes:
            app_package (String): An absolute path to the initially provided
                application artifact. Typically this will be the compressed
                Splunk App as a .tgz, .spl, etc. or a simple directory
                that is provided.

        Returns:
            AppPackage derived Object: Returns an AppPackage derived object
                that represents the type of application provided.
        """
        if os.path.isdir(app_package):
            return FolderAppPackage(app_package)
        elif app_package.endswith(".zip"):
            return ZipAppPackage(app_package)
        else:
            return TarAppPackage(app_package)

    def _get_basename_from_path(self, path_to_extract_from):
        """Extracts basename of a file resource from a file path. This accounts
        for nuances associated with hidden directories, hidden files, and file
        extensions.

        This is done because Python's os.path.basename does not handle the cases
        list above.

        Arguments:
            path_to_extract_from (String): an absolute path to a file resource

        Return:
            String: the basename of the file path provided
        """
        # The splitting on `.` is done because python's os.path.splitext is not
        # sufficiently accounting for instances of files like example.tar.gz.
        # In that case it would end up returning the name `example.tar` instead
        # of just `example`
        file_resource_normalized_path = os.path.normpath(path_to_extract_from)
        file_resource_full_name = os.path.basename(file_resource_normalized_path)
        split_file_resource_full_name = file_resource_full_name.split(".")

        # If the artifact has a `.` at the beginning of its name. For something
        # like `.example.tar.gz` it will look like
        # ['', 'example', 'tar', 'gz']. So instead of the file name being the
        # first element, it is the second, and the `.` character has been lost
        # This will account for that nuance, by making sure the first `.` is
        # returned
        if file_resource_full_name.startswith("."):
            file_resource_name_to_return = ".".join(split_file_resource_full_name[0:2])
        else:
            file_resource_name_to_return = split_file_resource_full_name[0]

        return file_resource_name_to_return

    @property
    def origin_artifact_name(self):
        """A helper function to retrieve the name of the Splunk App compressed
        artifact.

        Returns:
            String: A string that is the name of the compressed application
                package.
        """
        return self._get_basename_from_path(self.origin_path)

    @property
    def working_artifact_name(self):
        """A helper function to retrieve the name of the Splunk App after it has
        been extracted.

        Returns:
            String: A string that is the directory name of the extracted
                Splunk App.
        """
        return self._get_basename_from_path(self.working_path)

    @property
    def is_app(self):
        """A helper function created to maintain the is_app contract. Specifies
        if the app provided is a Splunk App or not.

        Returns:
            Bool: True if a Splunk App, False if it is not a Splunk App
        """
        return self.is_splunk_app(self.working_path)

    def does_origin_artifact_start_with_period(self):
        """Helper function for part of the origin artifact validity tests.

        Returns:
            boolean: True if origin artifact starts with `.` otherwise False
        """
        return (self.origin_path is not None and
                self.origin_path != "" and
                self.origin_artifact_name.startswith("."))

    def is_origin_artifact_valid_compressed_file(self):
        """Helper function for part of the origin artifact validity tests.

        Returns:
            Bool: True if origin artifact a valid compressed file
            otherwise False
        """
        error_message = "This is an abstract method meant to be over-ridden."
        raise NotImplementedError(error_message)

    def does_origin_artifact_have_read_permission(self):
        """Helper function for part of the origin artifact validity tests.

        Returns:
            # boolean: True if origin artifact has owner read permissions (400)
            otherwise False
        """
        return bool(stat.S_IMODE(os.lstat(self.origin_path).st_mode) & stat.S_IRUSR)

    def is_origin_artifact_a_splunk_app(self):
        """A function to determine if the artifact provided is a valid Splunk
        App.

        Valid Splunk Apps:
        - Origin artifact is a valid compressed file
        - Origin artifact has owner read permission
        - DO NOT start with a '.'

        Returns:
            Bool: True if a Splunk App, False if it is not a Splunk App
        """
        return (self.is_origin_artifact_valid_compressed_file() and
                self.does_origin_artifact_have_read_permission() and
                not self.does_origin_artifact_start_with_period())

    def does_working_artifact_contain_default_app_conf(self):
        """Helper function for determining if the working artifact contains a
        `default/app.conf` file.

        Returns:
            Boolean: True if `default/app.conf` exists
        """
        has_working_path_been_assigned = (self.working_path is not None and
                                          self.working_path != "")
        has_working_directory = os.path.isdir(self.working_path)
        has_default_directory = os.path.isdir(os.path.join(self.working_path, "default"))
        has_default_app_conf_file = os.path.isfile(os.path.join(self.working_path, "default", "app.conf"))

        return (has_working_path_been_assigned and
                has_working_directory and
                has_default_directory and
                has_default_app_conf_file)

    def does_working_artifact_contain_default_app_conf_with_valid_version_number(self):
        """Helper function for determining if the working artifact contains a
        `default/app.conf` file with an `[id]` stanza using the `version`
        property correctly.

        Returns:
            Boolean: True if `default/app.conf` exists and contains valid id
        """
        app_conf_file_path = os.path.join(self.working_path, "default", "app.conf")
        version_regex_pattern = r"^\d{1,3}.\d{1,3}(.\d{1,3})?(\s?\w[\w\d]{,9})?$"

        has_default_app_conf_file = self.does_working_artifact_contain_default_app_conf()
        has_default_app_conf_file_with_valid_version = False

        try:
            if has_default_app_conf_file:
                app_conf_configuration_file = splunk_appinspect.configuration_file.ConfigurationFile()
                with open(app_conf_file_path) as file:
                    app_config_file = splunk_appinspect.configuration_parser.parse(file,
                                                                                   app_conf_configuration_file,
                                                                                   splunk_appinspect.configuration_parser.configuration_lexer)

                # [id] stanza with version property takes precedence
                has_id_stanza_with_valid_version = (app_config_file.has_option("id", "version") and
                                                    re.match(version_regex_pattern, app_config_file.get("id", "version")))
                has_launcher_stanza_with_valid_version = (app_config_file.has_option("launcher", "version") and
                                                          re.match(version_regex_pattern, app_config_file.get("launcher", "version")))

                has_default_app_conf_file_with_valid_version = (True
                                                                if (has_id_stanza_with_valid_version or
                                                                    has_launcher_stanza_with_valid_version)
                                                                else False)
        except Exception as exception:
            logger_output = ("An attempt was made to validate a Splunk App's"
                             " default/app.conf, but failed."
                             " Splunk App: {}"
                             " Exception: {}").format(self.origin_artifact_name,
                                                      exception.message)
            logger.warning(logger_output)

        return (has_default_app_conf_file and
                has_default_app_conf_file_with_valid_version)

    def is_working_artifact_a_directory(self):
        """Helper function to determine if the working artifact is available and
        a directory.

        Returns:
            Boolean: True if working directory is a directory, False if it is
                not a directory
        """
        return os.path.isdir(self.working_path)

    def is_working_artifact_a_splunk_app(self, working_path):
        """A function to determine if the provided artifact, after being
        extracted, is a valid Splunk App.

        Valid Splunk Apps:
        - DO contain a default/app.conf
        - DO not contain prohibited directories
            - __MACOSX
            - directories that start with '.'

        Args:
            working_path (String): An absolute path to the extracted Splunk App
                artifact that was provided.

        Returns:
            Bool: True if a Splunk App, False if it is not a Splunk App
        """
        does_working_artifact_directory_start_with_a_period = self.working_artifact_name.startswith(".")
        return (self.does_working_artifact_contain_default_app_conf() and
                self.is_working_artifact_a_directory() and
                not does_working_artifact_directory_start_with_a_period and
                not self.does_contain_prohibited_folder(working_path) and
                not self.does_contain_invalid_directories(working_path) and
                not self.does_contain_invalid_files(working_path)
                )

    def is_splunk_app(self, working_path):
        """A helper function to determine if the Splunk App provided is a valid
        Splunk App.

        Returns:
            Bool: True if a Splunk App, False if it is not a Splunk App
        """
        return (self.is_origin_artifact_a_splunk_app() and
                self.is_working_artifact_a_splunk_app(working_path))

    @staticmethod
    def find_prohibited_files(directory_to_search, prohibited_files_regex_pattern, directory_whitelist=None):
        """Function to locate prohibited directories and files

        Args:
            directory_to_search (String): the absolute path of the directories
                to search
            prohibited_files_regex_pattern (String): the regex string to be used
                for locating prohibited files
            directory_whitelist (List of Strings): a list of strings that are
                directory names to be ignored

        Returns:
            Array of Strings: an array of strings that are absolute paths of the
                prohibited directories or files
        """
        if directory_whitelist is None:
            directory_whitelist = []

        file_paths_to_return = []

        directory_name = os.path.basename(directory_to_search)
        directory_path_match = re.findall(prohibited_files_regex_pattern,
                                          directory_name)

        # Whether the `directory_to_search` is a file or a directory, if it
        # violates the `prohibited_files_regex_pattern` it will be added
        if len(directory_path_match):
            file_paths_to_return.append(directory_name)

        # Searches sub-directories and files for matches
        if os.path.isdir(directory_to_search):
            for directory, sub_directories, files in os.walk(directory_to_search):
                # Filters out sub-directories for traversal
                sub_directories[:] = [sub_directory
                                      for sub_directory
                                      in sub_directories
                                      if sub_directory not in directory_whitelist]

                for sub_directory in sub_directories:
                    directory_name_matches = re.findall(prohibited_files_regex_pattern,
                                                        sub_directory)
                    if len(directory_name_matches):
                        directory_path = os.path.join(directory, sub_directory)
                        file_paths_to_return.append(directory_path)
                for file in files:
                    file_name_matches = re.findall(prohibited_files_regex_pattern,
                                                   file)
                    if len(file_name_matches):
                        file_path = os.path.join(directory, file)
                        file_paths_to_return.append(file_path)

        return file_paths_to_return

    def does_contain_prohibited_folder(self, directory):
        """Determine if a directory contains an prohibited directory.

        Args:
            directory (String): An absolute path to the directory being checked
                for prohibited paths.

        Returns:
            Bool: True if an prohibited directory is found, False if none are
                found.
        """
        prohibited_directories_and_files = self.find_prohibited_files(directory,
                                                                      self.NOT_ALLOWED_PATTERN,
                                                                      directory_whitelist=[".dependencies"])
        return (len(prohibited_directories_and_files) > 0)

    @staticmethod
    def find_invalid_directories_with_wrong_permission(directory_to_search, permissions_mask):
        """Function to find directories with incorrect permissions. Directories and sub directories
        must have the owner's permissions set to r/w/x (700).

        Args:
            directory_to_search (String): the absolute path of the directories
                to search

        Returns:
            Array of Strings: an array of strings that are absolute paths of the
                directories with incorrect permission
        """
        invalid_directories = []

        # Check this directory first
        mode = os.stat(directory_to_search).st_mode
        if (mode & permissions_mask) != permissions_mask:
            invalid_directories.append(directory_to_search)

        # Check all sub directories
        if os.path.isdir(directory_to_search):
            for directory, sub_directories, files in os.walk(directory_to_search):
                for sub_directory in sub_directories:
                    dir_path = os.path.join(directory, sub_directory)
                    mode = os.stat(dir_path).st_mode
                    if (mode & permissions_mask) != permissions_mask:
                        invalid_directories.append(dir_path)

        return invalid_directories

    @staticmethod
    def find_files_with_incorrect_permissions(directory_to_search, permissions_mask):
        """Function to find files with incorrect permissions. Files must have the owner's
        permissions set to r/w (600)

        Args:
            directory_to_search (String): the absolute path of the directories
                to search

        Returns:
            Array of Strings: an array of strings that are absolute paths of the
                files with incorrect permission
        """
        invalid_files = []

        for directory, sub_directories, files in os.walk(directory_to_search):
            # Check all files in this directory
            for filename in files:
                filepath = os.path.join(directory, filename)
                mode = os.stat(filepath).st_mode
                if (mode & permissions_mask) != permissions_mask:
                    invalid_files.append(filepath)

        return invalid_files

    def does_contain_invalid_directories(self, directory):
        """Determine if a directory contains invalid folders with incorrect permissions. Directories
        and sub directories must have the owner's permissions set to r/w/x (700).

        Args:
            directory (String): An absolute path to the directory being checked.

        Returns:
            Bool: True if an invalid directory with incorrect permission is found,
            False if none are found.
        """
        invalid_directories = self.find_invalid_directories_with_wrong_permission(directory, stat.S_IRWXU)
        return len(invalid_directories) > 0

    def does_contain_invalid_files(self, directory):
        """Determine if a directory contains invalid folders with incorrect permissions. Files
        must have the owner's permissions include read and write (600).

        Args:
            directory (String): An absolute path to the directory being checked.

        Returns:
            Bool: True if an invalid directory with incorrect permission is found,
            False if none are found.
        """
        invalid_files = self.find_files_with_incorrect_permissions(directory, stat.S_IRUSR | stat.S_IWUSR)
        return len(invalid_files) > 0

    def clean_up(self):
        """An abstract function for managing the clean up of an extracted Splunk
        App.

        Returns:
            None
        """
        working_path_is_a_directory = os.path.isdir(self.working_path)
        if (self.working_path is not None and
                self.working_path != "" and
                working_path_is_a_directory):
            # ACD-940 Permission Denied
            os.chmod(self.working_path, 0o777)
            for root, dirs, _ in os.walk(self.working_path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o777)

            logger.info("Cleaning temp directory: {}".format(self.working_path))
            shutil.rmtree(self.working_path)

    def _get_working_dir(self, temporary_directory):
        """A function to retrieve the `working` directory of a directory that was
        extracted to. The `working` directory should be the root directory that
        represents the top-most level directory that was extracted to.

        Arguments:
            temporary_directory (String): the absolute path to the directory
                that a `working_directory` is being looked for

        Returns:
            String: A string that is the root level directory of an extracted
                artifact
        """
        # If an extraction failure occurs, then no directories will exist and
        # `temporary_directory` will be an empty list. If this occurs the
        # temporary working directory created, is elected as the
        # `working_directory` of the artifact.
        # If multiple directories exist the same behaviour is performed
        if len(os.listdir(temporary_directory)) == 1:
            temporary_directory = os.path.join(temporary_directory,
                                               os.listdir(temporary_directory)[0])
        return temporary_directory


class FolderAppPackage(AppPackage):
    """This is a derived AppPackage class meant to control the logic for
    interacting with a Splunk App that is provided in the form of a directory.

    Attributes:
        - All attributes that are inherited from AppPackage
    """

    def __init__(self, app_package):
        """Constructor/initialization function.

        args:
            app_package (String): a absolute path to a potential splunk app

        returns:
            None
        """
        super(FolderAppPackage, self).__init__(app_package)
        self.working_path = os.path.abspath(self.origin_path)

    def clean_up(self):
        """A function for managing the clean up of an extracted Splunk App.

        Returns:
            None
        """
        # This is over-ridden so that the base class's method is not called
        # Directories do not need to be cleaned up.
        pass

    def is_origin_artifact_valid_compressed_file(self):
        """Helper function for part of the origin artifact validity tests.

        Returns:
            Bool: Always returns True because folders are not compressed
        """
        # This is returning True every time because FolderAppPackage's are not a
        # compressed artifact.
        # This has to be over-ridden because the base class `AppPackage` will
        # have its `is_origin_artifact_valid_compressed_file` called during the
        # `is_origin_artifact_a_splunk_app` check.
        # The alternative is to override `is_origin_artifact_a_splunk_app`, but
        # that means that we would be overriding the logic for the general
        # validation which does not seem preferable be cause it means we will
        # have to make sure that all logic is handled correctly during different
        # validation changes. Perhaps we will reverse this decision in the future
        return True


class TarAppPackage(AppPackage):
    """This is an AppPackage derived class meant to control the logic for
    interacting with a Splunk App that is provided in the form of a compressed
    Tar file.

    Attributes:
        - All attributes that are inherited from AppPackage
    """

    def __init__(self, app_package):
        """Constructor/initialization function.

        Args:
            app_package (String): a absolute path to a potential Splunk App
                package

        Returns:
            None
        """
        super(TarAppPackage, self).__init__(app_package)

        is_compressed_artifact_valid = self.is_origin_artifact_valid_compressed_file()
        if is_compressed_artifact_valid:
            self.working_path = self.extract_application(self.origin_path)
        else:
            # If can't be extracted then just set resource to be compressed file
            self.working_path = self.origin_path

    def is_origin_artifact_valid_compressed_file(self):
        """Helper function for part of the origin artifact validity tests.

        Returns:
            Bool: True if origin artifact a valid compressed file
            otherwise False
        """
        # TODO: This should be a containing method that calls the other methods
        #       to gauge validity, e.g. can_origin_artifact_be_extracted, etc.
        # TODO: This does the exact same behavior as `extract_application` and
        #       should be cleaned up because #DRY
        compressed_artifact_path = self.origin_path
        compressed_artifact_name = self.origin_artifact_name

        temporary_directory = tempfile.mkdtemp()

        is_orign_artifact_valid = True

        try:
            with tarfile.open(name=compressed_artifact_path) as tar:
                if self.does_traversal_attack_exist(compressed_artifact_path,
                                                    temporary_directory,
                                                    tar.getnames()):
                    tar.extractall(path=temporary_directory)
        except Exception as exception:
            is_orign_artifact_valid = False

            logger.warning("Failed to extract {}".format(compressed_artifact_name))
            logger.error(exception.message)
        finally:
            # Cleanup because this doesn't require the file to stay around
            shutil.rmtree(temporary_directory)

        return is_orign_artifact_valid

    @staticmethod
    def does_traversal_attack_exist(pkg_tar, target_dir, tar_list):
        """A function to determine if a traversal attack exists in a compressed
        file.

        Args:
            pkg_tar (String): an absolute path to the compressed artifact being
                check for traversal attacks.
            target_dir (String): the directory where the tar file will be extracted
            tar_list (List): tar file elements

        Returns:
            Bool: True if a Splunk App, False if it is not a Splunk App
        """
        for directory in tar_list:
            if not os.path.abspath(os.path.join(target_dir, directory)).startswith(target_dir):
                # TODO: tests needed
                logger.info("Invalid tar file {}. Possibly directory traversal attack at {}".format(
                    pkg_tar, directory))
                return False
        return True

    def extract_application(self, compressed_application_path):
        """Extracts a compressed file to a temporary location.

        Args:
            compressed_application_path (String): An absolute path to a
                compressed artifact

        Returns:
            (String): An absolute path to the extracted directory
        """
        temporary_directory = tempfile.mkdtemp()

        try:
            with tarfile.open(compressed_application_path) as tar:
                # TODO: I'm pretty sure this should be `if not self.does...`
                if self.does_traversal_attack_exist(compressed_application_path, temporary_directory, tar.getnames()):
                    tar.extractall(path=temporary_directory)
        except Exception as e:
            application_name = os.path.basename(compressed_application_path)
            logger.warning("Failed to extract {}".format(application_name))
            logger.error(e.message)

        # If user packs app by tar -cvzf app-folder.tgz app-folder, it's extracted in <temp-dir>/app-folder
        # If user packs app by tar -cvzf app-folder.tgz default bin metadata..., it's extracted in <temp-dor>
        # Checking app pattern for one layer deeper
        return self._get_working_dir(temporary_directory)


class ZipAppPackage(AppPackage):
    """This is an AppPackage derived class meant to control the logic for
    interacting with a Splunk App that is provided in the form of a compressed
    Zip file.

    Attributes:
        - All attributes that are inherited from AppPackage
    """

    def __init__(self, app_package):
        """Constructor/initialization function.

        Args:
            app_package (String): a absolute path to a potential Splunk App
                package

        Returns:
            None
        """
        super(ZipAppPackage, self).__init__(app_package)

        is_compressed_artifact_valid = self.is_origin_artifact_valid_compressed_file()
        if is_compressed_artifact_valid:
            self.working_path = self.extract_application(self.origin_path)
        else:
            # If can't be extracted then just set resource to be compressed file
            self.working_path = self.origin_path

    def is_origin_artifact_valid_compressed_file(self):
        """Helper function for part of the origin artifact validity tests.

        Returns:
            Bool: True if origin artifact a valid compressed file
            otherwise False
        """
        # TODO: This should be a containing method that calls the other methods
        #       to gauge validity, e.g. can_origin_artifact_be_extracted, etc.
        # TODO: This does the exact same behavior as `extract_application` and
        #       should be cleaned up because #DRY
        compressed_artifact_path = self.origin_path
        compressed_artifact_name = self.origin_artifact_name

        temporary_directory = tempfile.mkdtemp()

        is_orign_artifact_valid = True

        try:
            # ACD-450 Zip Traversal attack is managed by Python core
            with zipfile.ZipFile(compressed_artifact_path) as zip:
                zip.extractall(temporary_directory)
        except Exception as e:
            is_orign_artifact_valid = False
            logger.warning("Failed to extract {}".format(compressed_artifact_name))
            logger.error(e.message)
        finally:
            # Cleanup because this doesn't require the file to stay around
            shutil.rmtree(temporary_directory)

        return is_orign_artifact_valid

    def extract_application(self, compressed_application_path):
        """Extracts a compressed file to a temporary location.

        Args:
            compressed_application_path (String): An absolute path to a
                compressed artifact

        Returns:
            (String): An absolute path to the extracted directory
        """
        temporary_directory = tempfile.mkdtemp()
        try:
            # ACD-450 Zip Traversal attack is managed by Python core
            with zipfile.ZipFile(compressed_application_path) as zip:
                zip.extractall(temporary_directory)
        except Exception as e:
            self.is_valid_compressed_file = False
            application_name = os.path.basename(compressed_application_path)
            logger.warning("Failed to extract {}".format(application_name))
            logger.error(e.message)

        working_directory_to_return = self._get_working_dir(temporary_directory)

        # If the output returned from _get_working_directory is the same as the
        # input, then there is an indication the extraction did not retrieve
        # anything and that the zip file is likely bad. If that is the case
        # Then the compressed_application_path should be returned instead, in
        # order to degrade gracefully and so that application information will
        # be derived correctly from that artifact's name instead
        if working_directory_to_return == temporary_directory:
            working_directory_to_return = compressed_application_path

        return working_directory_to_return
