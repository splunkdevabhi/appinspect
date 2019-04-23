# Copyright 2018 Splunk Inc. All rights reserved.

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
        origin_package (AppPackage): AppPackage generated from input origin
            app_package artifact - retained so that it can be cleaned up
    """

    def __init__(self, app_package_path):
        """__init__ constructor for AppPackageHandler.

        Returns:
            None

        Arguments:
            app_package_path (String): The absolute path to the App that should
                be handled. This should be either a directory, spl, or tgz file.
        """
        # TODO: Remove self.apps, it is redundant and can be replaced by calling
        # the AppPackage.working_artifact_name and AppPackage.working_app_path
        self.apps = {}  # Dictionary of (app's folder name, app's path)
        self.app_packages = []  # Array of all AppPackage objects
        self.origin_package = AppPackage.factory(app_package_path)
        try:
            # Regular app
            if self.origin_package.is_splunk_app():
                # Found app in the root dir, this is a single app
                self._add_package(self.origin_package)
                logger.info("Found app in {}".format(self.origin_package.origin_path))

                # Gather and add any .dependencies app packages
                self._gather_package_dependencies()

                # Short circuits if simple app package is detected
                return

            # Invalid App, for example an invalid tarball that fails to extract
            if self.origin_package.working_artifact is None:
                # Treat as single app
                self._add_package(self.origin_package)
                logger.warn("Found invalid app with no package contents in {}"
                            .format(self.origin_package.origin_path))

                # Skip adding .dependencies app packages since no package contents
                # Short circuits if simple app package is detected
                return

            # Tar of tars, app of apps, etc.
            app_found = False
            files_not_part_of_valid_apps = []  # Array of filepaths outside of apps
            contents_path = self.origin_package.working_artifact
            resource_contents = []
            try:
                if os.path.isdir(contents_path):
                    resource_contents = os.listdir(self.origin_package.working_artifact)
            except:
                logger.warning("Issue reading contents of {}".format(
                    self.origin_package.working_artifact))
                pass  # if read perm or other error, stop

            if len(resource_contents) > 0:
                try:
                    resource_contents = os.listdir(contents_path)
                except:
                    logger.warning("Issue reading contents of {}".format(contents_path))
                    resource_contents = []
                for resource in resource_contents:
                    resource_path = os.path.join(contents_path, resource)
                    generated_app_package = AppPackage.generate_app_package_from_file_or_folder(
                        resource_path)
                    if generated_app_package is not None:
                        if not app_found:
                            # For first app == main app, make sure name is not a
                            # temp directory name - if so use name from origin
                            if (generated_app_package.working_app_path ==
                                    self.origin_package.working_artifact):
                                generated_app_package.working_artifact_name = self.origin_package.artifact_name
                        app_found = True
                        self._add_package(generated_app_package)
                        logger.info("Found app in {}".format(generated_app_package.origin_path))
                    else:
                        # Reject files/folders within the package but not
                        # app-related. Store as path relative to origin package
                        # contents folder
                        files_not_part_of_valid_apps.append(resource)

            if not app_found:
                logger.warning("No app(s) found. Apps must adhere to the checks"
                               " tagged with `packaging_standards`.")
                # Last ditch effort to support a package for review. Added as a
                # package so vetting can be performed using `packaging_standards`
                # tags to determine minimum package requirements needed in order
                # for full validation to be performed. Done so that validator.py
                # has a package to test with for validator.validate_package()
                self._add_package(self.origin_package)

            if len(self.app_packages) == 1 and isinstance(self.main_app_package, FolderAppPackage):
                # If there is a single app folder, this may be an app with valid
                # dependencies, assign the contents path outside the app to accomodate
                self.main_app_package.working_artifact = contents_path
            else:
                # Associate non-app files from the origin package with the
                # main_app_package so that they can be called out during package
                # validation
                self.main_app_package.origin_package_non_app_files = files_not_part_of_valid_apps

            # Gather and add any .dependencies app packages
            self._gather_package_dependencies()
        except Exception as exception:
            logger_output = ("An attempt was made to initialize"
                             " AppPackageHandler, but failed."
                             " Exception: {}").format(exception.message)
            logger.warning(logger_output)
            self.origin_package.clean_up()

    def _gather_package_dependencies(self):
        """Helper function to gather all dependencies, and their dependencies,
        etc. recursively from the .dependencies folder. Add any valid app
        packages to self.app_packages in a breadth-first-search manner.

        Returns:
            None
        """
        app_package_queue = self.app_packages[:]
        while len(app_package_queue) > 0:
            package = app_package_queue.pop(0)  # dequeue the first package
            if package.dependencies_folder is not None:
                try:
                    depdendency_paths = os.listdir(package.dependencies_folder)
                except:
                    logger.warning("Issue reading contents of {}".format(
                        package.dependencies_folder))
                    depdendency_paths = []  # in case of read error, etc
                for dependency_path in depdendency_paths:
                    dependency_full_path = os.path.join(package.dependencies_folder,
                                                        dependency_path)
                    dependency_app_package = AppPackage.generate_app_package_from_file_or_folder(
                        dependency_full_path)
                    if dependency_app_package is not None:
                        package.static_slim_dependency_app_packages.append(dependency_app_package)
                        dependency_app_package.is_static_slim_dependency = True
                        # Appends the package to self.app_packages
                        self._add_package(dependency_app_package)
                        # Also append to our working queue which is independent
                        # of self.app_packages
                        app_package_queue.append(dependency_app_package)

    def _add_package(self, package):
        """Adds package to the Package Handler for tracking.

        Returns:
            None

        Arguments:
            package (AppPackage object): The app package object to be tracked.
        """
        self.apps[package.working_artifact_name] = package.working_app_path
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
        self.origin_package.clean_up()


class AppPackage(object):
    """This is a class meant to control the logic for interacting with a
    potential Splunk App package provided. This is intended to control the
    initially provided application artifact and the extracted contents of the
    application artifact.

    Attributes:
        DEPENDENCIES_LOCATION (String): Fixed expected location of slim static
            depdendencies folder. This is the relative path from the root of the
            Splunk App.
        NOT_ALLOWED_PATTERN (Regex Object): A regex pattern used to identify
            invalid paths for directory names.
        dependencies_folder (String): Absolute path to dependencies folder or
            None if none exists
        is_splunk_app (Boolean): True if a Splunk App, False if it is not a
            Splunk App
        is_static_slim_dependency (Boolean): True if this AppPackage was
            derived from a package within another AppPackage's dependencies
            directory, False otherwise.
        origin_artifact_name (String): A string that is the name of the
            compressed application package.
        origin_package_non_app_files (List of Strings): Relative paths to files
            within origin package that are not associated with a valid app
        origin_path (String): An absolute path to the initially provided Splunk
            Application. Typically this will be the compressed Splunk
            Application as a .tgz, .spl, etc. or a directory that is provided.
        static_slim_dependency_app_packages (List of AppPackages): list of
            AppPackages derived from this AppPackage's dependency directory
        working_app_path (String): An absolute path to the extracted directory
            of the Splunk App folder itself. This should always be a directory.
        working_artifact (String): the path to the package contents, for
            FolderAppPackages working_artifact will refer to folder input, for
            CompressedAppPackages working_artifact will refer to the root
            directory containing the extracted contents (not just the path to
            the app within those contents)
        working_artifact_name (String): A string that is the directory name of
            the extracted Splunk App OR compressed file name if directory name
            is a temporary directory
        app_cloud_name (String): For most cases it will be the same to
            working_artifact_name, except that some apps would NOT have a standalone
            folder after extraction, this attr will simply point to those apps' temp
            folder. (see details ACD-2149)
    """

    DEPENDENCIES_LOCATION = ".dependencies"
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

    def __init__(self, app_package_path):
        """Constructor/Initialization function.

        Args:
            app_package_path (String): a absolute path to a potential Splunk App
                package

        Returns:
            None
        """
        self.is_static_slim_dependency = False
        self.origin_package_non_app_files = []
        self.origin_path = app_package_path
        self.static_slim_dependency_app_packages = []
        self.working_artifact = None
        self.working_artifact_name = self._get_basename_from_path(self.origin_path)
        self.app_cloud_name = self.working_artifact_name
        self.working_app_path = None

    @staticmethod
    def factory(app_package_path=""):
        """A helper function to facilitate the creation of AppPackage objects.

        Attributes:
            app_package_path (String): An absolute path to the initially
                provided application artifact. Typically this will be the
                compressed Splunk App as a .tgz, .spl, etc. or a simple
                directory that is provided.

        Returns:
            AppPackage derived Object: Returns an AppPackage derived object
                that represents the type of application provided.
        """
        if os.path.isdir(app_package_path):
            return FolderAppPackage(app_package_path)
        elif zipfile.is_zipfile(app_package_path):
            return ZipAppPackage(app_package_path)
        else:
            return TarAppPackage(app_package_path)

    @staticmethod
    def generate_app_package_from_file_or_folder(resource_path):
        """Detects whether input file or folder path is an app, returns
        AppPackage if so, None otherwise.

        Args:
            resource_path (String): absolute path to file or folder to check

        Returns
            AppPackage generated or None if not an app
        """
        # Only attempt package addition if the package is one our our
        # supported types (directory, tar, zip)
        # is_tarfile and is_zipfile need to guard against directories
        # being used as parameters otherwise an IOError will be
        # raised if a directory path is pass into those functions.
        # Python built-in library should really handle this better, but
        # not sure why it doesn't
        is_resource_a_directory = os.path.isdir(resource_path)
        is_resource_a_tar_file = (not is_resource_a_directory and
                                  tarfile.is_tarfile(resource_path))
        is_resource_a_zip_file = (not is_resource_a_directory and
                                  zipfile.is_zipfile(resource_path))

        if (is_resource_a_directory or
                is_resource_a_tar_file or
                is_resource_a_zip_file):
            app_package_candidate = AppPackage.factory(resource_path)
            try:
                if app_package_candidate.is_splunk_app():
                    return app_package_candidate
                else:
                    app_package_candidate.clean_up()
            except:
                app_package_candidate.clean_up()
        return None

    def _get_working_app_path(self, root_directory):
        """A function to retrieve the path identified as the folder containing
        the App itself. This will eventually be used as the App.app_dir which is
        the folder used for validation. A working app path should contain a
        default/ folder, a README file, etc. If multiple app-like folders are
        found then return the root_directory being searched.

        Arguments:
            root_directory (String): the absolute path to the directory
                that a `working_app_path` is being looked for

        Returns:
            String: A string that is the app-level directory of an extracted
                artifact
        """
        # If root_directory has a default/app.conf, call it good
        if self.does_dir_contain_default_app_conf(root_directory):
            return root_directory
        try:
            contents_of_root_dir = os.listdir(root_directory)
        except:
            logger.warning("Issue reading contents of {}".format(root_directory))
            # If read permissions error or other issue, abort and return root
            return root_directory
        # If exactly one app directory is found, return that - this will be
        # true of valid apps containing a .dependencies folder outside of the
        # app folder and also for apps containing invalid files outside of
        # the app folder
        app_folder = None
        for file_or_folder in contents_of_root_dir:
            resource_path = os.path.join(root_directory,
                                         file_or_folder)
            if (os.path.isdir(resource_path) and
                    self.does_dir_contain_default_app_conf(resource_path)):
                if app_folder is not None:
                    # If we already found another app_folder, we have an
                    # app of apps, so use the entire temp folder
                    return root_directory
                app_folder = resource_path
        if app_folder is not None:
            # We found exactly one app folder, use this
            return app_folder
        return root_directory

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
    def working_path(self):
        """Same as working_app_path, included for backwards compatibility.
        """
        return self.working_app_path

    @property
    def dependencies_folder(self):
        """
        Returns:
            String: Absolute path to dependencies folder or None if none exists
        """
        dependencies_path = os.path.join(self.working_artifact, self.DEPENDENCIES_LOCATION)
        return dependencies_path if os.path.isdir(dependencies_path) else None

    def does_package_contain_dependencies_folder(self):
        """
        Returns:
            Bool: True if dependencies folder exists, False otherwise
        """
        return self.dependencies_folder is not None

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
        return self.does_dir_contain_default_app_conf(self.working_app_path)

    @staticmethod
    def does_dir_contain_default_app_conf(directory):
        """Helper function for determining if the input directory contains a
        `default/app.conf` file.

        Returns:
            Boolean: True if `default/app.conf` exists
        """
        dir_exists = (directory is not None and
                      directory != "" and
                      os.path.isdir(directory))
        has_default_directory = os.path.isdir(os.path.join(directory, "default"))
        has_default_app_conf_file = os.path.isfile(os.path.join(directory, "default", "app.conf"))

        return (dir_exists and
                has_default_directory and
                has_default_app_conf_file)

    def does_working_artifact_contain_app_manifest(self):
        """Helper function for determining if the working artifact contains a
        `app.manifest` file.

        Returns:
            Boolean: True if `app.manifest` exists
        """
        return self.does_dir_contain_app_manifest(self.working_app_path)

    @staticmethod
    def does_dir_contain_app_manifest(directory):
        """Helper function for determining if the input directory contains a
        `app.manifest` file.

        Returns:
            Boolean: True if `app.manifest` exists
        """
        dir_exists = (directory is not None and
                      directory != "" and
                      os.path.isdir(directory))
        has_app_manifest_file = os.path.isfile(os.path.join(directory, "app.manifest"))

        return (dir_exists and
                has_app_manifest_file)

    def is_working_artifact_a_directory(self):
        """Helper function to determine if the working artifact is available and
        a directory.

        Returns:
            Boolean: True if working directory is a directory, False if it is
                not a directory
        """
        return os.path.isdir(self.working_app_path)

    def is_working_artifact_a_splunk_app(self):
        """A function to determine if the provided artifact, after being
        extracted, is a valid Splunk App.

        Valid Splunk Apps:
        - DO contain a default/app.conf
        - DO not contain prohibited directories
            - __MACOSX
            - directories that start with '.' INCLUDING .dependencies as that
              folder should only exist OUTSIDE of the splunk app folder

        Args:
            None

        Returns:
            Bool: True if a Splunk App, False if it is not a Splunk App
        """
        does_working_artifact_directory_start_with_a_period = self.working_artifact_name.startswith(".")
        return (self.does_working_artifact_contain_default_app_conf() and
                self.is_working_artifact_a_directory() and
                not does_working_artifact_directory_start_with_a_period and
                not self.does_contain_prohibited_files() and
                not self.does_contain_invalid_directories() and
                not self.does_contain_invalid_files()
                )

    def is_splunk_app(self):
        """A helper function to determine if the Splunk App provided is a valid
        Splunk App.

        Returns:
            Bool: True if a Splunk App, False if it is not a Splunk App
        """
        return (self.is_origin_artifact_a_splunk_app() and
                self.is_working_artifact_a_splunk_app())

    @property
    def is_app(self):
        """Same as is_splunk_app(), included for backwards compatibility.
        """
        return self.is_splunk_app()

    @staticmethod
    def find_prohibited_files(directory_to_search, directory_whitelist=None):
        """Function to locate prohibited directories and files

        Args:
            directory_to_search (String): the absolute path of the directories
                to search
            directory_whitelist (List of Strings): paths of files to ignore
                when returning list of prohibited files or None to include all

        Returns:
            Array of Strings: an array of strings that are absolute paths of the
                prohibited directories or files
        """
        if directory_whitelist is None:
            directory_whitelist = []
        file_paths_to_return = []

        directory_name = os.path.basename(directory_to_search)
        directory_path_match = re.findall(AppPackage.NOT_ALLOWED_PATTERN,
                                          directory_name)

        # Whether the `directory_to_search` is a file or a directory, if it
        # violates the `AppPackage.NOT_ALLOWED_PATTERN` it will be added
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
                    directory_name_matches = re.findall(AppPackage.NOT_ALLOWED_PATTERN,
                                                        sub_directory)
                    if len(directory_name_matches):
                        directory_path = os.path.join(directory, sub_directory)
                        file_paths_to_return.append(directory_path)
                for file in files:
                    file_name_matches = re.findall(AppPackage.NOT_ALLOWED_PATTERN,
                                                   file)
                    if len(file_name_matches):
                        file_path = os.path.join(directory, file)
                        file_paths_to_return.append(file_path)

        return file_paths_to_return

    def does_contain_prohibited_files(self):
        """Determine if package contains any prohibited files.

        Args:
            None

        Returns:
            Bool: True if a prohibited file is found, False if none are found.
        """
        prohibited_directories_and_files = self.find_prohibited_files(self.working_artifact,
                                                                      [self.DEPENDENCIES_LOCATION])
        return len(prohibited_directories_and_files) > 0

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

    def does_contain_invalid_directories(self):
        """Determine if a directory contains invalid folders with incorrect permissions. Directories
        and sub directories must have the owner's permissions set to r/w/x (700).

        Args:
            None

        Returns:
            Bool: True if an invalid directory with incorrect permission is found,
            False if none are found.
        """
        invalid_directories = self.find_invalid_directories_with_wrong_permission(self.working_artifact, stat.S_IRWXU)
        return len(invalid_directories) > 0

    def does_contain_invalid_files(self):
        """Determine if a directory contains invalid folders with incorrect permissions. Files
        must have the owner's permissions include read and write (600).

        Args:
            None

        Returns:
            Bool: True if an invalid directory with incorrect permission is found,
            False if none are found.
        """
        invalid_files = self.find_files_with_incorrect_permissions(self.working_artifact, stat.S_IRUSR | stat.S_IWUSR)
        return len(invalid_files) > 0

    def check_valid_package_for_SSAI(self):
        """Determine if the pacakge is not .ziptype.
        ZIP package is not valid for SSAI.

        Args:
            None

        Returns:
            Bool: True for valid, False for invalid
        """
        if zipfile.is_zipfile(self.origin_path):
            return False
        else:
            return True

    def find_files_not_part_of_valid_apps(self):
        """Determine if files are contained in package that are not part of the
        valid app_dir nor .dependencies folder.

        Args:
            None

        Returns:
            List: Strings of absolute paths to any non-app files
        """
        # If the working_artifact is the same as the working_dir (app_dir)
        # then it's a simple app folder, so any files in there are presumed to
        # be app related if the app is valid, if not valid simply return the
        # working_app_path folder
        working_app_path_is_app = self.is_working_artifact_a_splunk_app()
        if self.working_app_path == self.working_artifact:
            return [] if working_app_path_is_app else [self.working_app_path]
        # Determine if working_app_path is a valid app and if it contains an
        # app.manifest file, these will affect whether working_app_path and the
        # .dependencies folder are valid
        contents = set(os.listdir(self.working_artifact))
        relative_working_app_path = os.path.relpath(self.working_app_path, self.working_artifact)
        working_app_path_in_contents = relative_working_app_path in contents
        if working_app_path_in_contents and working_app_path_is_app:
            # We can remove the working_app_path from contents as it is a valid app
            contents.remove(relative_working_app_path)
            dependencies_folder_in_contents = self.DEPENDENCIES_LOCATION in contents
            dependencies_is_folder = os.path.isdir(
                os.path.join(self.working_artifact, self.DEPENDENCIES_LOCATION)
            )
            working_app_path_has_manifest = self.does_working_artifact_contain_app_manifest()
            if (dependencies_folder_in_contents and dependencies_is_folder and
                    working_app_path_has_manifest):
                # We can remove .dependencies folder as the app is valid, in
                # contents, and has an app.manifest. Otherwise, .dependencies
                # is not valid
                contents.remove(self.DEPENDENCIES_LOCATION)
        # TODO: apps other that working_app_path (e.g. app of apps)
        return [os.path.join(self.working_artifact, path) for path in contents]

    def clean_up(self):
        """An abstract function for managing the clean up of an extracted Splunk
        App.

        Returns:
            None
        """
        error_message = "This is an abstract method meant to be over-ridden."
        raise NotImplementedError(error_message)


class FolderAppPackage(AppPackage):
    """This is a derived AppPackage class meant to control the logic for
    interacting with a Splunk App that is provided in the form of a directory.

    Attributes:
        - All attributes that are inherited from AppPackage
    """

    def __init__(self, app_package_path):
        """Constructor/initialization function.

        args:
            app_package_path (String): a absolute path to a potential Splunk App

        returns:
            None
        """
        super(FolderAppPackage, self).__init__(app_package_path)
        self.working_artifact = os.path.abspath(self.origin_path)
        self.working_app_path = self._get_working_app_path(self.working_artifact)
        self.working_artifact_name = self._get_basename_from_path(self.working_app_path)
        # Refer to ACD-2149 for purpose of app_cloud_name
        self.app_cloud_name = self.working_artifact_name

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


class CompressedAppPackage(AppPackage):
    """This is the base class for any compressed app packages (.zip, .tgz, etc)

    Attributes:
        - All attributes that are inherited from AppPackage
        extracted_path (String): absolute path of temporary directory the
            package was extracted to, None if artifact was deemed invalid

    """

    def __init__(self, app_package_path):
        """Constructor/initialization function.

        Args:
            app_package_path (String): a absolute path to a potential Splunk App
                package

        Returns:
            None
        """
        super(CompressedAppPackage, self).__init__(app_package_path)
        # Attempt to extract origin path
        self.extracted_path = tempfile.mkdtemp()
        self.origin_artifact_is_valid_compressed_file = False
        try:
            traversal_attack_found = self._perform_extraction(self.origin_path, self.extracted_path)
            self.origin_artifact_is_valid_compressed_file = not traversal_attack_found
            self.working_artifact = self.extracted_path
            # If user packs app by tar -cvzf app-folder.tgz app-folder, it's extracted in <temp-dir>/app-folder
            # If user packs app by tar -cvzf app-folder.tgz default bin metadata..., it's extracted in <temp-dor>
            # Checking app pattern for one layer deeper
            self.working_app_path = self._get_working_app_path(self.working_artifact)
            if self.working_app_path != self.working_artifact:
                # If we found an app dir within the extracted path, use this
                # for the working artifact name
                self.working_artifact_name = self._get_basename_from_path(self.working_app_path)
                # Refer to ACD-2149 for purpose of app_cloud_name
                self.app_cloud_name = self.working_artifact_name
            else:
                self.app_cloud_name = os.path.basename(self.extracted_path)
        except Exception as e:
            # If can't be extracted then just set resource to be compressed file
            self.working_app_path = self.origin_path
            application_name = os.path.basename(self.origin_path)
            logger.warning("Failed to extract {}".format(application_name))
            logger.error(e.message)

    def _perform_extraction(self, compressed_application_path, temporary_directory):
        """Extracts a compressed file to a temporary location.

        Args:
            compressed_application_path (String): An absolute path to a
                compressed artifact
            temporary_directory (String): An absolute path to a temporary
                directory to extract to

        Returns:
            Boolean: True if a traversal attack found, False if not
        """
        error_message = "This is an abstract method meant to be over-ridden."
        raise NotImplementedError(error_message)

    def is_origin_artifact_valid_compressed_file(self):
        """Helper function for part of the origin artifact validity tests.

        Returns:
            Bool: True if origin artifact a valid compressed file
            otherwise False
        """
        return self.origin_artifact_is_valid_compressed_file

    def clean_up(self):
        """Function for managing the clean up of an extracted Splunk App.

        Returns:
            None
        """
        if (self.extracted_path is not None and
                self.extracted_path != "" and
                os.path.isdir(self.extracted_path)):
            # ACD-940 Permission Denied
            os.chmod(self.extracted_path, 0o777)
            for root, dirs, _ in os.walk(self.extracted_path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o777)

            logger.info("Cleaning temp directory: {}".format(self.extracted_path))
            try:
                shutil.rmtree(self.extracted_path)
            except OSError as e:
                print "OSError raised when cleaning temp directory", e
                raise


class TarAppPackage(CompressedAppPackage):
    """This is an AppPackage derived class meant to control the logic for
    interacting with a Splunk App that is provided in the form of a compressed
    Tar file.

    Attributes:
        - All attributes that are inherited from AppPackage
    """

    @staticmethod
    def does_traversal_attack_exist(pkg_tar, target_dir, tar_list):
        """A function to determine if a traversal attack exists in a compressed
        file i.e. the archive extracts to a directory outside of the target_dir

        Args:
            pkg_tar (String): an absolute path to the compressed artifact being
                check for traversal attacks.
            target_dir (String): the directory where the tar file will be extracted
            tar_list (List): tar file elements

        Returns:
            Boolean: True if a traversal attack, False if not
        """
        for directory in tar_list:
            if not os.path.abspath(os.path.join(target_dir, directory)).startswith(target_dir):
                # TODO: tests needed
                logger.info("Invalid tar file {}. Possibly directory traversal attack at {}".format(
                    pkg_tar, directory))
                return True
        return False

    def _perform_extraction(self, compressed_application_path, temporary_directory):
        """Extracts a compressed file to a temporary location.

        Args:
            compressed_application_path (String): An absolute path to a
                compressed artifact
            temporary_directory (String): An absolute path to a temporary
                directory to extract to

        Returns:
            Boolean: True if a traversal attack found, False if not
        """
        traversal_attack_found = False
        with tarfile.open(compressed_application_path) as tar:
            traversal_attack_found = self.does_traversal_attack_exist(compressed_application_path,
                                                                      temporary_directory,
                                                                      tar.getnames())
            if not traversal_attack_found:
                tar.extractall(path=temporary_directory)
        return traversal_attack_found


class ZipAppPackage(CompressedAppPackage):
    """This is an AppPackage derived class meant to control the logic for
    interacting with a Splunk App that is provided in the form of a compressed
    Zip file.

    Attributes:
        - All attributes that are inherited from AppPackage
    """

    def _perform_extraction(self, compressed_application_path, temporary_directory):
        """Extracts a compressed file to a temporary location.

        Args:
            compressed_application_path (String): An absolute path to a
                compressed artifact
            temporary_directory (String): An absolute path to a temporary
                directory to extract to

        Returns:
            Boolean: True if a traversal attack found, False if not
        """
        # ACD-450 Zip Traversal attack is managed by Python core
        with zipfile.ZipFile(compressed_application_path) as zip:
            zip.extractall(temporary_directory)
        # As of Python 2.7.4 traversal attacks should be handled automatically
        # for the ZipFile.extractall() method.
        # See: https://docs.python.org/2/library/zipfile.html#zipfile.ZipFile.extract
        # and https://docs.python.org/2/library/zipfile.html#zipfile.ZipFile.extractall
        return False
