# Copyright 2018 Splunk Inc. All rights reserved.

# Python Standard Libraries
import hashlib
import logging
import os
import re
import stat
import subprocess
import tarfile
import traceback
import StringIO
import platform
# Custom Libraries
import alert_actions
import app_configuration_file
import app_package_handler
import authentication_configuration_file
import authorize_configuration_file
import custom_commands
import custom_visualizations
import configuration_file
import configuration_parser
import distsearch_configuration_file
import file_resource
import indexes_configuration_file
import inputs_configuration_file
import inputs_specification_file
import inspected_file
import modular_inputs
import outputs_configuration_file
import props_configuration_file
import rest_map
import saved_searches
import transforms_configuration_file
import web_configuration_file
import workflow_actions
# Third Party Libraries
if not platform.system() == "Windows":
    import magic

logger = logging.getLogger(__name__)


class App(object):
    """A class for providing an interface to a Splunk App. Used to create helper
    functions to support common functionality needed to investigate a Splunk
    App and its contents.

    Args:
        location (String): Either a package(.spl, .tgz, or .zip) or a directory
            containing the app
        package (AppPackage Object): Previously packaged AppPackage associated
            with the input location, None if package has not yet been generated

    Attributes:
        package (AppPackage derived object): The AppPackage object that
            represents the Splunk App passed into the App for initialization.
        package_handler (AppPackageHandler object): The AppPackageHandler
            object that is created using the Splunk App provided for
            initialization.
        app_dir (String): The path of the Splunk App artifact after having been
            extracted.
        name (String): This is the file or directory name of the extracted
            Splunk App artifact passed in during initialization.
        dependencies_directory_path (String): String representing the absolute
            path of the App's static .dependencies directory
        is_static_slim_dependency (Boolean): True if this App was derived from
            a package within another App's dependencies directory, False
            otherwise.
        static_slim_app_dependencies (List of instances of this class): Apps
            or instances of subclass of App (e.g. DynamicApp) derived from
            AppPackages inside of this App's dependencies directory.
    """

    def __init__(self, location=None, package=None):
        if location is None and package is None:
            logger_output = ("splunk_appinspect.App requires either a"
                             " `location` or `package` argument to be"
                             " initialized.")
            logger.error(logger_output)
            self.package = None
            raise ValueError(logger_output)
        if package is None:
            package = app_package_handler.AppPackage.factory(location)
        self.package = package
        self._static_slim_app_dependencies = None

        self.LINUX_ARCH = "linux"
        self.WIN_ARCH = "win"
        self.DARWIN_ARCH = "darwin"
        self.DEFAULT_ARCH = "default"
        self.arch_bin_dirs = {
            self.LINUX_ARCH: [os.path.join(self.app_dir, "linux_x86", "bin"),
                              os.path.join(self.app_dir, "linux_x86_64", "bin")],
            self.WIN_ARCH: [os.path.join(self.app_dir, "windows_x86", "bin"),
                            os.path.join(self.app_dir, "windows_x86_64", "bin")],
            self.DARWIN_ARCH: [os.path.join(self.app_dir, "darwin_x86", "bin"),
                               os.path.join(self.app_dir, "darwin_x86_64", "bin")],
            self.DEFAULT_ARCH: [os.path.join(self.app_dir, "bin")]
        }
        # Store the base directories for scripts to be located. Generally
        # speaking any app-specific code will be in these base directories and
        # third-party libraries may be included within subdirectories of thesel
        self.base_bin_dirs = ([os.path.relpath(path, self.app_dir)
                               for arch in self.arch_bin_dirs
                               for path in self.arch_bin_dirs.get(arch)] +
                              [os.path.join("bin", "scripts")])
        self.info_from_file = {}
        if not platform.system() == "Windows":
            for directory, file, ext in self.iterate_files():
                current_file_relative_path = os.path.join(directory, file)
                current_file_full_path = self.get_filename(current_file_relative_path)
                output = magic.from_file(current_file_full_path)
                self.info_from_file[current_file_relative_path] = output 

    def targlob(self):
        """
        Create an in-memory tarball of all files in the directory
        """
        # TODO: tests needed
        glob = StringIO.StringIO()
        tar = tarfile.open(mode='w', fileobj=glob)
        tar.add(self.app_dir, recursive=True, arcname=self.name)
        tar.close()
        return glob.getvalue()

    def __del__(self):
        self.cleanup()

    @property
    def name(self):
        """Helper function to return the name of the extracted Splunk App.

        Returns:
            String: name of the extracted Splunk App
        """
        return self.package.working_artifact_name

    @property
    def app_dir(self):
        """Helper function to return the path to top level directory of the
        extracted Splunk App.

        Returns:
            String: an absolute path to the top level directory of the extracted
                Splunk App
        """
        return self.package.working_app_path

    @property
    def dependencies_directory_path(self):
        """
        Returns:
            String: Fixed expected location of slim static depdendencies
                folder relative to app_dir
        """
        return os.path.join(os.pardir, self.package.DEPENDENCIES_LOCATION)

    @property
    def is_static_slim_dependency(self):
        """
        Returns:
            Boolean: True if this App was derived from a package within another
            App's dependencies directory, False otherwise.
        """
        return self.package.is_static_slim_dependency

    @property
    def static_slim_app_dependencies(self):
        """
        Returns:
            List of instances of this class (App or class inherited from App)
            derived from AppPackages within the dependencies directory of
            this App.
        """
        # If we haven't generated self._static_slim_app_dependencies yet,
        # do this once and store the resulting list
        if self._static_slim_app_dependencies is None:
            self._static_slim_app_dependencies = []
            for dependency_package in self.package.static_slim_dependency_app_packages:
                dependency_app = self.__class__(package=dependency_package)
                self._static_slim_app_dependencies.append(dependency_app)
        return self._static_slim_app_dependencies

    def cleanup(self):
        if self.package is not None:
            self.package.clean_up()

    def get_config(self, name, dir='default', config_file=None):
        """Returns a parsed config file as a ConfFile object. Note that this
        does not do any of Splunk's layering- this is just the config file,
        parsed into a dictionary that is accessed via the ConfFile's helper
        functions.

        :param name The name of the config file.  For example, 'inputs.conf'
        :param dir The directory in which to look for the config file.  By default, 'default'
        """
        app_filepath = self.get_filename(dir, name)

        log_output = ("'{}' called '{}' to retrieve the configuration file '{}'"
                      " at directory '{}'. App filepath: {}").format(__file__,
                                                                     "get_config",
                                                                     name,
                                                                     dir,
                                                                     app_filepath)
        logger.debug(log_output)
        if not self.file_exists(app_filepath):
            error_output = ("No such conf file: {}").format(app_filepath)
            raise IOError(error_output)

        # Makes generic configuration file if no specified configuration file is
        # passed in
        if config_file is None:
            config_file = configuration_file.ConfigurationFile()

        with open(app_filepath) as file:
            try:
                config_file = configuration_parser.parse(file,
                                                         config_file,
                                                         configuration_parser.configuration_lexer)
            except Exception:
                # re-raise the error from parser
                raise

        return config_file

    def get_spec(self, name, dir='default', config_file=None):
        """Returns a parsed config spec file as a ConfFile object.

        :param name The name of the config file.  For example, 'inputs.conf.spec'
        :param dir The directory in which to look for the config file.  By default, 'default'
        """
        app_filepath = self.get_filename(dir, name)

        log_output = ("'{}' called '{}' to retrieve the configuration file '{}'"
                      " at directory '{}'. App filepath: {}").format(__file__,
                                                                     "get_config",
                                                                     name,
                                                                     dir,
                                                                     app_filepath)
        logger.debug(log_output)
        if not self.file_exists(app_filepath):
            error_output = ("No such conf file: {}").format(app_filepath)
            raise IOError(error_output)

        # Makes generic configuration file if no specified configuration file is
        # passed in
        if config_file is None:
            config_file = configuration_file.ConfigurationFile()

        with open(app_filepath) as file:
            config_file = configuration_parser.parse(
                file, config_file, configuration_parser.specification_lexer)

        return config_file

    def get_meta(self, name, directory='metadata', meta_file=None):
        """Returns a parsed meta file as a Meta object.

        :param name The name of the meta file.  For example, 'default.meta'
        :param directory The directory in which to look for the config file.
            By default, 'default'
        """
        # This uses the configuration file conventions because there does not
        # appear to be any difference between configuration files and meta
        # files.
        # TODO: investigate if meta file class should exist
        app_filepath = self.get_filename(directory, name)

        log_output = ("'{}' called '{}' to retrieve the configuration file '{}'"
                      " at directory '{}'. App filepath: {}").format(__file__,
                                                                     "get_config",
                                                                     name,
                                                                     directory,
                                                                     app_filepath)
        logger.debug(log_output)
        if not self.file_exists(app_filepath):
            error_output = ("No such metadata file: {}").format(app_filepath)
            raise IOError(error_output)

        # Makes generic meta file if no specified meta file is
        # passed in
        if meta_file is None:
            meta_file = configuration_file.ConfigurationFile()

        with open(app_filepath) as file:
            meta_file = configuration_parser.parse(file,
                                                   meta_file,
                                                   configuration_parser.configuration_lexer)

        return meta_file

    def get_raw_conf(self, name, dir='default'):
        """
        Returns a raw version of the config file.
        :param name: The name of the config file.  For example 'inputs.conf'
        :param dir The directory in which to look for the config file.  By default, 'default'
        :return: A raw representation of the conf file
        """
        # Should this be a with fh.open??
        app_filepath = self.get_filename(dir, name)
        fh = open(app_filepath, 'rb')
        conf_content = fh.read()
        fh.close()

        log_output = ("'{}' called '{}' to retrieve the configuration file '{}'"
                      " at directory '{}'. App filepath: {}").format(__file__,
                                                                     "get_raw_conf",
                                                                     name,
                                                                     dir,
                                                                     app_filepath)
        logger.debug(log_output)

        return conf_content

    def get_filename(self, *path_parts):
        """
        Given a relative path, return a fully qualified location to that file
        in a format suitable for passing to open, etc.

        example: app.get_filename('default', 'inputs.conf')
        """
        return os.path.join(self.app_dir, *path_parts)

    def _get_app_info(self, stanza, option):
        """A function to combine the efforts of retrieving app specific
        information from the `default/app.conf` file. This should always return
        a string.

        Returns:
            String: Will either be a string that is the value from the
                `default/app.conf` file or will be an error message string
                indicating that failure occurred.
        """
        try:
            app_config = self.app_conf()

            logger_error_message = ("An error occurred trying to retrieve"
                                    " information from the app.conf file."
                                    " Error: {}"
                                    " Stanza: {}"
                                    " Property: {}")

            property_to_return = app_config.get(stanza, option)
        except IOError as exception:
            error_message = repr(exception)
            logger_output = ("The `app.conf` file does not exist."
                             " Error: {}").format(error_message)
            logger.error(logger_output)
            property_to_return = "[MISSING `default/app.conf`]"
            raise exception
        except configuration_file.NoSectionError as exception:
            error_message = repr(exception)
            logger_output = logger_error_message.format(error_message, stanza, option)
            logger.error(logger_output)
            property_to_return = ("[MISSING `default/app.conf` stanza `{}`]"
                                  ).format(stanza)
            raise exception
        except configuration_file.NoOptionError as exception:
            # TODO: tests needed
            error_message = repr(exception)
            logger_output = logger_error_message.format(error_message, stanza, option)
            logger.error(logger_output)
            property_to_return = ("[MISSING `default/app.conf` stanza [{}]"
                                  " property `{}`]").format(stanza, option)
            raise exception
        except Exception as exception:
            # TODO: tests needed
            error_message = repr(exception)
            logger_output = ("An unexpected error occurred while trying to"
                             " retrieve information from the app.conf file"
                             " Error: {}").format(error_message)
            logger.error(logger_output)
            property_to_return = "[Unexpected error occurred]"
            raise exception
        finally:
            # The exceptions are swallowed here because raising an exception and
            # returning a value are mutually exclusive
            # If we want to always raise an exception this will have to be
            # re-worked
            return property_to_return

    def app_info(self):
        """Helper function to retrieve a set of information typically required
        for run-time. Tries to get author, description, version, label, and
        hash.

        Returns:
            Dict (string: string): a dict of string key value pairs
        """
        app_info = {}

        app_info['author'] = self.author
        app_info['description'] = self.description
        app_info['version'] = self.version
        app_info['name'] = self.name
        app_info['hash'] = self._get_hash()
        app_info['label'] = self.label

        return app_info

    @property
    def author(self):
        """Helper function to retrieve the app.conf [launcher] stanza's author
        property.

        Returns:
            String: the default/app.conf [launcher] stanza's author property
        """
        return self._get_app_info("launcher", "author")

    @property
    def description(self):
        """Helper function to retrieve the app.conf [launcher] stanza's
        `description` property.

        Returns:
            String: the default/app.conf [launcher] stanza's `description`
                property
        """
        return self._get_app_info("launcher", "description")

    @property
    def version(self):
        """Helper function to retrieve the app.conf [launcher] stanza's
        `version` property.

        Returns:
            String: the default/app.conf [launcher] stanza's `version`
                property
        """
        return self._get_app_info("launcher", "version")

    @property
    def label(self):
        """Helper function to retrieve the app.conf [ui] stanza's `label`
        property.

        Returns:
            String: the default/app.conf [ui] stanza's `label` property
        """
        return self._get_app_info("ui", "label")

    def _get_hash(self):
        md5 = hashlib.md5()

        try:
            for dir, file, ext in self.iterate_files():
                file_path = os.path.join(self.app_dir, dir, file)
                file = open(file_path)
                md5.update(file.read())
        except Exception as exception:
            logger.error(exception)

        return md5.hexdigest()

    def iterate_files(self, basedir='', excluded_dirs=None, types=None, excluded_types=None, excluded_bases=None,
                      recurse_depth=float("inf")):
        """Iterates through each of the files in the app, optionally filtered
        by file extension.

        Example:

        for file in app.iterate_files(types=['.gif', '.jpg']):
            pass

        This should be considered to only be a top down traversal/iteration.
        This is because the filtering of directories, and logic used to track
        depth are based on the os.walk functionality using the argument of
        `topdown=True` as a default value. If bottom up traversal is desired
        then a separate function will need to be created.

        :param basedir The directory or list of directories to start in
        :param excluded_dirs These are directories to exclude when iterating.
            Exclusion is done by directory name matching only. This means if you
            exclude the directory 'examples' it would exclude both `examples/`
            and `default/examples`, as well as any path containing a directory
            called `examples`.
        :param types An array of types that the filename should match
        :param excluded_types An array of file extensions that should be
            skipped.
        :param recurse_depth This is used to indicate how deep you want
            traversal to go. 0 means do no recurse, but return the files at the
            directory specified.
        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        check_extensions = len(types) > 0

        if not isinstance(basedir, list):
            basedir = [basedir]

        for subdir in basedir:
            root_path = os.path.join(self.app_dir, subdir, "")
            root_depth = root_path.count(os.path.sep)

            for base, directories, files in os.walk(root_path):
                # Adds a trailing '/' or '\'. This is needed to help determine the
                # depth otherwise the calculation is off by one
                base = os.path.join(base, "")
                current_iteration_depth = base.count(os.path.sep)
                current_depth = current_iteration_depth - root_depth

                # Filters undesired directories
                directories[:] = [directory
                                  for directory
                                  in directories
                                  if directory not in excluded_dirs]

                # Create the file's relative path from within the app
                dir_in_app = base.replace(self.app_dir + os.path.sep, '')
                if current_depth <= recurse_depth:
                    for file in files:
                        filebase, ext = os.path.splitext(file)
                        if ((check_extensions and ext not in types) or
                                (ext != '' and ext in excluded_types) or
                                (filebase.lower() in excluded_bases and ext in excluded_types)):
                            next
                        else:
                            yield (dir_in_app, file, ext)
                else:
                    next

    def get_filepaths_of_files(self, basedir="", excluded_dirs=None, filenames=None, types=None):
        excluded_dirs = excluded_dirs or []
        filenames = filenames or []
        types = types or []

        for directory, file, ext in self.iterate_files(basedir=basedir,
                                                       excluded_dirs=excluded_dirs,
                                                       types=types,
                                                       excluded_types=[]):
            current_file_full_path = os.path.join(self.app_dir,
                                                  directory,
                                                  file)
            current_file_relative_path = os.path.join(directory, file)
            split_filename = os.path.splitext(file)
            filename = split_filename[0]
            check_filenames = len(filenames) > 0

            filename_is_in_filenames = not(filename in filenames)
            if (check_filenames and filename_is_in_filenames):
                next
            else:
                yield (current_file_relative_path, current_file_full_path)

    def file_exists(self, *path_parts):
        """Check for the existence of a file given the relative path.
        Returns True/False

        Example:
        if app.file_exists('default', 'transforms.conf'):
             print "File exists! Validate that~!~"
        """
        file_path = os.path.join(self.app_dir, *path_parts)
        does_file_exist = os.path.isfile(file_path)

        log_output = ("'{}.{}' was called. File path being checked:'{}'."
                      " Does File Exist:{}").format(__file__,
                                                    "file_exists",
                                                    file_path,
                                                    does_file_exist)
        logger.debug(log_output)
        return does_file_exist

    def get_config_file_paths(self, config_file_name):
        """ Return a dict of existing config_file in given name and corresponding folder names
        :param config_file_name: name of configuration file
        :return: config_file_paths: map of folder name and configuration file name
        """
        config_file_paths = {}
        for config_folder in ["default", "local"]:
            if self.file_exists(config_folder, config_file_name):
                config_file_paths[config_folder] = config_file_name
        return config_file_paths

    def directory_exists(self, *path_parts):
        """Check for the existence of a directory given the relative path.
        Returns True/False

        Example:
        if app.file_exists('local'):
             print "Distributed apps shouldn't have a 'local' directory"
        """
        directory_path = os.path.join(self.app_dir, *path_parts)
        does_file_exist = os.path.isdir(directory_path)

        log_output = ("'{}.{} was called.'. Directory path being checked:'{}'."
                      " Does Directory Exist:{}").format(__file__,
                                                         "directory_exists",
                                                         directory_path,
                                                         does_file_exist)
        logger.debug(log_output)
        return does_file_exist

    def some_files_exist(self, files):
        """ Takes an array of relative filenames and returns true if any file
        listed exists.
        """
        # TODO: tests needed
        for file in files:
            if self.file_exists(file):
                return True
        return False

    def some_directories_exist(self, directories):
        """ Takes an array of relative paths and returns true if any file
        listed exists.
        """
        for directory in directories:
            if self.directory_exists(directory):
                return True
        return False

    def all_files_exist(self, files):
        """ Takes an array of relative filenames and returns true if all
        listed files exist.
        """
        # TODO: tests needed
        for file in files:
            if not(self.file_exists(file)):
                return False
        return True

    def all_directories_exist(self, directories):
        """ Takes an array of relative paths and returns true if all listed
        directories exists.
        """
        # TODO: tests needed
        for directory in directories:
            if not(self.directory_exists(directory)):
                return False
        return True

    def search_for_patterns(self, patterns, basedir='', excluded_dirs=None, types=None, excluded_types=None, excluded_bases=None):
        """ Takes a list of patterns and iterates through all files, running
        each of the patterns on each line of each of those files.

        Returns a list of tuples- the first element is the file (with line
        number), the second is the match from the regular expression.
        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        matches = []
        all_excluded_types = ['.pyc', '.pyo']
        all_excluded_types.extend(excluded_types)  # never search these files

        files_iterator = self.iterate_files(basedir=basedir,
                                            excluded_dirs=excluded_dirs,
                                            types=types,
                                            excluded_types=all_excluded_types,
                                            excluded_bases=excluded_bases)
        for dir, filename, ext in files_iterator:
            relative_filepath = os.path.join(dir, filename)
            file_to_inspect = inspected_file.InspectedFile.factory(os.path.join(self.app_dir,
                                                                                dir,
                                                                                filename))
            found_matches = file_to_inspect.search_for_patterns(patterns)
            matches_with_relative_path = []
            for (fileref_output, file_match) in found_matches:
                filepath, line_number = fileref_output.rsplit(":", 1)
                relative_file_ref_output = "{}:{}".format(relative_filepath,
                                                          line_number)
                matches_with_relative_path.append((relative_file_ref_output,
                                                   file_match))
            matches.extend(matches_with_relative_path)

        return matches

    def search_for_pattern(self, pattern, basedir='', excluded_dirs=None, types=None, excluded_types=None, excluded_bases=None):
        """ Takes a pattern and iterates over matching files, testing each line.
        Same as search_for_patterns, but with a single pattern.
        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        return self.search_for_patterns([pattern],
                                        basedir=basedir,
                                        excluded_dirs=excluded_dirs,
                                        types=types,
                                        excluded_types=excluded_types,
                                        excluded_bases=excluded_bases)

    def search_for_crossline_patterns(self, patterns, basedir='', excluded_dirs=None, types=None, excluded_types=None, excluded_bases=None, cross_line=10):
        """ Takes a list of patterns and iterates through all files, running
        each of the patterns on all lines those files.

        Returns a list of tuples- the first element is the file (with line
        number), the second is the match from the regular expression.
        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        matches = []
        all_excluded_types = ['.pyc', '.pyo']
        all_excluded_types.extend(excluded_types)  # never search these files

        files_iterator = self.iterate_files(basedir=basedir,
                                            excluded_dirs=excluded_dirs,
                                            types=types,
                                            excluded_types=all_excluded_types,
                                            excluded_bases=excluded_bases)
        for dir, filename, ext in files_iterator:
            relative_filepath = os.path.join(dir, filename)
            file_to_inspect = inspected_file.InspectedFile.factory(os.path.join(self.app_dir,
                                                                                dir,
                                                                                filename))
            found_matches = file_to_inspect.search_for_crossline_patterns(patterns=patterns, cross_line=cross_line)
            matches_with_relative_path = []
            for (fileref_output, file_match) in found_matches:
                filepath, line_number = fileref_output.rsplit(":", 1)
                relative_file_ref_output = "{}:{}".format(relative_filepath,
                                                          line_number)
                matches_with_relative_path.append((relative_file_ref_output,
                                                   file_match))
            matches.extend(matches_with_relative_path)

        return matches

    def search_for_crossline_pattern(self, pattern, basedir='', excluded_dirs=None, types=None, excluded_types=None, excluded_bases=None, cross_line=10):
        """ Takes a pattern and iterates over matching files, testing each line.
        Same as search_for_crossline_patterns, but with a single pattern.
        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        return self.search_for_crossline_patterns([pattern],
                                        basedir=basedir,
                                        excluded_dirs=excluded_dirs,
                                        types=types,
                                        excluded_types=excluded_types,
                                        excluded_bases=excluded_bases,
                                        cross_line=cross_line)

    def is_executable(self, filename):
        """ Checks to see if any of the executable bits are set on a file
        """
        # TODO: tests needed
        st = os.stat(os.path.join(self.app_dir, filename))
        return bool(st.st_mode & (stat.S_IXOTH | stat.S_IXUSR | stat.S_IXGRP))

    def is_text(self, filename):
        """Checks to see if the file is a text type via the 'file' command.
        Notice: This method should only be used in Unix environment
        """
        if filename in self.info_from_file:
            return True if re.search(r'.* text', self.info_from_file[filename], re.IGNORECASE) else False
        try:
            file_path = self.get_filename(filename)
            output = magic.from_file(file_path)
            return True if re.search(r'.* text', output, re.IGNORECASE) else False
        except Exception as e:
            # TODO: Self log error here.  Issues with hidden folders
            return False

    #---------------------------------
    # "Domain" Objects
    #---------------------------------
    def get_alert_actions(self):
        return alert_actions.AlertActions(self)

    def get_custom_commands(self):
        return custom_commands.CustomCommands(self)

    def get_custom_visualizations(self):
        return custom_visualizations.CustomVisualizations(self)

    def get_modular_inputs(self):
        return modular_inputs.ModularInputs.factory(self)

    def get_rest_map(self, dir='default'):
        return rest_map.RestMap(self, dir)

    def get_saved_searches(self):
        return saved_searches.SavedSearches(self)

    def get_workflow_actions(self):
        return workflow_actions.WorkFlowActions(self)

    #---------------------------------
    # ConfFile Helper Definitions
    #---------------------------------
    def app_conf(self, dir='default'):
        return self.get_config('app.conf',
                               dir=dir,
                               config_file=app_configuration_file.AppConfigurationFile())

    def authentication_conf(self, dir='default'):
        return self.get_config('authentication.conf',
                               dir=dir,
                               config_file=authentication_configuration_file.AuthenticationConfigurationFile())

    def authorize_conf(self, dir='default'):
        return self.get_config('authorize.conf',
                               dir=dir,
                               config_file=authorize_configuration_file.AuthorizeConfigurationFile())

    def distsearch_conf(self, dir='default'):
        return self.get_config('distsearch.conf',
                                dir=dir,
                                config_file=distsearch_configuration_file.DistsearchConfigurationFile())
                                
    def indexes_conf(self, dir='default'):
        return self.get_config('indexes.conf',
                               dir=dir,
                               config_file=indexes_configuration_file.IndexesConfigurationFile())

    def inputs_conf(self, dir='default'):
        return self.get_config('inputs.conf',
                               dir=dir,
                               config_file=inputs_configuration_file.InputsConfigurationFile())

    def outputs_conf(self, dir='default'):
        return self.get_config('outputs.conf',
                               dir=dir,
                               config_file=outputs_configuration_file.OutputsConfigurationFile())

    def props_conf(self, dir='default'):
        return self.get_config('props.conf',
                               dir=dir,
                               config_file=props_configuration_file.PropsConfigurationFile())

    def transforms_conf(self, dir='default'):
        return self.get_config('transforms.conf',
                               dir=dir,
                               config_file=transforms_configuration_file.TransformsConfigurationFile())

    def web_conf(self, dir='default'):
        return self.get_config('web.conf',
                               dir=dir,
                               config_file=web_configuration_file.WebConfigurationFile())

    def server_conf(self, dir='default'):
        return self.get_config('server.conf',
                               dir=dir,
                               config_file=outputs_configuration_file.OutputsConfigurationFile())

    #---------------------------------
    # SpecFile Helper Definitions
    #---------------------------------
    def get_inputs_specification(self):
        return inputs_specification_file.InputsSpecification()

    #---------------------------------
    # File Resource Helper Definitions
    #---------------------------------
    def app_icon(self):
        return file_resource.FileResource(os.path.join(self.app_dir, 'appserver/static/appIcon.png'))

    def setup_xml(self):
        return file_resource.FileResource(os.path.join(self.app_dir, 'default/setup.xml'))

    def custom_setup_view_xml(self, custom_setup_xml_name):
        return file_resource.FileResource(os.path.join(self.app_dir, 'default/data/ui/views',
                                                       '{}.xml'.format(custom_setup_xml_name)))

