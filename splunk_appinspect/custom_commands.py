# Copyright 2018 Splunk Inc. All rights reserved.

# Python Standard Libraries
import os
import re
import itertools
# Custom Libraries
import commands_configuration_file
from file_resource import FileResource
import splunk_appinspect

# http://docs.splunk.com/Documentation/Splunk/7.2.0/Search/Customcommandlocation#Platform-specific_custom_commands

class Command:
    """Represents a custom search command."""

    def __init__(self, section, file_name="", chunked=None):
        self.chunked = chunked
        self.name = section.name
        self.lineno = section.lineno
        self.file_name = file_name
        self.type = ""
        self.args = {}
        self.passauth = ""
        self.requires_srinfo = ""
        self.streaming_preop = ""
        self.requires_preop = ""
        self.enableheader = ""
        self.executable_files = []
        self.win_exes = []
        self.linux_exes = []
        self.win_arch_exes = []
        self.darwin_arch_exes = []
        self.linux_arch_exes = []
        self.v1_exes = []
        # the script with file name
        self.file_name_exe = None

    def executable_file(self):
        return FileResource(self.file_name)

    def is_v2(self):
        return self.chunked == "true"

    def file_name_specified(self):
        return self.file_name != ""

    def count_v1_exes(self):
        return splunk_appinspect.iter_ext.count_iter(self.v1_exes)

    def count_win_exes(self):
        return splunk_appinspect.iter_ext.count_iter(self.win_exes)

    def count_linux_exes(self):
        return splunk_appinspect.iter_ext.count_iter(self.linux_exes)

    def count_win_arch_exes(self):
        return splunk_appinspect.iter_ext.count_iter(self.win_arch_exes)

    def count_linux_arch_exes(self):
        return splunk_appinspect.iter_ext.count_iter(self.linux_arch_exes)

    def count_darwin_arch_exes(self):
        return splunk_appinspect.iter_ext.count_iter(self.darwin_arch_exes)


class CustomCommands:
    """Represents a commands.conf file from default/commands.conf.

    The CustomCommands object has a 1 to many relation for Command objects.
    
    Attributes:
        app (App Object): The app object that represents a Splunk app.
        commands_conf_file_path (String): The path to where the commands
            conf file exists.
        V1_EXE_TAG (String): A string used to tag a FileResource
            object with its respective custom command location
        WINDOWS_EXE_TAG (String): A string used to tag a FileResource
            object with its respective custom command location
        NIX_EXE_TAG (String): A string used to tag a FileResource
            object with its respective custom command location
        WINDOWS_EXES (List of Strings): A list of strings used that
            represents the allowed binary types that can be used for a custom
            command in a windows environment
        NIX_EXES (List of Strings): A list of strings used that
            represents the allowed binary types that can be used for a custom
            command in a linux environment
        V1_EXES (List of Strings): A list of strings used that
            represents the allowed binary types that can be used for a custom
            command in a linux environment
    """

    def __init__(self, app):
        self.app = app
        self.commands_conf_file_path = app.get_filename('default',
                                                        'commands.conf')
                                                
        # architecture stuff
        self.V1_EXE_TAG = "v1_exe"
        self.WINDOWS_EXE_TAG = "windows_exe"
        self.NIX_EXE_TAG = "nix_exe"

        self.V1_EXES = [".py", ".pl"]
        self.WINDOWS_EXES = self.V1_EXES + [".cmd", ".bat", ".exe", ".js"]
        self.NIX_EXES = self.V1_EXES + [".sh", "", ".js"]
        self.ALL_VALID_EXES = list(set(self.WINDOWS_EXES) | set(self.NIX_EXES)) 

    def configuration_file_exists(self):
        return self.app.file_exists('default', 'commands.conf')

    def get_configuration_file(self):
        return self.app.get_config('commands.conf',
                                   config_file=commands_configuration_file.CommandsConfigurationFile())

    def find_exes(self, name, is_v2, case_sensitive=True):
        """Returns a generator that yields a FileResource object representing an
        executable file that can be used for custom commands

        For a given named file, find scripts and exes in the standard folders

        : param name(String) - the name of the file to search for
        : param is_v2(Boolean) - Indicates if the custom command is chunked
            (a.k.a. custom command v2)
        : param case_sensitive(Boolean) - if the search for exe should be
            case-sensitve
        """
        # Find all the files across OS, across platform
        for arch in self.app.arch_bin_dirs:
            for bin_dir in self.app.arch_bin_dirs[arch]:

                # Determine which extensions to use when checking specific arch
                # folders
                if arch == self.app.LINUX_ARCH or arch == self.app.DARWIN_ARCH:
                    ext_filter = self.NIX_EXES
                elif arch == self.app.WIN_ARCH:
                    ext_filter = self.WINDOWS_EXES
                elif arch == self.app.DEFAULT_ARCH:
                    if not is_v2:
                        ext_filter = self.V1_EXES
                    else:
                        ext_filter = self.ALL_VALID_EXES

                for directory, filename, file_extension in self.app.iterate_files(basedir=bin_dir, types=ext_filter):
                    file_base_name, file_extension = os.path.splitext(filename)

                    # TODO: Add more flags if desired
                    regex_flags = (0
                                   if case_sensitive
                                   else re.IGNORECASE)

                    # This pattern is used in order to get an exact match for
                    # the name without checking length of the strings.
                    file_regex_pattern = "^{}$".format(name)
                    file_name_regex_object = re.compile(file_regex_pattern, regex_flags)
                    found_file_matching_custom_command_name = (re.search(file_name_regex_object, file_base_name) is not None)
                    if found_file_matching_custom_command_name:
                        file = os.path.join(self.app.app_dir, directory, filename)
                        path = os.path.join(self.app.name, directory, filename)
                        resource = splunk_appinspect.file_resource.FileResource(file,
                                                                                ext=file_extension,
                                                                                app_file_path=path,
                                                                                file_name=filename)
                        resource.tags.append(arch)

                        if file_extension in self.WINDOWS_EXES:
                            resource.tags.append(self.WINDOWS_EXE_TAG)

                        if file_extension in self.NIX_EXES:
                            resource.tags.append(self.NIX_EXE_TAG)

                        if not is_v2 and file_extension in self.V1_EXES:
                            resource.tags.append(self.V1_EXE_TAG)
                        
                        yield resource
                    else:
                        next

    def get_commands(self, case_sensitive=True):
        """Returns a generator that yields a Custom Command object representing a
        Splunk Custom Command configuration.

        Attributes:
            case_sensitive (Boolean): if the search for custom commands should be
                case-sensitve
        """

        # command_list = []

        for section in self.get_configuration_file().sections():

            command = Command(section)
            for key, value, lineno in self.get_configuration_file().items(section.name):
                command.args[key.lower()] = (value, lineno)

                if key.lower() == "filename":
                    command.file_name = value

                if key.lower() == "passauth":
                    command.passauth = value

                if key.lower() == "requires_srinfo":
                    command.requires_srinfo = value

                if key.lower() == "streaming_preop":
                    command.streaming_preop = value

                if key.lower() == "requires_preop":
                    command.requires_preop = value

                if key.lower() == "enableheader":
                    command.enableheader = value

                # V2 fields
                if key.lower() == "chunked":
                    command.chunked = value

            files = []
            for file_resource in self.find_exes(command.name, command.is_v2(), case_sensitive=case_sensitive):
                if file_resource.file_name == command.file_name:
                    command.file_name_exe = file_resource 
                files.append(file_resource)

            # Set the specific architecture files
            command.v1_exes = list(itertools.ifilter(
                lambda exe:
                self.app.DEFAULT_ARCH in exe.tags and
                self.V1_EXE_TAG in exe.tags,
                files))

            command.win_exes = list(itertools.ifilter(
                lambda exe:
                self.app.DEFAULT_ARCH in exe.tags and
                self.WINDOWS_EXE_TAG in exe.tags,
                files))

            command.linux_exes = list(itertools.ifilter(
                lambda exe:
                self.app.DEFAULT_ARCH in exe.tags and
                self.NIX_EXE_TAG in exe.tags,
                files))

            command.win_arch_exes = list(itertools.ifilter(
                lambda exe:
                self.app.WIN_ARCH in exe.tags and
                self.WINDOWS_EXE_TAG in exe.tags,
                files))

            command.linux_arch_exes = list(itertools.ifilter(
                lambda exe:
                self.app.LINUX_ARCH in exe.tags and
                self.NIX_EXE_TAG in exe.tags,
                files))

            command.darwin_arch_exes = list(itertools.ifilter(
                lambda exe:
                self.app.DARWIN_ARCH in exe.tags and
                self.NIX_EXE_TAG in exe.tags,
                files))

            command.executable_files = list(files)
            # command_list.append(command)

            yield command
