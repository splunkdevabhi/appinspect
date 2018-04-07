# Copyright 2016 Splunk Inc. All rights reserved.

"""This is a helper module to encapsulate the functionality that represents
Splunk's modular inputs feature.
"""

# Python Standard Libraries
import itertools
import logging
import re
import os
# Custom Libraries
import splunk_appinspect

logger = logging.getLogger(__name__)


class ModularInputs(object):
    """Encapsulates the logic and helper functions needed for Splunk's modular
    inputs.

    The ModularInputs object has a 1 to many relation for ModularInput objects.

    Args:
        app (App Object): The app object that represents a Splunk app.

    Attributes:
        app (App Object): The app object that represents a Splunk app.
        specification_directory_path (String): The path to where the modular
            inputs specification file exists.
        specification_filename (String): The modular inputs specification
            file name.
        CROSS_PLAT_EXE_TAG (String): A string used to tag a FileResource
            object with its respective modular input location
        WINDOWS_EXE_TAG (String): A string used to tag a FileResource
            object with its respective modular input location
        NIX_EXE_TAG (String): A string used to tag a FileResource
            object with its respective modular input location
        WINDOWS_EXES (List of Strings): A list of strings used that
            represents the allowed binary types that can be used for a modular
            input in a windows environment
        NIX_EXES (List of Strings): A list of strings used that
            represents the allowed binary types that can be used for a modular
            input in a linux environment
        CROSS_PLAT_EXES (List of Strings): A list of strings used that
            represents the allowed binary types that can be used for a modular
            input in a linux environment
    """

    def __init__(self, app):
        """Return None.

        Performs constructor initialization of the ModularInputs object.
        """
        self.app = app

        self.specification_directory_path = "README"
        self.specification_filename = "inputs.conf.spec"

        # architecture stuff
        self.CROSS_PLAT_EXE_TAG = "cross_plat_exe"
        self.WINDOWS_EXE_TAG = "windows_exe"
        self.NIX_EXE_TAG = "nix_exe"

        self.WINDOWS_EXES = [".cmd", ".bat", ".py", ".exe"]
        self.NIX_EXES = [".sh", ".py", ""]
        self.CROSS_PLAT_EXES = splunk_appinspect.iter_ext.intersect(self.WINDOWS_EXES,
                                                                    self.NIX_EXES)

    @staticmethod
    def factory(app):
        """A factory function to return a ModularInputs object.

        Args:
            app (App object): An app object that will be used to generate
                modular inputs from.
        Returns:
            ModularInputs object: A brand new ModularInputs object.
        """
        return ModularInputs(app)

    @staticmethod
    def modular_input_factory(name, chunked=False):
        """A factory function to retrieve a ModularInput object, which belongs
        to a ModularInputs object (Note the 's').

        name (String): The name of a Modular Input. This is the stanza of the
            Modular Inputs specification file. This does NOT include the
            protocol prefix of ://
        chunked (Boolean): Indicates if the modular input is chunked (a.k.a. mod
            input v2)

        Returns:
            ModularInput object: A Modular Input object.
        """
        return ModularInput(name, chunked=chunked)

    # TODO: generalize this to accept the filename and directory
    def has_specification_file(self):
        """Returns:
            Returns a boolean value representing if a modular inputs
            specification file exists
        """
        return self.app.file_exists(self.specification_directory_path,
                                    self.specification_filename)

    # TODO: generalize this to accept the filename and directory
    def get_specification_file(self):
        """Returns:
            Returns a InputsSpecification object that represents the Modular
            Inputs specificatoin file.
        """
        return self.app.get_spec(self.specification_filename,
                                 dir=self.specification_directory_path,
                                 config_file=splunk_appinspect.inputs_specification_file.InputsSpecification())

    # TODO: generalize this to accept the filename and directory
    def get_raw_specification_file(self):
        """Returns:
            Returns a string that represents the raw content of the Modular
            Inputs specification file.
        """
        return self.app.get_raw_conf(self.specification_filename,
                                     dir=self.specification_directory_path)

    def get_specification_app_filepath(self):
        """Returns:
            Returns a string that represents the absolute file path to Modular
            Inputs specification file.
        """
        return self.app.get_filename(self.specification_directory_path,
                                     self.specification_filename)

    def find_exes(self, name, case_sensitive=True):
        """Returns a generator that yields a FileResource object representing an
        executable file that can be used for modular inputs

        For a given named file, find scripts and exes in the standard folders

        : param name(String) - the name of the file to search for
        : param case_sensitive(Bool) - if the search for exe should be
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
                    ext_filter = self.WINDOWS_EXES + self.NIX_EXES

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
                    found_file_matching_mod_input_name = (re.search(file_name_regex_object, file_base_name) is not None)
                    if found_file_matching_mod_input_name:
                        file = os.path.join(self.app.app_dir, directory, filename)
                        path = os.path.join(self.app.name, directory, filename)
                        resource = splunk_appinspect.file_resource.FileResource(file,
                                                                                ext=file_extension,
                                                                                app_file_path=path)
                        resource.tags.append(arch)

                        if file_extension in self.WINDOWS_EXES:
                            resource.tags.append(self.WINDOWS_EXE_TAG)

                        if file_extension in self.NIX_EXES:
                            resource.tags.append(self.NIX_EXE_TAG)

                        if file_extension in self.CROSS_PLAT_EXES:
                            resource.tags.append(self.CROSS_PLAT_EXE_TAG)

                        yield resource
                    else:
                        next

    def has_modular_inputs(self):
        """Returns:
            A boolean value representing the number of modular inputs detected
        """
        return (len(list(self.get_modular_inputs())) > 0)

    def get_modular_inputs(self, case_sensitive=True):
        """Returns a generator that yields a ModularInput object representing a
        Splunk ModularInput configuration.

        Attributes:
            case_sensitive (Bool): if the search for modular inputs should be
                case-sensitve
        """
        for section in self.get_specification_file().section_names():

            mod_input = self.modular_input_factory(section)
            for key, value in self.get_specification_file().items(section):
                mod_input.args[key] = [value]

            files = []
            for file_resource in self.find_exes(mod_input.name, case_sensitive=case_sensitive):
                files.append(file_resource)

            # Set the specific architecture files
            mod_input.cross_plat_exes = list(itertools.ifilter(
                lambda exe:
                self.app.DEFAULT_ARCH in exe.tags and
                self.CROSS_PLAT_EXE_TAG in exe.tags,
                files))

            mod_input.win_exes = list(itertools.ifilter(
                lambda exe:
                self.app.DEFAULT_ARCH in exe.tags and
                self.WINDOWS_EXE_TAG in exe.tags,
                files))

            mod_input.linux_exes = list(itertools.ifilter(
                lambda exe:
                self.app.DEFAULT_ARCH in exe.tags and
                self.NIX_EXE_TAG in exe.tags,
                files))

            mod_input.win_arch_exes = list(itertools.ifilter(
                lambda exe:
                self.app.WIN_ARCH in exe.tags and
                self.WINDOWS_EXE_TAG in exe.tags,
                files))

            mod_input.linux_arch_exes = list(itertools.ifilter(
                lambda exe:
                self.app.LINUX_ARCH in exe.tags and
                self.NIX_EXE_TAG in exe.tags,
                files))

            mod_input.darwin_arch_exes = list(itertools.ifilter(
                lambda exe:
                self.app.DARWIN_ARCH in exe.tags and
                self.NIX_EXE_TAG in exe.tags,
                files))

            mod_input.executable_files = list(files)

            if mod_input.executable_files:
                yield mod_input


class ModularInput(object):
    """Represents a modular input.

    Args:
        name (String): The name of a Modular Input. This is the stanza of the
            Modular Inputs specification file. This does NOT include the
            protocol prefix of ://
        chunked (Boolean): Indicates if the modular input is chunked (a.k.a. mod
            input v2)

    Attributes:
        name (String): The name of a Modular Input. This is the stanza of the
            Modular Inputs specification file. This does NOT include the
            protocol prefix of ://
        chunked (Boolean): Indicates if the modular input is chunked (a.k.a. mod
            input v2)
        full_name (String): The name of a Modular Input. This is the stanza of
            the Modular Inputs specification file. This include the protocol
            prefix of ://
        args (Dict): A dictionary that represents the properties and values of
            the Modular Inputs stanza from the specification file
        executable_files (List of FileResource Objects): A list of FileResource
            objects that represent all the binary files detected for the modular
            input
        win_exes (List of FileResource Objects): A list of FileResource
            objects that represent the binary files detected for the modular
            input, but only with respect to allowed Windows binaries
        linux_exes (List of FileResource Objects): A list of FileResource
            objects that represent the binary files detected for the modular
            input, but only with respect to allowed Linux binaries
        win_arch_exes (List of FileResource Objects): A list of FileResource
            objects that represent the binary files detected for the modular
            input, but only with respect to allowed windows architecture
            binaries
        darwin_arch_exes (List of FileResource Objects): A list of FileResource
            objects that represent the binary files detected for the modular
            input, but only with respect to allowed OSX binaries
        linux_arch_exes (List of FileResource Objects): A list of FileResource
            objects that represent the binary files detected for the modular
            input, but only with respect to allowed Linux architecture binaries
        cross_plat_exes (List of FileResource Objects): A list of FileResource
            objects that represent the binary files detected for the modular
            input, but only with respect to allowed cross platform binaries
    """

    def __init__(self, name, chunked=False):
        """Returns:
            None

        A constructor initializer
        """
        self.name = name.split("://")[0]
        self.chunked = chunked

        self.full_name = name
        self.args = {}
        self.executable_files = []
        self.win_exes = []
        self.linux_exes = []
        self.win_arch_exes = []
        self.darwin_arch_exes = []
        self.linux_arch_exes = []
        self.cross_plat_exes = []

    @staticmethod
    def factory(name, chunked=False):
        """A factory function to retrieve a ModularInput object, which belongs
        to a ModularInputs object (Note the 's').

        name (String): The name of a Modular Input. This is the stanza of the
            Modular Inputs specification file. This does NOT include the
            protocol prefix of ://
        chunked (Boolean): Indicates if the modular input is chunked (a.k.a. mod
            input v2)

        Returns:
            ModularInput object: A Modular Input object.
        """
        return ModularInput(name, chunked=chunked)

    def args_exist(self):
        return len(self.args) > 0

    def count_cross_plat_exes(self):
        return splunk_appinspect.iter_ext.count_iter(self.cross_plat_exes)

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
