# Copyright 2016 Splunk Inc. All rights reserved.

# Python Standard Libraries
import os
# Custom Libraries
import commands_configuration_file
from file_resource import FileResource


class Command:
    """Represents a custom search command."""

    def __init__(self, name, file_name="", chunked=None):
        self.chunked = chunked
        self.name = name
        self.file_name = file_name
        self.type = ""
        self.args = {}
        self.passauth = ""
        self.requires_srinfo = ""
        self.streaming_preop = ""
        self.requires_preop = ""
        self.enableheader = ""

    def executable_file(self):
        return FileResource(self.file_name)

    def is_v2(self):
        return self.chunked == "true"


class CustomCommands:
    """Represents a commands.conf file from default/commands.conf."""

    def __init__(self, app):
        self.app = app
        self.commands_conf_file_path = app.get_filename('default',
                                                        'commands.conf')

    def configuration_file_exists(self):
        return self.app.file_exists('default', 'commands.conf')

    def get_configuration_file(self):
        return self.app.get_config('commands.conf',
                                   config_file=commands_configuration_file.CommandsConfigurationFile())

    def get_commands(self):

        command_list = []

        for section in self.get_configuration_file().section_names():

            command = Command(section)
            for key, value in self.get_configuration_file().items(section):
                command.args[key] = [value]

                if key.lower() == "filename":
                    command.file_name = os.path.join(self.app.app_dir,
                                                     "bin/",
                                                     value)

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

            command_list.append(command)

        return command_list
