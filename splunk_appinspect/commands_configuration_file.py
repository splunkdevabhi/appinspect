# Copyright 2016 Splunk Inc. All rights reserved.

# Custom Libraries
import configuration_file


class CommandsConfigurationFile(configuration_file.ConfigurationFile):
    """Represents an commands.conf file"""

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
