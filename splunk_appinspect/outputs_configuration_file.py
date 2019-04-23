# Copyright 2018 Splunk Inc. All rights reserved.

# Custom Library
import configuration_file


class OutputsConfigurationFile(configuration_file.ConfigurationFile):
    """Represents an `outputs.conf` file."""

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
