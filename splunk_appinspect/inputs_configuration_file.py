# Copyright 2016 Splunk Inc. All rights reserved.

# Custom Library
import configuration_file


class InputsConfigurationFile(configuration_file.ConfigurationFile):
    """Represents an `inputs.conf.spec` file from `default/inputs.conf`."""

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
