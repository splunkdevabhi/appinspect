# Copyright 2018 Splunk Inc. All rights reserved.

# Custom Library
import configuration_file


class InputsSpecification(configuration_file.ConfigurationFile):
    """Represents an input.conf.spec file from Readme/input.conf.spec."""

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
