# Copyright 2018 Splunk Inc. All rights reserved.

# Custom Libraries
import configuration_file


class AuthorizeConfigurationFile(configuration_file.ConfigurationFile):
    """Represents an authorize.conf file"""

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
