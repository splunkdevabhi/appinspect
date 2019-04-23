# Copyright 2018 Splunk Inc. All rights reserved.

# Custom Libraries
import configuration_file


class RestMapConfigurationFile(configuration_file.ConfigurationFile):
    """Represents a [transforms.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Transformsconf) file."""

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
