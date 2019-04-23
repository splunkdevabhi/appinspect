# Copyright 2018 Splunk Inc. All rights reserved.

# Custom Libraries
import configuration_file


class PropsConfigurationFile(configuration_file.ConfigurationFile):
    """Represents a [props.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf) file."""

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
