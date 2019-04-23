# Copyright 2018 Splunk Inc. All rights reserved.

# Custom Libraries
import configuration_file


class DistsearchConfigurationFile(configuration_file.ConfigurationFile):
    """Represents an [distsearch.conf](https://docs.splunk.com/Documentation/Splunk/7.2.0/Admin/Distsearchconf)
    file.
    """

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
