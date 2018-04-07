# Copyright 2016 Splunk Inc. All rights reserved.

# Custom Libraries
import configuration_file


class SavedSearchesConfigurationFile(configuration_file.ConfigurationFile):
    """Represents a [savedsearches.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Savedsearchesconf) file."""

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
