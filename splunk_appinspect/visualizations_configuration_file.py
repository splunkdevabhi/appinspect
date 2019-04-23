# Copyright 2018 Splunk Inc. All rights reserved.

# Custom Libraries
import configuration_file


class VisualizationsConfigurationFile(configuration_file.ConfigurationFile):
    """Represents a visualizations.conf file"""

    def __init__(self):
        configuration_file.ConfigurationFile.__init__(self)
