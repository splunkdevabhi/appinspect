# Copyright 2018 Splunk Inc. All rights reserved.

# Python Standard Libraries
import os
import itertools
# Custom
import splunk_appinspect


class CustomVisualizations():

    def __init__(self, app):
        self.app = app
        self.CONFIGURATION_DIRECTORY_PATH = "default"
        self.CONFIGURATION_FILE_NAME = 'visualizations.conf'
        self.VISUALIZATION_REQUIRED_FILES = ['formatter.html',
                                             'visualization.css',
                                             'visualization.js',
                                             'preview.png']

    def create_custom_visualization(self, stanza_section):

        # Required Properties
        description_option = stanza_section.get_option("description")
        label_option = stanza_section.get_option("label")
        search_fragment_option = stanza_section.get_option("search_fragment")

        # Optional Properties
        allow_user_selection_option = (stanza_section.get_option("allow_user_selection")
                                       if stanza_section.has_option("allow_user_selection")
                                       else None)
        default_height_option = (stanza_section.get_option("default_height")
                                 if stanza_section.has_option("default_height")
                                 else None)
        disabled_option = (stanza_section.get_option("disabled")
                           if stanza_section.has_option("disabled")
                           else None)

        custom_visualization = splunk_appinspect.custom_visualizations.CustomVisualization(self.app,
                                                                                           stanza_section.name,
                                                                                           description_option,
                                                                                           label_option,
                                                                                           search_fragment_option,
                                                                                           stanza_section.lineno,
                                                                                           allow_user_selection=allow_user_selection_option,
                                                                                           default_height=default_height_option,
                                                                                           disabled=disabled_option)
        return custom_visualization

    @staticmethod
    def visualizations_directory():
        return "appserver/static/visualizations/"

    @property
    def visualization_required_files(self):
        return self.VISUALIZATION_REQUIRED_FILES

    def get_custom_visualizations(self):
        visualizations_configuration_file = self.get_configuration_file()
        # Passes in a ConfigurationSection to be used for creation
        for section in visualizations_configuration_file.sections():
            yield self.create_custom_visualization(section)

    def does_visualizations_directory_exist(self):
        return self.app.directory_exists(CustomVisualizations.visualizations_directory())

    def has_configuration_file(self):
        return self.app.file_exists(self.CONFIGURATION_DIRECTORY_PATH,
                                    self.CONFIGURATION_FILE_NAME)

    def get_configuration_file(self):
        return self.app.get_config(self.CONFIGURATION_FILE_NAME,
                                   dir=self.CONFIGURATION_DIRECTORY_PATH,
                                   config_file=splunk_appinspect.visualizations_configuration_file.VisualizationsConfigurationFile())

    def get_raw_configuration_file(self):
        return self.app.get_raw_conf(self.CONFIGURATION_FILE_NAME,
                                     dir=self.CONFIGURATION_DIRECTORY_PATH)

    def get_configuration_file_path(self):
        return self.app.get_filename(self.CONFIGURATION_DIRECTORY_PATH,
                                     self.CONFIGURATION_FILE_NAME)


class CustomVisualization():
    # TODO: Couple visualization directory reference in this class

    @staticmethod
    def valid_preview_png_dimensions():
        return 116, 76

    def __init__(self,
                 app,
                 name,
                 description,
                 label,
                 search_fragment,
                 lineno,
                 allow_user_selection=None,
                 default_height=None,
                 disabled=None):

        self.app = app
        self.name = name
        self.lineno = lineno
        self.allow_user_selection = allow_user_selection
        self.default_height = default_height
        self.description = description
        self.disabled = disabled
        self.label = label
        self.search_fragment = search_fragment

    def visualization_directory(self):
        return os.path.join(CustomVisualizations.visualizations_directory(), self.name)

    def does_visualization_directory_exist(self):
        return self.app.directory_exists(self.visualization_directory())

    def preview_png_file_path(self):
        return os.path.join(self.visualization_directory(), 'preview.png')

    def does_preview_png_exist(self):
        return self.app.file_exists(self.preview_png_file_path())

