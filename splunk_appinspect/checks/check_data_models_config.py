# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Data model files and configurations

Data models are defined in a **datamodels.conf** file in the **/default** directory of the app. For more, see <a href="http://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutdatamodels" target="_blank">About data models</a> and <a href="http://docs.splunk.com/Documentation/Splunk/latest/Admin/Datamodelsconf" target="_blank">datamodels.conf</a>.
"""

# Python Standard Libraries
import logging
import os
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.splunk import normalizeBoolean

report_display_order = 25
logger = logging.getLogger(__name__)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.0.0")
@splunk_appinspect.display(report_display_order=1)
def check_validate_data_models_conf_file_in_correct_locations(app, reporter):
    """Check that when using data models, the `datamodels.conf` file only exists
    in the default directory.
    """
    # Gathers all datamodels.conf files
    datamodels_filepath = os.path.join("default", "datamodels.conf")

    for relative_filepath, full_filepath in app.get_filepaths_of_files(filenames=["datamodels"], types=[".conf"]):
        if relative_filepath != datamodels_filepath:
            reporter_output = ("A datamodels.conf file"
                               " was found outside of the default directory."
                               " File: {}").format(relative_filepath)
            reporter.fail(reporter_output, relative_filepath)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.0")
def check_validate_no_missing_json_data(app, reporter):
    """Check that each stanza in
    [datamodels.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Datamodelsconf)
    has a matching JSON file in `default/data/models/`.
    """
    data_model_location = "default/data/models"
    for relative_filepath, full_filepath in app.get_filepaths_of_files(filenames=["datamodels"], types=[".conf"]):
        config = app.get_config(name=relative_filepath, dir='.')

        for section in config.sections():
            json_filename = "{}.json".format(section.name)
            does_matching_json_file_exist = app.file_exists(data_model_location,
                                                            json_filename)
            if not does_matching_json_file_exist:
                reporter_output = ("There is no corresponding JSON file for [{}] in {}."
                                   "File: {}, Line: {}."
                                   ).format(section.name,
                                            relative_filepath,
                                            relative_filepath,
                                            section.lineno)
                reporter.fail(reporter_output, relative_filepath, section.lineno)


@splunk_appinspect.tags('splunk_appinspect', 'cloud')
@splunk_appinspect.cert_version(min='1.5.0')
@splunk_appinspect.display(report_display_order=4)
def check_for_datamodel_acceleration(app, reporter):
    """Check that the use of accelerated data models do not occur. If data model
    acceleration is required, developers should provide directions in documentation
    for how to accelerate data models from within the Splunk Web GUI.

    [data model acceleration](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Acceleratedatamodels)
    """
    if app.file_exists('default', 'datamodels.conf'):
        file_path = os.path.join("default", "datamodels.conf")
        datamodels_config = app.get_config("datamodels.conf")

        # check if acceleration=true is set in default stanza
        is_default_stanza_accelerated = (datamodels_config.has_section("default") and
                                         datamodels_config.has_option("default", "acceleration") and
                                         normalizeBoolean(datamodels_config.get("default", "acceleration").strip()))

        non_default_sections = [section for section in datamodels_config.sections() if section.name != "default"]
        for section in non_default_sections:
            is_accelerated = False
            lineno = None
            if section.has_option("acceleration"):
                if normalizeBoolean(section.get_option("acceleration").value.strip()):
                    is_accelerated = True
                    lineno = section.get_option("acceleration").lineno
            elif is_default_stanza_accelerated:
                is_accelerated = True
                lineno = datamodels_config.get_section("default").get_option("acceleration").lineno

            if is_accelerated:

                reporter_output = (
                    "Data model acceleration was detected in `default/datamodels.conf` for stanza "
                    "[{}]. Please do not enable data model acceleration by default. If data model "
                    "acceleration is required, please provide users with guidance on how to enable "
                    "data model acceleration from within the Splunk Web GUI. File: {}, Line: {}."
                ).format(section.name,
                         file_path,
                         lineno)
                reporter.fail(reporter_output, file_path, lineno)
    else:
        reporter.not_applicable("No datamodels.conf file exists.")
