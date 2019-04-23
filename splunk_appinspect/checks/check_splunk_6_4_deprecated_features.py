# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Deprecated features from Splunk Enterprise 6.4

The following features should not be supported in Splunk 6.4 or later. For more, see <a href="http://docs.splunk.com/Documentation/Splunk/latest/ReleaseNotes/Deprecatedfeatures#Previously_deprecated_features_that_still_work" target="_blank">Deprecated features</a> and <a href="http://docs.splunk.com/Documentation/Splunk/latest/Installation/ChangesforSplunkappdevelopers" target="_blank">Changes for Splunk App developers</a>.
"""

# Python Standard Libraries
import logging
import re
import os
# Third-Party Libraries
import bs4
# Custom Libraries
import splunk_appinspect

logger = logging.getLogger(__name__)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_4", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_simple_xml_single_element_with_deprecated_option_names(app, reporter):
    """Check Simple XML files for `<single>` panels with deprecated options
    'additionalClass', 'afterLabel', 'beforeLabel', 'classField', 'linkFields',
    'linkSearch', 'linkView'
    """
    attributes = ["additionalClass", "afterLabel", "beforeLabel", "classField",
                  "linkFields", "linkSearch", "linkView"]
    attribute_regex_string = "|".join(attributes)
    attribute_regex = re.compile(attribute_regex_string)
    xml_files = list(app.get_filepaths_of_files(basedir="default",
                                                types=[".xml"]))
    attributes_logging_string = ", ".join(attributes)

    #  Outputs not_applicable if no xml files found
    if not xml_files:
        reporter_output = "No xml files found."
        reporter.not_applicable(reporter_output)

    # Performs the checks
    for relative_filepath, full_filepath in xml_files:
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        # Get all single elements
        total_single_elements_with_options_found = 0
        attributes_found = []
        single_elements = list(soup.find_all("single"))

        for single_element in single_elements:
            # Gets all child option elements of said single, and filters out to
            # only the ones that have a name attribute with the deprecated
            # values
            option_elements = single_element.find_all("option",
                                                      {"name": attribute_regex})
            if option_elements:
                total_single_elements_with_options_found += 1
                for option_element in option_elements:
                    option_name = option_element.attrs["name"]
                    if option_name not in attributes_found:
                        attributes_found.append(option_name)
        if(total_single_elements_with_options_found > 0 or
                attributes_found):
            attributes_found_string = ", ".join(attributes_found)
            reporter_output = ("{} <single> panel(s) contain the"
                               " option(s): {}"
                               " File: {}").format(total_single_elements_with_options_found,
                                                   attributes_found_string,
                                                   relative_filepath)
            reporter.fail(reporter_output, relative_filepath)
        else:
            pass  # Do nothing, everything is fine


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_4", "deprecated_feature", "web_conf")
@splunk_appinspect.cert_version(min="1.1.11")
def check_web_conf_for_simple_xml_module_render(app, reporter):
    """Check that `web.conf` does not use the simple_xml_module_render
    property.
    """
    try:
        web_config = app.web_conf()
        web_config_file_path = os.path.join("default", "web.conf")
        for section in web_config.sections():
            for property, value, lineno in [(p, v, lineno)
                                    for p, v, lineno in section.items()
                                    if p == "simple_xml_module_render"]:
                reporter_output = ("File: {}, "
                                   "Stanza: {}, "
                                   "Line: {}."
                                   ).format(web_config_file_path,
                                            section.name,
                                            lineno)
                reporter.fail(reporter_output, web_config_file_path, lineno)
    except:
        reporter_output = ("No web.conf file found.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_4", "deprecated_feature", "web_conf")
@splunk_appinspect.cert_version(min="1.1.11")
def check_web_conf_for_simple_xml_force_flash_charting(app, reporter):
    """Check that a `web.conf` does not use the property
    'simple_xml_force_flash_charting'.
    """
    try:
        web_config = app.web_conf()
        web_config_file_path = os.path.join("default", "web.conf")

        for section in web_config.sections():
            all_secitions_with_flash_charting = [(p, v, lineno)
                                                 for p, v, lineno in section.items()
                                                 if p == "simple_xml_force_flash_charting"]
            for property, value, lineno in all_secitions_with_flash_charting:
                reporter_output = ("File: {}, "
                                   "Stanza: {}, "
                                   "Line: {}"
                                   ).format(web_config_file_path,
                                            section.name,
                                            lineno)
                reporter.fail(reporter_output, web_config_file_path, lineno)
    except:
        reporter_output = ("No web.conf file found.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_4", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_noninteger_height_option(app, reporter):
    """Check that `<option name="height">` uses an integer for the value. Do not
    use `<option name="height">[value]px</option>.`
    """
    # Helper function for determining if string is a number
    def is_number(string):
        try:
            float(string)
            return True
        except ValueError:
            return False

    xml_files = list(app.get_filepaths_of_files(basedir="default",
                                                types=[".xml"]))

    #  Outputs not_applicable if no xml files found
    if not xml_files:
        reporter_output = "No xml files found."
        reporter.not_applicable(reporter_output)

    # Performs the checks
    for relative_filepath, full_filepath in xml_files:
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        option_elements = soup.find_all("option", {"name": "height"})
        for option_element in option_elements:
            option_content = option_element.string
            if not is_number(option_content):
                reporter_output = ("File: {}").format(relative_filepath)
                reporter.fail(reporter_output, relative_filepath)
            else:
                pass  # Success- do nothing, it's all good here


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_4", "deprecated_feature", "web_conf")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_splunk_web_legacy_mode(app, reporter):
    """Check that the 'appServerPorts' property in the web.conf does not contain
    port 0.
    """
    # Per the documentation
    # This was a temporary setting for use in specific cases where SSO would
    # break using the new mode. These issues have since been resolved, and
    # therefore this workaround is no longer needed. Switching to normal mode is
    # recommended given the performance and configuration benefits

    # appServerPorts is a comma separated list of ports
    try:
        web_config = app.web_conf()
        web_config_file_path = os.path.join("default", "web.conf")

        property_being_checked = "appServerPorts"
        for section in web_config.sections():
            all_sections_with_app_server_ports = [(p, v, lineno)
                                                   for p, v, lineno in section.items()
                                                   if p == property_being_checked]

            for property, value, lineno in all_sections_with_app_server_ports:
                if(property == property_being_checked and
                        "0" in value.split(",")):
                    reporter_output = ("File: {}, "
                                       "Stanza: [{}], "
                                       "Line: {}."
                                       ).format(web_config_file_path,
                                                section.name,
                                                lineno)
                    reporter.fail(reporter_output, web_config_file_path, lineno)
    except:
        reporter_output = ("No web.conf file found.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_4", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_splunk_js_d3chartview(app, reporter):
    """Checks that views are not importing d3chartview."""
    library_import_pattern = "splunkjs/mvc/d3chart/d3chartview"
    relevant_file_types = [".js"]

    # This is a little lazy, but search for pattern doesn't return a list of
    # the files being searched, so in order to know the count I get the list of
    # iterated files and then completely ignore it if > 0
    files = list(app.get_filepaths_of_files(types=relevant_file_types))

    if not files:
        reporter_output = ("No {} files exist."
                           ).format(",".join(relevant_file_types))
        reporter.not_applicable(reporter_output)

    # Check starts here
    matches_found = app.search_for_pattern(library_import_pattern,
                                           types=relevant_file_types)
    for match_file_and_line, match_object in matches_found:
        match_split = match_file_and_line.rsplit(":", 1)
        match_file = match_split[0]
        match_line = match_split[1]
        reporter_output = ("File: {}"
                           " Line: {}"
                           ).format(match_file, match_line)
        reporter.fail(reporter_output, match_file, match_line)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_4", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_splunk_js_googlemapsview(app, reporter):
    """Checks that views are not importing googlemapsview."""
    library_import_pattern = "splunkjs/mvc/d3chart/googlemapsview"
    relevant_file_types = [".js"]

    # This is a little lazy, but search for pattern doesn't return a list of
    # the files being searched, so in order to know the count I get the list of
    # iterated files and then completely ignore it if > 0
    files = list(app.get_filepaths_of_files(types=relevant_file_types))

    if not files:
        reporter_output = ("No {} files exist."
                           ).format(",".join(relevant_file_types))
        reporter.not_applicable(reporter_output)

    # Check starts here
    matches_found = app.search_for_pattern(library_import_pattern,
                                           types=relevant_file_types)
    for match_file_and_line, match_object in matches_found:
        match_split = match_file_and_line.rsplit(":", 1)
        match_file = match_split[0]
        match_line = match_split[1]
        reporter_output = ("File: {}"
                           " Line: {}"
                           ).format(match_file, match_line)
        reporter.fail(reporter_output, match_file, match_line)
