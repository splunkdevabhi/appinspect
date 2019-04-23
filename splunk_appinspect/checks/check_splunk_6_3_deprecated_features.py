# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Deprecated features from Splunk Enterprise 6.3

These following features should not be supported in Splunk 6.3 or later. For more, see <a href="http://docs.splunk.com/Documentation/Splunk/6.3.5/ReleaseNotes/Deprecatedfeatures#Previously_deprecated_features_that_still_work" target="_blank">Deprecated features</a> and <a href="http://docs.splunk.com/Documentation/Splunk/6.3.5/Installation/ChangesforSplunkappdevelopers" target="_blank">Changes for Splunk App developers</a>.
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


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_3", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_simple_xml_seed_element(app, reporter):
    # Warning: This may give false positives on account that it checks EVERY
    # xml file, and there may be a possibility that someone may want to use
    # the <seed> element in a totally different context. That said this isn't
    # likely to cause problems in the future.
    """Check for the deprecated `<seed>` option in Simple XML forms.
    Use the `<initialValue>` element instead.
    """

    xml_files = list(app.get_filepaths_of_files(types=[".xml"]))
    #  Outputs not_applicable if no xml files found
    if not xml_files:
        reporter_output = "No xml files found."
        reporter.not_applicable(reporter_output)

    # Performs the checks
    for relative_filepath, full_filepath in xml_files:
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        seed_elements = soup.find_all("seed")
        if seed_elements:
            reporter_output = ("<seed> element detected in:"
                               " file: {}").format(relative_filepath)
            reporter.fail(reporter_output, relative_filepath)
        else:
            pass  # Do nothing, everything is fine


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_3", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_simple_xml_searchTemplate_element(app, reporter):
    # Warning: This may give false positives on account that it checks EVERY
    # xml file, and there may be a possibility that someone may want to use
    # the <searchTemplate> element in a totally different context. That said this isn't
    # likely to cause problems in the future.
    """Check for the deprecated `<searchTemplate>` element in Simple XML files.
    Use the `<search>` element instead.
    """

    xml_files = list(app.get_filepaths_of_files(basedir="default",
                                                types=[".xml"]))
    #  Outputs not_applicable if no xml files found
    if not xml_files:
        reporter_output = "No xml files found."
        reporter.not_applicable(reporter_output)

    # Performs the checks
    for relative_filepath, full_filepath in xml_files:
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        searchTemplate = soup.find_all("searchTemplate")
        if searchTemplate:
            reporter_output = ("<searchTemplate> detected in"
                               " file: {}").format(relative_filepath)
            reporter.fail(reporter_output, relative_filepath)
        else:
            pass  # Do nothing, everything is fine


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_3", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_simple_xml_option_element_with_name_previewResults(app, reporter):
    # Warning: This may give false positives on account that it checks EVERY
    # xml file, and there may be a possibility that someone may want to use
    # the <option name="previewResults"> element in a totally different context.
    # That said this isn't likely to cause problems in the future.
    """Check for the deprecated `<option name='previewResults'>` in Simple XML
    files.
    """

    xml_files = list(app.get_filepaths_of_files(basedir="default",
                                                types=[".xml"]))
    #  Outputs not_applicable if no xml files found
    if not xml_files:
        reporter_output = "No xml files found."
        reporter.not_applicable(reporter_output)

    # Performs the checks
    for relative_filepath, full_filepath in xml_files:
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        option_elements = soup.find_all("option", {"name": "previewResults"})
        if option_elements:
            reporter_output = ("<option name='previewResults'> detected in"
                               " file: {}").format(relative_filepath)
            reporter.fail(reporter_output, relative_filepath)
        else:
            pass  # Do nothing, everything is fine


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_3", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_simple_xml_chart_element_with_deprecated_option_names(app, reporter):
    # Warning: This may give false positives on account that it checks EVERY
    # xml file. That said this isn't likely to cause problems in the future.
    """Check for Simple XML `<chart>` panels with deprecated options
    `charting.axisLabelsY.majorTickSize` or
    `charting.axisLabelsY.majorLabelVisibility`.
    """
    attributes = ["charting.axisLabelsY.majorLabelVisibility",
                  "charting.axisLabelsY.majorTickSize"]
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
        # Get all chart elements
        chart_elements = list(soup.find_all("chart"))
        for chart_element in chart_elements:
            # Gets all child option elements of said charts, and filters out to
            # only the ones that have a name attribute with the deprecated
            # values
            option_elements = chart_element.find_all("option",
                                                     {"name": attribute_regex})
            if option_elements:
                reporter_output = ("A <chart> was detected with deprecated "
                                   "options in "
                                   "file: {}").format(relative_filepath)
                reporter.fail(reporter_output, relative_filepath)
            else:
                pass  # Do nothing, everything is fine


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_3", "deprecated_feature", "advanced_xml")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_advanced_xml_module_elements(app, reporter):
    """Check for Advanced XML `<module>` elements. The Module system was
    deprecated in Splunk 6.3 as part of the advanced XML deprecation. See:
    http://docs.splunk.com/Documentation/Splunk/latest/Module"""
    # Checks to see if any advanced xml file exists, using the existence of
    # `<module>` elements as a heuristic. This only applies to xml files in
    # default/data/ui/views.

    direcory_to_search = "default/data/ui/views"
    xml_files = list(app.get_filepaths_of_files(basedir=direcory_to_search,
                                                types=[".xml"]))

    #  Outputs not_applicable if no xml files found
    if not xml_files:
        reporter_output = "No xml files found."
        reporter.not_applicable(reporter_output)

    # Performs the checks
    for relative_filepath, full_filepath in xml_files:
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        # Get all module elements
        module_elements = list(soup.find_all("module"))
        for module_element in module_elements:
            reporter_output = ("<module> element found in"
                               " file: {}").format(relative_filepath)
            reporter.fail(reporter_output, relative_filepath)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_3", "deprecated_feature", "advanced_xml")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_advanced_xml_appserver_modules_directory(app, reporter):
    """Check for Module System `appserver/modules` directory. The Module system was
    deprecated in Splunk 6.3 as part of the advanced XML deprecation. See:
    http://docs.splunk.com/Documentation/Splunk/latest/Module"""
    # Checks to see if an appserver/modules directory exists. This is used as
    # a heuristic to determine if the Module System is being used.
    if app.directory_exists("appserver", "modules"):
        file_path = os.path.join("appserver", "modules")
        reporter_output = ("The Advanced XML `appserver/modules` directory was "
                           " detected. Please replace Advanced XMl with Simple "
                           " XML. File: {}"
                           ).format(file_path)
        reporter.fail(reporter_output, file_path)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_3", "deprecated_feature", "advanced_xml")
@splunk_appinspect.cert_version(min="1.5")
def check_for_advanced_xml_web_conf_endpoints(app, reporter):
    """Check for Module System web.conf endpoints. The Module system was
    deprecated in Splunk 6.3 as part of the advanced XML deprecation. See:
    http://docs.splunk.com/Documentation/Splunk/latest/Module"""
    # Checks to see if [endpoint:*] stanzas are defined in web.conf. This is
    # used as a heuristic to determine if the Module System is being used.
    if app.file_exists("default", "web.conf"):
        web_conf = app.web_conf()
        file_path = os.path.join("default", "web.conf")
        for section in web_conf.sections():
            if section.name.startswith("endpoint:"):
                reporter_output = ("Deprecated Module System endpoint found in"
                                   " web.conf. Please remove this stanza: [{}]."
                                   " File: {}, Line: {}."
                                   ).format(section.name,
                                            file_path,
                                            section.lineno)
                reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = "No web.conf file exists."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_3", "deprecated_feature", "advanced_xml")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_advanced_xml_view_element(app, reporter):
    """Check for Advanced XML `<view>` elements that do not have the
    `redirect` or `html` types.
    """
    # Per Siegfried Puchbauer
    # If it's a <view> element then it's a view XML. This can either be
    #   - A system view/page if the type attribute is html (ie. <view type="html">)
    #   - A redirect (not a view at all) if the type attribute is redirect (ie. <view type="redirect">)
    #   - Otherwise it's Advanced XML

    # Tried to make a sweet negative look ahead regex, but it wasn't working
    # Now you get a boring regex
    attributes = ["html", "redirect"]
    attribute_regex_string = "|".join(attributes)
    attribute_regex = re.compile(attribute_regex_string)

    # excludes default/data/ui/nav - #WARNING excludes any nav folder...
    excluded_directories = ["nav"]

    # Gets ALL xml files
    xml_files = list(app.get_filepaths_of_files(excluded_dirs=excluded_directories,
                                                types=[".xml"]))

    #  Outputs not_applicable if no xml files found
    if not xml_files:
        reporter_output = "No xml files found."
        reporter.not_applicable(reporter_output)

    # Performs the checks
    for relative_filepath, full_filepath in xml_files:
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        all_view_elements = list(soup.find_all("view"))
        non_advanced_xml_view_elements = list(soup.find_all("view", {"type": attribute_regex}))
        advanced_xml_elements = list(set(all_view_elements) - set(non_advanced_xml_view_elements))

        # Currently there is no alternatives for developers using
        # setup and advanced xml.  As such any files located in
        # default/data/ui/manager that use advanced xml are ignored.
        ignore_segments = ["default", "data", "ui", "manager"]
        path = os.path.normpath(relative_filepath)
        segs = path.split(os.sep)
        if all((s in segs for s in ignore_segments)):
            reporter_output = ("An XML file was detected that contains Advanced"
                               " XML <view> types.  This file has been ignored."
                               " File: {}").format(relative_filepath)
            reporter.not_applicable(reporter_output)
            continue

        if len(advanced_xml_elements) == 0:
            pass  # Do nothing, everything is fine

        elif len(advanced_xml_elements) >= 1:
            # Beautiful soup does not provide line numbers for match lxml/html
            # rather trimmed content elements
            # Read the file and find the view element line numbers.
            with open(full_filepath, 'r') as xml_file:
                content = xml_file.readlines()
                lines = [x for x in range(len(content)) if "<view" in content[x].strip()]

                for l in lines:
                    line_number = l + 1

                    reporter_output = ("An XML file that contains Advanced"
                                       " XML <view> types. was detected."
                                       " File: {}"
                                       " Line: {}").format(relative_filepath, line_number)
                    reporter.fail(reporter_output, relative_filepath, line_number)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_3", "deprecated_feature", "django_bindings")
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_django_bindings(app, reporter):
    """Check for use of Django bindings."""
    # Checks to see that the django directory exist. If it does, then
    # django bindings are being used.
    if app.directory_exists("django"):
        file_path = "django"
        reporter_output = ("The `django` directory was detected. File: {}"
                           ).format(file_path)
        reporter.fail(reporter_output, file_path)
    else:
        pass  # Do nothing, everything is fine
