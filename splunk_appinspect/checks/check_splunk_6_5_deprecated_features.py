# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Deprecated features from Splunk 6.5.

These features should not be supported in Splunk 6.5 and onward

- [List of deprecated features](http://docs.splunk.com/Documentation/Splunk/6.5.0/ReleaseNotes/Deprecatedfeatures).
- [Version changes](https://docs.splunk.com/Documentation/Splunk/latest/Installation/ChangesforSplunkappdevelopers).
"""

# Python Standard Libraries
import logging

# Third-Party Libraries
import bs4

# Custom Libraries
import splunk_appinspect

logger = logging.getLogger(__name__)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_5", "removed_feature")
@splunk_appinspect.cert_version(min="1.2.1")
def check_for_simple_xml_list_element(app, reporter):
    """Check Simple XML files for `<list>` element used in dashboards
    """
    xml_files = list(app.get_filepaths_of_files(basedir="default",
                                                types=[".xml"]))

    #  Outputs not_applicable if no xml files found
    if not xml_files:
        reporter_output = "No xml files found."
        reporter.not_applicable(reporter_output)
        return

    # Performs the checks
    for relative_filepath, full_filepath in xml_files:
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        list_elements = list(soup.find_all("list"))
        count = len(list_elements)
        if count > 0:
            reporter_output = ("{} <list> elements found File: {}".format(count, relative_filepath))
            reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_5", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.2.1")
def check_for_simple_xml_option_element_with_deprecated_attribute_value(app, reporter):
    """Check Simple XML files for `<option>` element with the deprecated option value "refresh.auto.interval"
     i.e. <option name="refresh.auto.interval">
    """
    xml_files = list(app.get_filepaths_of_files(basedir="default",
                                                types=[".xml"]))

    #  Outputs not_applicable if no xml files found
    if not xml_files:
        reporter_output = "No xml files found."
        reporter.not_applicable(reporter_output)
        return

    # Performs the checks
    for relative_filepath, full_filepath in xml_files:
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        total_options_found = 0
        option_elements = list(soup.find_all("option",
                                             {"name": "refresh.auto.interval"}))

        if option_elements:
            total_options_found += len(option_elements)

        if total_options_found > 0:
            reporter_output = ("{} <option> elements contain the attribute value refresh.auto.interval "
                               " File: {}").format(total_options_found, relative_filepath)
            reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "splunk_6_5", "deprecated_feature")
@splunk_appinspect.cert_version(min="1.2.1")
def check_for_splunk_js_header_and_footer_view(app, reporter):
    """
    Checks that views are not importing splunkjs/mvc/headerview or splunkjs/mvc/footerrview.
    These are replaced by LayoutView in Splunk 6.5.  LayoutView is not backwards compatible to Splunk 6.4 or earlier.
    Only use LayoutView if you are only targeting Splunk 6.5 or above.
    """
    library_import_pattern = ["splunkjs/mvc/headerview", "splunkjs/mvc/footerview"]
    relevant_file_types = [".js", ".html"]

    # This is a little lazy, but search for pattern doesn't return a list of
    # the files being searched, so in order to know the count I get the list of
    # iterated files and then completely ignore it if < 0
    files = list(app.get_filepaths_of_files(types=relevant_file_types))

    if not files:
        reporter_output = ("No {} files exist."
                           ).format(",".join(relevant_file_types))
        reporter.not_applicable(reporter_output)
        return

    # Check starts here
    matches_found = app.search_for_patterns(library_import_pattern,
                                            types=relevant_file_types)
    for match_file_and_line, match_object in matches_found:
        match_split = match_file_and_line.rsplit(":", 1)
        match_file = match_split[0]
        match_line = match_split[1]
        reporter_output = ("As of splunk 6.5 this functionality is deprecated and should be removed "
                           "in future app versions. Match: {} File: {} Line: {}"
                           ).format(match_object.group(), match_file, match_line)
        reporter.warn(reporter_output)
