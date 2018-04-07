# Copyright 2016 Splunk Inc. All rights reserved.

"""
### XML file standards
"""

# Python Standard Libraries
import os
import re
import xml
from xml.sax import make_parser
import logging
# Third-Party Libraries
import bs4
# Custom Libraries
import splunk_appinspect

logger = logging.getLogger(__name__)
report_display_order = 7


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud")
@splunk_appinspect.cert_version(min="1.0.0")
def check_that_all_xml_files_are_well_formed(app, reporter):
    """Check that all XML files are well-formed."""
    # From Python cookbook
    # https://www.safaribooksonline.com/library/view/python-cookbook-2nd/0596007973/ch12s02.html
    def parse_xml(filename):
        parser = make_parser()
        parser.setContentHandler(xml.sax.handler.ContentHandler())
        parser.parse(filename)

    for relative_filepath, full_filepath in app.get_filepaths_of_files(types=[".xml"]):
        try:
            parse_xml(full_filepath)
        except:
            reporter.fail("Invalid XML file: {}".format(relative_filepath))


@splunk_appinspect.tags("splunk_appinspect", "cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_iframe_in_xml_files(app, reporter):
    """ Check iframe elements for compliance with Splunk Cloud security policy.
    """
    iframe_regex_pattern = re.compile("<iframe[^>]*>|<\/iframe>",
                                      re.IGNORECASE | re.MULTILINE)
    for relative_filepath, full_filepath in app.get_filepaths_of_files(types=[".xml"]):
        with open(full_filepath, "r") as f:
            current_file_contents = f.read()

        iframe_matches = re.findall(iframe_regex_pattern,
                                    current_file_contents)
        if iframe_matches:
            reporter_output = ("An iframe has been detected."
                               " File: {}").format(relative_filepath)
            reporter.manual_check(reporter_output, relative_filepath)


@splunk_appinspect.tags("splunk_appinspect", "cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.0")
def check_validate_no_embedded_javascript(app, reporter):
    """Check any XML files that embed JavaScript via CDATA for compliance
    with Splunk Cloud security policy.
    """
    for relative_filepath, full_filepath in app.get_filepaths_of_files(types=[".xml"]):
        soup = bs4.BeautifulSoup(open(full_filepath), "html.parser")
        script_elements = soup.find_all("script")

        cdata_script_elements = [e for e in soup(text=True)
                                 if isinstance(e, bs4.CData) and re.search(r'<script\b', e) is not None]
        script_elements.extend(cdata_script_elements)

        if script_elements:
            total_lines_of_code_output = 0
            for element in script_elements:
                element_as_string = "{}".format(element)
                element_content_regex = re.compile(">(.*?)<.*(?:>)",
                                                   re.DOTALL |
                                                   re.IGNORECASE |
                                                   re.MULTILINE)
                content_matches = re.findall(element_content_regex,
                                             element_as_string)

                for content_match in content_matches:
                    content_match_split = content_match.splitlines()
                    total_lines_of_code_output += len(content_match_split)

            total_lines_of_code_output += len(cdata_script_elements)
            reporter_output = ("Embedded javascript has been detected."
                               " Total line(s) of code found: {}."
                               " File: {}.").format(total_lines_of_code_output,
                                                    relative_filepath)
            reporter.manual_check(reporter_output, relative_filepath)


@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.0")
def check_validate_no_event_handler(app, reporter):
    """Ensure that global event handlers are not used within XML files."""
    def has_global_event_handler_attribute(tag):
        global_event_handlers = ["onabort", "onblur", "onchange", "onclick",
                                 "onclose", "oncontextmenu", "ondblclick",
                                 "onerror", "onfocus", "oninput", "onkeydown",
                                 "onkeypress", "onkeyup", "onload", "onmousedown",
                                 "onmousemove", "onmouseout", "onmouseover",
                                 "onmouseup", "onpointercancel", "onpointerdown",
                                 "onpointerenter", "onpointerleave",
                                 "onpointermove", "onpointerout", "onpointerover",
                                 "onpointerup", "onreset", "onresize", "onscroll",
                                 "onselect", "onselectstart", "onsubmit",
                                 "ontouchcancel", "ontouchmove", "ontouchstart"]
        for global_event_handler in global_event_handlers:
            if tag.has_attr(global_event_handler):
                return True
        return False

    for relative_filepath, full_filepath in app.get_filepaths_of_files(types=[".xml"]):
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        elements = soup.find_all(has_global_event_handler_attribute)
        if elements:
            elements_as_strings = ["{}".format(element)
                                   for element
                                   in elements]
            reporter_output = ("A global event handler was detected in use."
                               " Please check and make sure that this is a "
                               " valid  use for it."
                               " Elements: {}"
                               " File: {}.").format("".join(elements_as_strings),
                                                    relative_filepath)
            reporter.manual_check(reporter_output, relative_filepath)
