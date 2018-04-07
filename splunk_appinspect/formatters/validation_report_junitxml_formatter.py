# Written by Aplura, LLC
# Released under GPLv2
# Python Standard Libraries
import json
# Third-Party Libraries
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
from xml.etree import ElementTree
from xml.dom import minidom
# Custom Libraries
import validation_report_formatter
import splunk_appinspect

class ValidationReportJUnitXMLFormatter(validation_report_formatter.ValidationReportFormatter):

    def __init__(self):
        super(ValidationReportJUnitXMLFormatter, self).__init__()

    def prettify(self, elem):
        """Return a pretty-printed XML string for the Element."""
        rough_string = ElementTree.tostring(elem, "utf-8")
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")

    def format_testsuite_element(self, application_validation_report,max_messages=None):
        summary = application_validation_report.get_summary()
        metrics = application_validation_report.metrics

        testsuite_element_attributes = {
            "name": "Splunk AppInspect",
            "failures": "{}".format(summary["failure"]),
            "manual_checks": "{}".format(summary["manual_check"]),
            "warnings": "{}".format(summary["warning"]),
            "errors": "{}".format(summary["error"]),
            "skipped": "{}".format(summary["not_applicable"] +
                                   summary["skipped"]),
            "tests": "{}".format(summary["skipped"] +
                                 summary["not_applicable"] +
                                 summary["success"] +
                                 summary["failure"] +
                                 summary["error"]),
            "time": "{}".format(metrics["execution_time"]),
            "timestamp": "{}".format(metrics["start_time"].isoformat())
        }
        testsuite_element = Element("testsuite", testsuite_element_attributes)
        testsuite_element.append(self.format_testsuite_properties(application_validation_report))

        for grouping in application_validation_report.groups():
            for group, check, reporter in grouping:
                testsuite_element.append(self.format_testcase_element(group,
                                                                      check,
                                                                      reporter,
                                                                      max_messages))
        return testsuite_element

    def format_testsuite_properties(self, application_validation_report):
        properties_element = Element("properties")

        app_name_property_attributes = {"name": "app_name",
                                        "value": application_validation_report.app_name}
        app_name_property_element = SubElement(properties_element,
                                               "property",
                                               app_name_property_attributes)

        included_tags_property_attributes = {"name": "included_tags",
                                             "value": ",".join(application_validation_report.run_parameters["included_tags"])}
        included_tags_property_element = SubElement(properties_element,
                                                    "property",
                                                    included_tags_property_attributes)

        excluded_tags_property_attributes = {"name": "excluded_tags",
                                             "value": ",".join(application_validation_report.run_parameters["excluded_tags"])}
        excluded_tags_property_element = SubElement(properties_element,
                                                    "property",
                                                    excluded_tags_property_attributes)

        return properties_element

    def format_testcase_element(self, group, check, reporter, max_messages=None):
        """Returns an XML element object representing the test case.

        :param group (Group) the result's group object
        :param check (Check) the result's check object
        :param reporter (Reporter) the result's reporter object
        format.
        """
        testcase_element_attributes = {"classname": group.name,
                                       "name": check.name,
                                       "time": "0"}
        testcase_element = Element("testcase",
                                   testcase_element_attributes)
        test_case_element_system_out = SubElement(testcase_element, 'system-out')
        test_case_element_system_out.text = self._sanitize(check.doc())
        result_element = self.format_testcase_result_element(group, check, reporter, max_messages)
        if result_element is not None:
            testcase_element.append(result_element)

        return testcase_element

    def format_testcase_result_element(self, group, check, reporter, max_messages=None):
        """Returns None if no failues detected. Otherwise it returns the
        respective result required by JUnit.

        :param group (Group) the result's group object
        :param check (Check) the result's check object
        :param reporter (Reporter) the result's reporter object
        format.
        """
        if max_messages is None:
            max_messages = splunk_appinspect.main.MAX_MESSAGES_DEFAULT

        # JUnit/Bamboo only use skipped/failure/success/errors as options so
        # they are combined below
        result = reporter.state()
        result_element_to_return = None
        result_combined_messages = {"files": [], "messages": []}
        if result == "skipped" or result == "not_applicable":
            result_element_to_return = Element("skipped")
        else:
            for report_record in reporter.report_records(max_records=max_messages):
                result_combined_messages["filename"] = report_record.filename
                result_combined_messages["messages"].append(report_record.message)
        if result == "failure":
            result_element_to_return = Element("failure",
                                               {"message": result_combined_messages["filename"]})
            result_element_to_return.text = self._sanitize(", ".join(result_combined_messages["messages"]))
        if result == "error":
            result_element_to_return = Element("error",
                                               {"message": result_combined_messages["filename"]})
            result_element_to_return.text = self._sanitize(", ".join(result_combined_messages["messages"]))
        if result == "manual_check":
            result_element_to_return = Element("manual_check",
                                               {"message": result_combined_messages["filename"]})
            result_element_to_return.text = self._sanitize(", ".join(result_combined_messages["messages"]))
        if result == "warning":
            result_element_to_return = Element("warning",
                                               {"message": result_combined_messages["filename"]})
            result_element_to_return.text = self._sanitize(", ".join(result_combined_messages["messages"]))

        return result_element_to_return

    def format_application_validation_report(self, application_validation_report,max_messages=None):
        """Returns JUnitXML testsuite element."""
        if max_messages is None:
            max_messages = splunk_appinspect.main.MAX_MESSAGES_DEFAULT
        return self.format_testsuite_element(application_validation_report, max_messages)

    def format_application_validation_reports(self, validation_report, max_messages=None):
        """Returns JUnitXML top-level testsuites element."""
        root_element = Element("testsuites")
        for application_validation_report in validation_report.application_validation_reports:
            root_element.append(self.format_application_validation_report(application_validation_report,max_messages))

        return root_element

    def _sanitize(self, string):
        return string.decode('utf-8', 'ignore').encode('utf-8').replace('\x0C', '')

    def format(self, validation_report, max_messages=None):
        root_element = self.format_application_validation_reports(validation_report, max_messages)
        return self.prettify(root_element)
