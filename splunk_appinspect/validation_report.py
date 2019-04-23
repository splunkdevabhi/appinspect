# Copyright 2018 Splunk Inc. All rights reserved.

# Python Standard Libraries
import collections
import copy
from datetime import datetime
import logging
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect


logger = logging.getLogger(__name__)


class ValidationReport(object):

    def __init__(self):
        self._application_validation_reports = []
        self._metrics = {
            "start_time": None,
            "end_time": None,
            "execution_time": None,
        }
        # can be `not_executed`, `in_progress`, `completed`, or `error`
        self.status = "not_executed"
        self.errors = []

    def add_application_validation_report(self, application_validation_report):
        self.application_validation_reports.append(application_validation_report)

    @property
    def application_validation_reports(self):
        return self._application_validation_reports

    @application_validation_reports.setter
    def application_validation_reports(self, value):
        self._application_validation_reports = value

    def get_summary(self):
        summary_dict = collections.defaultdict(int)

        for application_validation_report in self.application_validation_reports:
            for key, value in application_validation_report.get_summary().iteritems():
                summary_dict[key] += value

        return summary_dict

    @property
    def metrics(self):
        return self._metrics

    @metrics.setter
    def metrics(self, value):
        self._metrics = value

    def validation_start(self):
        """Return None.

        Helper function to be called at the start of a validation.
        """
        self.metrics["start_time"] = datetime.now()
        if self.status != "error":
            self.status = "in_progress"

    def validation_completed(self):
        # TODO: rename to validation_complete to align with start
        """Return None.

        Helper function to be called at the end of a validation.
        """
        self.metrics["end_time"] = datetime.now()
        self.metrics["execution_time"] = (self.metrics["end_time"] - self.metrics["start_time"]).total_seconds()
        if self.status != "error":
            self.status = "completed"

    def validation_error(self, exception):
        """Return None.

        Helper function to be called when an error is encountered during
        validation.
        """
        self.status = "error"
        self.errors.append(exception)

    @property
    def has_invalid_packages(self):
        """Returns boolean if packaging checks failed or error."""
        return any(rpt.has_invalid_package for rpt in self.application_validation_reports)


class ApplicationValidationReport(object):

    def __init__(self, application, run_parameters):
        self.run_parameters = copy.copy(run_parameters)

        self.app_author = application.author
        self.app_description = application.description
        self.app_version = application.version
        self.app_name = application.label
        self.app_hash = application._get_hash()

        self._results = None
        self._metrics = {
            "start_time": None,
            "end_time": None,
            "execution_time": None
        }

        # can be `not_executed`, `in_progress`, `completed`, or `error`
        self.status = "not_executed"
        self.errors = []

    def groups(self):
        """Returns a list of lists containing tuples of a Group object, a Check
        object, and a Reporter object. Each nested list is all the checks
        grouped together based on the group they belong to. This means that each
        check in a nested list should contain the same group object.
        [
            [(group, check, reporter), (group, check, reporter), ... ]
            [(group, check, reporter), (group, check, reporter), ... ]
        ]
        """
        grouped_results = collections.defaultdict(list)
        # Get the results, adding basic ordering
        for group, check, reporter in self.results:
            key = "{}-{}".format(group.report_display_order, group.name)
            grouped_results[key].append((group, check, reporter))

        # Return the groups in order of key
        return [group_with_key[1] for group_with_key in sorted(grouped_results.items(), key=lambda t: t[0])]

    @property
    def results(self):
        """Returns the list of results as that is really just a list of the
        checks.
        """
        return self._results

    @results.setter
    def results(self, new_results):
        self._results = new_results

    @property
    def metrics(self):
        return self._metrics

    @metrics.setter
    def metrics(self, value):
        self._metrics = value

    def get_total_test_count(self):
        """Returns a scalar value representing the total test count."""
        return sum(self.get_summary().itervalues)

    def checks(self):
        """Returns the list of results as that is really just a list of the
        checks.
        """
        return self.results()

    def get_group_results(self, group_name):
        """Returns an array containing tuples that match the group name
        specified. Should be an array with a length greater than 1 as groups can
        have multiple checks.

        :param group_name the group name to retrieve results by
        """
        return [(group, check, reporter)
                for group, check, reporter
                in self.results
                if group.name == group_name]

    def get_check_results(self, check_name):
        """Returns an array containing tuples that match the check name
        specified. Should be an array with a length of 1 as checks should not be
        duplicated.

        :param check_name the check name to be searched for in the results
        """
        return [(group, check, reporter)
                for group, check, reporter
                in self.results
                if check.name == check_name]

    def has_group(self, group_name):
        """Returns a boolean value indicating if the group_name exists in the
        results.

        :param group_name the group name to be searched for in the results
        """
        return self.get_group_results(group_name)

    @property
    def has_invalid_package(self):
        """Returns a boolean value indicating if the report includes failed
        packaging checks.
        """
        if self._results is None or len(self._results) == 0:
            return False

        fails = [(group, check, reporter)
                for group, check, reporter in self._results
                if check.matches_tags(["packaging_standards"], [""])
                and (reporter.state() == "failure" or reporter.state() == "error")]

        return len(fails) > 0

    def has_check(self, check_name):
        """Returns a boolean value indicating if the check_name exists in the
        results.

        :param check_name the group name to be searched for in the results
        """
        if self.get_check_results(check_name):
            return True
        return False

    def get_summary(self):
        """Returns a dictionary with the cumulative count of result states."""
        summary_dict = dict.fromkeys(splunk_appinspect.reporter.STATUS_TYPES, 0)

        for group, check, reporter in self.results:
            summary_dict[reporter.state()] += 1

        return summary_dict

    def validation_start(self):
        """Return None.

        Helper function to be called at the start of a validation.
        """
        self.metrics["start_time"] = datetime.now()
        if self.status != "error":
            self.status = "in_progress"

    def validation_completed(self):
        # TODO: rename to validation_complete to align with start
        """Return None.

        Helper function to be called at the end of a validation.
        """
        self.metrics["end_time"] = datetime.now()
        self.metrics["execution_time"] = (self.metrics["end_time"] - self.metrics["start_time"]).total_seconds()
        if self.status != "error":
            self.status = "completed"

    def validation_error(self, exception):
        """Return None.

        Helper function to be called when an error is encountered during
        validation.
        """
        self.status = "error"
        self.errors.append(exception)
