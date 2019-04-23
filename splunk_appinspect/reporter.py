# Copyright 2018 Splunk Inc. All rights reserved.

""" The Reporter class is intended to be used as a general interface to send
errors detected during validation to.

This is done in order to avoid raising errors for logging, and instead
provide a mechanism to store and retrieve report records such that a completed
validation check can be performed and provide detailed feedback for the errors
encountered.
"""

# Python Standard Library
import collections
from datetime import datetime
import inspect
import os.path
import traceback
import string
import logging
import re

logger = logging.getLogger(__name__)
# Used for storing the records, no ReportRecord class created because OO not
# needed
ReportRecord = collections.namedtuple('ReportRecord',
                                      ['result', 'message', 'filename', 'line', 'code', 'message_filename', 'message_line'])
MAX_MESSAGES_PER_CHECK = 25
STATUS_TYPES = ['error', 'failure', 'skipped',
                'manual_check', 'not_applicable', 'warning', 'success']
STATUS_PRIORITIES = {}

FILE_PATTERN = r'(F|f)ile:\s*[.0-9a-zA-Z\\/_-]*'
LINE_PATTERN = r'(L|l)ine\s*\w*:\s*\d*'

for idx, status in enumerate(STATUS_TYPES):
    STATUS_PRIORITIES[status] = idx

def _reduce_record_summary(acc, x):
    acc[x.result] = acc.get(x.result, 0) + 1
    return acc

def _extract_values(pattern, message):
    """Find the filename AND line depending on the pattern."""
    v1 = None
    v2 = None
    result = re.search(pattern, message)
    if result:
        group = result.group()
        v1, v2 = group.split(":", 1)
        if v1 and v2:
            v1 = v1.strip()
            v2 = v2.strip()
    return v1, v2

def extract_filename_lineno(message):
    filename = _extract_values(FILE_PATTERN, message)[1]
    lineno = _extract_values(LINE_PATTERN, message)[1]
    return filename, lineno

class Reporter(object):

    def __init__(self):
        self._report_records = []
        self.metrics = {
            "start_time": None,
            "end_time": None,
            "execution_time": None
        }

    def report_records(self,
                       max_records=MAX_MESSAGES_PER_CHECK,
                       status_types_to_return=STATUS_TYPES):
        """Returns a list of the report records that have been accumulated

        :param: max_records The number of records to return. To return all 
            records pass in sys.maxint
        :param: status_types_to_return a list of strings specifying the report 
            status types to return
        """
        all_records = sorted(self._report_records,
                             key=lambda x: STATUS_PRIORITIES[x.result])
        filtered_records = [report_record
                            for report_record
                            in all_records
                            if report_record.result in status_types_to_return]
        if len(filtered_records) > max_records:
            last_index = max_records - 1  # Last record is a summary of the remainder
            records = filtered_records[:last_index]
            remainder = filtered_records[last_index:]
            counts = reduce(_reduce_record_summary, remainder, dict())
            summaries = []
            for status, count in counts.iteritems():
                summaries.append("{} {} messages".format(count, status))
            text = ", ".join(summaries)

            # Used to respect to __save_result_message conventions
            current_frame = inspect.currentframe()
            _, file, line, _, code, _ = inspect.getouterframes(current_frame)[1]
            filepath, filename = os.path.split(file)
            records.append(ReportRecord("warning",
                                        "Suppressed " + text,
                                        filename,
                                        line,
                                        code[0].strip(), 
                                        None, 
                                        None))
            return records
        else:
            return filtered_records

    def __save_result_message(self, result, message, frame, file_name=None, line_number=None, frameoffset=1):
        # What is this black magic below????
        _, file, line, _, code, _ = inspect.getouterframes(frame)[frameoffset]
        (filepath, filename) = os.path.split(file)
        message_stripped_of_unprintables = ''.join(s
                                                   for s in message
                                                   if s in string.printable)
        report_record = ReportRecord(result,
                                     message_stripped_of_unprintables,
                                     filename,
                                     line,
                                     code[0].strip(),
                                     file_name,
                                     line_number)
        self._report_records.append(report_record)

    def __format_message(self, message, file_name=None, line_number=None):
        """Formats file and numbers in a consistent fashion"""
        if file_name is not None and line_number is None:
            reporter_output = "{} File: {}".format(message, file_name)
        elif file_name is not None and line_number is not None:
            reporter_output = "{} File: {} Line Number: {}".format(message, file_name, line_number)
        else:
            reporter_output = message
        return reporter_output

    def warn(self, message, file_name=None, line_number=None):
        """A warn will require that the app be inspected by a real human. Like a
        todo item
        """
        reporter_output = self.__format_message(message, file_name, line_number)
        self.__save_result_message('warning', reporter_output, inspect.currentframe(), file_name, line_number)

    def assert_warn(self, assertion, message, file_name=None, line_number=None):
        """If assertion is false, log a warning"""
        if not(assertion):
            self.warn(message, file_name, line_number)

    def manual_check(self, message, file_name=None, line_number=None):
        """Declare that this check requires a human to validate"""
        reporter_output = self.__format_message(message, file_name, line_number)
        self.__save_result_message('manual_check',
                                   reporter_output,
                                   inspect.currentframe(),
                                   file_name,
                                   line_number)

    def assert_manual_check(self, assertion, message, file_name=None, line_number=None):
        """If assertion is false, add to a human's todo list"""
        if not(assertion):
            self.manual_check(message, file_name, line_number)

    def not_applicable(self, message):
        """Report that this check does not apply to the current app"""
        self.__save_result_message('not_applicable',
                                   message,
                                   inspect.currentframe())
        logger.debug(message)

    def skip(self, message):
        """Report that this check was not run."""
        self.__save_result_message('skipped',
                                   message,
                                   inspect.currentframe())
        logger.debug(message)

    def assert_not_applicable(self, assertion, message):
        """If assertion is false, put this in a human's queue"""
        if not(assertion):
            self.not_applicable(message)

    def fail(self, message, file_name=None, line_number=None):
        """Failure is when a problem has been found that the app can't be
        accepted without fixing
        """
        reporter_output = self.__format_message(message, file_name, line_number)
        self.__save_result_message('failure', reporter_output, inspect.currentframe(), file_name, line_number)

    def assert_fail(self, assertion, message, file_name=None, line_number=None):
        """If assertion is false, log failure"""
        if not(assertion):
            self.fail(message, file_name, line_number)

    def exception(self, exception, category='error'):
        """Error is when there's something wrong with the check script. 
        Don't call this directly- just throw an exception
        """
        message = str(exception[1].message)
        stack_frame = traceback.extract_tb(exception[2])[0]
        line_number = None
        code_section = None
        filename = None

        if stack_frame:
            filename = stack_frame[0]
            line_number = stack_frame[1]
            code_section = stack_frame[3]

        report_record = ReportRecord(category,
                                     message,
                                     filename,
                                     line_number,
                                     code_section,
                                     None,
                                     None)
        self._report_records.append(report_record)

    def warnings(self):
        """Retrieve all advice report_records to return to submitter"""
        return [m for m in self._report_records if m.result == 'warning']

    def start(self):
        """Sets metrics to store when the check started."""
        self.metrics["start_time"] = datetime.now()

    def complete(self):
        """Sets metrics to store when the check completed."""
        if self.metrics["start_time"] is None:
            raise Exception("Start must be called prior to complete.")
        self.metrics["end_time"] = datetime.now()
        self.metrics["execution_time"] = (self.metrics["end_time"] - self.metrics["start_time"]).total_seconds()

    def state(self):
        """Return the overall state of the checks
        Checks can be (In order of severity):
        - error
        - failure
        - manual_check
        - not_applicable
        - warning
        - skipped
        - success  # default

        Note that the reporter starts in a success state, and if there is no
        interaction it will stay that way.
        """
        # Relates to ACD-1001
        counts = reduce(_reduce_record_summary, self._report_records, dict())
        for index in ['error', 'failure', 'manual_check', 'not_applicable', 'warning', 'skipped']:
            if counts.get(index) > 0:
                return index
        return 'success'
