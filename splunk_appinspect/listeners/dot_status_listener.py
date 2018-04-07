# Copyright 2016 Splunk Inc. All rights reserved.

# Python Standard Libraries
import logging
import sys
# Third-Party Libraries
import click
# Custom Libraries
import listener
import splunk_appinspect


logger = logging.getLogger(__name__)


class DotStatusListener(listener.Listener):

    def __init__(self, stream=sys.stdout, column_wrap=80, skip_manual=True, max_report_messages=splunk_appinspect.main.MAX_MESSAGES_DEFAULT):
        """
        :param stream The output to write to
        :param column_wrap the column wrap length
        :param skip_manual skip manual checks
        :param max_messages the maximum number of messages to return for a single check
        """
        self.idx = 0
        self.column_wrap = column_wrap
        self.stream = stream
        self.exit_status = 0
        self.skip_manual = skip_manual
        self.max_messages = max_report_messages

    def format_error(message, reporter):
        return reporter.message()

    def on_start_app(self, app):
        """Returns None

        :param app (App) The app object representing the Splunk Application.
        """
        command_line_output = ("Validating: {} Version: {}"
                               ).format(app.name,
                                        app.version)
        click.echo(command_line_output)

    def on_finish_check(self, check, reporter):
        """Returns None

        :param check (Check) The check object that was executed.
        :param reporter (Reporter) The reporter object that contains the results
            of the check that was executed.
        """
        self.idx += 1
        result = reporter.state()
        glyph = "."
        if (result == "failure"):
            glyph = "F"
            self.exit_status += 1
        elif (result == "error"):
            glyph = "E"
            self.exit_status += 1
        elif (result == "skipped"):
            glyph = "S"
        elif (result == "manual_check"):
            if self.skip_manual:
                return
            else:
                glyph = "M"
        self.stream.write(glyph)
        if (self.idx % self.column_wrap == 0):
            self.stream.write("\n")
        self.stream.flush()

    def on_finish_app(self, app, application_validation_report):
        """Returns None

        Prints  out the output of failed checks with respect to their group.

        :param app (App) The app object being validated
        :param application_validation_report (ApplicationValidationReport) The 
            application validation report that contains the results of the 
            validation.
        """
        result_types = ["error", "failure"]

        if not self.skip_manual:
            result_types.append("manual_check")

        click.echo("\n")
        splunk_appinspect.command_line_helpers.print_result_records(application_validation_report,
                                                                    max_messages=self.max_messages,
                                                                    result_types=result_types)
        click.echo("\n")
        summary_header = "{} Report Summary".format(app.name)
        splunk_appinspect.command_line_helpers.output_summary(application_validation_report.get_summary(),
                                                              summary_header=summary_header)
        click.echo("\n")
