"""Command-line helpers in order to help with command-line presentation."""

# Python Standard Libraries
import collections
# Third-Party Libraries
import click
import painter

# Custom Libraries
import splunk_appinspect

result_colors = collections.defaultdict(dict, {
    "error": {
        "bg": "red",
        "fg": "white"
    },
    "failure": {
        "fg": "red",
        "bg": "black"
    },
    "manual_check": {
        "fg": "yellow"
    },
    "success": {
        "fg": "green"
    },
    "not_applicable": {
        "fg": "blue"
    },
    "warning": {
        "fg": "black",
        "bg": "yellow"
    }
})


glyphs = {
    'error': ' E ',
    'failure': ' F ',
    'manual_check': ' M ',
    'skipped': ' S ',
    'warning': ' W ',
    'success': ' P ',
    'not_applicable': 'N/A'
}


def output_summary(summary, summary_header=None):
    """Return None.

    Prints a summary of checks executed during a Splunk AppInspect run.

    :param summary (Dict) A dictionary of key representing the check result
        states possible and the values being the aggregate counts of results.
    :param summary_header (String) A string that can be the alternative header
        denoting the summary results.
    """
    (click.echo("Summary:\n")
        if summary_header is None
        else click.echo("{}:\n".format(summary_header)))

    total = 0
    for key, value in summary.iteritems():
        total = total + value
        click.echo(click.style("{:>14}: {:>2}".format(key, str(value)),
                               **result_colors[key]))
    click.echo("-" * 19)
    click.echo("{:>14}: {:>2}".format("Total", str(total)))


def print_result_records(application_validation_report,
                         max_messages=None,
                         result_types=None):
    """Return None.

    :param application_validation_report (ApplicationValidationReport) An
        application validation report that should have completed.
    :param max_messages the maximum number of messages to return for a single check
    :param result_types (List) A list of result types of what to print.
    """
    if result_types is None:
        result_types = splunk_appinspect.reporter.STATUS_TYPES
    if max_messages is None:
        max_messages = splunk_appinspect.main.MAX_MESSAGES_DEFAULT
    if max_messages == splunk_appinspect.main.MAX_MESSAGES_DEFAULT:
        click.echo ('A default value of {0} for max-messages will be used.'.format(str(max_messages)))

    for grouping in application_validation_report.groups():
        checks_with_errors = [(group, check, reporter)
                              for group, check, reporter
                              in grouping
                              if reporter.state() in result_types]
        if checks_with_errors:
            print_group_documentation = True
            for group, check, reporter in checks_with_errors:
                if print_group_documentation:
                    formatted_group_documentation = format_cli_string(group.doc(), left_padding=0)
                    click.echo(painter.paint.green(formatted_group_documentation))
                    print_group_documentation = False

                formatted_check_documentation = format_cli_string(check.doc(),
                                                                  left_padding=4)
                click.echo(formatted_check_documentation)
                for report_record in reporter.report_records(max_records=max_messages):
                    format = result_colors[report_record.result]
                    result_message = "        {}: {}".format(report_record.result.upper(),
                                                             format_cli_string(report_record.message,
                                                                               left_padding=12).lstrip())
                    click.secho(result_message, **format)


def format_cli_string(string_to_format, left_padding=4, column_wrap=80):
    """Return a string.

    Takes in a string and then formats it to support padding and column wrapping
    for prettier output.

    :param string_to_format (String) An unformatted string.
    :param left_padding (Int) The amount of left padding applied to each new
        line
    :param column_wrap (Int) The string length at which a newline is determined
    """
    allowed_line_length = column_wrap - left_padding
    new_string = ""
    new_string += (" " * left_padding)  # Gotta pad that first line
    split_strings = string_to_format.split()
    current_index = len(new_string)

    for split_string in split_strings:
        current_word_length = len(split_string)
        new_index = current_index + current_word_length + 1  # The plus 1 is for the space that is added at the end
        # The line is over the column wrap, add a new line and then the word
        if new_index > allowed_line_length:
            new_string += "\n" + (" " * left_padding)
            new_string += split_string
            new_index = current_word_length
        # Just add the word
        else:
            new_string += split_string

        new_string += " "
        current_index = new_index

    return new_string
