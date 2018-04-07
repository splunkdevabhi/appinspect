#!/usr/bin/env python

# Copyright 2016 Splunk Inc. All rights reserved.

"""The main splunk-appinspect command line entry point."""

# Python Standard Libraries
import collections
import itertools
import logging
import sys
# Third-Party Libraries
import click
import painter
# Custom Libraries
import splunk_appinspect

# Commands
DOCUMENTATION_COMMAND = "documentation"
INSPECT_COMMAND = "inspect"
LIST_COMMAND = "list"

# `documentation` Command arguments
DOCUMENTATION_TYPE_ARGUMENT = "documentation-types"
CRITERIA_DOCUMENTATION_TYPE = "criteria"
TAG_REFERENCE_DOCUMENTATION_TYPE = "tag-reference"

# `list` Command arguments and details
LIST_TYPE_ARGUMENT = "list-type"
CHECKS_LIST_TYPE = "checks"
GROUPS_LIST_TYPE = "groups"
TAGS_LIST_TYPE = "tags"
VERSION_LIST_TYPE = "version"

# `inspect` Arguments
APP_PACKAGE_ARGUMENT = "app-package"

# Shared options and option details
INCLUDED_TAGS_OPTION = "--included-tags"
INCLUDED_TAGS_OPTION_HELP_OUTPUT = ("This allows the ability to select checks"
                                    " to INCLUDE based on functionality. Use"
                                    " `splunk-appinspect {} {}` to view"
                                    " all available tags. To include multiple"
                                    " tags use `{} <tag1> {} <tag2>`..."
                                    ).format(LIST_COMMAND,
                                             TAGS_LIST_TYPE,
                                             INCLUDED_TAGS_OPTION,
                                             INCLUDED_TAGS_OPTION)

EXCLUDED_TAGS_OPTION = "--excluded-tags"
EXCLUDED_TAGS_OPTION_HELP_OUTPUT = ("This allows the ability to select checks"
                                    " to EXCLUDE based on functionality. Use"
                                    " `splunk-appinspect {} {}` to view"
                                    " all available tags. To include multiple"
                                    " tags use `{} <tag1> {} <tag2>`..."
                                    ).format(LIST_COMMAND,
                                             TAGS_LIST_TYPE,
                                             EXCLUDED_TAGS_OPTION,
                                             EXCLUDED_TAGS_OPTION)

CUSTOM_CHECKS_DIR_OPTION = "--custom-checks-dir"
CUSTOM_CHECKS_OPTION_HELP_OUTPUT = ("This allows the ability to specify a custom"
                                    " directory that contains additional custom"
                                    " checks, that are not a part of Splunk"
                                    " AppInspect.")

# `inspect` Options and option details
MODE_OPTION = "--mode"
TEST_MODE = "test"
PRECERT_MODE = "precert"
MODE_OPTION_HELP_OUTPUT = ("This allows the ability to specify different"
                           " run-time output when performing an inspect"
                           " validation."
                           "\n`{}` - Returns muted output, providing more"
                           " information relevant to unit testing. `.`"
                           " represents success, and `F` represents failure."
                           " Manual results are ignored by default. To enable"
                           " manual results in this mode use the"
                           " `--included-tags manual` option."
                           "\n`{}` - Returns verbose output providing"
                           " more information relevant to Splunk"
                           " Certification. [default: `{}`]").format(TEST_MODE,
                                                                     PRECERT_MODE,
                                                                     TEST_MODE)

OUTPUT_FILE_OPTION = "--output-file"
OUTPUT_FILE_OPTION_HELP_OUTPUT = ("This allows the ability to output the"
                                  " results of Splunk AppInspect to the"
                                  " specified file path.")

DATA_FORMAT_OPTION = "--data-format"
JSON_DATA_FORMAT = "json"
JUNIT_XML_DATA_FORMAT = "junitxml"
DATA_FORMAT_OPTION_HELP_OUTPUT = ("This allows the ability to specify the data"
                                  " format of the Splunk AppInspect output."
                                  " [default: `{}`]").format(JSON_DATA_FORMAT)

LOG_LEVEL_OPTION = "--log-level"
NOTSET_LOG_LEVEL = logging.getLevelName(logging.NOTSET)  # "NOTSET"
DEBUG_LOG_LEVEL = logging.getLevelName(logging.DEBUG)  # "DEBUG"
INFO_LOG_LEVEL = logging.getLevelName(logging.INFO)  # "INFO"
WARNING_LOG_LEVEL = logging.getLevelName(logging.WARNING)  # "WARNING"
ERROR_LOG_LEVEL = logging.getLevelName(logging.ERROR)  # "ERROR"
CRITICAL_LOG_LEVEL = logging.getLevelName(logging.CRITICAL)  # "CRITICAL"
LOG_LEVEL_OPTION_HELP_OUTPUT = ("This allows the ability to specify the log"
                                " level for Python's logging library."
                                " [default: `{}`]").format(CRITICAL_LOG_LEVEL)

LOG_FILE_OPTION = "--log-file"
LOG_FILE_OPTION_HELP_OUTPUT = ("This allows the ability to specify a custom log"
                               " file for Python's logging library.")

MAX_MESSAGES_OPTION = "--max-messages"
MAX_MESSAGES_DEFAULT = 25
MAX_MESSAGES_OPTION_HELP_OUTPUT = ("This allows the ability to configure AppInspect to return as much or as little"
                                   " information as desired."
                                   " [default: `{}`]").format(MAX_MESSAGES_DEFAULT)

# Valid values for arguments and options
VALID_VALUES = {
    DOCUMENTATION_TYPE_ARGUMENT: [
        CRITERIA_DOCUMENTATION_TYPE,
        TAG_REFERENCE_DOCUMENTATION_TYPE
    ],
    LIST_TYPE_ARGUMENT: [
        CHECKS_LIST_TYPE,
        GROUPS_LIST_TYPE,
        TAGS_LIST_TYPE,
        VERSION_LIST_TYPE
    ],
    MODE_OPTION: [
        TEST_MODE,
        PRECERT_MODE
    ],
    DATA_FORMAT_OPTION: [
        JSON_DATA_FORMAT,
        JUNIT_XML_DATA_FORMAT
    ],
    LOG_LEVEL_OPTION: [
        NOTSET_LOG_LEVEL,
        DEBUG_LOG_LEVEL,
        INFO_LOG_LEVEL,
        WARNING_LOG_LEVEL,
        ERROR_LOG_LEVEL,
        CRITICAL_LOG_LEVEL
    ],
}

# Meta Vars
STRING_META_VAR = "<STRING>"
MAX_MESSAGES_METAVAR = "<INT or `all`>"


# A custom type for validation as per https://github.com/pallets/click/blob/master/docs/parameters.rst
class MaxMessagesParamType(click.ParamType):
    name = 'maxmessages'

    def convert(self, value, param, ctx):
        try:
            if value == 'all':
                return sys.maxint
            elif int(value) > 0:
                return int(value)
            else:
                self.fail('"{}" is not a valid value for max-messages. Only positive integers or "all" are valid for this parameter.'.format(value), param, ctx)
        except ValueError:
            self.fail('"{}" is not a valid value for max-messages. Only positive integers or "all" are valid for this parameter.'.format(value), param, ctx)


@click.group()
def documentation_cli():
    """This is the command line utility used to generate Splunk AppInspect's
    release documentation.
    """
    pass


@click.group()
def report_cli():
    """This is the command line utility used to manage the interface commands
    to list information about Splunk AppInspect.
    """
    pass


@click.group()
def validation_cli():
    """This is the command line utility to support the usage of Splunk
    AppInspect to validate Splunk Apps.
    """
    pass


@documentation_cli.command("documentation", short_help="Generate the documentation of Splunk AppInspect")
@click.argument(DOCUMENTATION_TYPE_ARGUMENT, nargs=-1, required=True)
@click.option(INCLUDED_TAGS_OPTION, default=None, multiple=True, metavar=STRING_META_VAR, help=INCLUDED_TAGS_OPTION_HELP_OUTPUT)
@click.option(EXCLUDED_TAGS_OPTION, default=None, multiple=True, metavar=STRING_META_VAR, help=EXCLUDED_TAGS_OPTION_HELP_OUTPUT)
@click.option(CUSTOM_CHECKS_DIR_OPTION, default=None, metavar=STRING_META_VAR, help=CUSTOM_CHECKS_OPTION_HELP_OUTPUT)
@click.option(OUTPUT_FILE_OPTION, type=click.Path(file_okay=True, writable=True), metavar=STRING_META_VAR, help=OUTPUT_FILE_OPTION_HELP_OUTPUT)
def documentation(documentation_types, included_tags, excluded_tags, custom_checks_dir, output_file):
    """Creates the release documentation check-list."""

    # Guarantees a fresh file every time, otherwise the appending below borks it
    if output_file is not None:
        with open(output_file, 'w') as file:
            pass

    if CRITERIA_DOCUMENTATION_TYPE in documentation_types:
        html_markup_criteria = splunk_appinspect.documentation.criteria_generator.generate_critera_as_html(included_tags,
                                                                                                           excluded_tags,
                                                                                                           custom_checks_dir)
        # TODO: Do we want this to also support json?
        # Print to standard stream if no output file provided
        if output_file is None:
            click.echo("{} HTML CRITERIA CONTENT {}".format("=" * 20, "=" * 20))
            click.echo(html_markup_criteria)
        # Print to file
        else:
            with open(output_file, 'a') as file:
                file.write("\n<!--                      -->\n")
                file.write("<!-- HTML CRITERA CONTENT -->\n")
                file.write("<!--                      -->\n")
                file.write(html_markup_criteria)

    if TAG_REFERENCE_DOCUMENTATION_TYPE in documentation_types:
        html_markup_tag_reference = splunk_appinspect.documentation.tag_reference_generator.generate_tag_reference_as_html(custom_checks_dir)

        # TODO: Do we want this to also support json?
        # Print to standard stream if no output file provided
        if output_file is None:
            click.echo("{} HTML TAG REFERENCE {}".format("=" * 20, "=" * 20))
            click.echo(html_markup_tag_reference)
        # Print to file
        else:
            with open(output_file, 'a') as file:
                file.write("\n<!--                      -->\n")
                file.write("<!-- HTML TAG REFERENCE CONTENT -->\n")
                file.write("<!--                      -->\n")
                file.write(html_markup_tag_reference)

    # This is just the error catching logic to call out invalid tags provided
    all_tags_provided_by_the_user = included_tags + excluded_tags
    invalid_tags_found = []
    groups = splunk_appinspect.checks.groups()

    all_valid_tags = []
    for group in groups:
        for tag in group.tags():
            all_valid_tags.append(tag)
    unique_valid_tags = set(all_valid_tags)

    for tag_provided_by_the_user in all_tags_provided_by_the_user:
        if tag_provided_by_the_user not in unique_valid_tags:
            invalid_tags_found.append(tag_provided_by_the_user)

    for invalid_tag_found in invalid_tags_found:
        unexpected_tag_output = ("Unexpected tag provided: {}"
                                 ).format(invalid_tag_found)
        click_formatted_output = click.style("{}".format(unexpected_tag_output),
                                             **splunk_appinspect.command_line_helpers.result_colors["error"])
        click.echo(click_formatted_output)

    # This error catching has to be done because the documentation-type is an
    # nargs option and there is no validation on what is passed in
    unexpected_documentation_types = [documentation_type
                                      for documentation_type in documentation_types
                                      if documentation_type not in VALID_VALUES[DOCUMENTATION_TYPE_ARGUMENT]]
    for unexpected_documentation_type in unexpected_documentation_types:
        unexpected_documentation_type_output = ("Unexpected documentation-type detected: {}"
                                                ).format(unexpected_documentation_type)
        click.echo(click.style("{}".format(unexpected_documentation_type_output),
                               **splunk_appinspect.command_line_helpers.result_colors["error"]))


@report_cli.command(LIST_COMMAND, short_help="List information about Splunk AppInspect")
@click.argument(LIST_TYPE_ARGUMENT, nargs=-1, required=True)
@click.option(INCLUDED_TAGS_OPTION, default=None, multiple=True, metavar=STRING_META_VAR,
              help=INCLUDED_TAGS_OPTION_HELP_OUTPUT)
@click.option(EXCLUDED_TAGS_OPTION, default=None, multiple=True, metavar=STRING_META_VAR,
              help=EXCLUDED_TAGS_OPTION_HELP_OUTPUT)
@click.option(CUSTOM_CHECKS_DIR_OPTION, default=None, metavar=STRING_META_VAR, help=CUSTOM_CHECKS_OPTION_HELP_OUTPUT)
def report(list_type, included_tags, excluded_tags, custom_checks_dir):
    """
    List is used to generate information about Splunk AppInspect.

    \b
    LIST_TYPE can be the combination of any of the following strings:
    [checks | groups | tags | version]
    """

    def create_header(header_title, header_column_length=80):
        horizontal_line_rule = "=" * header_column_length
        return "\n{}\n{}\n{}".format(horizontal_line_rule,
                                     header_title,
                                     horizontal_line_rule)

    def print_group_checks(group):
        for check in group.checks():
            check_name_output = ("{}- {} {}").format(" " * 4,
                                                     painter.paint.cyan("Name:"),
                                                     check.name)
            check_documentation_output = ("{}- {} {}").format(" " * 8,
                                                              painter.paint.cyan("Description:"),
                                                              splunk_appinspect.command_line_helpers.format_cli_string(
                                                                  check.doc(),
                                                                  left_padding=20).lstrip())
            check_version_output = ("{}- {} {}").format(" " * 8,
                                                        painter.paint.cyan("Version:"),
                                                        check.version_doc())
            check_tag_output = ("{}- {} {}").format(" " * 8,
                                                    painter.paint.cyan("Tags:"),
                                                    ", ".join(check.tags))
            click.echo(check_name_output)
            click.echo(check_documentation_output)
            click.echo(check_version_output)
            click.echo(check_tag_output)
            click.echo("\n")

    def print_groups(groups_iterator, list_type, included_tags=[], excluded_tags=[], custom_checks_dir=None):
        if not list(groups_iterator):
            return
        for group in groups_iterator:
            if GROUPS_LIST_TYPE in list_type:
                group_name_output = ("{}").format(painter.paint.green(group.name))
                group_doc_output = ("{}").format(painter.paint.yellow(group.doc()))
                group_header_output = "{} ({})".format(group_doc_output,
                                                       group_name_output)
                click.echo(group_header_output)

            if CHECKS_LIST_TYPE in list_type:
                print_group_checks(group)

    standard_groups_iterator = splunk_appinspect.checks.groups(included_tags=included_tags,
                                                               excluded_tags=excluded_tags)
    custom_groups_iterator = splunk_appinspect.checks.groups(check_dirs=[],
                                                             custom_checks_dir=custom_checks_dir,
                                                             included_tags=included_tags,
                                                             excluded_tags=excluded_tags)
    # Print Version Here:
    if VERSION_LIST_TYPE in list_type:
        click.echo("Splunk AppInspect Version {}".format(splunk_appinspect.version.__version__))

    # Print Standard Checks here
    if CHECKS_LIST_TYPE in list_type:
        click.echo(create_header("Standard Certification Checks"))
    elif GROUPS_LIST_TYPE in list_type:
        click.echo(create_header("All Groups"))

    print_groups(standard_groups_iterator, list_type, included_tags, excluded_tags)

    # Print Custom Checks here
    if (CHECKS_LIST_TYPE in list_type) and (custom_checks_dir is not None):
        click.echo(create_header("Custom Checks"))
    print_groups(custom_groups_iterator, list_type)

    # Print Group Metrics Here
    if GROUPS_LIST_TYPE in list_type:
        click.echo(create_header("Group Metrics"))
        standard_group_count = len(list(standard_groups_iterator))
        custom_group_count = len(list(custom_groups_iterator))
        click.echo("Standard Groups Count: {:>2}".format(standard_group_count))
        click.echo("Custom Groups Count:   {:>2}".format(custom_group_count))
        click.echo("Total Groups Count:    {:>2}".format(standard_group_count + custom_group_count))
    # Print Check Metrics Here
    if CHECKS_LIST_TYPE in list_type:
        click.echo(create_header("Check Metrics"))
        standard_checks = [check
                           for group in standard_groups_iterator
                           for check in group.checks()]
        custom_checks = [check
                         for group in custom_groups_iterator
                         for check in group.checks()]
        standard_check_count = len(standard_checks)
        custom_check_count = len(custom_checks)
        click.echo("Standard Checks Count: {}".format(standard_check_count))
        click.echo("Custom Checks Count:   {}".format(custom_check_count))
        click.echo("Total Checks Count:    {}".format(standard_check_count + custom_check_count))

    # Print Tags here
    if TAGS_LIST_TYPE in list_type:
        click.echo(create_header("All Tags"))
        all_tags = collections.defaultdict(int)
        # TODO: This nesting should be fixed, #CyclomaticComplexity
        for group in splunk_appinspect.checks.groups(custom_checks_dir=custom_checks_dir):
            for check in group.checks():
                for tag in check.tags:
                    all_tags[tag] += 1

        # Used to sort tags because the counting dictionaries cannot be sorted, maybe look into OrderedDict?
        sorted_tags = sorted(all_tags)
        # Uses the longest tag name to determine padding length
        padding_length = max(itertools.imap(len, sorted_tags))
        for tag in sorted_tags:
            tag_output_format = "{:<" + str(padding_length) + "}\t{}"
            tag_output = tag_output_format.format(tag, all_tags[tag])
            click.echo(tag_output)
        click.echo("\n")

    # This error catching has to be done because the list-type is a nargs
    # option and there is no validation on what is passed in
    unexpected_list_types = [l_type
                             for l_type in list_type
                             if l_type not in VALID_VALUES[LIST_TYPE_ARGUMENT]]
    for unexpected_list_type in unexpected_list_types:
        unexpected_list_type_output = ("Unexpected list-type detected: {}"
                                       ).format(unexpected_list_type)
        click.echo(click.style("{}".format(unexpected_list_type_output),
                               **splunk_appinspect.command_line_helpers.result_colors["error"]))


@validation_cli.command(INSPECT_COMMAND, short_help="Inspect a Splunk Application")
@click.argument(APP_PACKAGE_ARGUMENT, type=click.Path(exists=True), required=True)
@click.option(MODE_OPTION, type=click.Choice(VALID_VALUES[MODE_OPTION]), default=TEST_MODE,
              help=MODE_OPTION_HELP_OUTPUT)
@click.option(INCLUDED_TAGS_OPTION, default=None, multiple=True, metavar=STRING_META_VAR,
              help=INCLUDED_TAGS_OPTION_HELP_OUTPUT)
@click.option(EXCLUDED_TAGS_OPTION, default=None, multiple=True, metavar=STRING_META_VAR,
              help=EXCLUDED_TAGS_OPTION_HELP_OUTPUT)
@click.option(OUTPUT_FILE_OPTION, type=click.Path(file_okay=True, writable=True), metavar=STRING_META_VAR,
              help=OUTPUT_FILE_OPTION_HELP_OUTPUT)
@click.option(DATA_FORMAT_OPTION, type=click.Choice(VALID_VALUES[DATA_FORMAT_OPTION]), default=JSON_DATA_FORMAT,
              help=DATA_FORMAT_OPTION_HELP_OUTPUT)
@click.option(CUSTOM_CHECKS_DIR_OPTION, default=None, metavar=STRING_META_VAR, help=CUSTOM_CHECKS_OPTION_HELP_OUTPUT)
@click.option(LOG_LEVEL_OPTION, type=click.Choice(VALID_VALUES[LOG_LEVEL_OPTION]), default=CRITICAL_LOG_LEVEL,
              help=LOG_LEVEL_OPTION_HELP_OUTPUT)
@click.option(LOG_FILE_OPTION, default=None, metavar=STRING_META_VAR, help=LOG_FILE_OPTION_HELP_OUTPUT)
@click.option(MAX_MESSAGES_OPTION, default=MAX_MESSAGES_DEFAULT, metavar=MAX_MESSAGES_METAVAR,
              help=MAX_MESSAGES_OPTION_HELP_OUTPUT, type=MaxMessagesParamType())
def validate(app_package,
             mode,
             included_tags,
             excluded_tags,
             output_file,
             data_format,
             custom_checks_dir,
             log_level,
             log_file,
             max_messages
             ):
    """
    Inspect is used to validate a Splunk application.

    APP PACKAGE is the path to the Splunk Application that is to be validated.
        This can be a .tar.gz, .tgz, or .spl file. This file can also contain
        one nested level of Splunk Apps inside it, in order to validate
        multiple Splunk Apps at once.
    """

    # The root logger is configured so any other loggers inherit the settings
    root_logger = logging.getLogger()
    configure_logger(root_logger, log_level, log_file)

    check_dirs = [splunk_appinspect.checks.DEFAULT_CHECKS_DIR]

    try:
        app_package_handler = splunk_appinspect.app_package_handler.AppPackageHandler(app_package)
    except Exception:
        root_logger.critical("An unexpected error occurred during extracting app package", exc_info=1)
        exit(3)  # invalid package

    # Mode configuration
    if mode == TEST_MODE:
        # Manual checks executed only if user explicitly includes tag
        skip_manual = "manual" not in included_tags

        listener = splunk_appinspect.listeners.DotStatusListener(skip_manual=skip_manual,
                                                                 max_report_messages=max_messages)
    elif mode == PRECERT_MODE:
        listener = splunk_appinspect.listeners.CertStatusListener(max_report_messages=max_messages)

    FORMATTERS = {
        JSON_DATA_FORMAT: splunk_appinspect.formatters.ValidationReportJSONFormatter,
        JUNIT_XML_DATA_FORMAT: splunk_appinspect.formatters.ValidationReportJUnitXMLFormatter,
    }
    formatter = FORMATTERS[data_format]()

    package_validation_failed = False
    validation_report_has_errors = False
    validation_report_summary_has_errors = False
    try:
        # Check Generation for validation
        groups_to_validate = splunk_appinspect.checks.groups(check_dirs=check_dirs,
                                                             custom_checks_dir=custom_checks_dir,
                                                             included_tags=included_tags,
                                                             excluded_tags=excluded_tags)

        validation_runtime_arguments = {"included_tags": included_tags,
                                        "excluded_tags": excluded_tags}

        # A list of application summaries that have been returned
        root_logger.info(("Beginning execution of Splunk AppInspect version: {}"
                          ).format(splunk_appinspect.version.__version__))
        validation_report = splunk_appinspect.validator.validate_packages(app_package_handler,
                                                                          args=validation_runtime_arguments,
                                                                          groups_to_validate=groups_to_validate,
                                                                          listeners=[listener])

        # Print a total summary if more than one app exists
        validation_report_summary = validation_report.get_summary()
        if len(validation_report.application_validation_reports) > 1:
            click.echo("=" * 80)
            click.echo("\n")
            splunk_appinspect.command_line_helpers.output_summary(validation_report_summary,
                                                                  summary_header="Total Report Summary")

        if output_file is not None:
            with open(output_file, 'w') as file:
                file.write(formatter.format(validation_report, max_messages))

        # Exit code generation
        package_validation_failed = validation_report.has_invalid_packages
        validation_report_has_errors = (len(validation_report.errors) > 0)
        validation_report_summary_has_errors = ("error" in validation_report_summary and
                                                validation_report_summary["error"] > 0)

    except Exception:
        root_logger.critical("An unexpected error occurred during the run-time of Splunk AppInspect", exc_info=1)
    finally:
        app_package_handler.cleanup()

    # Exit code precedence: invalid package (cant' start) exit code 3 >
    # invalid validation run-time exit code 2 > invalid checks exit code 1
    if package_validation_failed:
        exit_code = 3
    elif validation_report_has_errors:
        exit_code = 2
    elif validation_report_summary_has_errors:
        exit_code = 1
    else:
        exit_code = 0

    exit(exit_code)


def configure_logger(logger, log_level, log_file):
    """Intended to be used for the configuring the root logger of Python's
    logging library.
    """
    logging_message_format = ("LEVEL=\"%(levelname)s\""
                              " TIME=\"%(asctime)s\""
                              " NAME=\"%(name)s\""
                              " FILENAME=\"%(filename)s\""
                              " MODULE=\"%(module)s\""
                              " MESSAGE=\"%(message)s\"")
    handler_formatter = logging.Formatter(fmt=logging_message_format,
                                          datefmt=None)

    logging_handler = None
    if log_file is not None:
        logging_handler = logging.FileHandler(log_file,
                                              mode="ab+",
                                              encoding="ascii",
                                              delay=False)
    else:
        # Default to STDOUT
        logging_handler = logging.StreamHandler(stream=None)
    logging_handler.setFormatter(handler_formatter)

    logger.handlers = []
    logger.addHandler(logging_handler)
    logger.setLevel(log_level)


def execute():
    """An execution wrapper function."""
    command_line_interface = click.CommandCollection(sources=[documentation_cli,
                                                              report_cli,
                                                              validation_cli])
    command_line_interface()
    logging.shutdown()  # Used to clean up the logging bits on finish


if __name__ == "__main__":
    execute()
