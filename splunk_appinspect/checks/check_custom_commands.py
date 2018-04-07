# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Custom search command structure and standards

[Custom search commands](https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutcustomsearchcommands)
are defined in a [default/commands.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Commandsconf).
"""

# Python Standard Library
import logging
import re

# Custom Modules
import splunk_appinspect

report_display_order = 20
logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands')
@splunk_appinspect.cert_version(min='1.1.7')
@splunk_appinspect.display(report_display_order=1)
def check_command_conf_exists(app, reporter):
    """Check that `commands.conf` exists at `default/commands.conf`."""
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        pass
    else:
        reporter_message = "No commands.conf exists."
        reporter.not_applicable(reporter_message)


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands')
@splunk_appinspect.cert_version(min='1.1.7')
@splunk_appinspect.display(report_display_order=2)
def check_default_meta_exists(app, reporter):
    """Check that a valid
    [default.meta](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Defaultmetaconf)
    file exists when using a custom search command.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        try:
            if app.get_config("default.meta", "metadata"):
                pass
        except IOError:
            reporter_message = ("No default.meta exists.")
            reporter.fail(reporter_message)


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands')
@splunk_appinspect.cert_version(min='1.1.7')
@splunk_appinspect.display(report_display_order=2)
def check_command_scripts_exist(app, reporter):
    """Check that custom search commands have an executable or script per 
    stanza.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        for command in custom_commands.get_commands():
            exe = command.executable_file()

            if(not exe.file_path.endswith(".py") and
                    not exe.file_path.endswith(".pl")):
                reporter_message = ("The stanza [{}] in commands.conf must use a .py or "
                                    ".pl script").format(command.name)
                reporter.fail(reporter_message)

            if exe.exists():
                pass
            else:
                reporter_message = ("No binary file was found."
                                    " File: {}").format(exe.file_path)
                reporter.fail(reporter_message)


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands', 'custom_search_commands_v2')
@splunk_appinspect.cert_version(min='1.1.7')
def check_ignored_parameters_v2_command(app, reporter):
    """Check for ignored arguments in `commands.conf` when `chunked=true`.
    [Commands.conf reference](https://docs.splunk.com/Documentation/Splunk/6.4.2/Admin/Commandsconf)
    """

    # TODO: When the version of Splunk being targeted is available check
    # chunked only on 6.3 and above.
    chunked_attributes_regex = "(filename)|(chunked)|(is_risky)|(maxchunksize)|(maxwait)|(command\.arg\.\d+)"
    rex = re.compile(chunked_attributes_regex)

    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        for command in custom_commands.get_commands():
            if command.is_v2():
                # Warn that other args will be ignored
                for a in command.args:
                    if rex.search(a.lower()) is None:
                        reporter_message = ("The field {} will be ignored as"
                                            " chunked is being used in the"
                                            " command : {}").format(a, command.name)
                        reporter.fail(reporter_message)
    else:
        reporter.not_applicable("No `commands.conf` file exists.")


# TODO: When the version of Splunk being targeted is available check
# chunked only on 6.3 and above.
@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands', 'custom_search_commands_v2')
@splunk_appinspect.cert_version(min='1.1.20')
def check_ignored_parameters_v1_command(app, reporter):
    """Check that the custom commands attributes `maxwait` and `maxchunksize`
    are only used when `chunked = true`.
    [Commands.conf reference](https://docs.splunk.com/Documentation/Splunk/6.4.2/Admin/Commandsconf)
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        for command in custom_commands.get_commands():
            if not command.is_v2():
                # Warn that v2 args will be ignored
                for a in command.args:
                    if a == "maxwait" or a == "maxchunksize":
                        reporter_message = ("The field {} will be ignored because"
                                            " chunked is not specified in the"
                                            " command : {}").format(a, command.name)
                        reporter.fail(reporter_message)
    else:
        reporter.not_applicable("No `commands.conf` file exists.")


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands', 'custom_search_commands_v2')
@splunk_appinspect.cert_version(min='1.1.7')
def check_passauth_and_enableheader(app, reporter):
    """Check that custom search commands using `passauth` have `enableheader`
    set to true.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        for command in custom_commands.get_commands():
            if not command.is_v2():
                if(command.passauth == "true" and
                        not command.enableheader == "true"):
                    reporter_message = ("enableheader is not set to true,"
                                        " passauth will be ignored for"
                                        " {}").format(command.name)
                    reporter.warn(reporter_message)


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands', 'custom_search_commands_v2')
@splunk_appinspect.cert_version(min='1.1.7')
def check_requires_srinfo_and_enableheader(app, reporter):
    """Check that custom search commands using `requires_srinfo` have 
    `enableheader` set to true.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        command_list = custom_commands.get_commands()

        for command in command_list:
            if not command.is_v2():
                if(command.requires_srinfo == "true" and
                        not command.enableheader == "true"):
                    reporter_message = ("enableheader is not set to true,"
                                        " requires_srinfo will be ignored for"
                                        " {}").format(command.name)
                    reporter.warn(reporter_message)


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands', 'custom_search_commands_v2')
@splunk_appinspect.cert_version(min='1.1.7')
def check_requires_preop_and_streaming_preop(app, reporter):
    """ Check that custom search commands using `requires_preop` have 
    `streaming_preop` set to true.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        command_list = custom_commands.get_commands()

        for command in command_list:
            if not command.is_v2():
                if(command.requires_preop == "true" and
                        command.streaming_preop == ""):
                    reporter_message = ("requires_preop is not set to true,"
                                        " streaming_preop will be ignored for"
                                        " {}").format(command.name)
                    reporter.warn(reporter_message)
