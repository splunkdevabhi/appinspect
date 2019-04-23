# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Custom search command structure and standards

Custom search commands are defined in a **commands.conf** file in the **/default** directory of the app. For more, see <a href="http://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutcustomsearchcommands" target="_blank">About writing custom search commands</a> and <a href="http://docs.splunk.com/Documentation/Splunk/latest/Admin/Commandsconf" target="_blank">commands.conf</a>.
"""

# Python Standard Library
import logging
import re
import os
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


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands', 'manual')
@splunk_appinspect.cert_version(min='1.1.7')
@splunk_appinspect.display(report_display_order=2)
def check_command_scripts_exist(app, reporter):
    """Check that custom search commands have an executable or script per
    stanza.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        file_path = os.path.join("default", "commands.conf")
        for command in custom_commands.get_commands():
            lineno = None
            with_path_suffix_pattern = ".*\.path$"
            if command.file_name_specified():
                lineno = command.args["filename"][1]
                file_name_base, file_name_ext = os.path.splitext(command.file_name)
            # script in bin does not exist or 
            # not match filename in commands.conf
            # (not including .path file here)
            if (command.file_name_specified() and 
                    file_name_ext in custom_commands.ALL_VALID_EXES and 
                        not re.match(with_path_suffix_pattern, command.file_name) and
                            not command.file_name_exe):
                reporter_message = ("No binary file `{}` was found."
                                    " File: {}, Line: {}."
                                    ).format(command.file_name,
                                             file_path,
                                             lineno)
                reporter.fail(reporter_message, file_path, lineno)
            # custom command is v1, only valid for .py and .pl script in default/bin
            elif (not command.is_v2() and 
                    command.count_v1_exes() <= 0):
                reporter_message = ("The stanza [{}] in commands.conf must use a .py or "
                                    ".pl script. File: {}, Line: {}."
                                    ).format(command.name,
                                             file_path,
                                             lineno)
                reporter.fail(reporter_message, file_path, lineno)
            # custom command is v2:
            # - file ends with .path
            elif (command.is_v2() and
                    command.file_name_specified() and
                        re.match(with_path_suffix_pattern, command.file_name)):
                reporter_message = ("The custom command is chunked and "
                                    "the stanza [{}] in commands.conf has field of "
                                    "`filename` with value ends with `.path`. "
                                    "Please manual check whether this path pointer files "
                                    "are inside of app container and use relative path. "
                                    "File: {}, Line: {}."
                                    ).format(command.name,
                                            file_path,
                                            lineno)
                reporter.manual_check(reporter_message, file_path, lineno)
            # custom command is v2:
            # - file per plat in default/bin
            # - file per arch
            elif (command.is_v2() and 
                    ((command.count_win_exes() <= 0 and 
                        command.count_linux_exes() <= 0) and 
                     (command.count_linux_arch_exes() <= 0 and
                        command.count_win_arch_exes() <= 0 and
                            command.count_darwin_arch_exes() <= 0))):
                reporter_message = ("Because the custom command is chunked, "
                                    "the stanza [{}] in commands.conf must use a .py, "
                                    ".pl, .cmd, .bat, .exe, .js, .sh or no extension "
                                    "script. File: {}, Line: {}."
                                    ).format(command.name,
                                            file_path,
                                            lineno)
                reporter.fail(reporter_message, file_path, lineno)
    else:
        reporter.not_applicable("No `commands.conf` file exists.")


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
        file_path = os.path.join("default", "commands.conf")
        for command in custom_commands.get_commands():
            if command.is_v2():
                # Warn that other args will be ignored
                for a in command.args:
                    if rex.search(a.lower()) is None:
                        lineno = command.args[a][1]
                        reporter_message = ("The field {} will be ignored because"
                                            " chunked is being used in the"
                                            " command : {}. File: {}, Line: {}."
                                            ).format(a,
                                                     command.name,
                                                     file_path,
                                                     lineno)
                        reporter.fail(reporter_message, file_path, lineno)
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
        file_path = os.path.join("default", "commands.conf")
        for command in custom_commands.get_commands():
            if not command.is_v2():
                # Warn that v2 args will be ignored
                for a in command.args:
                    if a == "maxwait" or a == "maxchunksize":
                        lineno = command.args[a][1]
                        reporter_message = ("The field {} will be ignored because"
                                            " chunked is not specified in the"
                                            " command : {}. File: {}, Line: {}."
                                            ).format(a,
                                                     command.name,
                                                     file_path,
                                                     lineno)
                        reporter.fail(reporter_message, file_path, lineno)
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
        file_path = os.path.join("default", "commands.conf")
        for command in custom_commands.get_commands():
            if not command.is_v2():
                if(command.passauth == "true" and
                        command.enableheader and
                        not command.enableheader == "true"):
                    lineno = command.args["enableheader"][1]
                    reporter_message = ("Because enableheader is not set to true,"
                                        " passauth will be ignored for"
                                        " {}. File: {}, Line: {}."
                                        ).format(command.name,
                                                 file_path,
                                                 lineno)
                    reporter.warn(reporter_message, file_path, lineno)


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands', 'custom_search_commands_v2')
@splunk_appinspect.cert_version(min='1.1.7')
def check_requires_srinfo_and_enableheader(app, reporter):
    """Check that custom search commands using `requires_srinfo` have
    `enableheader` set to true.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        file_path = os.path.join("default", "commands.conf")
        command_list = custom_commands.get_commands()

        for command in command_list:
            if not command.is_v2():
                if(command.requires_srinfo == "true" and
                        command.enableheader and
                        not command.enableheader == "true"):
                    lineno = command.args["enableheader"][1]
                    reporter_message = ("Because enableheader is not set to true,"
                                        " requires_srinfo will be ignored for"
                                        " {}. File: {}, Line: {}."
                                        ).format(command.name,
                                                 file_path,
                                                 lineno)
                    reporter.warn(reporter_message, file_path, lineno)


@splunk_appinspect.tags('splunk_appinspect', 'custom_search_commands', 'custom_search_commands_v2')
@splunk_appinspect.cert_version(min='1.1.7')
def check_requires_preop_and_streaming_preop(app, reporter):
    """ Check that custom search commands using `requires_preop` have
    `streaming_preop` set to true.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        file_path = os.path.join("default", "commands.conf")
        command_list = custom_commands.get_commands()

        for command in command_list:
            if not command.is_v2():
                if(command.requires_preop == "true" and
                        command.streaming_preop == ""):
                    lineno = command.args["requires_preop"][1]
                    reporter_message = ("Because requires_preop is not set to true,"
                                        " streaming_preop will be ignored for"
                                        " {}. File: {}, Line: {}."
                                        ).format(command.name,
                                                 file_path,
                                                 lineno)
                    reporter.warn(reporter_message, file_path, lineno)
