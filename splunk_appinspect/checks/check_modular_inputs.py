# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Modular inputs structure and standards

[Modular Inputs](https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsIntro)
 are configured via an
[inputs.conf.spec](https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsSpec)
 file located at `README/inputs.conf.spec`.
[How to create a Modular Input](https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsBasicExample#Basic_implementation_requirements)
"""

# Python Standard Library
import logging
# Custom Modules
import splunk_appinspect


report_display_order = 12

logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
@splunk_appinspect.display(report_display_order=1)
def check_inputs_conf(app, reporter):
    """Check that a valid `inputs.conf.spec` file are located in the `README/`
    directory.
    """
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        pass
    else:
        reporter_output = ("No `{}` file exists.").format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
@splunk_appinspect.display(report_display_order=2)
def check_inputs_conf_spec_has_stanzas(app, reporter):
    """Check that README/inputs.conf.spec contains stanzas."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():

        inputs_specification_file = modular_inputs.get_specification_file()
        inputs_specification_file_stanzas_count = len(list(inputs_specification_file.sections()))
        if inputs_specification_file_stanzas_count == 0:
            reporter_output = ("The inputs.conf.spec {} does not specify any "
                               "stanzas."
                               ).format(modular_inputs.get_specification_app_filepath)
            reporter.fail(reporter_output)
        else:
            pass  # Success - stanzas were found
    else:
        reporter_output = ("No `{}` file exists.").format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_inputs_conf_spec_stanzas_have_properties(app, reporter):
    """Check that modular inputs specify arguments."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        if modular_inputs.has_modular_inputs():
            for modular_input in modular_inputs.get_modular_inputs():
                if not modular_input.args_exist():
                    reporter_output = ("The stanza [{}] does not include any args."
                                       ).format(modular_input.name)
                    reporter.fail(reporter_output)
                else:
                    pass  # SUCCESS - The modular input has arguments
        else:
            reporter_output = "No modular inputs were detected."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = ("No `{}` file exists.").format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_inputs_conf_spec_has_no_duplicate_stanzas(app, reporter):
    """Check that modular inputs do not have duplicate stanzas."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        inputs_specification_file = modular_inputs.get_specification_file()

        for error, line_number, section, in inputs_specification_file.errors:
            if error.startswith("Duplicate stanza"):
                reporter_output = ("{}"
                                   " File: `{}`"
                                   " Stanza: {}"
                                   " Line Number: {}").format(error,
                                                              modular_inputs.specification_filename,
                                                              section,
                                                              line_number)
                reporter.warn(reporter_output)
    else:
        reporter_output = ("No `{}` was detected."
                           ).format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_inputs_conf_spec_has_no_duplicate_properties(app, reporter):
    """Check that modular input stanzas do not contain duplicate arguments."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        inputs_specification_file = modular_inputs.get_specification_file()

        for error, line_number, section, in inputs_specification_file.errors:
            if error.startswith("Repeat item name"):
                reporter_output = ("{}"
                                   " File: `{}`"
                                   " Stanza: {}"
                                   " Line Number: {}").format(error,
                                                              modular_inputs.specification_filename,
                                                              section,
                                                              line_number)
                reporter.warn(reporter_output)
    else:
        reporter_output = ("No `{}` was detected."
                           ).format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_inputs_conf_spec_stanza_args_broken_correctly(app, reporter):
    """Check lines breaks are included in configuration when using a modular
    input.
    """

    modular_inputs = app.get_modular_inputs()

    if modular_inputs.has_specification_file():
        raw_specification_file = modular_inputs.get_raw_specification_file()

        # From https://github.com/splunk/splunk-app-validator
        if len(raw_specification_file.split('\n')) > 1:
            pass
        else:
            reporter_output = "The inputs.conf.spec has incorrect line breaks."
            reporter.fail(reporter_output)
    else:
        reporter_output = ("No `{}` was detected."
                           ).format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_modular_inputs_scripts_exist(app, reporter):
    """Check that there is a script file in `bin/` for each modular input
    defined in `README/inputs.conf.spec`.
    """

    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        if modular_inputs.has_modular_inputs():
            for mi in modular_inputs.get_modular_inputs():

                # a) is there a cross plat file (.py) in default/bin?
                if mi.count_cross_plat_exes() > 0:
                    continue

                win_exes = mi.count_win_exes()
                linux_exes = mi.count_linux_exes()
                win_arch_exes = mi.count_win_arch_exes()
                linux_arch_exes = mi.count_linux_arch_exes()
                darwin_arch_exes = mi.count_darwin_arch_exes()

                # b) is there a file per plat in default/bin?
                if(win_exes > 0 and
                        linux_exes > 0):
                    continue

                # c) is there a file per arch?
                if(win_arch_exes > 0 or
                        linux_arch_exes > 0 or
                        darwin_arch_exes > 0):
                    continue
                else:
                    reporter.fail("No executable exists for the modular "
                                  "input '{}'".format(mi.name))
        else:
            reporter_output = "No modular inputs were detected."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = ("No `{}` was detected."
                           ).format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)
