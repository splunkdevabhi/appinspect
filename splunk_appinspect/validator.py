# Copyright 2016 Splunk Inc. All rights reserved.

"""This is the core validation logic used to centralize validation run-time.

This module contains functions to accumulate and run checks under configurations
as needed.
"""

# Python Standard Libraries
import logging
# Third-Party Libraries
import concurrent.futures
from futures_then import ThenableFuture
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.checks import Group
from splunk_appinspect.validation_report import ValidationReport
from splunk_appinspect.validation_report import ApplicationValidationReport


logger = logging.getLogger(__name__)
PACKAGING_STANDARDS_TAG = "packaging_standards"


def _emit(eventname, listeners, *args):
    for listener in listeners:
        listener.handle_event(eventname, *args)


class Validator(object):
    """The core validation class. Meant to encapsulate the entire validation
    workflow.
    """

    def __init__(self, app_package_handler, args=None, groups_to_validate=None, listeners=None, resource_manager=None, app_class=None):
        """The core validation class. Meant to encapsulate the entire validation
                workflow.

        Args:
            app_package_handler (AppPackageHandler Object): Contains the AppPackage
                objects to be used for validation.
            args (Dict): Key value arguments that will be used to modify check
                selection, check run-time, and check execution.
            groups_to_validate (List of Group objects): Groups that contain the
                filtered checks to perform.
            listeners (List of Listener derived objects): Listeners that are used to
                hook into events of the validation workflow
            resource_manager (ResourceManager derived object): used to help
                facilitate dependency injection for checks
            app_class (An App derived object): represents the overall Splunk App
                being validator. It exposes functionality for interacting with an app.

        Attributes:
            app_package_handler (AppPackageHandler Object): Contains the AppPackage
                objects to be used for validation.
            args (Dict): Key value arguments that will be used to modify check
                selection, check run-time, and check execution.
            groups_to_validate (List of Group objects): Groups that contain the
                filtered checks to perform.
            listeners (List of Listener derived objects): Listeners that are used to
                hook into events of the validation workflow
            resource_manager (ResourceManager derived object): used to help
                facilitate dependency injection for checks
            app_class (An App derived object): represents the overall Splunk App
                being validator. It exposes functionality for interacting with an app.
            appinspect_version (String): The version of AppInspect being used for
                validation
            app_names (List of Strings): All the names of the apps being validated
            validation_report (ValidationReport object): The report object
                containing validation results
        """
        super(Validator, self).__init__()
        self.app_package_handler = app_package_handler
        self.args = args
        self.groups_to_validate = groups_to_validate
        self.resource_manager = resource_manager
        self.app_class = app_class
        self.listeners = listeners
        self.__validation_groups = None

        if args is None:
            self.args = {}
        if groups_to_validate is None:
            self.groups_to_validate = []
        if listeners is None:
            self.listeners = []
        if resource_manager is None:
            self.resource_manager = splunk_appinspect.resource_manager.ResourceManager()
        if app_class is None:
            self.app_class = splunk_appinspect.App
        else:
            logger_output = ("The custom app_class '{}' was provided to the"
                             " validate_packages function.").format(app_class)
            logger.info(logger_output)

        self.appinspect_version = splunk_appinspect.version.__version__
        logger.info("Executing checks using Splunk AppInspect version {}".format(self.appinspect_version))
        self.args["appinspect_version"] = self.appinspect_version
        self.app_names = self.app_package_handler.apps.keys()
        self.validation_report = ValidationReport()

    def __emit_event(self, eventname, listeners, *args):
        for listener in self.listeners:
            listener.handle_event(eventname, *args)

    @property
    def packaging_groups(self):
        """Returns the internal and custom packaging checks"""

        # Find packaging checks built into the CLI/library
        consolidated_groups = {}
        packaging_grps = splunk_appinspect.checks.groups(included_tags=[PACKAGING_STANDARDS_TAG])
        for grp in packaging_grps:
            consolidated_groups[grp.name] = grp

        # Find all the checks including custom packaging checks may have been provided.
        # Ignore duplicates already listed in packaging_grps
        custom_checks = []
        for grp in self.groups_to_validate:
            for check in grp.checks(included_tags=[PACKAGING_STANDARDS_TAG]):
                add_check = True
                for pkg_grp in packaging_grps:
                    if pkg_grp.has_check(check):
                        add_check = False

                if add_check:
                    custom_checks.append((grp, check))

        # Create a new group (possibly could do a clone/copy)
        for grp, check in custom_checks:
            if grp.module in consolidated_groups:
                consolidated_groups[grp.name].add_check(check)
            else:
                custom_group = Group(grp.module, [check], grp.report_display_order)
                consolidated_groups[custom_group.name] = custom_group

        return consolidated_groups.values()

    @property
    def validation_groups(self):
        """Returns the internal and custom checks not marked as packaging checks"""

        if self.__validation_groups:
            return self.__validation_groups
        else:
            self.__validation_groups = []

            for grp in self.groups_to_validate:
                for chk in grp.checks(excluded_tags=[PACKAGING_STANDARDS_TAG]):
                    custom_group = Group(grp.module, [chk], grp.report_display_order)
                    self.__validation_groups.append(custom_group)

            return self.__validation_groups

    def validate(self):
        """Validates the package supplied by the package handler"""

        self.validation_report = ValidationReport()
        self.validation_report.validation_start()
        self.__emit_event('start_validation', self.listeners, self.app_names)

        try:
            apps = map(lambda x: self.app_class(x), self.app_package_handler.apps.values())
            splunk_args = {}

            if 'splunk_version' in self.args:
                splunk_args['splunk_version'] = self.args['splunk_version']

            splunk_args['apps'] = apps
            with self.resource_manager.context(splunk_args) as context:
                for app in apps:
                    application_validation_report = ApplicationValidationReport(app, self.args)
                    application_validation_report.validation_start()
                    self.__emit_event('start_app', self.listeners, app)

                    self.__emit_event('start_package_validation', self.listeners, app)
                    packaging_results = self.__run_checks(app, context, self.packaging_groups)
                    application_validation_report.results = packaging_results
                    self.__emit_event('finish_package_validation', self.listeners, app)

                    if application_validation_report.has_invalid_package:
                        # If there are packaging issues, skip the remaining checks.
                        skipped_results = self.__skip_checks(self.validation_groups)
                        for grp, check, rpt in skipped_results:
                            application_validation_report.results.append((grp, check, rpt))
                    else:
                        if len(self.validation_groups) > 0:
                            self.__emit_event('start_app_validation', self.listeners, app)
                            validation_results = self.__run_checks(app, context, self.validation_groups)
                            for grp, check, rpt in validation_results:
                                application_validation_report.results.append((grp, check, rpt))
                            self.__emit_event('finish_app_validation', self.listeners, app)

                    application_validation_report.validation_completed()
                    self.__emit_event('finish_app', self.listeners, app, application_validation_report)
                    self.validation_report.add_application_validation_report(application_validation_report)

            self.validation_report.validation_completed()

        except Exception as exception:
            self.validation_report.validation_error(exception)
            raise
        finally:
            self.__emit_event('finish_validation', self.listeners, self.app_names, self.validation_report)

    def __execute_check(self, context, app, check):
        self.__emit_event('start_check', self.listeners, check)
        reporter = check.run(app, context)
        self.__emit_event('finish_check', self.listeners, check, reporter)
        return reporter

    def __dispatch_check(self, ready_for_deferred, threadpool, context, app, check):
        if check.deferred:
            return ready_for_deferred.then(lambda _: threadpool.submit(self.__execute_check, context, app, check))
        else:
            return threadpool.submit(self.__execute_check, context, app, check)

    def __skip_checks(self, groups):
        """Returns a list of tuples containing a Group object, a Check object, and a
        Reporter object.

        :param app (groups) - A list of groups with checks to skip.
        """

        for grp in groups:
            for check in grp.checks():
                self.__emit_event('start_check', self.listeners, check)
                reporter = splunk_appinspect.reporter.Reporter()
                reporter.start()
                reporter.skip("Skipping due to package validation issues.")
                logger.debug("Skipping {}".format(check))
                reporter.complete()
                self.__emit_event('finish_check', self.listeners, check, reporter)
                yield grp, check, reporter

    def __run_checks(self, app, context, groups):
        """Returns a list of tuples containing a Group object, a Check object, and a
        Reporter object.

        :param app (App Object) - An App object that represents the Splunk App
            object
        """
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as threadpool:
            ready_for_deferred = ThenableFuture()

            logger.debug("Beginning validation execution.")
            for group in groups:
                logger.debug(("Executing start_group event for"
                              " Group: {}"
                              " Group_Checks: {}"
                              " Listeners: {}"
                              ).format(group,
                                       list(group.checks()),
                                       self.listeners))

                self.__emit_event('start_group', self.listeners, group, group.checks())
                # This runs the initial checks
                future_checks = map(lambda check: (check, self.__dispatch_check(ready_for_deferred, threadpool, context, app, check)),
                                    group.checks())
                # This accumulates the deferred checks
                futures.append((group, future_checks))

                logger.debug(("Executing finish_group event for"
                              " Group: {}"
                              " Group_Checks: {}"
                              " Listeners: {}"
                              ).format(group,
                                       list(group.checks()),
                                       self.listeners))
                self.__emit_event('finish_group', self.listeners, group, group.checks())

            # This allows the deferred checks to be run
            ready_for_deferred.set_result(True)

        # After exiting 'with', all checks are run.
        # future.result() calls a promise that returns the reporter
        return_values = [(group_object, check_object, future.result())
                         for group_object, checks
                         in futures
                         for check_object, future
                         in checks]
        return return_values


def validate_packages(app_package_handler,
                      args=None,
                      groups_to_validate=None,
                      listeners=None,
                      resource_manager=None,
                      app_class=None):
    """A legacy entry point for the validation process.

    Returns:
        ValidationReport object: The report object containing validation results

    Args:
        app_package_handler (AppPackageHandler Object): Contains the AppPackage
            objects to be used for validation.
        args (Dict): Key value arguments that will be used to modify check
            selection, check run-time, and check execution.
        groups_to_validate (List of Group objects): Groups that contain the
            filtered checks to perform.
        listeners (List of Listener derived objects): Listeners that are used to
            hook into events of the validation workflow
        resource_manager (ResourceManager derived object): used to help
            facilitate dependency injection for checks
        app_class (An App derived object): represents the overall Splunk App
            being validator. It exposes functionality for interacting with an app.
    """
    vaidator = Validator(app_package_handler, args, groups_to_validate, listeners, resource_manager, app_class)
    vaidator.validate()
    return vaidator.validation_report
