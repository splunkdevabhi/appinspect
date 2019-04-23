# Copyright 2018 Splunk Inc. All rights reserved.

"""Checks contains both the group class and the check class. These classes
serve as the basic scaffolding to connect the implied structure of validation
checks. One group consists of many checks. Implementation wise, each file in
the folder of splunk_appinspect/checks/ is a group. Inside each on of those
files are checks.
"""

# Python Standard Libraries
import imp
import inspect
import logging
import operator
import os
import re
import sys
# Third-Party Libraries
import bs4
import markdown
# Custom Libraries
import splunk_appinspect
import splunk_appinspect.infra

logger = logging.getLogger(__name__)

DEFAULT_CHECKS_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                  'checks')


class ResourceUnavailableException(Exception):
    """An exception to throw when the Check class cannot find a resource needed
    for dependency injection.
    """
    pass


def get_module_name_from_path(base, path):
    """Given a full path to a file, pull out the base filename."""
    name, ext = os.path.splitext(os.path.relpath(path, base))
    return name.replace(os.sep, ".")


def import_group_modules(directory_paths):
    """Returns a list of python modules from a set of directory paths

    Returns:
        List of Python Module objects

    Arguments:
        directory_paths (List of Strings): A list of directory paths
    """
    group_modules_to_return = []

    for check_dir in directory_paths:
        file_pattern_regex = re.compile('check_.+.py$', re.IGNORECASE)
        for directory_path, directory_names, file_names in os.walk(check_dir):
            logger.debug("Beginning group generation on directory: {}".format(check_dir))
            for file in [file_name for file_name in file_names if re.match(file_pattern_regex, file_name)]:
                filepath = os.path.join(directory_path, file)
                group_module_name = get_module_name_from_path(check_dir, filepath)
                group_module = imp.load_source(group_module_name, filepath)
                group_modules_to_return.append(group_module)

    return group_modules_to_return


def generate_checks(module):
    """A helper function to create a list of Check objects from a provided
    module.

    Returns:
        List of Check objects: A list of check objects that represent each
            function in the module.

    Arguments:
    """
    checks = [Check(function_name, function)
              for function_name, function
              in inspect.getmembers(module, inspect.isfunction)
              if function_name.startswith("check_")]
    return checks


def generate_group(group_module, included_tags=None, excluded_tags=None, version=None, splunk_version='latest', custom_group=False):
    """A helper function to create a group object based on a modules that is
    provided.

    Returns:
        Group object: Returns a Group object. The Group object should represent
            the respective module that was provided.

    Arguments:
        group_module (List of Python Module objects): A list of python module
            objects
        included_tags (List of Strings) - Tags to select checks with
        excluded_tags (List of Strings) - Tags to deselect checks with
        version (String) - The version of Splunk AppInspect being targeted
        splunk_version (String) - The version of Splunk being targeted
        custom_group (Boolean) - If the group being created is a custom group
    """
    if included_tags is None:
        included_tags = []
    if excluded_tags is None:
        excluded_tags = []
    if version is None:
        version = splunk_appinspect.version.__version__

    # Group Generation
    logger.debug("Beginning check generation on group name: {}".format(group_module.__name__))

    # Check Generation
    check_list = generate_checks(group_module)

    filtered_checks = [check
                       for check in check_list
                       if (check.matches_tags(included_tags, excluded_tags) and
                           check.matches_version(version))]

    # Debuging output for check filtering
    logger.debug("Included Tags: {}".format(",".join(included_tags)))
    logger.debug("Excluded Tags: {}".format(",".join(excluded_tags)))
    logger.debug("Version: {}".format(version))
    logger.debug("Splunk Version: {}".format(splunk_version))
    logger.debug("Is Custom Group: {}".format(custom_group))
    logger.debug("--- All Checks ---")
    for check in check_list:
        logger_output = ("check_name:{},matches_tags:{},matches_version:{}"
                         ).format(check.name,
                                  check.matches_tags(included_tags, excluded_tags),
                                  check.matches_version(version))
        logger.debug(logger_output)

    logger.debug("--- Filtered Checks ---")
    for check in filtered_checks:
        logger_output = ("check_name:{},matches_tags:{},matches_version:{}"
                         ).format(check.name,
                                  check.matches_tags(included_tags, excluded_tags),
                                  check.matches_version(version))
        logger.debug(logger_output)

    new_group = Group(group_module, checks=filtered_checks, custom_group=custom_group)

    return new_group


def groups(check_dirs=None, custom_checks_dir=None, included_tags=None, excluded_tags=None, version=None, splunk_version='latest'):
    """Return a list of Group objects.

    Generates a list of Group objects by iterating through specified directories
    and concatenates them together into a single list.

    :param check_dirs (List of strings) - A list of strings that are paths to
        directories that contain group files. Inside the group file check
        functions exist.
    :param custom_checks_dir (String) - A string that is a path to a custom
        check directory.
    """
    if check_dirs is None:
        check_dirs = [DEFAULT_CHECKS_DIR]
    if included_tags is None:
        included_tags = []
    if excluded_tags is None:
        excluded_tags = []
    if version is None:
        version = splunk_appinspect.version.__version__

    groups_to_return = []
    check_group_modules = import_group_modules(check_dirs)
    for group_module in check_group_modules:
        check_group = generate_group(group_module,
                                     included_tags=included_tags,
                                     excluded_tags=excluded_tags,
                                     version=version,
                                     splunk_version=splunk_version,
                                     custom_group=False)
        # Don't return a group that does not have checks
        if list(check_group.checks()):
            groups_to_return.append(check_group)

    # TODO: Convert to support mutiple custom checks directory
    #       Do not forget to convert command line to support multiple directories
    # TODO: tests needed
    if custom_checks_dir:
        custom_group_modules = import_group_modules([custom_checks_dir])
        for group_module in custom_group_modules:
            custom_check_group = generate_group(group_module,
                                                included_tags=included_tags,
                                                excluded_tags=excluded_tags,
                                                version=version,
                                                splunk_version=splunk_version,
                                                custom_group=True)

            # Don't return a group that does not have checks
            if list(custom_check_group.checks()):
                groups_to_return.append(custom_check_group)

    groups_ordered_by_report_display_order = sorted(groups_to_return,
                                                    key=operator.attrgetter('report_display_order'))
    return groups_ordered_by_report_display_order


def checks(checks_dirs=[DEFAULT_CHECKS_DIR], custom_checks_dir=None):
    """Return a generator object that yields a Check object.

    Iterate through all checks.

    :param checks_dirs (List of Strings) - A list of strings that are paths
        pointing to directories containing group files.
    :param custom_checks_dirs (String) - A strings that is the path pointing to
        a custom directory containing group files.
    """
    # TODO: Known bug - This is broken as `checks_dir` is used and not `checks_dirs`
    # TODO: tests needed
    for group in groups(checks_dirs=checks_dirs):
        for check in group.checks(checks_dir, custom_checks_dir):
            yield check


class Group(object):
    """A group represents a group of checks- namely, all those contained within
    a single file. The documentation for the group is extracted from the Python
    module docstring.
    """

    def __init__(self, module, checks=None, report_display_order=None, custom_group=False):
        """Constructor function."""
        self.name = module.__name__
        self.module = module

        # Checks
        # If checks aren't provided then, they are generated from the module
        if checks is None:
            self._checks = splunk_appinspect.checks.generate_checks(module)
        else:
            self._checks = checks

        # Report Display Order
        if report_display_order is None:
            report_order = getattr(module,
                                   'report_display_order',
                                   1000)
            if custom_group:
                # Order custom checks to be last.
                report_order += 10000
        else:
            report_order = report_display_order
        self.report_display_order = report_order

        # Custom Group
        self.custom_group = custom_group

    def doc(self):
        """Returns the docstring for the module, or if not defined the name."""
        return self.doc_text()

    def doc_raw(self):
        """Returns the raw doc string."""
        docstring = self.module.__doc__
        if docstring:
            return docstring
        else:
            return self.name

    def doc_text(self):
        """Returns the plain text version of the doc string."""
        doc = self.doc_raw()
        soup = bs4.BeautifulSoup(markdown.markdown(doc), "lxml")
        text = ''.join(soup.findAll(text=True))
        if self.custom_group:
            text = text + " (CUSTOM CHECK GROUP)"
        return text

    def doc_name_human_readable(self):
        """Returns the contents of the Markdown h3 element from the top of the
        group's docstring."""
        html = markdown.markdown(self.doc_raw(),
                                 extensions=['markdown.extensions.fenced_code'])
        bs_html = bs4.BeautifulSoup(html, 'html.parser')
        if bs_html.h3 is not None and len(bs_html.h3.contents) > 0:
            return unicode(bs_html.h3.contents[0]).strip()
        return u""

    def doc_html(self):
        """Returns the docstring (provided in markdown) as a html element."""
        html = markdown.markdown(self.doc_raw(),
                                 extensions=['markdown.extensions.fenced_code'])
        bs_html = bs4.BeautifulSoup(html, 'html.parser')
        # Create a <a name="check_group_name"></a> to optionally be used for TOC
        new_tag = bs_html.new_tag('a')
        new_tag['name'] = self.name
        bs_html.h3.contents.insert(0, new_tag)
        return unicode(bs_html)

    def has_checks(self, **kwargs):
        """Checks to see whether the group has checks or not.

        NOTE: that filters are applied, so if a tags or version is specified,
        this may return 0 even if there are checks defined.
        """
        # TODO: tests needed
        return len([check for check in self.checks(**kwargs)]) > 0

    def count_total_static_checks(self, included_tags=None, excluded_tags=None, version=None, splunk_version='latest'):
        """A helper function to return the count of static checks.

        Returns:
            Integer: A number representing the amount of checks that are dynamic
            checks.

        Arguments:
            included_tags (List of Strings) - Tags to select checks with
            excluded_tags (List of Strings) - Tags to deselect checks with
            version (String) - The version of Splunk AppInspect being targeted
            splunk_version (String) - The version of Splunk being targeted
        """
        # TODO: tests needed
        if included_tags is None:
            included_tags = []
        if excluded_tags is None:
            excluded_tags = []
        if version is None:
            version = splunk_appinspect.version.__version__

        total_static = len([check
                            for check
                            in self.checks(included_tags=included_tags,
                                           excluded_tags=excluded_tags,
                                           version=version,
                                           splunk_version=splunk_version)
                            if not check.is_dynamic_check()])
        return total_static

    def count_total_dynamic_checks(self, included_tags=None, excluded_tags=None, version=None, splunk_version='latest'):
        """A helper function to return the count of standalone checks.

        Returns:
            Integer: A number representing the amount of checks that are dynamic
            checks.

        Arguments:
            included_tags (List of Strings) - Tags to select checks with
            excluded_tags (List of Strings) - Tags to deselect checks with
            version (String) - The version of Splunk AppInspect being targeted
            splunk_version (String) - The version of Splunk being targeted
        """
        # TODO: tests needed
        if included_tags is None:
            included_tags = []
        if excluded_tags is None:
            excluded_tags = []
        if version is None:
            version = splunk_appinspect.version.__version__

        total_dynamic = len([check
                             for check
                             in self.checks(included_tags=included_tags,
                                            excluded_tags=excluded_tags,
                                            version=version,
                                            splunk_version=splunk_version)
                             if check.is_dynamic_check()])
        return total_dynamic

    def count_total_standalone_checks(self, included_tags=None, excluded_tags=None, version=None, splunk_version='latest'):
        """A helper function to return the count of standalone checks.

        Returns:
            Integer: A number representing the amount of checks that are cluster
            checks.

        Arguments:
            included_tags (List of Strings) - Tags to select checks with
            excluded_tags (List of Strings) - Tags to deselect checks with
            version (String) - The version of Splunk AppInspect being targeted
            splunk_version (String) - The version of Splunk being targeted
        """
        # TODO: tests needed
        if included_tags is None:
            included_tags = []
        if excluded_tags is None:
            excluded_tags = []
        if version is None:
            version = splunk_appinspect.version.__version__

        total_standalone = len([check
                                for check
                                in self.checks(included_tags=included_tags,
                                               excluded_tags=excluded_tags,
                                               version=version,
                                               splunk_version=splunk_version)
                                if check.is_standalone_check()])
        return total_standalone

    def count_total_cluster_checks(self, included_tags=None, excluded_tags=None, version=None, splunk_version='latest'):
        """A helper function to return the count of cluster checks.

        Returns:
            Integer: A number representing the amount of checks that are cluster
            checks.

        Arguments:
            included_tags (List of Strings) - Tags to select checks with
            excluded_tags (List of Strings) - Tags to deselect checks with
            version (String) - The version of Splunk AppInspect being targeted
            splunk_version (String) - The version of Splunk being targeted
        """
        # TODO: tests needed
        if included_tags is None:
            included_tags = []
        if excluded_tags is None:
            excluded_tags = []
        if version is None:
            version = splunk_appinspect.version.__version__

        total_cluster = len([check
                             for check
                             in self.checks(included_tags=included_tags,
                                            excluded_tags=excluded_tags,
                                            version=version,
                                            splunk_version=splunk_version)
                             if check.is_cluster_check()])
        return total_cluster

    def add_check(self, check_to_add):
        """A helper function for adding Check objects to the Group.

        Returns:
            None

        Arguments:
            check_to_add (Check object): A check object that will be added to
                the group's list of checks.
        """
        # TODO: tests needed
        self._checks.append(check_to_add)

    def remove_check(self, check_to_remove):
        """A helper function for removiong Check objects from the Group.

        Returns:
            None

        Arguments:
            check_to_remove (Check object): A check object that will be removed
                from the group's list of checks.
        """
        # TODO: tests needed
        self._checks.remove(check_to_remove)

    def checks(self, included_tags=None, excluded_tags=None, version=None, splunk_version='latest'):
        """A function to return the checks that the group owns.

        Returns:
            An iterator of Check objects: A list of check objects representing
                the checks owned by the group, that were filtered accordingly.

        Arguments:
            included_tags (List of Strings) - Tags to select checks with
            excluded_tags (List of Strings) - Tags to deselect checks with
            version (String) - The version of Splunk AppInspect being targeted
            splunk_version (String) - The version of Splunk being targeted
        """
        if included_tags is None:
            included_tags = []
        if excluded_tags is None:
            excluded_tags = []
        if version is None:
            version = splunk_appinspect.version.__version__

        check_list = self._checks

        ordered_checks = sorted(check_list,
                                key=operator.attrgetter('report_display_order'))

        for check in ordered_checks:
            should_check_be_returned = (check.matches_tags(included_tags, excluded_tags) and
                                        check.matches_version(version))
            logger_output = ("check_name:{},matches_tags:{},matches_version:{},should_check_be_returned:{}"
                             ).format(check.name,
                                      check.matches_tags(included_tags, excluded_tags),
                                      check.matches_version(version),
                                      should_check_be_returned)
            logger.debug(logger_output)

            if should_check_be_returned:
                yield check

    def check_count(self):
        """A helper function to return the number of checks that exist.

        Returns:
            Integer: the total number of checks that exist.
        """
        # TODO: tests needed
        return len(list(self.checks()))

    def has_check(self, check):
        """A helper function to determine if the check exists.

        Returns:
            Boolean: Checks exists.
        """
        return any(chk.name == check.name for chk in self._checks)

    def tags(self):
        """Helper function to generate the set of tags that for all the checks
        in the group.

        Returns:
            List of strings: A list of tags found in the checks. Only unique
                tags will be returned. (No tags will be duplicated)
        """
        tags_to_return = []
        for check in self._checks:
            for tag in check.tags:
                if tag not in tags_to_return:
                    tags_to_return.append(tag)

        return tags_to_return


class Check(object):
    """Wraps a check function and allows for controlled execution."""

    def __init__(self, name, fun):
        """Constructor Initialization

        Arguments:
            name (String): a short name to identify the check. By default the
                name of the python function
            fun (Function): A callable that will be executed when the check is
                run.
        """
        self.name = name
        self.fun = fun

    def __repr__(self):
        """A function overload for getting the string representation of an
        object.

        Returns:
            String - representing the object's debug info.
        """
        return "<splunk_appinspect.check:" + self.name + ">"

    def is_dynamic_check(self):
        """A helper function identifiyng if the check requires a splunk instance
        to be created in order to execute.

        Returns:
            Boolean - True if dynamic check or is a standalone check
        """
        # TODO: tests needed
        return self.is_cluster_check() or self.is_standalone_check()

    def is_cluster_check(self):
        """A helper function identifiyng if the check requires a splunk instance
        to be created in order to execute.

        Returns:
            Boolean - True if splunk instance is needed, False if is NOT needed
        """
        # TODO: tests needed
        spec = inspect.getargspec(self.fun)
        if "cluster" in spec.args:
            return True
        else:
            return False

    def is_standalone_check(self):
        """A helper function identifiyng if the check does NOT require a splunk
        instance to be created in order to execute.

        Returns:
            Boolean - True if splunk instance is NOT needed, False if it is
                needed
        """
        # TODO: tests needed
        spec = inspect.getargspec(self.fun)
        if "standalone" in spec.args:
            return True
        else:
            return False

    def has_tag(self, tags):
        """A helper function identifiyng if the check has tags.

        Returns:
            Boolean - True if the check has tags, False if it is does NOT have
                tags
        """
        for tag in tags:
            if tag in self.tags:
                return True
        return False

    def matches_version(self, version_to_match):
        """Returns true if version is greater than the min_version set on the
        function (if one is set) and version is less than max_version on the
        function (if set).  If no min_version is set return true.

        :param version_to_match: the version to match on
        """
        if version_to_match is None:
            return True

        if hasattr(self.fun, 'min_version'):
            return (version_to_match >= self.fun.min_version and
                    (self.fun.max_version is None or
                     version_to_match <= self.fun.max_version))
        else:
            return True

    def doc(self, include_version=False):
        """Returns the docstring provided with the underlying function, or the
        name if not provided.

        :param include_version - Bool - defaults to false. specifies if the
            check version should be included in the documentation.
        """
        # TODO: tests needed
        doc_text = self.doc_text()
        if include_version:
            doc_text = "{} {}".format(doc_text, self.version_doc())

        return doc_text

    def doc_html(self, include_version=False):
        """Returns the docstring (provided in markdown) as a html element."""
        # TODO: tests needed
        html = markdown.markdown(self.doc_raw(),
                                 extensions=['markdown.extensions.fenced_code'])

        if include_version:
            html = "{} {}".format(html, self.version_doc())

        return html

    def doc_text(self):
        """Returns the plain text version of the doc string."""
        # Normalize spacing (as found in code), keep line breaks
        # TODO: tests needed
        p = re.compile(r'([ \t])+')
        doc = p.sub(r'\1', self.doc_raw().strip())

        soup = bs4.BeautifulSoup(markdown.markdown(doc), "lxml")
        text = ''.join(soup.findAll(text=True))
        return text

    def doc_raw(self):
        """Returns the raw stripped doc string."""
        # TODO: tests needed
        docstring = self.fun.__doc__
        if docstring:
            return docstring
        else:
            return self.name

    def version_doc(self):
        """Returns the version range of the check."""
        # TODO: tests needed
        ver_doc = "({}-{})".format(self.min_version_doc, self.max_version_doc)
        return ver_doc

    @property
    def report_display_order(self):
        """Return an integer.

        Returns a report display order number. This indicates the order to
        display report elements in.
        """
        if not getattr(self.fun, 'report_display_order', False):
            return 1000
        else:
            return self.fun.report_display_order

    @property
    def deferred(self):
        """Returns true if the underlying function has 'deferred' advice. This
        is used for tests that should be run after all other tests.
        """
        return getattr(self.fun, 'deferred', False)

    @property
    def min_version_doc(self):
        """Returns the min version specified against the check."""
        # TODO: tests needed
        if not getattr(self.fun, 'min_version', False):
            return "1.0"
        else:
            return self.fun.min_version

    @property
    def max_version_doc(self):
        """Returns the max version specified against the check."""
        # TODO: tests needed
        if not getattr(self.fun, 'max_version', False):
            return "*"
        else:
            return self.fun.max_version

    @property
    def tags(self):
        """Returns the tags of the checks if they exist  or returns an empty
        tuple.
        """
        if hasattr(self.fun, 'tags'):
            return self.fun.tags
        else:
            return tuple()

    def matches_tags(self, included_tags, excluded_tags):
        """Returns a boolean.

        Returns a boolean indicating if the check object's tags match the
        included or excluded tags.

        If included tags has values and excluded tags has values the included
        tags take precendence and will match.

        If only included tags has values then all tags are white list matched
        against included tags.

        If only excluded tags has values, then all tags are black list matched
        against excluded tags.

        If neither included_tags and excluded_tags has values then it will
        always return True as a match.

        :param included_tags (A list of Strings) - Include only checks with the
            defined tags.
        :param excluded_tags (A list of Strings) - Exclude checks with these tags
        """
        check_tags_set = set(self.tags)
        included_tags_set = set(included_tags)
        excluded_tags_set = set(excluded_tags)
        included_excluded_intersection_set = included_tags_set.intersection(excluded_tags_set)

        # The Splunk AppInspect business rule
        # If included_tags and excluded_tags are not specified then the check
        #   should be returned regardless A.K.A. a left join on the
        #   included_tags
        # If included_tags and excluded_tags contain the same tag then
        #   included_tags take precedent
        # If included_tags and excluded_tags contain the different tags then
        #   both of them will match
        if included_excluded_intersection_set:
            excluded_tags_set -= included_excluded_intersection_set

        if(not included_tags_set and
                not excluded_tags_set):
            return True
        elif(included_tags_set and
             not excluded_tags_set):
            return (not check_tags_set.isdisjoint(included_tags_set))
        elif(not included_tags_set and
             excluded_tags_set):
            return check_tags_set.isdisjoint(excluded_tags_set)
        elif(included_tags_set and
             excluded_tags_set):
            return (not check_tags_set.isdisjoint(included_tags_set) 
                    and check_tags_set.isdisjoint(excluded_tags_set))

    def run(self, app, resource_manager_context={}):
        """This is in a way the central method of this library.  A check can be
        run, and it returns a 'reporter' object.  Whatever the result- success,
        failure, exception, etc, it will be encoded in that reporter
        object.

        :param app The app to run this check against.
        :param splunk_instances Some instances require a running Splunk
          instance.  This dictionary provides references to those instances by
          name, and they are matched on the parameter name for the underlying
          function.  For example, if both a cluster and a standalone instance
          are created for use by the tests, creating a check function with the
          signature

          def check_something(reporter, standalone):
            pass

          will get the standalone instance passed as the second parameter,
          provided splunk_instances contains a 'standalone' key.  This is
          extended so that if the value is callable, it will be called and the
          result will be passed in as that parameter.
        """
        reporter = splunk_appinspect.reporter.Reporter()
        reporter.start()
        try:
            logging.debug("Executing " + self.name)
            # This is a bit of magic, the idea for which was taken from pytest.
            # Basically checks will need some variety of app, reporter, and/or
            # access to a splunk instance (or instances).  Instead of having a
            # crazy set of parameters, use the name of the parameters to map to
            # what we pass.  As a result, the signature of a check can be:
            #   def check_something(app, reporter)        -> app directory and reporter
            #   def check_something(app)                  -> we are going to use assert
            #   def check_something(standalone, reporter) -> we are going to use standalone and reporter
            #   def check_something(cluster)              -> using the cluster and just assert
            #   def check_something(foobarbaz)            -> throws a TypeError.
            # Any splunk instance passed in using the splunk_instances named
            # parameter becomes an available argument to the checks.
            available_args = dict()

            available_args['app'] = app
            available_args['reporter'] = reporter

            args = []
            function_arguments = inspect.getargspec(self.fun).args
            for arg in function_arguments:
                if arg in available_args:
                    val = available_args[arg]
                    if callable(val):
                        args.append(val())
                    else:
                        args.append(val)
                elif arg in resource_manager_context:
                    # TODO: tests needed
                    logging.debug("Getting resource: '{}' for {}".format(arg,
                                                                         self.fun.__name__))
                    args.append(resource_manager_context[arg])
                else:
                    # TODO: tests needed
                    error_string = ("{} has been skipped because the specified"
                                    " instances provided did not match the"
                                    " required instance types."
                                    " Instances provided: {}."
                                    "").format(self.fun.__name__,
                                               resource_manager_context.keys())
                    raise ResourceUnavailableException(error_string)
            self.fun.__call__(*args)
        except NotImplementedError:
            e = sys.exc_info()
            reporter.exception(e, 'failure')
        except ResourceUnavailableException:
            e = sys.exc_info()
            reporter.exception(e, 'skipped')
        except:
            e = sys.exc_info()
            logging.exception(e)
            reporter.exception(e)

        logging.debug("check %s %s",
                      self.name,
                      reporter.state())

        reporter.complete()
        return reporter
