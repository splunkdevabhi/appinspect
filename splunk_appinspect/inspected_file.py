# Copyright 2018 Splunk Inc. All rights reserved.

# Standard Python Libraries
import os
import re
# Third-Party Libraries
# N/A
# Custom Libraries
# N/A


class InspectedFile(object):

    def __init__(self, path=""):
        self._path = path

    @staticmethod
    def factory(path=""):
        """
        :param path: file path
        :return: Inspected File object
        """
        if not (os.path.isfile(path) and os.access(path, os.R_OK)):
            return None

        fname, fext = os.path.splitext(path)
        if fext == ".py":
            return PythonFile(path)
        if fext == ".js":
            return CStyleFile(path)
        ###
        # Add more type here
        # TODO:
        # - html
        # - conf
        # - etc.
        ###
        return InspectedFile(path)

    def _preserve_line(self, text):
        """
        :param text: multi-line string
        :return: multiple empty lines
        """
        re_endline = re.compile(r"\r?\n", re.MULTILINE)
        return ''.join([x[0] for x in re_endline.findall(text)])

    def _evaluate_match(self, match, keep_group, remove_group):
        """
        :param match: regex match
        :param keep_group: name of group to be kept
        :param remove_group: name of group to be removed
        :return: string after evaluated
        """
        group = match.groupdict()
        if group[keep_group]:
            return group[keep_group]
        return self._preserve_line(group[remove_group])

    def _remove_comments(self, content):
        """
        :param content: text string
        :return:
        """
        # In general text file, no need to remove comments
        return content

    def search_for_patterns(self, patterns, excluded_comments=True, regex_option=0):
        """
        :param patterns: regex patterns array
        :param excluded_comments: excluded comment from test
        :param regex_option: regex option
        :return: array of match objects
        """

        matches = []

        with open(self._path) as inspected_file:
            line_no = 0
            content = inspected_file.read()
            if excluded_comments:
                content = self._remove_comments(content)
            for line in content.splitlines():
                line_no += 1
                for rx in [re.compile(p, regex_option) for p in patterns]:
                    for p_match in rx.finditer(line):
                        fileref_output = "{}:{}".format(self._path, line_no)
                        matches.append((fileref_output, p_match))

        return matches

    def search_for_pattern(self, pattern, excluded_comments=True, regex_option=0):
        """ Same with search_for_patterns except single pattern."""
        return self.search_for_patterns([pattern], excluded_comments, regex_option)

    def search_for_crossline_patterns(self, patterns, excluded_comments=True, cross_line=10):
        """
        :param patterns: regex patterns array
        :param excluded_comments: excluded comment from test
        :return: array of match objects
        """

        matches = []

        with open(self._path) as inspected_file:
            line_no = 0
            content = inspected_file.read()
            if excluded_comments:
                content = self._remove_comments(content)

            lines_content = content.splitlines()
            lines_count = len(lines_content)

            for line_no in range(0,lines_count):
                multi_line = ''
                start_line = line_no
                end_line = (start_line+cross_line) if (start_line+cross_line) <= lines_count  else lines_count
                for item in lines_content[start_line:end_line]:
                    multi_line += item + '\n'

                for rx in [re.compile(p) for p in patterns]:
                    if rx.match(multi_line):
                        fileref_output = "{}:{}".format(self._path, line_no+1)
                        matches.append((fileref_output, rx.match(multi_line))) 

        return matches

    def search_for_crossline_pattern(self, pattern, excluded_comments=True, cross_line=10):
        """ Same with search_for_crossline_patterns except single pattern."""
        return self.search_for_crossline_patterns(patterns=[pattern],
                                                  excluded_comments=excluded_comments,
                                                  cross_line=cross_line)


class PythonFile(InspectedFile):

    COMMENT_PATTERN = re.compile(
        r"""
            (?P<comments>
                \s*\#(?:[^\r\n])*	# single line comment
            )
            | (?P<code>
                .[^\#]*           # sourcecode
            )
            """,
        re.VERBOSE | re.MULTILINE | re.DOTALL
    )
    DOCSTRING_PATTERN = re.compile(
        r"""
            (?P<start>
                ^\s*"{3}	# start triple double quotes
                | ^\s*'{3}	# start triple single quotes
            )
            | (?P<end>
                "{3}\s*$	# end triple double quotes
                | '{3}\s*$	# end trible single quotes
            )
        """,
        re.VERBOSE
    )

    def __init__(self, path=""):
        self._path = path
        super(PythonFile, self).__init__(path)

    def _remove_comments(self, content):
        """ Override _remove_comments."""
        content = ''.join(map(lambda m: self._evaluate_match(m, "code", "comments"),
                              self.COMMENT_PATTERN.finditer(content)))
        stripped_content = ""
        line_skip = False
        for line in content.splitlines():
            match = self.DOCSTRING_PATTERN.findall(line)
            if len(match) > 0:
                if len(match) == 1:
                    line_skip = not line_skip   # Only one tripe double/single quotes
                # If there are 2 triple double/single quotes, it's already
                # completed docstring
                stripped_content += "\r\n"
                continue

            if line_skip:
                stripped_content += "\r\n"
                continue

            stripped_content += line + "\r\n"

        return stripped_content


class CStyleFile(InspectedFile):

    COMMENT_PATTERN = re.compile(
        r"""
              (?P<comments>
                    /\*[^*]*\*+(?:[^/*][^*]*\*+)*/          # multi-line comments
                  | \s*(?<!:)//(?:[^\r\n])*                 # single line comment
              )
            | (?P<code>
                .[^/]*                              # sourcecode
              )
        """,
        re.VERBOSE | re.MULTILINE | re.DOTALL
    )

    def __init__(self, path=""):
        self._path = path
        super(CStyleFile, self).__init__(path)

    def _remove_comments(self, content):
        """ Override _remove_comments."""
        return ''.join(map(lambda m: self._evaluate_match(m, "code", "comments"),
                           self.COMMENT_PATTERN.finditer(content)))
