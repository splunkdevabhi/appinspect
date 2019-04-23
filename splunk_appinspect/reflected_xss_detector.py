from abc import ABCMeta, abstractmethod
from bs4 import BeautifulSoup

from splunk_appinspect.regex_matcher import RegexMatcher
from splunk_appinspect.regex_matcher import JSReflectedXSSMatcher

import os
import re

class ReflectedXSSDetector:

    def __init__(self, app):
        self.app = app

        self.rule_list = self._build_rules()

    def detect(self):

        ans = []
        for rule in self.rule_list:
            ans.extend(rule.check(self.app))
        return ans

    def _build_rules(self):

        rules = [
            # html input text value
            InputTextValueUsedInJavascript("Possible html input text's value used in javascript"),
            # simple xml variables
            SimpleXMLVariableUsedInElementSource("Possible SimpleXML input text's value used in src attribute"),
            # possible xss attack in javascript code
            UserJavascriptReflectedXSSDetectRule('Possible reflected xss found in javascript code'),
            # malicious image element
            DefaultSrcTagByLeavingItOutEntirely('Image src tag is not found, possible image xss attack'),
            DefaultSrcTagByLeavingItEmpty('Image src tag is empty, possible image xss attack'),
            DefaultSrcTagToGetPastFiltersThatCheckSrcDomain('Image src tag is #, possible image xss attack'),
            ImageXSSUsingJavascriptDirective('Possible image xss attack in src attribute'),
            ImageDynsrc('Possible image xss attack in dynsrc attribute'),
            ImageLowsrc('Possible image xss attack in lowsrc attribute'),
            ImageXSSOnErrorAlert('Image src tag is /, possible image xss attack'),
            # A element
            MalformedATag('A href tag is not found, possible xss attack'),
            # iframe and frame
            IframeAndFrameXSSCheck('Possible iframe or frame tag xss attack'),
            # input image
            InputTypeImageXSSCheck('Possible image type input tag xss attack'),
            # body
            BodyTagXSSCheck('Possible body tag xss attack'),
            # svg
            SvgTagXSSCheck('Possible svg tag xss attack'),
            # table and td
            TableAndTdXSSCheck('Possible table or td tag xss attack'),
            # link
            LinkXSSCheck('Possible link tag xss attack'),
            # div
            DivStyleSheetXSSCheck('Possible div style xss attack')]

        return rules


class ReflectedXSSDetectRule:

    __metaclass__ = ABCMeta

    def __init__(self, rule_description):
        self.rule_description = rule_description

    @abstractmethod
    def check(self, app): pass


class InputTextValueUsedInJavascript(ReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(InputTextValueUsedInJavascript, self).__init__(rule_description)

    def check(self, app):

        input_ids = self._collect_input_ids(app)
        id_to_match_result_dict = self._build_match_result_dict(app, input_ids)
        return self._check_all_match_result(id_to_match_result_dict)

    def _collect_input_ids(self, app):

        input_ids = set()
        for directory, f, ext in app.iterate_files(types=['.html']):
            current_file_full_path = app.get_filename(directory, f)
            soup = BeautifulSoup(open(current_file_full_path, 'r').read(), 'html.parser')
            input_list = soup.find_all("input", {'type': 'text'})
            for input in input_list:
                if input.get('id') is not None:
                    input_ids.add(input['id'])

        return input_ids

    def _build_match_result_dict(self, app, input_ids):

        id_to_match_result_dict = {}
        for id in input_ids:
            id_to_match_result_dict[id] = []
        for id in input_ids:
            regex_pattern = ".{0,50}=.{0,50}" + id + '.{0,50}'
            matcher = RegexMatcher([regex_pattern])
            for directory, f, ext in app.iterate_files(types=['.js']):
                current_file_full_path = app.get_filename(directory, f)
                result_list = matcher.match_file(current_file_full_path)
                for result in result_list:
                    add_tuple = (os.path.join(directory, f),)
                    add_tuple += result
                    id_to_match_result_dict[id].append(add_tuple)
        return id_to_match_result_dict

    def _check_all_match_result(self, id_to_match_result_dict):

        ans = []
        for id, result_list in id_to_match_result_dict.items():
            # if one id was used for too many times, it could be a false positive
            if len(result_list) < 200:
                for result in result_list:
                    reporter_output = ("{}. The following line will be inspected during code review."
                                       " Match: {}"
                                       " File: {}"
                                       " Line: {}"
                                       ).format(self.rule_description, result[2].strip(), result[0], result[1])
                    ans.append((reporter_output, result[0], result[1]))
        return ans

class SimpleXMLVariableUsedInElementSource(ReflectedXSSDetectRule):
    def __init__(self, rule_description):
        super(SimpleXMLVariableUsedInElementSource, self).__init__(rule_description)

    def check(self, app):

        ans = []
        for directory, f, ext in app.iterate_files(types=['.xml']):
            current_file_full_path = app.get_filename(directory, f)
            # collect tokens in this file
            soup = BeautifulSoup(open(current_file_full_path, 'r').read(), 'lxml')
            tokens = set()
            for element in soup.findAll("input", {"type": "text"}):
                if element.get('token') is not None:
                    tokens.add(element.get('token'))

            for element in soup.findAll():
                if element.get("src") is not None:
                    src_value = element.get("src")
                    for token in tokens:
                        # only report one manual check for one element
                        if token in src_value:
                            reporter_output = ("{}. The following line will be inspected during code review."
                                               " Match: {}"
                                               " File: {}"
                                               ).format(self.rule_description, src_value, os.path.join(directory, f))
                            ans.append((reporter_output, os.path.join(directory, f)))
                            break
        return ans


class UserJavascriptReflectedXSSDetectRule(ReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(UserJavascriptReflectedXSSDetectRule, self).__init__(rule_description)

    def check(self, app):

        ans = []
        matcher = JSReflectedXSSMatcher()
        for directory, f, ext in app.iterate_files(types=['.js']):
            current_file_full_path = app.get_filename(directory, f)
            result_list = matcher.match_file(current_file_full_path, re.IGNORECASE)
            for result in result_list:
                reporter_output = ("The following line will be inspected during code review."
                                   " Match: {}"
                                   " File: {}"
                                   " Line: {}"
                                   ).format(result[1], os.path.join(directory, f), result[0])
                ans.append((reporter_output, os.path.join(directory, f), result[0]))
        return ans

class UserHTMLReflectedXSSDetectRule(ReflectedXSSDetectRule):

    __metaclass__ = ABCMeta

    def __init__(self, rule_description):
        super(UserHTMLReflectedXSSDetectRule, self).__init__(rule_description)

        # define some common patterns
        self.js_code_pattern = re.compile('javascript:(?!false)[^0].*?', re.IGNORECASE)
        self.start_with_on_pattern = re.compile('^on.*$', re.IGNORECASE)

        # report output template
        self.reporter_output = ("{}. The following line will be inspected during code review."
                                " Match: {}"
                                " File: {}"
                                )

    def check(self, app):

        ans = []
        for directory, f, ext in app.iterate_files(types=['.html']):
            current_file_full_path = app.get_filename(directory, f)
            current_file_path = os.path.join(directory, f)
            soup = BeautifulSoup(open(current_file_full_path, 'r').read(), 'html.parser')
            ans.extend(self.check_file(app, current_file_path, soup))
        return ans

    @abstractmethod
    def check_file(self, app, current_file_path, soup): pass

    def _xml_attribute_exists_and_pattern_match_check(self, attribute_name, attr_dict, attribute_name_pattern=None,
                                                      attribute_value_pattern=None):
        '''
            attribute_name:          attribute we want to check
            attr_dict:               attribute dictionary we work on
            attribute_name_pattern:  attribute name need to match this pattern if exists
            attribute_value_pattern: attribute value need to match this pattern if exists
        '''
        if attribute_name in attr_dict:
            attribute_value = attr_dict[attribute_name]
            if (attribute_name_pattern is not None) and (not re.match(attribute_name_pattern, attribute_name)):
                return False
            if (attribute_value_pattern is not None) and (not re.match(attribute_value_pattern, attribute_value)):
                return False
            return True
        else:
            return False


class DefaultSrcTagToGetPastFiltersThatCheckSrcDomain(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(DefaultSrcTagToGetPastFiltersThatCheckSrcDomain, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("img", {'src': '#'}):
            attr_dict = result.attrs
            for attr_name, attr_value in attr_dict.items():
                if self._xml_attribute_exists_and_pattern_match_check(attr_name, attr_dict, self.start_with_on_pattern):
                    ans.append((self.reporter_output.format(self.rule_description, attr_value, current_file_path), current_file_path))
        return ans


class DefaultSrcTagByLeavingItEmpty(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(DefaultSrcTagByLeavingItEmpty, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("img", {'src': ''}):
            attr_dict = result.attrs
            for attr_name, attr_value in attr_dict.items():
                if self._xml_attribute_exists_and_pattern_match_check(attr_name, attr_dict, self.start_with_on_pattern):
                    ans.append((self.reporter_output.format(self.rule_description, attr_value, current_file_path), current_file_path))
        return ans


class DefaultSrcTagByLeavingItOutEntirely(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(DefaultSrcTagByLeavingItOutEntirely, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("img"):
            attr_dict = result.attrs
            if 'src' not in attr_dict:
                for attr_name, attr_value in attr_dict.items():
                    if self._xml_attribute_exists_and_pattern_match_check(attr_name, attr_dict, self.start_with_on_pattern):
                        ans.append((self.reporter_output.format(self.rule_description, attr_value, current_file_path), current_file_path))
        return ans


class ImageXSSOnErrorAlert(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(ImageXSSOnErrorAlert, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("img", {'src': '/'}):
            attr_dict = result.attrs
            if 'onerror' in attr_dict:
                if self._xml_attribute_exists_and_pattern_match_check('onerror', attr_dict):
                    ans.append((self.reporter_output.format(self.rule_description, attr_dict['onerror'], current_file_path), current_file_path))
        return ans


class ImageXSSUsingJavascriptDirective(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(ImageXSSUsingJavascriptDirective, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("img"):
            attr_dict = result.attrs
            if 'src' in attr_dict:
                if self._xml_attribute_exists_and_pattern_match_check('src', attr_dict, None, self.js_code_pattern):
                    ans.append((self.reporter_output.format(self.rule_description, attr_dict['src'], current_file_path), current_file_path))
        return ans


class ImageDynsrc(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(ImageDynsrc, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("img"):
            attr_dict = result.attrs
            if 'dynsrc' in attr_dict:
                if self._xml_attribute_exists_and_pattern_match_check('dynsrc', attr_dict, None, self.js_code_pattern):
                    ans.append((self.reporter_output.format(self.rule_description, attr_dict['dynsrc'], current_file_path), current_file_path))
        return ans


class ImageLowsrc(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(ImageLowsrc, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("img"):
            attr_dict = result.attrs
            if 'lowsrc' in attr_dict:
                if self._xml_attribute_exists_and_pattern_match_check('lowsrc', attr_dict, None, self.js_code_pattern):
                    ans.append((self.reporter_output.format(self.rule_description, attr_dict['lowsrc'], current_file_path), current_file_path))
        return ans


class MalformedATag(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(MalformedATag, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all('a'):
            attr_dict = result.attrs
            if 'href' not in attr_dict:
                for attr_name, attr_value in attr_dict.items():
                    if self._xml_attribute_exists_and_pattern_match_check(attr_name, attr_dict, self.start_with_on_pattern, None):
                        ans.append((self.reporter_output.format(self.rule_description, attr_value, current_file_path), current_file_path))
        return ans


class IframeAndFrameXSSCheck(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(IframeAndFrameXSSCheck, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all(['iframe', 'frame']):
            attr_dict = result.attrs
            if 'src' in attr_dict:
                if attr_dict['src'] == '#':
                    for attr_name, attr_value in attr_dict.items():
                        if self._xml_attribute_exists_and_pattern_match_check(attr_name, attr_dict,
                                                                              self.start_with_on_pattern, None):
                            ans.append((self.reporter_output.format(self.rule_description, attr_value, current_file_path), current_file_path))
                else:
                    if self._xml_attribute_exists_and_pattern_match_check('src', attr_dict, None, self.js_code_pattern):
                        ans.append((self.reporter_output.format(self.rule_description, attr_dict['src'], current_file_path), current_file_path))
        return ans


class InputTypeImageXSSCheck(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(InputTypeImageXSSCheck, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("input", {"type": re.compile("^image$", re.I)}):
            attr_dict = result.attrs
            if 'src' in attr_dict:
                if self._xml_attribute_exists_and_pattern_match_check('src', attr_dict, None, None):
                    ans.append((self.reporter_output.format(self.rule_description, attr_dict['src'], current_file_path), current_file_path))
        return ans


class BodyTagXSSCheck(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(BodyTagXSSCheck, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("body"):
            attr_dict = result.attrs
            if 'onload' in attr_dict:
                if self._xml_attribute_exists_and_pattern_match_check('onload', attr_dict, None, None):
                    ans.append((self.reporter_output.format(self.rule_description, attr_dict['onload'], current_file_path), current_file_path))
            if 'background' in attr_dict:
                if self._xml_attribute_exists_and_pattern_match_check('background', attr_dict, None, None):
                    ans.append((self.reporter_output.format(self.rule_description, attr_dict['background'], current_file_path), current_file_path))
        return ans


class SvgTagXSSCheck(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(SvgTagXSSCheck, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all("svg"):
            attr_dict = result.attrs
            if 'onload' in attr_dict and self._xml_attribute_exists_and_pattern_match_check('onload', attr_dict, None, None):
                ans.append((self.reporter_output.format(self.rule_description, attr_dict['onload'], current_file_path), current_file_path))
        return ans


class TableAndTdXSSCheck(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(TableAndTdXSSCheck, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all(['table', 'td']):
            attr_dict = result.attrs
            if 'background' in attr_dict and self._xml_attribute_exists_and_pattern_match_check('background', attr_dict, None, None):
                ans.append((self.reporter_output.format(self.rule_description, attr_dict['background'], current_file_path), current_file_path))
        return ans


class LinkXSSCheck(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(LinkXSSCheck, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all('link'):
            attr_dict = result.attrs
            if 'href' in attr_dict and self._xml_attribute_exists_and_pattern_match_check('href', attr_dict, None, self.js_code_pattern):
                ans.append((self.reporter_output.format(self.rule_description, attr_dict['href'], current_file_path), current_file_path))
        return ans


class DivStyleSheetXSSCheck(UserHTMLReflectedXSSDetectRule):

    def __init__(self, rule_description):
        super(DivStyleSheetXSSCheck, self).__init__(rule_description)

    def check_file(self, app, current_file_path, soup):

        ans = []
        for result in soup.find_all('div'):
            attr_dict = result.attrs
            if 'style' in attr_dict and self._xml_attribute_exists_and_pattern_match_check('style', attr_dict, None, 'background-image:\s*url\(javascript:(?!false)[^0].*?'):
                ans.append((self.reporter_output.format(self.rule_description, attr_dict['style'], current_file_path), current_file_path))
        return ans
