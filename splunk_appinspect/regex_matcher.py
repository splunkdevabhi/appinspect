# Copyright 2018 Splunk Inc. All rights reserved.

# Python Standard Libraries
import logging
import re
import os

# Custom Libraries
import inspected_file

logger = logging.getLogger(__name__)


class RegexMatcher(object):

    MESSAGE_LIMIT = 80

    def __init__(self, regex_list):
        self.__regex_list = regex_list
        self.has_valid_files = False

    def match(self, string, regex_option=0):
        ''' return all match results in sorted order '''
        ans = []
        for regex in self.__regex_list:
            pattern = re.compile(regex, regex_option)
            result = re.finditer(pattern, string)
            for match_result in result:
                ans.append(self._get_match_result(match_result))
        ans.sort()
        return ans

    def match_string_array(self, string_array, regex_option=0):
        ''' return all match results in (lineno, result) tuple and in sorted order '''
        ans = []
        for regex in self.__regex_list:
            pattern = re.compile(regex, regex_option)
            for index, string in enumerate(string_array):
                result = re.finditer(pattern, string)
                for match_result in result:
                    ans.append((index + 1, self._get_match_result(match_result)))
        ans.sort()
        return ans

    def match_file(self, filepath, regex_option=0, excluded_comments=True):
        ''' return all match results in (lineno, result) tuple and in sorted order '''
        if not os.path.exists(filepath):
            return []

        ans = []
        patterns = []
        for regex in self.__regex_list:
            patterns.append(regex)

        file_to_inspect = inspected_file.InspectedFile.factory(filepath)
        matches = file_to_inspect.search_for_patterns(patterns,
                                                      excluded_comments=excluded_comments,
                                                      regex_option=regex_option)

        for fileref_output, file_match in matches:
            lineno = fileref_output.rsplit(":", 1)[1]
            ans.append((int(lineno), self._get_match_result(file_match)))

        ans.sort()
        return ans

    def match_results_iterator(self, app_dir, file_iterator, regex_option=0, excluded_comments=True):
        directory = _empty = object()
        for directory, filename, ext in file_iterator:
            absolute_path = os.path.join(app_dir, directory, filename)
            file_path = os.path.join(directory, filename)
            match_result = self.match_file(filepath=absolute_path,
                                           regex_option=regex_option,
                                           excluded_comments=excluded_comments)
            result_dict = {}
            # dedup result in one line
            for lineno, result in match_result:
                if lineno not in result_dict:
                    result_dict[lineno] = set()
                result_dict[lineno].add(result)
            for lineno, result_set in result_dict.items():
                for result in result_set:
                    yield result, file_path, lineno

        if directory != _empty:
            self.has_valid_files = True

    def _get_match_result(self, match_result):
        raw_result = match_result.group(0)
        if len(raw_result) <= self.MESSAGE_LIMIT:
            return raw_result
        else:
            # concatenate sub-groups together
            result = '...'.join(filter(lambda group: len(group) <= self.MESSAGE_LIMIT, match_result.groups()))
            # sub-groups are defined in regex
            if result != '':
                result = '...' + result + '...'
            else:
                result = raw_result[0 : self.MESSAGE_LIMIT] + '...'
            return result

class JSInsecureHttpRequestMatcher(RegexMatcher):

    def __init__(self):

        possible_insecure_http_request_regex_patterns = [
            '\w{1,10}\.open\s*\(\s*[\"\'](GET|POST)[\"\']\s*,\s*((?![\"\']https://)[\w.:/\-\"\']+).*?\)',
            '(\$|jQuery)\.(get|post|getJSON|getScript)\s*\(\s*((?![\"\']https://)[\w.:/\-\"\']+).*?\)',
            '(http|request|axios|superagent|fly|got)\.(get|post)\s*\(\s*((?![\"\']https://)[\w.:/\-\"\']+).*?\)',
            '(\$|jQuery)\.ajax(?![\w.])\s*[(]?']
        super(JSInsecureHttpRequestMatcher, self).__init__(possible_insecure_http_request_regex_patterns)


class JSIFrameMatcher(RegexMatcher):

    def __init__(self):

        possible_iframe_regex_patterns = [
            '(<iframe[^>]*src=[\'"]([^\'">]*)[\'"][^>]*>)'
        ]
        super(JSIFrameMatcher, self).__init__(possible_iframe_regex_patterns)


class JSConsoleLogMatcher(RegexMatcher):
    def __init__(self):
        possible_console_log_regex_patterns = [
            'console.log\([^)]*(pass|passwd|password|token|auth|priv|access|secret|login|community|key|privpass)[^)]*\)'
        ]
        super(JSConsoleLogMatcher, self).__init__(possible_console_log_regex_patterns)


class JSRemoteCodeExecutionMatcher(RegexMatcher):

    def __init__(self):

        # use {0,50} to avoid matching a very long eval string
        possible_remote_code_execution_regex_patterns = [
            '(\$|\w{1,10})\.globalEval\s*\([^)]{0,50}',
            'eval\s*\([^)]{0,50}'
        ]
        super(JSRemoteCodeExecutionMatcher, self).__init__(possible_remote_code_execution_regex_patterns)


class JSWeakEncryptionMatcher(RegexMatcher):
    def __init__(self):
        weak_encryption_regex_patterns = [
            'CryptoJS\s*\.\s*(DES\s*\.\s*encrypt|MD5|SHA1)'
        ]
        super(JSWeakEncryptionMatcher, self).__init__(weak_encryption_regex_patterns)


class JSUDPCommunicationMatcher(RegexMatcher):
    def __init__(self):
        udp_communication_regex_patterns = [
            'getUserMedia',
            'RTCPeerConnection',
            'UDPSocket',
            'chrome.sockets.udp',
        ]
        super(JSUDPCommunicationMatcher, self).__init__(udp_communication_regex_patterns)


class JSReflectedXSSMatcher(RegexMatcher):

    def __init__(self):
        reflected_xss_regex_patterns = [
            '<img[ ]+(dynsrc|lowsrc|src)\s*=\s*[\"\' ]javascript:(?!false)[^0].*?>',
            '<(bgsound|iframe|frame)[ ]+src\s*=\s*[\"\' ]javascript:(?!false)[^0].*?>',
            '<a\s*(on.*)\s*=.*?>',
            '<img """><script>.*?</script>">',
            '<img[ ]+(on.*?)\s*=.*?>',
            '<(img|iframe)[ ]+src\s*=\s*#\s*(on.*)\s*=.*?>',
            '<img[ ]+src\s*=\s*(on.*)\s*=.*?>',
            '<img[ ]+src\s*=\s*/\s*onerror\s*=.*?>',
            '<input[ ]+type\s*=\s*[\"\']image[\"\']\s*src\s*=\s*[\"\']javascript:(?!false)[^0].*?>',
            '<(body|table|td)[ ]+background\s*=\s*[\"\']javascript:(?!false)[^0].*?>',
            '<svg[ ]+onload\s*=.*?>',
            '<body\s*ONLOAD\s*=.*?>',
            '<br[ ]+size\s*=\s*[\"\']&\{.*?\}[\"\']>',
            '<link[ ]+href\s*=\s*[\"\']javascript:(?!false)[^0].*?>',
            '<div\s*style\s*=\s*[\"\']background-image:\s*url\(javascript:(?!false)[^0].*?>'
        ]
        super(JSReflectedXSSMatcher, self).__init__(reflected_xss_regex_patterns)


class ConfEndpointMatcher(RegexMatcher):
    def __init__(self):
        conf_endpoint_regex_patterns = [
            'servicesNS/\S*configs/\S*conf-\S*/\S*',
            'services/configs/conf-\S*/\S*',
            'services/properties/\S*/\S*'
        ]
        super(ConfEndpointMatcher, self).__init__(conf_endpoint_regex_patterns)
