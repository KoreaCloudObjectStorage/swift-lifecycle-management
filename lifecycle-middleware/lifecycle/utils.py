# coding=utf-8

import xml.etree.ElementTree as ET
import time
import ast
import re
import calendar
from datetime import datetime

from exceptions import LifecycleConfigException
from swift.common.utils import normalize_delete_at_timestamp

LifeCycle_Sysmeta = 'X-Container-Sysmeta-S3-Lifecycle-Configuration'
LifeCycle_Response_Header = 'X-Lifecycle-Response'
day_seconds = 86400

outbound_filter = ['X-Object-Meta-Rule-Id',
                   'X-Object-Meta-Expiration-Last-Modified',
                   'X-Object-Meta-Transition-Last-Modified']

def xml_to_list(xml):
    root = ET.fromstring(xml)
    rules = root.findall("Rule")
    rulelist = list()

    # TODO 1000개가 넘을 경우 정확히 어떤 메세지가 오는지 확인해야함.
    if len(rules) > 1000:
        exceptionMsg = dict();
        exceptionMsg['code'] = "OverUploadedRules"
        exceptionMsg['msg'] = "1000"
        raise LifecycleConfigException(exceptionMsg)

    for rule in rules:
        ruledata = dict()

        prefix = rule.find("Prefix").text

        if prefix is None:
            prefix = ''

        if rule.find('ID').text is not None:
            id = rule.find("ID").text
        else:
            id = 'Rule for '
            if prefix == '':
                id += 'the Entire Bucket'
            else:
                id += prefix

        status = rule.find("Status").text

        ruledata.update(ID=id)
        ruledata.update(Prefix=prefix)
        ruledata.update(Status=status)

        transition = parseAction("Transition", rule)
        if transition:
            ruledata['Transition'] = transition

        expiration = parseAction("Expiration", rule)
        if expiration:
            ruledata['Expiration'] = expiration

        if expiration and transition:
            if 'Days' in (expiration or transition) and \
               'Date' in (expiration and transition):
                exceptionMsg = dict()
                exceptionMsg['status'] = 400
                exceptionMsg['code'] = 'InvalidRequest'
                exceptionMsg['msg'] = 'Found mixed \'Date\' and \'Days\' ' \
                                      'based Expiration and ' \
                                      'Transition actions'\
                                      'in lifecycle rule for prefix \'%s\''\
                                      % prefix
                raise LifecycleConfigException(exceptionMsg)

        rulelist.append(ruledata)

    return rulelist


def parseAction(action_name, rule):
    actiondic = dict()
    action = rule.find(action_name)

    if action is None:
        return None

    daysSet = False
    if action.find('Days') is not None:
        actiondic["Days"] = action.find("Days").text
        daysSet = True

    if action.find('Date') is not None:
        # 하나의 action에 days와 date가 동시에 설정 시, days로 설정된다.
        if daysSet is False:
            # TODO Date 가 ISO 8601 Formate 이고 0시로 설정되었는지 검사
            actiondic['Date'] = action.find('Date').text

    if action_name == "Transition":
        actiondic['StorageClass'] = action.find("StorageClass").text

    name = action_name.lower()

    actiondic[name + "-last-modified"] = normalize_timestamp(time.time())
    actiondic[name + "-propagated"] = '0'

    return actiondic


def normalize_timestamp(timestamp):
    return '%010d' % min(max(0, float(timestamp)), 9999999999)


def updateLifecycleMetadata(prevLifecycle, currLifecycle):
    '''
    같은 RULE ID에 대해 내용이 같으면, 이전에 설정된 last-modified 값으로 설정한다.
    :param prevLifecycle:
    :param currLifecycle:
    :return:
    '''

    prevLifecycle = ast.literal_eval(prevLifecycle)
    validationFlg = True
    for prev in prevLifecycle:
        for curr in currLifecycle:
            if curr['ID'] != prev['ID']:
                continue

            for key, value in curr.iteritems():
                if key not in prev:
                    validationFlg = False
                    break
                elif key in prev and type(value) is dict:
                    validationFlg = False
                    if 'Days' in value and 'Days' in prev[key]:
                        validationFlg = True if value['Days'] == \
                                                prev[key]['Days'] else False
                    if 'Date' in value and 'Date' in prev[key]:
                        validationFlg = True if value['Date'] == \
                                                prev[key]['Date'] else False
                    break
                elif key in prev and prev[key] != value:
                    validationFlg = False
                    break

            if validationFlg is True:
                if 'Transition' in curr.keys() and 'Transition' in prev.keys():
                    curr['Transition']['transition-last-modified'] = \
                        str(prev['Transition']['transition-last-modified'])
                    curr['Transition']['transition-propagated'] = \
                        str(prev['Transition']['transition-propagated'])
                if 'Expiration' in curr.keys() and 'Expiration' in prev.keys():
                    curr['Expiration']['expiration-last-modified'] = \
                        str(prev['Expiration']['expiration-last-modified'])
                    curr['Expiration']['expiration-propagated'] = \
                        str(prev['Expiration']['expiration-propagated'])
            validationFlg = True


def validationCheck(rulelist):
    """
    [Reference]
    http://stackoverflow.com/questions/72899/how-do-i-sort-a-list-of-
    dictionaries-by-values-of-the-dictionary-in-python
    """
    # Prefix를 알파벳 순서대로 정렬
    sortedList = sorted(rulelist, key=lambda k: k['Prefix'].lower())
    length = len(sortedList)
    tmpIndex = None
    for i in range(length - 1):
        basePrefix = sortedList[i]['Prefix']
        if tmpIndex and i < tmpIndex:
            continue

        for j in range(i+1, length):
            comparePrefix = sortedList[j]['Prefix']
            if basePrefix == comparePrefix:
                exceptionMsg = dict()
                exceptionMsg['status'] = 400
                exceptionMsg['code'] = 'InvalidRequest'
                exceptionMsg['msg'] = 'Found two rules with ' \
                                      'same prefix \'%s\'' % basePrefix
                raise LifecycleConfigException(exceptionMsg)

            if comparePrefix.startswith(basePrefix):
                # 같은  action 으로 설정되어있으면 오류! 다르면 건너뜀
                if 'Transition' in sortedList[i].keys() and \
                   'Transition' in sortedList[j].keys():
                    exceptionMsg = dict()
                    exceptionMsg['status'] = 400
                    exceptionMsg['code'] = 'InvalidRequest'
                    exceptionMsg['msg'] = 'Found overlapping prefixes' \
                                          ' \'%s\' and \'%s\' ' \
                                          'for same action type \'%s\''\
                                          % (basePrefix, comparePrefix,
                                             'Transition')
                    raise LifecycleConfigException(exceptionMsg)

                if 'Expiration' in sortedList[i].keys() and\
                   'Expiration' in sortedList[j].keys():
                    exceptionMsg = dict()
                    exceptionMsg['status'] = 400
                    exceptionMsg['code'] = 'InvalidRequest'
                    exceptionMsg['msg'] = 'Found overlapping prefixes' \
                                          ' \'%s\' and \'%s\' ' \
                                          'for same action type \'%s\''\
                                          % (basePrefix, comparePrefix,
                                             'Expiration')
                    raise LifecycleConfigException(exceptionMsg)
                tmpIndex = j
        if tmpIndex:
            tmpIndex += 1


def list_to_xml(rulelist):
    root = ET.Element('LifecycleConfiguration')

    for rule in rulelist:
        rulenode = ET.SubElement(root, 'Rule')

        for key, value in rule.items():
            if type(value) is dict:
                action = ET.SubElement(rulenode,key)
                for dickey, dicvalue in value.items():
                    if not dickey.startswith(key.lower()):
                        child = ET.SubElement(action, dickey)
                        child.text = dicvalue
            else:
                child = ET.SubElement(rulenode,key)
                child.text = value

    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + ET.tostring(root)


def dict_to_xml(rule):
    root = ET.Element('LifecycleConfiguration')
    rulenode = ET.SubElement(root, 'Rule')

    for key, value in rule.items():
        if type(value) is dict:
            action = ET.SubElement(rulenode, key)
            for dickey, dicvalue in value.items():
                if not dickey.startswith(key.lower()):
                    child = ET.SubElement(action, dickey)
                    child.text = dicvalue
        else:
            child = ET.SubElement(rulenode,key)
            child.text = value
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + ET.tostring(root)


def get_status_int(status):
    return int(status.split(' ', 1)[0])


def is_Lifecycle_in_Header(headers):
    if LifeCycle_Sysmeta in headers and headers[LifeCycle_Sysmeta] != 'None':
        return True
    return False


def get_lifecycle_headers(rule, current_time):
    headers = dict()
    actionList = dict()

    headers['X-Object-Meta-Rule-Id'] = rule['ID']

    if 'Expiration' in rule:
        expiration = rule['Expiration']
        headers['X-Object-Meta-expiration-last-modified'] = \
            expiration['expiration-last-modified']

        # Date type is ISO 8601
        if 'Date' in expiration:
            #Reference : https://gist.github.com/squioc/3078803
            actionList['expiration'] = calendar.timegm(
                datetime.strptime(expiration['Date'],
                                  "%Y-%m-%dT%H:%M:%S+00:00").timetuple())
        elif 'Days' in expiration:
            actionList['expiration'] =  \
                normalize_delete_at_timestamp(calc_nextDay(current_time) +
                                              int(expiration['Days']) *
                                              day_seconds)

    if 'Transition' in rule:
        transition = rule['Transition']
        headers['X-Object-Meta-transition-last-modified'] = \
            transition['transition-last-modified']
        actionList['transition'] = normalize_delete_at_timestamp(\
            calc_nextDay(current_time) + int(transition['Days']) * day_seconds)

    return headers, actionList


def calc_nextDay(timestamp):
    current = normalize_delete_at_timestamp(int(timestamp) / day_seconds *
                                            day_seconds)
    return int(current) + day_seconds


def lifecycle_filter(header):
    reg = re.compile('|'.join(outbound_filter), re.IGNORECASE).match
    removed = filter(reg, header)

    if removed:
        for r in removed:
            header.pop(r)

    return header