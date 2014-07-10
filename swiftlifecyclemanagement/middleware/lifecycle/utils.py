# coding=utf-8

import xml.etree.ElementTree as ET
import time
import ast
import calendar
from datetime import datetime
from swift.common.utils import normalize_delete_at_timestamp

from swiftlifecyclemanagement.common.lifecycle import CONTAINER_LIFECYCLE_SYSMETA, OBJECT_LIFECYCLE_META
from exceptions import LifecycleConfigException


day_seconds = 86400

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


def _iter_same_id(lc1, lc2):
    for l1 in lc1:
        for l2 in lc2:
            if l1['ID'] != l2['ID']:
                continue
            yield l1, l2


def _to_prev_info(_to, _from):
    for key, value in _from.iteritems():
        if not key.endswith('modified') and not key.endswith('propagated'):
            continue
        _to[key] = value


def updateLifecycleMetadata(prevLifecycle, currLifecycle):
    '''
    같은 RULE ID에 대해 내용이 같으면, 이전에 설정된 last-modified 값으로 설정한다.
    :param prevLifecycle:
    :param currLifecycle:
    :return:
    '''
    for prev, curr in _iter_same_id(prevLifecycle, currLifecycle):
        for key, value in curr.iteritems():
            if key not in prev:
                continue
            if type(value) is not dict:
                continue

            to_check = None
            if 'Days' in value and 'Days' in prev[key]:
                to_check = 'Days'
            elif 'Date' in value and 'Date' in prev[key]:
                to_check = 'Date'

            if not to_check:
                continue

            if value[to_check] == prev[key][to_check]:
                _to_prev_info(curr[key], prev[key])


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


def is_lifecycle_in_header(headers):
    if CONTAINER_LIFECYCLE_SYSMETA in headers and \
       headers[CONTAINER_LIFECYCLE_SYSMETA] != 'None':
        return True
    return False


def make_object_metadata_from_rule(rule):
    headers = dict()
    headers[OBJECT_LIFECYCLE_META['id']] = rule['ID']
    if 'Expiration' in rule:
        expiration = rule['Expiration']
        headers[OBJECT_LIFECYCLE_META['expire-last']] = \
            expiration['expiration-last-modified']

    if 'Transition' in rule:
        transition = rule['Transition']
        headers[OBJECT_LIFECYCLE_META['transition-last']] = \
            transition['transition-last-modified']
    return headers


def calc_nextDay(timestamp):
    current = normalize_delete_at_timestamp(int(timestamp) / day_seconds *
                                            day_seconds)
    return int(current) + day_seconds
