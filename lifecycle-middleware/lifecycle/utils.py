# coding=utf-8

from swift.common.swob import Response
from swift.common.http import HTTP_BAD_REQUEST

import xml.etree.ElementTree as ET
import time
import json
from exceptions import LifecycleConfigurationException


def xmltodict(xml):
    root = ET.fromstring(xml)
    rules = root.findall("Rule")

    rulelist = list()

    if len(rules) > 1000:
        exceptionMsg = dict();
        exceptionMsg['code'] = "OverUploadedRules"
        raise LifecycleConfigurationException(exceptionMsg)

    # TODO prefix 중복 검사 - 서로다른 rule 이여도 prefix가 같고, expire, transition이 각각 설정되어있는 경우를 고려해야함.
    for rule in rules:
        ruledata = dict()

        id = rule.find("ID").text
        prefix = rule.find("Prefix").text
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
            if 'Days' in (expiration or transition) and 'Date' in (expiration and transition):
                exceptionMsg = dict()
                exceptionMsg['status'] = 400
                exceptionMsg['code'] = 'InvalidRequest'
                exceptionMsg['msg'] = 'Found mixed \'Date\' and \'Days\' based Expiration and Transition actions'\
                                      'in lifecycle rule for prefix \'%s\'' % prefix
                raise LifecycleConfigurationException(exceptionMsg)

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
    prevLifecycle = prevLifecycle.replace('\'', '\"')

    prevLifecycle = json.loads(prevLifecycle)
    for curr in currLifecycle:
        currId = curr['ID']

        for prev in prevLifecycle:
            prevId = prev['ID']
            if currId == prevId:
                if 'Transition' in curr.keys() and 'Transition' in prev.keys():
                    curr['Transition']['transition-last-modified'] = str(prev['Transition']['transition-last-modified'])
                    curr['Transition']['transition-propagated'] = str(prev['Transition']['transition-propagated'])
                if 'Expiration' in curr.keys() and 'Expiration' in prev.keys():
                    curr['Expiration']['expiration-last-modified'] = str(prev['Expiration']['expiration-last-modified'])
                    curr['Expiration']['expiration-propagated'] = str(prev['Expiration']['expiration-propagated'])
                break


def validationCheck(rulelist):
    """
    [Reference]
    http://stackoverflow.com/questions/72899/how-do-i-sort-a-list-of-dictionaries-by-values-of-the-dictionary-in-python
    """
    # Prefix를 알파벳 순서대로 정렬
    sortedList = sorted(rulelist, key=lambda k: k['Prefix'].lower())
    length = len(sortedList)
    tmpIndex = None
    for i in range(length - 1):
        basePrefix = sortedList[i]['Prefix']

        if tmpIndex and i < tmpIndex:
            continue

        for j in range(1, length):
            comparePrefix = sortedList[j]['Prefix']

            if basePrefix == comparePrefix:
                exceptionMsg = dict()
                exceptionMsg['status'] = 400
                exceptionMsg['code'] = 'InvalidRequest'
                exceptionMsg['msg'] = 'Found two rules with same prefix \'%s\'' % basePrefix
                raise LifecycleConfigurationException(exceptionMsg)

            if comparePrefix.startswith(basePrefix):
                # 같은  action 으로 설정되어있으면 오류! 다르면 건너뜀
                if 'Transition' in sortedList[i].keys() and 'Transition' in sortedList[j].keys():
                    exceptionMsg = dict()
                    exceptionMsg['status'] = 400
                    exceptionMsg['code'] = 'InvalidRequest'
                    exceptionMsg['msg'] = 'Found overlapping prefixes \'%s\' and \'%s\' ' \
                                          'for same action type \'%s\'' % (basePrefix, comparePrefix, 'Transition')
                    raise LifecycleConfigurationException(exceptionMsg)

                if 'Expiration' in sortedList[i].keys() and 'Expiration' in sortedList[j].keys():
                    exceptionMsg = dict()
                    exceptionMsg['status'] = 400
                    exceptionMsg['code'] = 'InvalidRequest'
                    exceptionMsg['msg'] = 'Found overlapping prefixes \'%s\' and \'%s\' ' \
                                          'for same action type \'%s\'' % (basePrefix, comparePrefix, 'Expiration')
                    raise LifecycleConfigurationException(exceptionMsg)
                tmpIndex = j
        if tmpIndex:
            tmpIndex += 1
