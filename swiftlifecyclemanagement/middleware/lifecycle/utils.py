# coding=utf-8
import dateutil.parser
import xml.etree.ElementTree as ET
import time
from copy import copy

from swiftlifecyclemanagement.common.lifecycle import \
    CONTAINER_LIFECYCLE_SYSMETA, OBJECT_LIFECYCLE_META
from exceptions import LifecycleConfigException


def xml_to_list(xml):
    root = ET.fromstring(xml)
    rules = root.findall("Rule")
    rulelist = list()

    for rule in rules:
        ruledata = dict()

        if rule.find('Prefix') is not None and rule.find('Prefix').text:
            prefix = rule.find("Prefix").text
        else:
            prefix = ''

        if rule.find('ID') is not None and rule.find('ID').text:
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
                                      'Transition actions' \
                                      'in lifecycle rule for prefix \'%s\'' \
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
            actiondic['Date'] = action.find('Date').text
            timetuple = dateutil.parser.parse(actiondic['Date']).timetuple()
            for i in range(3, 6):
                if timetuple[i] == 0:
                    continue
                exceptionMsg = dict()
                exceptionMsg['status'] = 400
                exceptionMsg['code'] = 'InvalidArgument'
                exceptionMsg['msg'] = "'Date' must be at midnight GMT'"
                raise LifecycleConfigException(exceptionMsg)

    if action_name == "Transition":
        actiondic['StorageClass'] = action.find("StorageClass").text

    actiondic['LastModified'] = normalize_timestamp(time.time())
    actiondic['Propagated'] = False

    return actiondic


def normalize_timestamp(timestamp):
    return '%010d' % min(max(0, float(timestamp)), 9999999999)


def _iter_same_id_prefix(lc1, lc2):
    for l1 in lc1:
        for l2 in lc2:
            if l1['ID'] != l2['ID']:
                continue
            if l1['Prefix'] != l2['Prefix']:
                continue
            yield l1, l2


def updateLifecycleMetadata(prevLifecycle, currLifecycle):
    '''
    같은 RULE ID에 대해 내용이 같으면, 이전에 설정된 last-modified 값으로 설정한다.
    :param prevLifecycle:
    :param currLifecycle:
    :return:
    '''
    for prev, curr in _iter_same_id_prefix(prevLifecycle, currLifecycle):
        for key in ('Expiration', 'Transition'):
            prev2 = copy(prev[key]) if key in prev else dict()
            curr2 = copy(curr[key]) if key in curr else dict()

            if len(prev2) == 0 and len(curr2) == 0:
                continue

            if len(prev2) != 0:
                del prev2['LastModified']
                del prev2['Propagated']

            if len(curr2) != 0:
                del curr2['LastModified']
                del curr2['Propagated']

            if len(set(prev2.items()) ^ set(curr2.items())) != 0:
                continue

            curr[key]['LastModified'] = prev[key]['LastModified']
            curr[key]['Propagated'] = prev[key]['Propagated']


def check_lifecycle_validation(rulelist):
    """
    [Reference]
    http://stackoverflow.com/questions/72899/how-do-i-sort-a-list-of-
    dictionaries-by-values-of-the-dictionary-in-python
    """
    # Prefix를 알파벳 순서대로 정렬
    sortedList = sorted(rulelist, key=lambda k: k['Prefix'].lower())
    length = len(sortedList)

    # TODO 1000개가 넘을 경우 정확히 어떤 메세지가 오는지 확인해야함.
    if length > 1000:
        raise Exception

    for base, comp in _iter_list_to_compare(sortedList):
        basePrefix = base['Prefix']
        baseId = base['ID']

        comparePrefix = comp['Prefix']
        compareId = comp['ID']

        if baseId == compareId:
            exceptionMsg = dict()
            exceptionMsg['status'] = 400
            exceptionMsg['code'] = 'InvalidRequest'
            message = '<?xml version="1.0" encoding="UTF-8"?>' \
                      '<Error><Code>InvalidArgument</Code>' \
                      '<Message>Rule ID must be unique. ' \
                      'Found same ID for more than one rule</Message>' \
                      '<ArgumentValue>%s</ArgumentValue>' \
                      '<ArgumentName>ID</ArgumentName>' % baseId
            exceptionMsg['msg'] = message
            raise LifecycleConfigException(exceptionMsg)

        if basePrefix == comparePrefix:
            exceptionMsg = dict()
            exceptionMsg['status'] = 400
            exceptionMsg['code'] = 'InvalidRequest'
            exceptionMsg['msg'] = 'Found two rules with ' \
                                  'same prefix \'%s\'' % basePrefix
            raise LifecycleConfigException(exceptionMsg)

        for key in ('Expiration', 'Transition'):
            # overlapped prefix 에 같은 action이 설정된 경우
            if key in base and key in comp:
                exceptionMsg = dict()
                exceptionMsg['status'] = 400
                exceptionMsg['code'] = 'InvalidRequest'
                exceptionMsg['msg'] = 'Found overlapping prefixes' \
                                      ' \'%s\' and \'%s\' ' \
                                      'for same action type \'%s\'' \
                                      % (basePrefix, comparePrefix, key)
                raise LifecycleConfigException(exceptionMsg)

        # 같은 prefix에 대해, days와 date를 혼용하여 쓸 경우
        action_data = [r[k].keys() for r in (base, comp) for k in (
            'Expiration', 'Transition') if k in r]
        action_data = [i for s in action_data for i in s]
        is_mixed = len(({'Days', 'Date'} - set(action_data)))
        if is_mixed == 0:
            exceptionMsg = dict()
            exceptionMsg['status'] = 400
            exceptionMsg['code'] = 'InvalidRequest'
            exceptionMsg['msg'] = 'Found mixed \'Date\' and \'Days\' ' \
                                  'based Expiration and Transition actions' \
                                  'in lifecycle rule for prefixs \'%s\'' \
                                  'and \'%s\'' % (basePrefix, comparePrefix)
            raise LifecycleConfigException(exceptionMsg)


def _iter_list_to_compare(sortedlist):
    length = len(sortedlist)

    for i in range(length - 1):
        base = sortedlist[i]
        for j in range(i + 1, length):
            comp = sortedlist[j]
            if not comp['Prefix'].startswith(base['Prefix']):
                break
            yield base, comp


def lifecycle_to_xml(rulelist):
    root = ET.Element('LifecycleConfiguration')

    for rule in rulelist:
        rule_to_xmlnode(rule, root)

    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + ET.tostring(root)


def rule_to_xmlnode(rule, root):
    node = ET.SubElement(root, 'Rule')
    for key, value in rule.items():
        if type(value) is dict:
            del rule[key]['LastModified']
            del rule[key]['Propagated']
            action = ET.SubElement(node, key)
            for dickey, dicvalue in value.items():
                child = ET.SubElement(action, dickey)
                child.text = dicvalue
        else:
            child = ET.SubElement(node, key)
            child.text = value


def get_status_int(status):
    return int(status.split(' ', 1)[0])


def is_lifecycle_in_header(headers):
    if CONTAINER_LIFECYCLE_SYSMETA in headers and \
       headers[CONTAINER_LIFECYCLE_SYSMETA] != 'None':
        return True
    return False


def make_object_metadata_from_rule(rule):
    headers = dict()
    headers[OBJECT_LIFECYCLE_META['ID']] = rule['ID']

    for key in ('Expiration', 'Transition'):
        if key not in rule:
            continue
        action = rule[key]
        headers[OBJECT_LIFECYCLE_META[key]] = action['LastModified']

    return headers

