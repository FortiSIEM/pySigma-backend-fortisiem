from enum import Enum
import csv
import re
import xml.etree.ElementTree as ET
from lxml import etree

class RULE_STATUS(Enum):
    NOCHANGE = 1,
    ONLYLINK = 2, 
    MODIFIED = 3,
    NEW = 4,
    DELETE = 5 

def statusToStr(status):
    if status == RULE_STATUS.NOCHANGE:
        return  "No Change"
    elif  status == RULE_STATUS.ONLYLINK:
        return "Only link Change"
    elif  status == RULE_STATUS.MODIFIED:
        return "Modified"
    elif  status == RULE_STATUS.NEW:
        return "New"
    elif  status == RULE_STATUS.DELETE:
        return "Delete"
    else:
        return status.name

def updateLinkOnly(RuleFile, ymlFileList):
    ymlfileNames = {} #filePath---> fileName
    for ymlfilePath in ymlFileList:
        tmp = ymlfilePath.split("/")[-1]
        ymlfileNames[tmp.lower()] = ymlfilePath

    rulesDicts = {}
    rulesDicts["ruleName"] = {}

    renameFileMap = loadRenameFileMap()
    tree = ET.parse(RuleFile)
    root = tree.getroot()
    
    countDel = 0;
    countChange = 0;
    countNoChange = 0;
    for rule in root.findall('Rule'):
        ruleName = ruleName = rule.find('Name').text.strip(' ')
        addUpdatedStatus(rule, RULE_STATUS.NOCHANGE)
        filePath = rule.find('SigmaFileName')
        if filePath is None:
            rulesDicts["ruleName"][ruleName] = (rule, RULE_STATUS.NOCHANGE);
            countNoChange = countNoChange + 1
            continue
        filePath = filePath.text.replace("https://github.com/SigmaHQ/sigma/blob/master/", "").strip(' ')
        newfilePath = filePath
        newfilePath = convertOldPath2NewPath(renameFileMap, filePath, ymlfileNames)
        if newfilePath in ymlFileList:
            if filePath == newfilePath:
                addUpdatedStatus(rule, RULE_STATUS.NOCHANGE)
                rulesDicts["ruleName"][ruleName] = (rule, RULE_STATUS.NOCHANGE);
                countNoChange = countNoChange + 1
            else:
                countChange = countChange + 1
                updateFileNameInRule(rule, newfilePath)
                addUpdatedStatus(rule, RULE_STATUS.ONLYLINK)
                rulesDicts["ruleName"][ruleName] = (rule, RULE_STATUS.ONLYLINK);
        else:
            countDel = countDel + 1
            addUpdatedStatus(rule, RULE_STATUS.DELETE)
            rulesDicts["ruleName"][ruleName] = (rule, RULE_STATUS.DELETE);
    print(f"No Change {countNoChange}")
    print(f"Only link Change {countChange}")
    print(f"Delete {countDel}")
    return rulesDicts

def loadRulesXML(RuleFile, ymlFileList):
    ymlfileNames = {} #filePath---> fileName
    for ymlfilePath in ymlFileList:
        tmp = ymlfilePath.split("/")[-1]
        ymlfileNames[tmp.lower()] = ymlfilePath

    rulesDicts = {}
    rulesDicts["ruleName"] = {}
    rulesDicts["filePath"] = {}
    rulesDicts["ruleDes"] = {}

    maxRuleIndex = 0
    if RuleFile is None:
       return rulesDicts, maxRuleIndex

    renameFileMap = loadRenameFileMap()
    tree = ET.parse(RuleFile)
    root = tree.getroot()

    for rule in root.findall('Rule'):
        ruleName = rule.find('Name').text.strip(' ')
        ruleName = ruleName.lower();
        index = int(rule.get("id").split("_")[-1].strip(' '))
        if index > maxRuleIndex:
            maxRuleIndex = index
        addUpdatedStatus(rule, RULE_STATUS.DELETE)

        filePath = rule.find('SigmaFileName').text.strip(' ')
        newfilePath = filePath
        newfilePath = convertOldPath2NewPath(renameFileMap, filePath, ymlfileNames)

        newname = newfilePath.split("/")[-1]
        rulesDicts["filePath"][newname.lower()] = ruleName;
        rulesDicts["ruleName"][ruleName] = (rule, RULE_STATUS.DELETE);
    return rulesDicts,maxRuleIndex

def updateFileNameInRule(rule, newFilePath):
     for e in rule.iter("SigmaFileName"):
        e.text = f"https://github.com/SigmaHQ/sigma/blob/master/{newFilePath}"

     for e in rule.iter("Description"):
         index = e.text.lower().find(" this rule is adapted from https")
         des = e.text
         index = des.lower().find(" this rule is adapted from https")
         if index != -1:
             des = des[0:index]
         e.text = f"{des}. This rule is adapted from  https://github.com/SigmaHQ/sigma/blob/master/{newFilePath}"


def loadRenameFileMap():
    fileName = "./tools/config/RenameFileName.csv"
    RenameFileMap = {}

    with open(fileName, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',')
            for row in spamreader:
                if len(row) == 3:
                    if row[0] == "FULLPATH":
                        if row[0] not in RenameFileMap.keys():
                            RenameFileMap[row[0]] = {}
                        RenameFileMap[row[0]][row[1]]=row[2];
                    else:
                        if row[0] not in RenameFileMap.keys():
                            RenameFileMap[row[0]] = []
                        pair = (row[1], row[2])
                        RenameFileMap[row[0]].append(pair)
    return RenameFileMap

def convertOldPath2NewPath(loadRenameFileMap, path, filelist):
    attrs = path.strip(' ').split("/")
    folder = attrs[-2].lower()
    fileName = attrs[-1].lower()
    if fileName in filelist.keys():
        return filelist[fileName]

    if "FULLPATH" in loadRenameFileMap.keys():
        tmp = loadRenameFileMap["FULLPATH"]
        if attrs[-1] in tmp.keys():
            fileName = tmp[attrs[-1]]
            if fileName in filelist.keys():
                return filelist[fileName]

    if folder in loadRenameFileMap.keys():
         tmp = loadRenameFileMap[folder]
         for item in tmp:
             fileName = ""
             if item[0] == "START":
                 fileName = "%s%s" % (item[1], attrs[-1])
             else:
                fileName = attrs[-1].replace(item[0], item[1])

             if fileName in filelist.keys():
                return filelist[fileName]
    return path

def shouldUpdated(oldRule):
    ignoreUpdate = oldRule.find("ignoreSIGMAUpdate")
    if ignoreUpdate is None:
       return True

    if ignoreUpdate.text.strip(' ').lower() == "true":
       return False
    else:
       return True

def addUpdatedStatus(rule, status):
    node = rule.find("SIGMAUpdateStatus")
    if node is None:
       ET.SubElement(rule, "SIGMAUpdateStatus")
    rule.find("SIGMAUpdateStatus").text = statusToStr(status)

def addSigmaStatus(rule, status):
    node = rule.find("SIGMAStatus")
    if node is None:
       ET.SubElement(rule, "SIGMAStatus")
    rule.find("SIGMAStatus").text = status

def addNewRule(rulesDicts, newRuleXML : str, filePath, ruleIndex):
     newRule = ET.fromstring(newRuleXML)
     if newRule is None:
         print("The new rule should not be None")
         exit(-1);
     else:
        fileName = filePath.split("/")[-1]
        if fileName.lower() in rulesDicts["filePath"].keys():
            ruleName = rulesDicts["filePath"][fileName];
        else:
            nameNode= newRule.find('Name');
            ruleName = filePath;
            if nameNode is not None:
                ruleName = nameNode.text.strip(' ')


        ruleName = ruleName.lower();

        '''
        if ruleName not in rulesDicts["ruleName"].keys():
           desNode= newRule.find('Description');
           if desNode is not None:
                des = desNode.text.strip(' ').lower()
                index = des.find(" this rule is adapted from https")
                if index != -1:
                    des = des[0:index]

                if des in rulesDicts["ruleDes"]:
                   ruleName = rulesDicts["ruleDes"][des]
         '''
        if ruleName in rulesDicts["ruleName"].keys() and rulesDicts["ruleName"][ruleName][0] is not None:
             oldRule = rulesDicts["ruleName"][ruleName][0]

             if not shouldUpdated(oldRule):
                 #print("No Change Rule %s" % filePath)
                 addUpdatedStatus(oldRule, RULE_STATUS.NOCHANGE)
                 rulesDicts["ruleName"][ruleName] = (oldRule, RULE_STATUS.NOCHANGE)
                 return ruleIndex

             if newRule.find("ErrMsg") is not None:
                #print("Modified Rule %s" % filePath)
                rulesDicts["ruleName"][ruleName] = (oldRule, RULE_STATUS.MODIFIED, newRule)
                return ruleIndex;

             ruleId = oldRule.get('id');
             newRule.set('id', ruleId)
             
             oldFilePath = oldRule.find('SigmaFileName').text.strip(' ')
             newFilePath = newRule.find('SigmaFileName').text.strip(' ')
            
             updateFileNameInRule(oldRule, newFilePath)
             updateFileNameInRule(newRule, newFilePath)
                 
             if not diffRules(newRule, oldRule):
                 if newFilePath not in oldFilePath:
                     addUpdatedStatus(newRule, RULE_STATUS.ONLYLINK)
                     rulesDicts["ruleName"][ruleName] = (oldRule, RULE_STATUS.ONLYLINK)
                 else:
                     addUpdatedStatus(newRule, RULE_STATUS.NOCHANGE)
                     rulesDicts["ruleName"][ruleName] = (oldRule, RULE_STATUS.NOCHANGE)

             else: # filterstr1 != filterstr2 or groupbystr1 != groupbystr2:
                 finialNewRule = updateAttrFromOldToNew(oldRule, newRule) 
                 addUpdatedStatus(finialNewRule, RULE_STATUS.MODIFIED)
                 rulesDicts["ruleName"][ruleName] = (oldRule, RULE_STATUS.MODIFIED, finialNewRule)
        else:
            ruleIndex = ruleIndex + 1

            newFilePath = newRule.find('SigmaFileName').text.strip(' ')
            updateFileNameInRule(newRule, newFilePath)

            addUpdatedStatus(newRule, RULE_STATUS.NEW)
            rulesDicts["ruleName"][ruleName] = (None, RULE_STATUS.NEW, newRule)
        return ruleIndex

def updateAttrFromOldToNew(oldRule, newRule):
    eventType = oldRule.find('IncidentDef').get('eventType')
    for elem in newRule.iter('IncidentDef'):
        elem.set('eventType', eventType)

    IncidentTitle  = oldRule.find('IncidentTitle')
    if IncidentTitle is not None:
        if "on $hostName" in IncidentTitle.text:
             for e in newRule.iter("IncidentTitle"):
                 e.text = e.text.strip(' ') + " on $hostName"

    origNewRule = newRule;
    newRule = oldRule;

    for newElem in origNewRule.iter():
        for e in newRule.iter(newElem.tag):
            if newElem.text is not None:
                e.text = newElem.text
            if newElem.attrib is None:
                continue

            for name, value in newElem.attrib.items():
                elem.set(name, value)
    return newRule

def getQuoteStr(conditionStr):
        nextIndex = 1;
        while(nextIndex < len(conditionStr)):
            if conditionStr[nextIndex]== '\\':
                nextIndex = nextIndex + 2
            elif conditionStr[nextIndex]== '"':
                return nextIndex
            else:
                nextIndex = nextIndex + 1
        error = "Doubel quote doesn't match."
        raise NotImplementedError(error)

def getFilter(conditionStr):
       x = re.split(" (?:AND|OR) ", conditionStr)
       if len(x) == 1:
           return conditionStr, ""

       nextIndex = 0;
       inQuoteStr = False
       while(nextIndex < len(conditionStr)):
            if conditionStr[nextIndex]== '"':
                nextQuoteIndex = getQuoteStr(conditionStr[nextIndex:])
                if not nextQuoteIndex:
                    print(f"Quote doesn't match in {conditionStr}")
                    return remainStr, None
                nextIndex = nextIndex + nextQuoteIndex
            else:
                if conditionStr[nextIndex:].startswith(" AND ") or conditionStr[nextIndex:].startswith(" OR "):
                    return conditionStr[0: nextIndex], conditionStr[nextIndex:].strip(" ")

            nextIndex = nextIndex + 1
       return conditionStr, "";

def getParenthesesExpression(conditionStr):
        count = 1;
        nextIndex = 1;
        remainStr = "";
        currDict = ()
        while(nextIndex < len(conditionStr)):
            if conditionStr[nextIndex]== '"':
                nextQuoteIndex = getQuoteStr(conditionStr[nextIndex:])
                if not nextQuoteIndex:
                    return remainStr, None
                nextIndex = nextIndex + nextQuoteIndex
            elif conditionStr[nextIndex]== '(':
                count = count + 1
            elif conditionStr[nextIndex]== ')':
                count = count - 1;
                if count == 0:
                    remainStr = conditionStr[ nextIndex + 1:]
                    currDict = generateDictFromExpression(conditionStr[1:nextIndex])
                    break

            nextIndex = nextIndex + 1

        if count > 0:
            error = "Parentheses doesn't match."
            raise NotImplementedError(error)

        return currDict, remainStr.strip(" ")

def compareDict(oldDict, newDict):
    if oldDict[0] != newDict[0]:
        return False

    if len(oldDict[1]) !=  len(newDict[1]):
        return False
    
    eqCount = 0; 
    for oldItem in oldDict[1]:
        if isinstance(oldItem, str):
            for newItem in newDict[1]:
                if isinstance(newItem, str):
                    if oldItem.replace(" ", "") == newItem.replace(" ", ""):
                        eqCount = eqCount + 1
                        break
        else:
            for newItem in newDict[1]:
                if isinstance(newItem, tuple):
                    if compareDict(oldItem, newItem):
                        eqCount = eqCount + 1
                        break

    return eqCount == len(newDict[1])

def generateDictFromExpression(conditionStr):
        remainStr = str(conditionStr).strip(" ");
        currDict = ()
        currFilterList = []
        token = ""

        subFilterList = []
        while remainStr != "":
            if remainStr[0] == '(':
                subFilterDict, remainStr = getParenthesesExpression(remainStr)
                if subFilterDict is None:
                    continue;
                if len(subFilterDict[1]) == 0:
                    continue;
                elif len(subFilterDict[1]) == 1:
                    currFilterList.append(subFilterDict[1][0])
                    continue;
                else:
                    subFilterList.append(subFilterDict)
            elif remainStr.startswith("AND "):
                token = " AND "
                remainStr = remainStr[4:]
            elif remainStr.startswith("OR "):
                token = " OR "
                remainStr = remainStr[3:]
            else: 
                oneCond, remainStr = getFilter(remainStr)
                part = re.split("(\s*=\s*| CONTAIN | REGEXP | IN | IS | BETWEEN )", oneCond)
                attr = part[0].strip(" ")

                op = ""
                oneCond = oneCond[len(part[0]):].strip(" ")
                index = oneCond.find(" ")
                if oneCond[0] == '=':
                    op = "="
                    index = 1
                else:
                    op = oneCond[0 : index].strip(" ")

                val = oneCond[index:].strip(" ")
                oneCond = f"{attr} {op} {val}"
                currFilterList.append(oneCond.strip(" "))

            remainStr = remainStr.strip(" ")

        for item in subFilterList:
            if token == item[0]:
                currFilterList = currFilterList + item[1]
            else:
                currFilterList.append(item)

        if len(currFilterList) == 0:
               return None
           
        return (token, currFilterList)


def diffRules(newRule, oldRule):
    errNode = newRule.find("ErrMsg")
    if errNode is not None:
        return True
    ruleConstr1 = oldRule.find("./PatternClause/SubPattern/SingleEvtConstr").text
    oldDict = generateDictFromExpression(ruleConstr1)

    ruleConstr2 = newRule.find("./PatternClause/SubPattern/SingleEvtConstr").text
    newDict = generateDictFromExpression(ruleConstr2)
    return not compareDict(oldDict, newDict)
