from enum import Enum
import csv
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
        addUpdatedStatus(rule, RULE_STATUS.NOCHANGE)
        rulesDicts["ruleName"][ruleName] = (rule, RULE_STATUS.DELETE);

        filePath = rule.find('SigmaFileName').text.strip(' ')
        newfilePath = filePath
        newfilePath = convertOldPath2NewPath(renameFileMap, filePath, ymlfileNames)
        #if filePath != newfilePath:
        #   print("%s,%s" % (filePath, newfilePath))
        newname = newfilePath.split("/")[-1]
        rulesDicts["filePath"][newname.lower()] = ruleName;

        '''
        des = rule.find('Description').text.strip(' ').lower()
        index = des.find(" this rule is adapted from https")
        if index != -1:
           des = des[0:index]
           rulesDicts["ruleDes"][des] = ruleName;
        '''

    return rulesDicts,maxRuleIndex

def loadRenameFileMap():
    fileName = "./tools/config/RenameFileName.csv"
    RenameFileMap = {}

    return RenameFileMap

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

def diffRules(newRule, oldRule):
    errNode = newRule.find("ErrMsg")
    if errNode is not None:
        return True

    groupBy1 = oldRule.find("./PatternClause/SubPattern/GroupByAttr");
    groupbystr1 = "";
    if groupBy1 is not None:
       groupbystr1 = ",".join(sorted(groupBy1.text.replace(" ", "").split(",")))

    ruleconstr1 = oldRule.find("./PatternClause/SubPattern/SingleEvtConstr").text.replace(" ", "")

    groupBy2 = newRule.find("./PatternClause/SubPattern/GroupByAttr");
    groupbystr2=""
    if groupBy2 is not None:
       groupbystr2 = ",".join(sorted(groupBy2.text.replace(" ", "").split(",")))

    ruleconstr2 = newRule.find("./PatternClause/SubPattern/SingleEvtConstr").text.replace(" ", "")

    if ruleconstr1 == ruleconstr2 and groupbystr1 == groupbystr2:
        return False
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
             
             filePath1 = newRule.find('SigmaFileName').text.strip(' ')
             for elem in newRule.iter('SigmaFileName'):
                 elem.text = f"https://github.com/SigmaHQ/sigma/blob/master/{filePath1}"

             if not diffRules(newRule, oldRule):
                 #print("No Change Rule %s" % filePath)
                 #SIGMAStatus = newRule.find('SIGMAStatus')
                 #if SIGMAStatus is not None:
                    # addSigmaStatus(oldRule, SIGMAStatus.text.strip(' '))

                 addUpdatedStatus(newRule, RULE_STATUS.NOCHANGE)
                 filePath = oldRule.find('SigmaFileName').text.strip(' ')
                 filePath1 = newRule.find('SigmaFileName').text.strip(' ')
                 if filePath1 not in filePath:
                     for elem in oldRule.iter('SigmaFileName'):
                         elem.text = filePath1 
                     des = newRule.find('Description').text.strip(' ')
                     for elem in oldRule.iter('Description'):
                         elem.text = des
                     rulesDicts["ruleName"][ruleName] = (oldRule, RULE_STATUS.ONLYLINK)
                 else:
                     rulesDicts["ruleName"][ruleName] = (oldRule, RULE_STATUS.NOCHANGE)

             else: # filterstr1 != filterstr2 or groupbystr1 != groupbystr2:
                 #print("%s\n%s\n%s\n%s" % (filterstr1,filterstr2,groupbystr1,groupbystr2))
                 print("Modified Rule %s" % filePath)
                 finialNewRule = updateAttrFromOldToNew(oldRule, newRule) 
                 addUpdatedStatus(finialNewRule, RULE_STATUS.MODIFIED)
                 rulesDicts["ruleName"][ruleName] = (oldRule, RULE_STATUS.MODIFIED, finialNewRule)
        else:
            ruleIndex = ruleIndex + 1
            #print("New Rule %s" % filePath)
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

    eventType = newRule.find('IncidentTitle')
        
    filePath = newRule.find('SigmaFileName').text.strip(' ')
    des = newRule.find('Description').text.strip(' ')
    des = f"{des}. This rule is adapted from {filePath}"
    newRule.find("Description").text = des;
    dataSrc = oldRule.find('DataSource')
   
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

