from enum import Enum
import csv
import re
import xml.etree.ElementTree as ET
from lxml import etree
import subprocess

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

    renameFileMap = loadRenameFileMap()
    tree = ET.parse(RuleFile)
    root = tree.getroot()
    
    for rule in root.findall('Rule'):
        ruleName = rule.find('Name').text.strip(' ')
        addUpdatedStatus(rule, RULE_STATUS.NOCHANGE)
        filePath = rule.find('SigmaFileName')
        if filePath is None:
            rulesDicts["ruleName"][ruleName.lower()] = (rule, RULE_STATUS.NOCHANGE);
            continue
        filePath = filePath.text.replace("https://github.com/SigmaHQ/sigma/blob/master/", "").strip(' ')
        newfilePath = filePath
        newfilePath = convertOldPath2NewPath(renameFileMap, filePath, ymlfileNames)
        if newfilePath in ymlFileList:
            rulesDicts["filePath"][newfilePath] = ruleName;
            if filePath == newfilePath:
                addUpdatedStatus(rule, RULE_STATUS.NOCHANGE)
                rulesDicts["ruleName"][ruleName.lower()] = (rule, RULE_STATUS.NOCHANGE);
            else:
                updateFileNameInRule(rule, newfilePath)
                addUpdatedStatus(rule, RULE_STATUS.ONLYLINK)
                rulesDicts["ruleName"][ruleName.lower()] = (rule, RULE_STATUS.ONLYLINK);
        else:
            #eventType = rule.find('IncidentDef').get('eventType')
            #cmd = f"sed -i s/{eventType}.*//g /projects/phoenix/data-definition/eventType/phoenix-eventtype.csv"
            #subprocess.run(cmd, shell=True)
            addUpdatedStatus(rule, RULE_STATUS.DELETE)
            rulesDicts["ruleName"][ruleName.lower()] = (rule, RULE_STATUS.DELETE);

    return rulesDicts

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
                    if row[0] == "FULL_FILE_NAME" or row[0] == "FULL_FILE_PATH":
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

    if "FULL_FILE_PATH" in loadRenameFileMap.keys():
        tmp = loadRenameFileMap["FULL_FILE_PATH"]
        if path in tmp.keys():
            print(f"{path}{tmp[path]}")
            return tmp[path]

    if "FULL_FILE_NAME" in loadRenameFileMap.keys():
        tmp = loadRenameFileMap["FULL_FILE_NAME"]
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
     newRule = prepareRule(newRuleXML)
     if newRule is None:
         print("The new rule should not be None")
         exit(-1);
     else:
         
        if filePath in rulesDicts["filePath"].keys(): #update rules
            ruleName = rulesDicts["filePath"][filePath];
        else: #new rules
            nameNode= newRule.find('Name');
            ruleName = filePath;
            if nameNode is not None:
                ruleName = nameNode.text.strip(' ')

        ruleName = ruleName.lower();
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

             if diffRules(newRule, oldRule):
                 # filterstr1 != filterstr2 or groupbystr1 != groupbystr2:
                 updateFileNameInRule(newRule, filePath)
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

def prepareRule(ruleXML):
    rule = ET.fromstring(ruleXML)
    if rule is None:
        return None

    ruleConstr = rule.find("./PatternClause/SubPattern/SingleEvtConstr")
    if ruleConstr is not None:
        re_pattarn = r"\beventType(\s*=\s*|\s*!=\s*|\s+(?:NOT\s+)?CONTAIN |\s+(?:NOT\s+)?REGEXP |\s+(?:NOT\s+)?IN | IS | \s+(?:NOT\s+)?BETWEEN )"
        matches = re.search(re_pattarn, ruleConstr.text)
        if not matches:
           ET.SubElement(rule, "ErrMsg")
           rule.find("ErrMsg").text = "There is no eventType"

    return rule

def updateAttrFromOldToNew(oldRule, newRule):
    ruleId = oldRule.get('id');
    for elem in newRule.iter("Rule"):
        elem.set('id', ruleId)
             

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
                    error = "Quote doesn't match."
                    raise NotImplementedError(error)
                    #return remainStr, None, None
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
                    #if oldItem.replace(" ", "") == newItem.replace(" ", ""):
                    if oldItem == newItem:
                        eqCount = eqCount + 1
                        break
        else:
            for newItem in newDict[1]:
                if isinstance(newItem, tuple):
                    if compareDict(oldItem, newItem):
                        eqCount = eqCount + 1
                        break

    return eqCount == len(newDict[1])

def formatAttrOpVal(oneCond):
     part = re.split("(\s*=\s*|\s*!=\s*| CONTAIN | REGEXP | IN | IS | BETWEEN\s*\()", oneCond)
     part[0] = part[0].strip("(")

     attr = part[0].strip(" ")
     attr = re.sub(r"\s+NOT$", " NOT", attr)

     op = ""
     oneCond = oneCond[len(part[0]):].strip(" ")
     index = oneCond.find(" ")
     if oneCond[0] == '=':
         op = "="
         index = 1
     elif oneCond[0:1] == '!=':
         op = "!="
         index = 2
     else:
         op = oneCond[0 : index].strip(" ")

     val = oneCond[index:].strip(" ")
     if op == "CONTAIN":
         pass
     elif op == "REGEXP":
        val = val.strip("\"")
        regex_pattern = r"(?<!\\)\|"
        vals = re.split(regex_pattern, val)
        modified_vals = [re.sub(r"^\.\*|\.\*$", "", val) for val in vals]
        modified_vals = sorted(modified_vals)
        val = "|".join(modified_vals)
        val = f"\"{val}\""
     elif op == "IN":
         val = val[1:-1].strip(" ")
         val = val[1:-1]#remove "
         vals = re.split(r'"\s*,\s*"', val)
         vals = sorted(vals)
         val =  '","'.join(vals)
         val = f'("{val}")'
     elif op == "BETWEEN":
         regex_pattern = r"\"\s*,\s*\""
         replacement = "\",\""
         val = re.sub(regex_pattern, replacement, val)
         val = re.sub(r"\(\s*", "(", val)
         val = re.sub(r"\s*\)", ")", val)
     #oneCond = f"{attr} {op} {val}"
     return attr,op,val

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
                    subFilterList.append(subFilterDict[1][0])
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
                attr,op,val = formatAttrOpVal(oneCond);
                oneCond = f"{attr} {op} {val}"
                currFilterList.append(oneCond)

            remainStr = remainStr.strip(" ")

        #Remove Redundant Parentheses
        #token==""  means only one filter in this current constr
        if  token == "" and (len(currFilterList) + len(subFilterList)) > 1: 
            error = f"OR and AND is missing in {conditionStr}."
            print(error)
            raise NotImplementedError(error)
             

        for item in subFilterList:
            if isinstance(item, str):
                currFilterList.append(item);
                continue;
            elif token == "":#this means only one filter in this current constr
                token, currFilterList = removeRedundantParentheses(item[0], item[1])
                break;
            elif item[0] == "":
                subToken, subFilters = removeRedundantParentheses(item[0], item[1])
                if subToken == "":
                    currFilterList.append(subFilters);
                else:
                    if subToken == token:
                        currFilterList = currFilterList + subFilters
                    else:
                        currFilterList.append((subToken, subFilters));
                continue;
            elif token == item[0]:
                currFilterList = currFilterList + item[1]
            else:
                currFilterList.append(item)

        token,currFilterList = mergeRegex(token, currFilterList);
        return (token,currFilterList)

def removeRedundantParentheses(token, currFilterList):
        if token != "":
            return (token, currFilterList);

        if len(currFilterList) > 1:
            error = f"OR and AND is missing between {currFilterList}"
            print(error)
            raise NotImplementedError(error)

        subItem = currFilterList[0]
        while isinstance(subItem, tuple):
            if subItem[0] != "":  # subItem[0]=="" that means only one filter in this sub constr
                break;
            if len(subItem[1]) > 1:
                error = f"OR and AND is missing between {subItem[1]}."
                print(error)
                raise NotImplementedError(error)
            subItem = subItem[1][0]


        if isinstance(subItem, str):
            return (token, subItem);
        else:
            token = subItem[0];
            currFilterList = subItem[1]
            return (token, currFilterList)

def mergeRegex(token, currFilterList):
        #===================================
        # Merge REGEX 
        #{attr:[val1, val2]}
        regConditon = {}
        newFilterList = []
        for item in currFilterList:
            if isinstance(item, tuple):
               newFilterList.append(item)
               continue
               
            attr,op,val = formatAttrOpVal(item);
            if op != "REGEXP":
                newFilterList.append(item)
                continue;

            if attr not in regConditon.keys():
                regConditon[attr] = []
            regConditon[attr].append(val)

        if len(regConditon) == 0:
              return (token, currFilterList)

        #print(f"token {token}")
        #print(f"currFilterList {currFilterList}")
        #print(f"newFilterList {newFilterList}")
        #print(f"regConditon {regConditon}")
        #print(f"token {token}")

        for attr in regConditon.keys():
               keys = regConditon[attr];
               if len(keys) == 0:
                   continue;
               elif len(keys) == 1:
                   val = regConditon[attr].pop(0)
                   oneCond = f"{attr} REGEXP {val}"
                   newFilterList.append(oneCond)
               elif ( token == " AND " and attr.endswith(" NOT")) or (token == " OR " and not attr.endswith(" NOT") ) :
                   val = "|".join(key.strip('"') for key in keys)
                   oneCond = f"{attr} REGEXP \"{val}\""

                   attr,op,val = formatAttrOpVal(oneCond)
                   oneCond = f"{attr} REGEXP {val}"
                   newFilterList.append(oneCond)
               else:
                   for val in keys:
                       oneCond = f"{attr} REGEXP {val}"
                       newFilterList.append(oneCond)

        #print(f"newFilterList:{newFilterList}")
        return (token, newFilterList)


def diffRules(newRule, oldRule):
    errNode = newRule.find("ErrMsg")
    if errNode is not None:
        return True
    ruleConstr1 = oldRule.find("./PatternClause/SubPattern/SingleEvtConstr").text
    #print("=============")
    #print(f"FFFF{ruleConstr1}")
    oldDict = generateDictFromExpression(ruleConstr1)
    #print(f"DDDD{oldDict}")

    #print("*****************")
    ruleConstr2 = newRule.find("./PatternClause/SubPattern/SingleEvtConstr").text
    #print(f"FFFF{ruleConstr2}")
    newDict = generateDictFromExpression(ruleConstr2)
    #print(f"DDDD{newDict}")
    return not compareDict(oldDict, newDict)


def ruleDictToConstr(ruleDict):
    currFormatedStr = None
    currToken = ruleDict[0]
    currFilterList = ruleDict[1];

    for item in currFilterList:
         substr = None;
         if isinstance(item, str):
             substr = item
             if currFormatedStr is not None:
                currFormatedStr += currToken +  substr;
             else:
                currFormatedStr = substr
         else:
             substr = ruleDictToConstr(item)
             substr = "( " +  substr + " )"
             if currFormatedStr is not None:
                currFormatedStr += currToken + substr;
             else:
                 currFormatedStr = substr
         continue;
    return currFormatedStr;

def prettyConstr(ruleDict, indent=""):
    #ruleDict = {token, currFilterList}
    currFormatedStr = None
    currToken = ruleDict[0]
    currFilterList = ruleDict[1];

    for item in currFilterList:
         substr = None;
         if isinstance(item, str):
             substr = item
             if currFormatedStr is not None:
                currFormatedStr += currToken + "\n" + indent + substr;
             else:
                currFormatedStr = indent + substr
         else:
             substr = prettyConstr(item, indent + "    ")
             substr = "(\n" +  substr + "\n"+ indent +")"
             if currFormatedStr is not None:
                currFormatedStr += currToken + substr;
             else:
                 currFormatedStr = indent + substr
         continue;
    return currFormatedStr;

#CONSTR="(rawEventMsg CONTAIN \"dpapi::masterkey\" OR rawEventMsg CONTAIN \"eo.oe.kiwi\" OR rawEventMsg CONTAIN \"event::clear\" OR rawEventMsg CONTAIN \"event::drop\" OR rawEventMsg CONTAIN \"gentilkiwi.com\" OR rawEventMsg CONTAIN \"kerberos::golden\" OR rawEventMsg CONTAIN \"kerberos::ptc\" OR rawEventMsg CONTAIN \"kerberos::ptt\" OR rawEventMsg CONTAIN \"kerberos::tgt\" OR rawEventMsg CONTAIN \"Kiwi Legit Printer\" OR rawEventMsg CONTAIN \"lsadump::\" OR rawEventMsg CONTAIN \"mimidrv.sys\" OR rawEventMsg CONTAIN \"\mimilib.dll\" OR rawEventMsg CONTAIN \"misc::printnightmare\" OR rawEventMsg CONTAIN \"misc::shadowcopies\" OR rawEventMsg CONTAIN \"misc::skeleton\" OR rawEventMsg CONTAIN \"privilege::backup\" OR rawEventMsg CONTAIN \"privilege::debug\" OR rawEventMsg CONTAIN \"privilege::driver\" OR rawEventMsg CONTAIN \"sekurlsa::\") AND eventType!=\"15\""
#CONSTR="(eventType = \"Win-Security-5136\" AND propName IN (\"gPCMachineExtensionNames\", \"gPCUserExtensionNames\") AND propValue REGEXP \"AADCED64-746C-4633-A97C-D61349046527|CAB54552-DEEA-4691-817E-ED4A4D1AFC72\") OR (eventType = \"Win-Security-5145\" AND fileAccess REGEXP \"%%4417|WriteData\" AND fileName REGEXP \"\\SYSVOL$\" AND targetName REGEXP \"ScheduledTasks\.xml$\")"
#CONSTR="( A=B AND (C=C OR D=D OR G=G) AND (C=C OR D=D OR G=G) ) OR ( A=B AND (C=C OR D=D OR G=G) AND (C=C OR D=D OR G=G) )"
#newDict = generateDictFromExpression(CONSTR)
#formatStr = prettyConstr("", newDict)
#print(formatStr)
