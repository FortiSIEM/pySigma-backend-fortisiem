import os
import sys
import csv
import xml.etree.ElementTree as ET
from lxml import etree
from enum import Enum
from tools.updateRule import RULE_STATUS
from tools.updateEventTypeFile import *

def prettyXML(elem):
     if elem is None:
          return "<Rule/>"
     root = etree.XML(ET.tostring(elem))
     content = etree.tostring(root, pretty_print = True, encoding = str)
     return content

def outputStatuRules(rulesDicts, outFile, status):
    if outFile is None:
        return
    
    try:
        out = open(outFile, "w", encoding='utf-8')
    except (IOError, OSError) as e:
        print("Failed to open output file '%s': %s" % (outFile, str(e)), file=sys.stderr)
        exit(-1)

    count = 0
    print("<Rules>", file=out)
    for item in rulesDicts["ruleName"].values():
        if status is None:
           if item[1] != RULE_STATUS.NEW:
              outputRule = item[0]
              if item[1] in (RULE_STATUS.NEW, RULE_STATUS.MODIFIED):
                  if item[2].find("ErrMsg") is not None:
                     continue;
                  outputRule = item[2]
              xmlstr = prettyXML(outputRule)
              count = count + 1
              print(xmlstr, file=out)
        else:# stat == status:
            if item[1] == status and status == RULE_STATUS.MODIFIED:
               newRulexmlstr = prettyXML(item[2])
               oldRulexmlstr = prettyXML(item[0])
               count = count + 1
               print("<!--************************ -->", file=out)
               print(oldRulexmlstr, file=out)
               print(newRulexmlstr, file=out)
            elif item[1] == status:
                outputRule = item[0]
                if status in (RULE_STATUS.NEW, RULE_STATUS.MODIFIED):
                    outputRule = item[2]
                    if item[2].find("ErrMsg") is not None:
                       continue;
                xmlstr = prettyXML(outputRule)
                count = count + 1
                print(xmlstr, file=out)
    print("</Rules>", file=out)
    out.close()
    if status is None:
        print("Total Rules %d" % count)
    else:
        print("%s Rules %d" % (status.name, count))

def outputRules(rulesDicts, outFile):
    if outFile is None:
        return
    
    newRuleFile = None
    modifiedRuleFile = None
    deleteRuleFile = None
    nochangeRuleFile = None
    onlyLinkChanged = None
    errorRuleFile = "SIGMA_error.xml"
    if os.path.isdir(outFile):
        outFile = outFile.rstrip()
        newRuleFile = "%s/SIGMA_new.xml" % (outFile)
        modifiedRuleFile = "%s/SIGMA_modified.xml" % (outFile)
        deleteRuleFile = "%s/SIGMA_deleted.xml" % (outFile)
        nochangeRuleFile= "%s/SIGMA_no_change.xml" % (outFile)
        errorRuleFile = "%s/SIGMA_error.xml" % (outFile)
        onlyLinkChanged = "%s/SIGMA_FileChange.xml" % (outFile)

        #updateEventType(rulesDicts["ruleName"], outFile)
    else:# os.path.isfile(outFile):
        newRuleFile = outFile 
   
    count = 0 
    out = open(errorRuleFile, "w", encoding='utf-8')
    for item in rulesDicts["ruleName"].values():
         if item[1] in (RULE_STATUS.NEW, RULE_STATUS.MODIFIED) and item[2].find("ErrMsg") is not None:
             prettyXML(item[2])
             xmlstr = prettyXML(item[2])
             count = count + 1
             print(xmlstr, file=out)

    print("ERROR Rules %d" % (count))
    out.close()

    if modifiedRuleFile is None:
        outputStatuRules(rulesDicts, newRuleFile, None) 
    else:
        outputStatuRules(rulesDicts, newRuleFile, RULE_STATUS.NEW) 
        outputStatuRules(rulesDicts, nochangeRuleFile, RULE_STATUS.NOCHANGE)
        outputStatuRules(rulesDicts, onlyLinkChanged, RULE_STATUS.ONLYLINK)
        outputStatuRules(rulesDicts, deleteRuleFile, RULE_STATUS.DELETE)
        outputStatuRules(rulesDicts, modifiedRuleFile, RULE_STATUS.MODIFIED)    


def toCsvString(orgStr):
  if orgStr is None:
      csvString = ""
      return csvString

  csvString = orgStr.strip(" ")
  csvString = csvString.replace( "\n", " ");
  if orgStr.find(',') != -1:
     csvString = csvString.replace("\"", "\"\"");
     csvString = "\"%s\"" % csvString;
  return csvString;        

'''
Append some columns in csv
def outputRulesCsv(inputfile, csvFile):
    fileName = ""
    rules = None
    out = open(csvFile, "w", encoding='utf-8')
    print("Rule Id, Rule Name, Use Case, Description, Severity, Enable, SIGMA Status, Data Source, DetectionTechnology, Group, Technique, Tactic, Link, File Name", file=out)
    with open(inputfile, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',')
            for row in spamreader:
                newFileName='../../data-definition/rules/'
                newFileName= newFileName + row[10].strip(" ")

                if newFileName != fileName:
                    fileName = newFileName
                    tree = ET.parse(fileName)
                    root = tree.getroot()
                    rules = root.findall('Rule')
                    print(newFileName)

                ruleId =  row[0].strip(' ')
                print("XX%sXXX" % ruleId)
                for rule in rules:    
                    ruleIndex = rule.get("id").strip(' ')
                      
                    if ruleIndex == ruleId:
                       print("ZZ%sZZZ" % ruleIndex)
                       group  = rule.get("function")
                       if group is not None:
                           group = group.strip(' ')
                       else:
                           group = ""

                       technique = rule.get("technique")
                       if technique is not None:
                           technique = technique.strip(' ')
                       else:
                           technique =""

                       tactic = rule.get("subFunction")
                       if tactic is not None:
                           tactic = tactic.strip(' ')
                       else:
                           tactic = ""

                       print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (toCsvString(row[0]), toCsvString(row[1]), toCsvString(row[2]), toCsvString(row[3]), toCsvString(row[4]), toCsvString(row[5]), toCsvString(row[6]), toCsvString(row[7]), toCsvString(row[8]),toCsvString(group), toCsvString(technique), toCsvString(tactic), toCsvString(row[9]), toCsvString(row[10])), file=out)
                       break
                         
    out.close();
    exit(0)

'''

#RuleId,RuleName,SIGMAStatus,SingleEvtConstr,Descriptiton
def outputRulesCsv(inputs, csvFile):
    filelist = []

    if os.path.isfile(inputs):
        filelist.append(inputs)
    else:
    #is Dir
      tmp= []
      for root, dirs, files in os.walk(inputs):
        for file in files:
            tmp.append(os.path.join(root, file))

      for name in tmp:
        if name.endswith(".xml"):
            filelist.append(name)
    
    out = open(csvFile, "w", encoding='utf-8')
    print("Rule Id, Rule Name, Description, Severity, Enable, SIGMA Status, Data Source, DetectionTechnology, Link, File Name", file=out)
    for RuleFile in filelist:
      fileName = RuleFile.split('/')[-1]
      tree = ET.parse(RuleFile)
      root = tree.getroot()
      for rule in root.findall('Rule'):
        ruleName = toCsvString(rule.find('Name').text)
        ruleIndex = rule.get("id").strip(' ')
        active=""
        if rule.find('active') is not None:
            active = rule.find('active').text.strip(' ')
        severity = rule.find('IncidentDef').get('severity').strip(' ')

        sigmastatus = ""
        if rule.find('SIGMAStatus') is not None:
            sigmastatus = rule.find('SIGMAStatus').text.strip(' ')
        
        filePath=""
        if rule.find('SigmaFileName') is not None:
            filePath = rule.find('SigmaFileName').text.strip(' ')
        des = toCsvString(rule.find('Description').text)

        dataSource=""
        if rule.find('DataSource') is not None:
            dataSource = rule.find('DataSource').text
            dataSource = toCsvString(dataSource)

        detectionTechnology=""
        if detectionTechnology:    
            detectionTechnology = rule.find('DetectionTechnology').text
            detectionTechnology = toCsvString(detectionTechnology)
        #singleEvtConstr  = rule.find("./PatternClause/SubPattern/SingleEvtConstr").text.strip(' ')
        #singleEvtConstr = toCsvString(singleEvtConstr)
        #print("%s,%s,%s,%s,%s" % (ruleIndex, ruleName, sigmastatus, singleEvtConstr, des), file=out)
        #rule id, rule name, Severity, enable/Disable, SIGMA Status
        print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (ruleIndex, ruleName, des, severity, active, sigmastatus, dataSource, detectionTechnology, filePath, fileName), file=out)
    out.close()
    exit(0) 

def outputReportsCsv(inputs, csvFile):
    filelist = []

    if os.path.isfile(inputs):
        filelist.append(inputs)
    else:
    #is Dir
      tmp= []
      for root, dirs, files in os.walk(inputs):
        for file in files:
            tmp.append(os.path.join(root, file))

      for name in tmp:
        if name.endswith(".xml"):
            filelist.append(name)

    out = open(csvFile, "w", encoding='utf-8')
    print("Report Id, Report Name, Description, SingleEvtConstr, GroupBy, File Name", file=out)
    for RuleFile in filelist:
      fileName = RuleFile.split('/')[-1]
      tree = ET.parse(RuleFile)
      root = tree.getroot()
      for rule in root.findall('Report'):
        ruleName = toCsvString(rule.find('Name').text)
        ruleIndex = rule.get("id").strip(' ')
        des = toCsvString(rule.find('Description').text)
        singleEvtConstr  = rule.find("./PatternClause/SubPattern/SingleEvtConstr").text
        if singleEvtConstr:
            singleEvtConstr = toCsvString(singleEvtConstr)

        groupBy = ""
        if rule.find("./PatternClause/SubPattern/GroupByAttr") is not None:
            groupBy = rule.find("./PatternClause/SubPattern/GroupByAttr").text
            if groupBy:
                groupBy= toCsvString(groupBy)

        print("%s,%s,%s,%s,%s,%s" % (ruleIndex, ruleName, des, singleEvtConstr, groupBy, fileName), file=out)
    out.close()
    exit(0)


def getDeletedRulesBetweenTwoFiles(oldRuleFile, newRuleFile, outFile):
    newRuleIdMap = {}
    tree = ET.parse(newRuleFile)
    root = tree.getroot()
    for rule in root.findall('Rule'):
        ruleIndex = rule.get("id").strip(' ')
        newRuleIdMap[ruleIndex] = rule;

    out = open(outFile, "w", encoding='utf-8')
    count = 0 

    tree1 = ET.parse(oldRuleFile)
    root1 = tree1.getroot()
    for rule in root1.findall('Rule'):
        ruleIndex = rule.get("id").strip(' ')
        if ruleIndex in newRuleIdMap.keys():
            continue
        count = count + 1
        ruleName = rule.find('Name').text.strip(' ')
        des = toCsvString(rule.find('Description').text)
        singleEvtConstr  = rule.find("./PatternClause/SubPattern/SingleEvtConstr").text
        singleEvtConstr = toCsvString(singleEvtConstr)
        print("%s,%s,%s,%s" % (ruleIndex, ruleName, singleEvtConstr, des), file=out)

    out.close()
    print("%d deleted rules" % count)

    

    

