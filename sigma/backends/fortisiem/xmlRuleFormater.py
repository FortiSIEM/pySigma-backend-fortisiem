import sys
import re
import copy
import xml.etree.ElementTree as ET
from lxml import etree
from sigma.rule import SigmaRule,SigmaDetection,SigmaLevel
from sigma.pipelines.fortisiem.config import FortisiemConfig
class FortisiemXMLRuleFormater:
    ruleRoot =None 

    ruleId = None;
    yml_file_name = None
    config = None

    def __init__(self, config: FortisiemConfig, file_name, ruleId):
        self.ruleId = ruleId;
        self.yml_file_name = file_name
        self.config = config


    def formatDescription(self, des):
        des = des.replace('\n', ' ')
        return des

    def formatRuleName(self, name, product):
        #ruleName has invalid characters. It only accepts: a-zA-Z0-9 \/:.$-
        ruleName = re.sub('\s*[^a-zA-Z0-9 \/:.$_\'\"-]+\s*', ' ', name)
        ruleName = re.sub('_', '-', ruleName)
        ruleName = re.sub('[\'"\(\)+,]*', '', ruleName)

        if product != "windows":
            return ruleName

        ruleName = "Windows: %s" % ruleName
        if "Windows: Invoke-Obfuscation" in ruleName or "Windows: Moriya Rootkit" in ruleName:
            match = re.search(r"^.*( - \S+)$", ruleName)
            if match:
               name = match.group(1)
               if name.lower() in (" - security"):
                  ruleName = ruleName.replace(name, ": Security Log")
               elif name.lower() in (" - system"):
                  ruleName = ruleName.replace(name, ": System Log")
            else: 
               ruleName = "%s: Sysmon" % ruleName

        return ruleName

    def formatRuleEventType(self, ruleET):
        #rule event type has invalid characters. It only accepts: A-z,0-9,_
        ruleET = re.sub('\W+', '_', ruleET)
        ruleET = re.sub('_+', '_', ruleET)
        ruleET = ruleET.strip('_')
        return ruleET

    def formatRuleTitle(self, name):
        #IncidentTitle has invalid characters. It only accepts: a-zA-Z0-9 _$-
        titleName = re.sub('\s*[^a-zA-Z0-9 _-]+\s*', ' ', name)
        return titleName;

    def formatRuleEvtType(self, name):
        #IncidentTitle has invalid characters. It only accepts: a-zA-Z0-9 _$-
        tmp = re.sub('\s*[^a-zA-Z0-9 _]+\s*', ' ', name)
        tmp = tmp.replace(" ", "_")
        ruleEvtType="PH_RULE_%s" % tmp
        return ruleEvtType

    def setymlfile(self, yml_file_name):
        self.yml_file_name = yml_file_name

    def getymlfile(self):
        return self.yml_file_name

    def getElemText(self, elemName):
        for elem in self.ruleRoot.iter(elemName):
            return elem.text
            
    def getElemAttr(self, elemName, attrName):
        for elem in self.ruleRoot.iter(elemName):
            return elem.get(attrName)

    def setElemText(self, elemName, text):
        for elem in self.ruleRoot.iter(elemName):
            elem.text = text

    def setElemAttr(self, elemName, attrName, attrVal):
        for elem in self.ruleRoot.iter(elemName):
            elem.set(attrName, attrVal)

    def addAnElem(self, paraElem, chileElemName):
        for elem in self.ruleRoot.iter(paraElem):
            ET.SubElement(elem, chileElemName)

    def formatGroupName(self, groupname):
        return groupname

    def getRuleId(self):
        return self.ruleId;

    def formatSubFunctionAndTechniqueId(self, techniqueIds):
        sub_function_str = "Persistence";
        technique_str = None
        techniqueIds = sorted(techniqueIds)
        if len(techniqueIds) == 0:
           return sub_function_str, technique_str

        for item in techniqueIds:
            tmp = self.config.technique_dict.get(item, None)
            if tmp is None:
                item = "%s.0001" % item
                tmp = self.config.technique_dict.get(item, None)
                if tmp is None:
                    continue
            technique_str = ",%s" % item;
            tmp = tmp.split(",")
            sub_function_str = tmp[0];

        if technique_str is not None:
           technique_str = technique_str[1:]
        return sub_function_str, technique_str

    def generateRuleHeader(self, sigma_ruleTags):
        rulename = self.formatGroupName("PH_SYS_RULE_THREAT_HUNTING")
        tags = set()
        for item in sigma_ruleTags:
            tags.add(item.name)

        technique = []
        for tag in tags:
            match = re.search('(t|T)(\d+\.\d+|\d+)\s*', tag)
            if match is not None:
                tag = tag[1:]
                technique.append("T%s" % tag)
            else:
                match = re.search('\d', tag)
                if match is not None:
                    continue
                tag = re.sub('_',' ', tag).title()
        
        sub_function_str, technique_str= self.formatSubFunctionAndTechniqueId(technique)

        result = None
        self.ruleRoot.set('group', rulename)
        if self.ruleId:
            self.ruleRoot.set('id', str(self.ruleId))
        self.ruleRoot.set('phIncidentCategory', 'Server' )
        self.ruleRoot.set('function', "Security")
        self.ruleRoot.set('subFunction', sub_function_str )
        if technique_str is not None:
            self.ruleRoot.set('technique', technique_str )

    def generateRuleCommonPart(self, name, description, status, product):
        curRuleName = self.formatRuleName(name, product)
        curTitleName = self.formatRuleTitle(name)

        ET.SubElement(self.ruleRoot, "Name")
        ET.SubElement(self.ruleRoot, "IncidentTitle")
        ET.SubElement(self.ruleRoot, "active")
        ET.SubElement(self.ruleRoot, "Description")
        ET.SubElement(self.ruleRoot, "DetectionTechnology")
        self.setElemText("Name", curRuleName)
        self.setElemText("IncidentTitle", curTitleName)
        self.setElemText("active", "true")
        self.setElemText("DetectionTechnology", "Correlation")
        description = self.formatDescription(description)
        self.setElemText("Description", description)
        if self.yml_file_name is not None:
            ET.SubElement(self.ruleRoot, "SigmaFileName")
            self.setElemText("SigmaFileName", self.yml_file_name) 
        
        if status is not None:
            ET.SubElement(self.ruleRoot, "SIGMAStatus")
            self.setElemText("SIGMAStatus", status)

        ET.SubElement(self.ruleRoot, "ignoreSIGMAUpdate")
        self.setElemText("ignoreSIGMAUpdate", "false")
        ET.SubElement(self.ruleRoot, "CustomerScope")
        self.setElemAttr("CustomerScope", "groupByEachCustomer", "true")
        self.addAnElem("CustomerScope", "Include")
        self.addAnElem("CustomerScope", "Exclude")
        self.setElemAttr("Include", "all", "true")


    def generateRuleIncidentDef(self, name, level, attrset):
        if level == SigmaLevel.LOW:
            severity = 3
        elif level == SigmaLevel.MEDIUM:
            severity = 5
        elif level == SigmaLevel.HIGH:
            severity = 7
        elif level == SigmaLevel.CRITICAL:
            severity = 9
        else:
            severity = 1

        ruleEvtType = self.formatRuleEvtType(name)
        
        filterStr = set()
        for item in attrset:
            if item == 'eventType':
                filterStr.add('compEventType = Filter.eventType')
            else:
                filterStr.add('%s = Filter.%s' % (item, item))

        filterStr=sorted(filterStr)
        arglist = ",".join(filterStr)
        curFilterAttrs = ",".join(attrset)

        ET.SubElement(self.ruleRoot, "IncidentDef")
        self.addAnElem("IncidentDef", "ArgList")
        self.setElemAttr("IncidentDef", "eventType", ruleEvtType)
        self.setElemAttr("IncidentDef", "severity", str(severity))
        self.setElemText("ArgList", arglist)

    def formatSingleEvtConstr(self, singleEvtConstr):
        ruleName = self.getElemText("Name")
        if "Local User Creation" in ruleName:
           if " OR " in singleEvtConstr:
               singleEvtConstr = "( %s ) AND isLocalUser = \"yes\"" % (singleEvtConstr)
           else:
               singleEvtConstr = "%s AND isLocalUser = \"yes\"" % (singleEvtConstr)
               
        return singleEvtConstr

    def generateRulePatternClause(self, condition, groupByAttrs):
        singleEvtConstr = condition
        singleEvtConstr = self.formatSingleEvtConstr(singleEvtConstr)
        groupByAttr = ",".join(groupByAttrs)

        ET.SubElement(self.ruleRoot, "PatternClause")
        self.setElemAttr("PatternClause", "window", "300")

        self.addAnElem("PatternClause", "SubPattern")
        self.setElemAttr("SubPattern", "displayName", "Filter")
        self.setElemAttr("SubPattern","name", "Filter")
        
        self.addAnElem("SubPattern", "SingleEvtConstr")
        self.addAnElem("SubPattern", "GroupByAttr")
        self.addAnElem("SubPattern",  "GroupEvtConstr")

        self.setElemText("SingleEvtConstr", singleEvtConstr)
        self.setElemText("GroupByAttr", groupByAttr)
        self.setElemText("GroupEvtConstr", str("COUNT(*) >= 1"))

    def generateRuleTriggerEventDisplay(self, displayAttrs):
        displayAttrs = sorted(displayAttrs)
        
        if len(displayAttrs) == 0:
            fields = "phRecvTime,rawEventMsg"
        else:
            fields = "phRecvTime," +  ",".join(displayAttrs) + ",rawEventMsg" 

        ET.SubElement(self.ruleRoot, "TriggerEventDisplay")
        self.addAnElem("TriggerEventDisplay", "AttrList")
        self.setElemText("AttrList", fields)

    def getDisplayAttr(self, attrset):
        attrset.discard("hostName")
        attrset.discard("eventType")
        attrset.discard("phRecvTime")
        attrset = sorted(attrset)
        return attrset;
    
    def getIncidentDefAttr(self, attrset):
        attrset.discard("eventType")
        attrset.add("hostName")
        attrset = sorted(attrset)
        return attrset;

    def getGroupByAttr(self, attrset):
        attrset.discard("eventType")   
        attrset.add("hostName")
        attrset = sorted(attrset)
        return attrset

    def getCurAttrs(self, sigma_rule: SigmaRule):
        currArr=[]
        for key, sigmaDetection in sigma_rule.detection.detections.items():
            if key.startswith('_cond_'):
                continue;
            for arg in sigmaDetection.detection_items:
                if isinstance(arg, SigmaDetection):
                    for arg1 in arg.detection_items:
                        if arg1.field is not None:
                            currArr.append(arg1.field)
                else:
                    if arg.field is not None:
                        currArr.append(arg.field)
        return currArr

    def generateXMLRule(self, sigma_rule: SigmaRule, condition):
        conditionStr = str(condition)

        self.ruleRoot = ET.fromstring("<Rule/>")

        product = None
        logsource = sigma_rule.logsource
        if logsource is not None:
            product = logsource.product.strip(" ").lower()

        date = sigma_rule.date
        name = sigma_rule.title 
        des = sigma_rule.description 
        level = sigma_rule.level 
        status = "%s" %  sigma_rule.status
        tags = sigma_rule.tags
        if conditionStr is None:
                self.addAnElem("Rule",  "ErrMsg")
                self.setElemText("ErrMsg", errMsg)
                self.addAnElem("Rule",  "Name")
                curRuleName = self.formatRuleName(name);
                self.setElemText("Name", curRuleName)
                self.addAnElem("Rule",  "SigmaFileName")
                self.setElemText("SigmaFileName",  self.yml_file_name)
                return self.ruleRoot
        
        curAttrs = self.getCurAttrs(sigma_rule)
        groupByAttr=set(curAttrs)
        displayAttr=set(curAttrs)
        incidentDefAttr= set(curAttrs)
        groupByAttr = self.getGroupByAttr(groupByAttr)
        displayAttr = self.getDisplayAttr(displayAttr)
        incidentDefAttr = self.getIncidentDefAttr(incidentDefAttr)

        self.generateRuleHeader(tags)
        self.generateRuleCommonPart(name, des, status, product)
        self.generateRuleIncidentDef(name, level, incidentDefAttr)
        self.generateRulePatternClause(conditionStr, groupByAttr)
        self.generateRuleTriggerEventDisplay(displayAttr)
        return self.prettyXML(self.ruleRoot)

    def prettyXML(self, elem):
        if elem is None:
            return "<Rule/>"
        root = etree.XML(ET.tostring(elem))
        content = etree.tostring(root, pretty_print = True, encoding = str)
        return content
