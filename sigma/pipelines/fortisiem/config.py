import sys
import csv 
import sigma
import yaml
import re
import copy
import os
import json
from pathlib import Path
from sigma.rule import SigmaDetection, SigmaRule
from sigma.types import SigmaString,SpecialChars

class FortisiemConfig:
    fortisiem_attrs_dict = {}
    fortisiem_attr_type_dict = {}
    skip_rule_by_logsource_dict= {}
    event_id_2_event_type_dict = {}
    technique_dict = {}

    #logsource_Condition_map = {}
    #title_Condition_map = {}

    #{product: { attrName: {attrVal : ET} } }
    evt_type_condition = {}

    #def __init__(self):

    def loadLogsourceToETMap(self, csvFileName):
        with open(csvFileName, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',')
            for row in spamreader:
                if len(row) < 3:
                    continue;
                else:
                    tmp = self.logsource_Condition_map.get(row[0].lower(), None)
                    if tmp is None:
                        self.logsource_Condition_map[row[0]] = {}
                    self.logsource_Condition_map[row[0]][row[1]] = {"eventType": row[2]}

    def getFilesListFromDir(self, filedir, endsWith=".csv"):
        tmp= []
        filelist = []
        for root, dirs, files in os.walk(filedir):
            for file in files:
                filelist.append(os.path.join(root, file))

        for name in filelist:
            if name.endswith(endsWith):
               tmp.append(name)
        return tmp

    #EvtTypeConditionAppend
    def loadEvtTypeCondition(self, attrFolder):
        csvFiles = self.getFilesListFromDir(attrFolder);
        for csvFullFilePath in csvFiles:
            with open(csvFullFilePath, newline='') as csvfile:
                 #title
                 attrName = Path(csvFullFilePath).stem.lower()
                 spamreader = csv.reader(csvfile, delimiter=',')
                 for row in spamreader:
                     if len(row) < 3:
                        continue;
                     else:
                        product = row[0].strip(" ").lower()
                        tmp = self.evt_type_condition.get(product, None)
                        if tmp is None:
                           self.evt_type_condition[product] = {}
                           self.evt_type_condition[product][attrName] = {}

                        tmp = self.evt_type_condition[product].get(attrName, None)
                        if tmp is None:
                            self.evt_type_condition[product][attrName] = {}

                        self.evt_type_condition[product][attrName][row[1].lower().strip(" ")] = {"eventType": row[2].strip(" ")}


    def loadFieldNameToFortiSIEMAttrNameMap(self, attrFolder):
        jsonFiles = self.getFilesListFromDir(attrFolder, ".json");
        for fullFilePath in jsonFiles: 
            with open(fullFilePath, 'r', encoding='utf-8') as f:
                product = Path(fullFilePath).stem.lower()
                if product == 'attrtype':
                    self.fortisiem_attr_type_dict = json.load(f)
                else:
                    self.fortisiem_attrs_dict[product] = json.load(f)

        '''
        print("=======")
        json_string = json.dumps(self.fortisiem_attrs_dict, indent=2)
        print(json_string)
        print("=======")
        json_string = json.dumps(self.fortisiem_attr_type_dict, indent=2)
        print(json_string)
        '''

    def getFortiSIEMAttrDict(self, product, service):
        tmp = self.fortisiem_attrs_dict.get(product.lower(), {})
        return tmp;

    def getFortiSIEMAttrType(self, attrName):
        return self.fortisiem_attr_type_dict.get(attrName, "string")

    def loadFieldValToFortiSIEMFieldValMap(self, csvFileName):
        with open(csvFileName, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',')
            typeET = []
            for row in spamreader:
                if len(row) > 2:
                    if row[0].lower() == "windows":
                        typeET = row[1].lower().split(",")
                        for t in typeET:
                            self.event_id_2_event_type_dict[t] = {}
                            self.event_id_2_event_type_dict[t]["keyword"]= row[2].strip(" ")
                        continue

                if len(row) > 1:
                     for t in typeET:
                         self.event_id_2_event_type_dict[t][row[0]] = row[1]

    def loadLogsourceUsedToSkipRuleMap(self, csvFileName):
        with open(csvFileName, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',')
            for row in spamreader:
                if len(row) > 1:
                     self.skip_rule_by_logsource_dict[row[0].lower()] = row[1].lower()

    def skipRuleByLogsource(self, rule: SigmaRule):
        product = None
        service = None
        logsource = rule.logsource
        if logsource is not None:
            product = logsource.product
            service = logsource.service
            if not service:
                 service = logsource.category

        if product is None:
            product = ""

        if service is None:
            service = ""

        product = service.lower()
        service = service.lower()

        for key, val in self.skip_rule_by_logsource_dict.items():
            if key == product:
                if val == "":
                    return True
                else:
                    val = ",%s," % val
                    service = ",%s," % service
                    if val.find(service) != -1:
                        return True
        return False

    def loadMitreAttackMatrixFile(self, techniquefile):
        if techniquefile is None:
            return

        if len(self.technique_dict) == 0:
            with open(techniquefile, newline='') as f:
                spamreader = csv.reader(f, delimiter=',')
                for row in spamreader:
                    if len(row) < 3:
                        continue
                    else:
                        if row[2] != "":
                            self.technique_dict[row[0]] = row[2]

    def getEvtTypeByEvtID(self, service, code):
         tmp = self.event_id_2_event_type_dict.get(service.lower(), None)
         if tmp is None:
             return None,None
         keyword = tmp.get("keyword", None) 
         tmp = tmp.get(code, None)
         if tmp is not None and ',' in tmp:
             return tmp.split(","), keyword

         return tmp, keyword
    
    def convertEvtID2EvtType(self, service, code, provider=None):
        if not code.isdigit():
            return code

        if provider is not None:
            val, tmp  = self.getEvtTypeByEvtID("Provider_Name", code)
            if val is not None:
                #evt = val.split(",")
                #val = ",".join(evt) 
                return val
            
            providerStr = None
            for p in provider:
                if type(p) is str:
                    providerStr = p
                    break
                elif type(p) is list:
                    for e in p:
                        if type(e) is str:
                            providerStr = e
                            break
            if providerStr:
                code = "%s-%s" % (provider, code)
                code = re.sub(' ', '-', code)

            tmp, keyword = self.getEvtTypeByEvtID(service, code)
            val = "%s-%s" % (keyword, code)
            return val

        val, keyword = self.getEvtTypeByEvtID(service, code)
        if val:
            return val
        elif keyword:
            if "Win-Sysmon" == keyword:
                val = "Win-Sysmon-%s-.*" % code
            else:
                val = "%s-%s" % (keyword, code)
            return val
        else:
            return "Win-.*-%s[^\\d]*" % code

    def formatEvtTypeVal(self, code: str, product, service, provider=None):
        if product != "windows":
            return code

        if not service: 
            return code
        
        val = self.convertEvtID2EvtType(service, code, provider)
        return val

    def convert_value_to_str(self, value):
        if type(value) != sigma.types.SigmaString: 
           return str(value)

        s = ""
        for c in value:
            if isinstance(c, SpecialChars):  # special handling for special characters
                if c == SpecialChars.WILDCARD_MULTI:
                    s += ".*"
                    continue
                elif c == SpecialChars.WILDCARD_SINGLE:
                    s += "?"
                    continue
            s += c
        return s

    def convertDetectionItemValue(self, fieldName, value, product, service, provider):
        if fieldName == "eventType":
            s=self.convert_value_to_str(value);
            vals = self.formatEvtTypeVal(s, product, service, provider);
            return vals
        else:
            #print("WARNING: Unsupport to convert value of %s" % fieldName)
            return None

    def shouldAppendCondition(self, rule: SigmaRule):
        product = None
        service = None
        logsource = rule.logsource
        title = rule.title.lower()
        if logsource is not None:
            product = logsource.product
            service = logsource.service
            if not service:
                 service = logsource.category

        if product == "windows":
            currArr = self.getAllAttrName(rule);
            if "EventID" in currArr:
                return  product, service, None

        product2ETCondition = self.evt_type_condition.get(product, None);
        if not product2ETCondition:
            return product, service, None

        title2ETCondition = product2ETCondition.get('title', None)
        if title2ETCondition:
           ETConditon = title2ETCondition.get(title, None);
           if ETConditon:
               return product, service, ETConditon

        logsource2ETCondition = product2ETCondition.get('logsource', None)
        if logsource2ETCondition:
           ETConditon  = logsource2ETCondition.get(service, None) 
           if ETConditon:
               return product, service, ETConditon

        #else:
        #    print("WARNING: Unsupport to get condition for %s in getConditionByLogsource" % product )
        return product, service, None

    def getAllAttrName(self, rule: SigmaRule):
        currArr=[]
        for key, sigmaDetection in rule.detection.detections.items():
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
