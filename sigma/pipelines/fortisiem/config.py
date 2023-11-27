import sys
import csv 
import sigma
import yaml
import re
import copy
from sigma.rule import SigmaDetection, SigmaRule

Windows_logsource_Condition_map = {
 "process_creation":{"eventType": "Win-Sysmon-1-Create-Process"},
 "network_connection": {"eventType": "Win-Sysmon-3-Network-Connect*"},
 "dns_query":{"eventType": "Win-Sysmon-22-DNS-Query"},
 "registry_event":{"eventType": "Win-Sysmon-12-Registry-*|Win-Sysmon-13-Registry-*|Win-Sysmon-14-Registry-*"},
 "file_event":{"eventType": "Win-Sysmon-11-FileCreate"},
 "process_access":{"eventType": "Win-Sysmon-10-ProcessAccess"},
 "image_load":{"eventType": "Win-Sysmon-7-Image-Loaded"},
 "driver_load":{"eventType": "Win-Sysmon-6-Driver-Loaded"},
 "process_termination":{"eventType": "Win-Sysmon-5-Process-Terminated"},
 }

class FortisiemConfig:
    fortisiem_attrs_dict = {}
    fortisiem_attr_type_dict = {}
    skip_rule_by_logsource_dict= {}
    event_id_2_event_type_dict = {}
    technique_dict = {}

    #def __init__(self):
     
    def loadFieldNameToFortiSIEMAttrNameMap(self, csvFileName):
        with open(csvFileName, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',')
            for row in spamreader:
                if len(row) < 2:
                    continue;
                elif len(row) == 2:
                    self.fortisiem_attr_type_dict[row[1]] = "string"
                else:
                    self.fortisiem_attr_type_dict[row[1]] = row[2]

                self.fortisiem_attrs_dict[row[0]] = row[1]

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
                         if row[1].find(".*") == -1:
                             self.event_id_2_event_type_dict[t][row[0]] = row[1]
                         else:
                             self.event_id_2_event_type_dict[t][row[0]] = "FSM_REG_WILDCARD" + row[1]

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
         return tmp, keyword

    def convertEvtID2EvtType(self, service, code, provider=None):
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
            else:
                print("ERROR: Unsupport to get provider name from %s in convertEvtID2EvtType" %  str(provider))

            tmp, keyword = self.getEvtTypeByEvtID(service, code)
            val = "%s-%s" % (keyword, code)
            return val

        val, keyword = self.getEvtTypeByEvtID(service, code)
        if val is not None:
            #evt = val.split(",")
            #val = ",".join(["\"%s\"" % item for item in evt])
            return val
        elif keyword is not None:
            if "Win-Sysmon" == keyword:
                val = "FSM_REG_WILDCARDWin-Sysmon-%s-.*" % code
            else:
                val = "%s-%s" % (keyword, code)
            return val
        else:
            return "FSM_REG_WILDCARDWin-.*-%s[^\\d]*" % code

    def formatEvtTypeVal(self, code: str, product, service, provider=None):
        if product != "windows":
            return code

        if not service: 
            return code
        
        val = self.convertEvtID2EvtType(service, code, provider)
        return val

    def convertDetectionItemValue(self, fieldName, value, product, service, provider):
        if fieldName == "eventType":
            vals = self.formatEvtTypeVal(str(value), product, service, provider);
            return vals
        else:
            print("ERROR: Unsupport to convert value of %s" % fieldName)
            return None

    def shouldAppendCondition(self, rule: SigmaRule):
        product = None
        service = None
        logsource = rule.logsource
        if logsource is not None:
            product = logsource.product
            service = logsource.service
            if not service:
                 service = logsource.category

        if product == "windows":
            currArr = self.getAllAttrName(rule);
            if "EventID" in currArr:
                return  product, service, None

            if service in Windows_logsource_Condition_map:
                return product, service, Windows_logsource_Condition_map[service]
        else:
            print("ERROR: Unsupport to get condition for %s in getConditionByLogsource" % product )
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
