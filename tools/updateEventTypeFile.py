import subprocess
from tools.updateRule import RULE_STATUS

def copyEvtType(fileFullPath, destDir):
    fileName = fileFullPath.split("/")[-1]
    cmd = "cp -rf %s %s" % (fileFullPath, destDir);
    #print(cmd)
    subprocess.run(cmd, shell=True)
    return ("%s/%s" % (destDir, fileName))

'''
   ../../data-definition/eventType/phoenix-error-et.csv
   ../../data-definition/eventType/phoenix-eventtype.csv 
'''

AddedEvtType = []
def deleteEventType(rule, fileName):
    if rule.find("ErrMsg") is not None:
        return
    eventType = rule.find('IncidentDef').get('eventType')
    if eventType in AddedEvtType:
        return;

    cmd = "sed -i '/^%s,/d' %s" % (eventType, fileName)
    subprocess.run(cmd, shell=True)

def addEventType(rule, fileName):
    if rule.find("ErrMsg") is not None:
        return
    eventType = rule.find('IncidentDef').get('eventType')
    name = rule.find('Name').text.strip(' ')   
    if eventType in AddedEvtType:
        return;

    cmd = "grep '%s,' %s " % (eventType, fileName)
    out = subprocess.getoutput(cmd)
    if out != "":
        return

    AddedEvtType.append(eventType)
    cmd = "echo '%s,%s,PH_SYS_EVENT_PH_RULE_SEC,9,' >> %s" %(eventType, name, fileName) 
    subprocess.run(cmd, shell=True)


def getEventType(rule):
    if rule.find("ErrMsg") is not None:
        return ""
    eventType = rule.find('IncidentDef').get('eventType')
    return eventType

def updateEventType(ruleNameDicts, destDir):
    fileName = copyEvtType("../../data-definition/eventType/phoenix-eventtype.csv", destDir);
    fileName1 = copyEvtType("../../data-definition/eventType/phoenix-error-et.csv", destDir);
    for item in ruleNameDicts.values():
        if item[1]  == RULE_STATUS.DELETE:
            deleteEventType(item[0], fileName)
            deleteEventType(item[0], fileName1)
        elif item[1] == RULE_STATUS.NEW:
            addEventType(item[2], fileName)


