#!/usr/bin/env python3.9
import sys
import csv        
import os
import argparse
import yaml
import json
import pathlib
import itertools
import logging
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaValueError, SigmaConditionError,SigmaRelatedError
from sigma.pipelines.fortisiem.fortisiem import fortisiem_pipeline
from sigma.pipelines.fortisiem.config import FortisiemConfig
from sigma.backends.fortisiem.fortisiem import FortisemBackend 
from sigma.backends.fortisiem.xmlRuleFormater import FortisiemXMLRuleFormater 
sigma_path = os.getcwd()
sys.path.insert(0, sigma_path)
from tools.output import outputRules
from tools.updateRule import addNewRule, loadRulesXML, RULE_STATUS
import codecs

sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())

def set_argparser():
    argparser = argparse.ArgumentParser(description="Convert Sigma rules int FortiSIEM signatures.", formatter_class=argparse.RawTextHelpFormatter)
    argparser.add_argument("--inputs", "-i", default=None, help="Used to input files")
    argparser.add_argument("--ymlFile", "-f", default=None, help="Used to input one yml file")
    argparser.add_argument("--output", "-o", default=None, help="It's a file used to output results")
    argparser.add_argument("--ruleFile", "-r",default=None, help="It's a rule file which needs to be updated.")
    argparser.add_argument("--ruleStartIndex", "-s", default=1, help="Options Rule start id.")
    argparser.add_argument("--action", "-a", default=None, help="""
How to deal with the YAML file.
    New: Only output the new rules which aren't in the '--ruleFile' file. 
    Update: Update the '--ruleFile' file. It only updates rules when the rule is found in '--inputs'.
    OnlyUpdateLink: Only update the file link in rules in the '--ruleFile' file.
    FullUpdate: Update all rules in the '--ruleFile' file. Delete, update and add rules in '--ruleFile'
    Diff: Get deleted rules between two rule files.
    ReportToCsv: Generate CSV file from report file.
    RuleToCsv: Generate CSV file from rule files.""")
    #If forGui is False, the xml format can be imported into FortiSIEM by backend command
    argparser.add_argument("--forGui",action='store_true', help="The XML format can be imported into FortiSIEM by GUI")
    return argparser

def getRuleId(rulesDicts, filePath, ruleType, ruleIndex):
    fileName = filePath.split("/")[-1]
    if len(rulesDicts) != 0:
        if fileName in rulesDicts["ruleName"].keys():
            return rulesDicts["ruleName"][fileName][0].get("id")
     
    if ruleIndex is None:
       ruleIndex = 1

    if ruleType is None:
        ruleId = "PH_Rule_SIGMA_%d" % (ruleIndex)
    else:
        ruleId = "PH_Rule_%s_SIGMA_%d" % (ruleType, ruleIndex)
    return ruleId

def getFilesListFromInputDir(filedir):
    tmp= []
    filelist = []
    for root, dirs, files in os.walk(filedir):
        for file in files:
            filelist.append(os.path.join(root, file))

    for name in filelist:
        if name.endswith(".yml"):
            tmp.append(name)
    return tmp 

def getFilesListFromInputFile(fileName):
    filelist = []
    with open(fileName, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',')
            for row in spamreader:
                if len(row) > 1:
                     if row[1] == "Deleted":
                         continue;
                     filelist.append(row[0])
                     
                elif len(row) > 0:
                    filelist.append(row[0])

    return filelist

def loadYml(file_path):
    try:
        with open(file_path, 'r') as file:
            file_content = file.read()
    except FileNotFoundError:
        print(f"The file '{file_path}' was not found.")
        return None
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None
    ymlRule = SigmaCollection.from_yaml(file_content);
    return ymlRule; 


def main():
    argparser = set_argparser()
    cmdargs = argparser.parse_args()

    if cmdargs.action is None:
        print("There is not action.  select a value of --action/-a.", file=sys.stderr)
        exit(-1)

    outFile = cmdargs.output
    #to Csv
    if cmdargs.action == "RuleToCsv":
       if cmdargs.inputs is None:
            print("There is not input rule file. Input one with --inputs/-i.", file=sys.stderr)
            exit(-1)
       if outFile is None:
            print("There is not a file used to output result. Input one with--output/-o.", file=sys.stderr)
            exit(-1)
       outputRulesCsv(cmdargs.inputs, outFile);
       exit(-1)

    if cmdargs.action == "ReportToCsv":
       if cmdargs.inputs is None:
            print("There is not input report file. Input one with --inputs/-i.", file=sys.stderr)
            exit(-1)
       if outFile is None:
            print("There is not a file used to output result. Input one with--output/-o.", file=sys.stderr)
            exit(-1)
       outputReportsCsv(cmdargs.inputs, outFile);
       exit(-1)


    #Get deleted rule between two rule' files
    if cmdargs.action == "Diff":
       if cmdargs.inputs is None:
            print("There is not new rule file. Input one with --inputs/-i.", file=sys.stderr)
            exit(-1)
       if cmdargs.ruleFile is None:
            print("There is not original rule file. Input one with --ruleFile/-r.", file=sys.stderr)
            exit(-1)
       if outFile is None:
            print("There is not a file used to output result. Input one with--output/-o.", file=sys.stderr)
            exit(-1)
       getDeletedRulesBetweenTwoFiles(cmdargs.ruleFile, cmdargs.inputs, outFile);
       exit(-1)


    if outFile is None:
        print("There is not file used to output result. Input one with--output/-o.", file=sys.stderr)
        sys.exit(-1)
    elif os.path.isdir(outFile):
        outFile = outFile + "/New_Rule_File.xml"
    else:
        pass
     

    error = 0
    sigmaFileList = []
    if cmdargs.inputs is None:
        if not cmdargs.ymlFile:
            print("""It is a directory where YAML file is in or It's a csv file listed YAML file name Input one with --inputs/-i\n
or one YAML file name. Input one with --ymlFile/-f.""", file=sys.stderr)
            sys.exit(-1)
    elif os.path.isdir(cmdargs.inputs):
        sigmaFileList = getFilesListFromInputDir(cmdargs.inputs)
    elif os.path.isfile(cmdargs.inputs):
        sigmaFileList = getFilesListFromInputFile(cmdargs.inputs)
    else:
        print("Please check whether the directory and file exist. Please check the value -inputs/-i")
        sys.exit(-1)

    if cmdargs.ymlFile:
        sigmaFileList.append(cmdargs.ymlFile);

    forGUI = False
    if cmdargs.forGui:
        forGUI = True

    rulesDicts = {"filePath":{}, "ruleName":{}}
    noEvtTyRule = []
    ruleIndex = int(cmdargs.ruleStartIndex)
    needHandledYmlList = []
    if cmdargs.action == "OnlyUpdateLink":
        if cmdargs.ruleFile is None:
            print("--ruleFile/-r can't be empty. It's a rule file which needs to be updated.")
            sys.exit(-1)
        rulesDicts = loadRulesXML(cmdargs.ruleFile, sigmaFileList);
        outputRules(rulesDicts, outFile, None);
        sys.exit(0)
    elif cmdargs.action == "FullUpdate":
        if cmdargs.ruleFile is None:
            print("--ruleFile/-r can't be empty. It's a rule file which needs to be updated.")
            sys.exit(-1)
        rulesDicts = loadRulesXML(cmdargs.ruleFile, sigmaFileList)
        needHandledYmlList = sigmaFileList
    elif cmdargs.action == "Update":
        if cmdargs.ruleFile is None:
            print("--ruleFile/-r can't be empty. It's a rule file which needs to be updated.")
            sys.exit(-1)
        rulesDicts = loadRulesXML(cmdargs.ruleFile, sigmaFileList)
        newYmlList = rulesDicts["filePath"].keys();
        for newYml in newYmlList:
            if newYml in sigmaFileList:
                needHandledYmlList.append(newYml)
    elif cmdargs.action == "New":
        if cmdargs.ruleFile is None:
            needHandledYmlList = sigmaFileList
        else:
            rulesDicts = loadRulesXML(cmdargs.ruleFile, sigmaFileList)
            oldYmlList = rulesDicts["filePath"].keys();
            for newYml in sigmaFileList:
                if newYml not in oldYmlList:
                    needHandledYmlList.append(newYml)
    else:
        print("The action value is not right")
        sys.exit(1)
        
    config = FortisiemConfig(); 
    config.loadMitreAttackMatrixFile("tools/config/MITRE-Attack-matrix.csv");
    config.loadFieldNameToFortiSIEMAttrNameMap("tools/config/winAttr2InternalAttr.csv");
    config.loadFieldValToFortiSIEMFieldValMap("tools/config/WinCode2ET.csv")
    config.loadLogsourceUsedToSkipRuleMap("tools/config/SkipRuleByLogsource.csv")
    config.loadLogsourceToETMap("tools/config/Logsource2ET.csv")

    for sigmaFile in needHandledYmlList:
        try:
            print(sigmaFile)
            sigmaCollection = loadYml(sigmaFile); 
            if not sigmaCollection:
                print("Failed to parser Sigma file %s:\n" % (sigmaFile), file=sys.stderr)
                continue

            for rule in sigmaCollection.rules:
               if config.skipRuleByLogsource(rule):
                   print("Skip to generate rule for Sigma file %s:\n" % (sigmaFile), file=sys.stderr)
                   continue

               processing_pipeline = fortisiem_pipeline(config, rule)
               backend = FortisemBackend(processing_pipeline=processing_pipeline)
               
               logsource = rule.logsource
               ruleType = None
               if logsource is not None:
                  ruleType = logsource.product

               if forGUI:
                   formater = FortisiemXMLRuleFormater(config, sigmaFile, None, forGUI)
                   xmlRules = backend.convert(rule, formater)
               else:
                   ruleId = getRuleId(rulesDicts, sigmaFile, ruleType, ruleIndex)
                   formater = FortisiemXMLRuleFormater(config, sigmaFile, ruleId, forGUI)
                   xmlRules = backend.convert(rule, formater)


               for item in xmlRules:
                    ruleIndex = addNewRule(rulesDicts, item, sigmaFile, ruleIndex)

        except OSError as e:
            print("\nFailed to open %s:\n    %s" % (sigmaFile, str(e)), file=sys.stderr)
        except (yaml.parser.ParserError, yaml.scanner.ScannerError) as e:
            print("\n%s is no valid YAML:\n    %s" % (sigmaFile, str(e)), file=sys.stderr)
        except (SigmaConditionError,SigmaRelatedError) as e:
            print("\n%s is no valid YAML:\n    %s" % (sigmaFile, str(e)), file=sys.stderr)
        except (NotImplementedError, TypeError) as e:
            print("\n%s converted failed:\n    %s" % (sigmaFile, str(e)),file=sys.stderr)
   
    if cmdargs.action == "Update":
        outputRules(rulesDicts, outFile, [RULE_STATUS.NOCHANGE, RULE_STATUS.ONLYLINK, RULE_STATUS.DELETE, RULE_STATUS.MODIFIED])
    elif cmdargs.action == "FullUpdate":
        outputRules(rulesDicts, outFile, [RULE_STATUS.NOCHANGE, RULE_STATUS.ONLYLINK, RULE_STATUS.DELETE, RULE_STATUS.MODIFIED, RULE_STATUS.NEW])
    else:
        outputRules(rulesDicts, outFile, [RULE_STATUS.NEW])

    sys.exit(error)

if __name__ == "__main__":
    main()
