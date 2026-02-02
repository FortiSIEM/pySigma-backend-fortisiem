from flask import Flask, request, jsonify,send_file
import subprocess
from flask_cors import CORS
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
from xml.dom import minidom
import os
import requests
import difflib
import uuid
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaValueError, SigmaConditionError,SigmaRelatedError
from sigma.pipelines.fortisiem.fortisiem import fortisiem_pipeline
from sigma.pipelines.fortisiem.config import FortisiemConfig
from sigma.backends.fortisiem.fortisiem import FortisemBackend
from sigma.backends.fortisiem.xmlRuleFormater import FortisiemXMLRuleFormater
from tools.output import outputRules,generateErrRule,getEventTypeCsv,getDeletedRulesBetweenTwoFiles, prettyXML
from tools.updateRule import diffRules, addNewRule, loadRulesXML, prettyConstr,ruleDictToConstr, generateDictFromExpression,  RULE_STATUS
from tools.util import getRuleId, getFilesListFromInputDir, getFilesListFromInputFile,loadYml
from websocketServer import start_ws
import threading


app = Flask(__name__)
CORS(app)
#print("Current working directory:", os.getcwd())

LOG_FILE="./log/sigma_http_server_log.txt"
FORTISIEM_DIR="/opt/phoenix/data-definition/rules/"
FORTISIEM_RULEFILE_PREFIX="THREAT_HUNTING_RULES_WIN_SIGMA_"
CONFIG = FortisiemConfig();

SIGMA_DIR="./sigma"
SIGMA_PREFIX = "https://github.com/SigmaHQ/sigma/blob/master/"
RAW_SIGMA_PREFIX = "https://raw.githubusercontent.com/SigmaHQ/sigma/refs/heads/master/"
CLONE_URL = "https://github.com/SigmaHQ/sigma.git"
current_commit_id = ""

def init():
    CONFIG.loadMitreAttackMatrixFile("tools/config/MITRE-Attack-matrix.csv");
    CONFIG.loadFieldNameToFortiSIEMAttrNameMap("tools/config/Attr2InternalAttr");
    CONFIG.loadFieldValToFortiSIEMFieldValMap("tools/config/AttrVal2InternalVal/windows-EventID.csv")
    CONFIG.loadLogsourceUsedToSkipRuleMap("tools/config/SkipRuleByLogsource.csv")
    CONFIG.loadEvtTypeCondition("tools/config/EvtTypeConditionAppend")
    os.makedirs("tmp", exist_ok=True)
    os.makedirs("log", exist_ok=True)

def execute_cmd(cmd):
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        return {
            "code": proc.returncode,
            "result": proc.stdout,
            "errMsg": proc.stderr
        }
    except Exception as e:
        return {"code": -1, "errMsg": str(e)}


def out_put_log(log):
    now = datetime.now()
    time_str = now.strftime("%Y-%m-%dT%H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
         f.write(f"{time_str} {log}\n")

def prepare_sigma_repo(clone_url, commit_id):
    cmd = ["bash", "./scripts/prepare_sigma_repo.sh", clone_url, commit_id, ">", "./log/prepare_sigma_repo.txt"]
    return execute_cmd(cmd) 

def get_new_rule_filename(filename, errFilename, eventTypeFile):
    Path("tmp").mkdir(exist_ok=True)
    now = datetime.now()
    time_str = now.strftime("%Y%m%d_%H%M%S")

    if filename is not None and filename.strip() != "":
        file_name = f"tmp/{filename}"
    else:
        file_name = f"tmp/sigma_rule_{time_str}.xml"

    if errFilename is not None and errFilename.strip() != "":
        err_file_name = f"tmp/{errFilename}"
    else:
        err_file_name = f"tmp/sigma_rule_convert_failed_{time_str}.xml"

   
    if eventTypeFile is not None and eventTypeFile.strip() != "":
        evtType_file_name = f"tmp/{eventTypeFile}"
    else:
        evtType_file_name = f"tmp/sigma_rule_eventType_{time_str}.csv";

    return file_name, err_file_name, evtType_file_name

def getFortiSIEMRuleFiles(fortisiemDir: str, prefix: str):
    tmp= []
    filelist = []
    for root, dirs, files in os.walk(fortisiemDir):
        for filename in files:
            if filename.startswith(prefix):
                fullpath = os.path.join(root, filename)
                filelist.append(fullpath)
    return filelist

def getFortiSIEMRulesDicts(fortisiemDir: str, prefix: str, sigmaFileList: list):
    ruleFiles = getFortiSIEMRuleFiles(fortisiemDir, prefix);
    fortiSIEMRulesDicts = {}
    for ruleFile in ruleFiles:
      rulesDicts = {"filePath":{}, "ruleName":{}}
      rulesDicts = loadRulesXML(ruleFile, sigmaFileList);
      fortiSIEMRulesDicts[ruleFile] = rulesDicts;

    return fortiSIEMRulesDicts;

def generateRules(needHandledYmlList: list, rulesDicts:dict, ruleIndex: int):
    for sigmaFile in needHandledYmlList:
        xmlRules = []
        try:
            sigmaCollection = loadYml(sigmaFile); 
            if not sigmaCollection:
                errMsg = "Failed to parser YAML"
                xmlRules.append(generateErrRule(errMsg, sigmaFile))
                continue

            for rule in sigmaCollection.rules:
               if CONFIG.skipRuleByLogsource(rule):
                   errMsg = "Skip to generate rule for YAML"
                   xmlRules.append(generateErrRule(errMsg, sigmaFile))
                   continue

               otherParam = {"sigmaFile": sigmaFile}
               processing_pipeline = fortisiem_pipeline(CONFIG, rule, otherParam)
               backend = FortisemBackend(processing_pipeline=processing_pipeline)

               logsource = rule.logsource
               ruleType = None
               if logsource is not None:
                  ruleType = logsource.product
                  ruleId = getRuleId(rulesDicts, sigmaFile, ruleType, ruleIndex)
                  formater = FortisiemXMLRuleFormater(CONFIG, sigmaFile, ruleId, False)
                  xmlRules = backend.convert(rule, formater)
        except OSError as e:
            errMsg = "Failed to open YAML. Err:%s" % str(e)
            xmlRules.append(generateErrRule(errMsg, sigmaFile))
        except (yaml.parser.ParserError, yaml.scanner.ScannerError) as e:
            errMsg = "Invalid YAML. Err: %s" % str(e)
            xmlRules.append(generateErrRule(errMsg, sigmaFile))
        except (SigmaConditionError,SigmaRelatedError) as e:
            errMsg = "Invalid YAML. Err: %s" % str(e)
            xmlRules.append(generateErrRule(errMsg, sigmaFile))
        except (NotImplementedError, TypeError) as e:
            errMsg = "Failed to convert YAML. Err: %s" % str(e)
            xmlRules.append(generateErrRule(errMsg, sigmaFile))

        for item in xmlRules:
            ruleIndex = addNewRule(rulesDicts, item, sigmaFile, ruleIndex)

    return rulesDicts;

@app.route("/update", methods=["POST"])
def update():
    global current_commit_id
    out_put_log(request.form)
    #clone_url = request.form.get("clone_url")
    sigma_path = request.form.get("sigma_path")
    commit_id = request.form.get("commit_id")
    old_commit_id = request.form.get("old_commit_id")
    update_action = request.form.get("update_action");
    rule_file = request.form.get("rule_file")
    new_rule_filename = request.form.get("new_rule_filename");
    error_rule_status_filename = request.form.get("error_rule_status_filename");
    fortisiem_dir = FORTISIEM_DIR;
    fortisiem_rulefile_prefix = FORTISIEM_RULEFILE_PREFIX;
    ruleIndex = int(request.form.get("new_rule_start_index", "0"));
    new_eventtype_filename = request.form.get("new_eventtype_filename");

    #clone_url = "https://github.com/SigmaHQ/sigma.git";
    #sigma_path = "rules/windows"
    print(f"sigma_path: {sigma_path}, sigma_new_commit_id: {commit_id}, action: {update_action}")
    commit_id = ""

    if update_action != "New":
       if rule_file is None:
          errMsg = "Please elect a rule file to update."
          response = jsonify({ "code": -1,"errMsg": "Please elect a rule file to update."});
          out_put_log(f"{response}");
          return response;

       TMP_DIR = Path("./tmp")
       rule_file = TMP_DIR/rule_file

       if not os.path.exists(rule_file):
             response = jsonify({
                "code": -1,
                 "errMsg": f"{rule_file} does not exist, re-select"
             })
             out_put_log(response);
             return response

    rt = prepare_sigma_repo(CLONE_URL, commit_id)
    if rt["code"] != 0:
        response = jsonify({
            "code": -1,
            "errMsg": "Failed to prepare sigma repo:\n" + rt["errMsg"]
        })
        out_put_log(f"Failed to prepare sigma repo. {response}");
        return response
    else:
        current_commit_id = commit_id
        out_put_log(f"Prepare sigma repo {CLONE_URL} successfully")

    convertedRuleFileName, convertFailedRuleFileName, newEvtTypeFile = get_new_rule_filename(new_rule_filename, error_rule_status_filename, new_eventtype_filename);
    sigmaFileList = []
    if os.path.isfile(sigma_path):
       sigmaFileList.append(sigma_path);
    elif os.path.isdir(sigma_path):
       sigmaFileList = getFilesListFromInputDir(sigma_path)

    needHandledYmlList = []
    rulesDicts = {"filePath":{}, "ruleName":{}}
    #New: It will generate all rule in sigma_path
    #Update: It only updates rules when the rule is found in the rule file
    #OnlyExclude: It's only output rules when the rule is not in the rule file 
    #OnlyUpdateLink: Only update the file link in rules in the rule file.
    #FullUpdate: Delete, update and add rules in the rule file.
    statusOfRuleOutputed = None;
    if update_action == "New":
        needHandledYmlList = sigmaFileList
        statusOfRuleOutputed = [RULE_STATUS.NEW]

    elif update_action == "OnlyUpdateLink":
        rulesDicts = loadRulesXML(rule_file, sigmaFileList);
       
        statusOfRuleOutputed = [RULE_STATUS.NOCHANGE, RULE_STATUS.ONLYLINK, RULE_STATUS.MODIFIED, RULE_STATUS.DELETE]

    elif update_action == "FullUpdate":
        rulesDicts = loadRulesXML(rule_file, sigmaFileList)
        needHandledYmlList = sigmaFileList

        statusOfRuleOutputed = [RULE_STATUS.NOCHANGE, RULE_STATUS.ONLYLINK, RULE_STATUS.MODIFIED, RULE_STATUS.NEW]

    elif update_action == "OnlyExclude":
         rulesDicts = loadRulesXML(rule_file, sigmaFileList)
         oldYmlList = rulesDicts["filePath"].keys();
         for newYml in sigmaFileList:
             if newYml not in oldYmlList:
                 needHandledYmlList.append(newYml)

         statusOfRuleOutputed = [RULE_STATUS.NEW]
    else:#update
        rulesDicts = loadRulesXML(rule_file, sigmaFileList)
        newYmlList = rulesDicts["filePath"].keys();
        for newYml in newYmlList:
            if newYml in sigmaFileList:
                needHandledYmlList.append(newYml)
        statusOfRuleOutputed = [RULE_STATUS.NOCHANGE, RULE_STATUS.ONLYLINK, RULE_STATUS.DELETE, RULE_STATUS.MODIFIED]

    #Output rules
    out_put_log(f"Update Action: {update_action}, Status of rule to output: {statusOfRuleOutputed}")
        
    if len(needHandledYmlList) !=0:
        generateRules(needHandledYmlList, rulesDicts, ruleIndex);

    outputRules(rulesDicts, convertedRuleFileName, convertFailedRuleFileName, statusOfRuleOutputed)
    rt2 = {"code":0, "errMsg":""}
    if len(rulesDicts["ruleName"]) == 0:
       rt2["code"] = -1;
       rt2["errMsg"] = "Failed to convert"
       response = jsonify(rt2)
       out_put_log(f"Failed to convert rule, {response}")
    else:
       rt2["NewRuleFileName"] =os.path.basename(convertedRuleFileName);
       rt2["ErrRuleFileName"] =os.path.basename(convertFailedRuleFileName);

       if update_action == "New":
           print(f"Generate eventType file {newEvtTypeFile} from {convertedRuleFileName}")
           getEventTypeCsv(convertedRuleFileName, newEvtTypeFile);
           rt2["NewEvtTypeFileName"] =os.path.basename(newEvtTypeFile);

       response = jsonify(rt2)
       print(response)
       out_put_log("Convert rules successfully");
    return response


@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    base_dir = Path(__file__).parent.parent / "tmp"
    path = base_dir / filename
    if path.exists() and path.is_file():
        out_put_log("Download file successfully");
        return send_file(str(path), as_attachment=True)
    else:
        response = jsonify({"code": -1, "stderr": "File not found"}) 
        out_put_log(f"Failed to download file. {response}");
        return response, 404

@app.route("/open/<filename>", methods=["GET"])
def view_in_browser(filename):
    base_dir = Path(__file__).parent.parent / "tmp"
    path = base_dir / filename
    if path.exists() and path.is_file():
        out_put_log("Open file successfully");
        return send_file(str(path), as_attachment=False)
    else:
        response = jsonify({"code": -1, "stderr": "File not found"})
        out_put_log(f"Failed to download file. {response}");
        return response, 404


@app.route("/view/<filename>", methods=["GET"])
def view_file(filename):
    commitId = request.args.get("sigma_commitId")
    sigmaReturn = setSigmaCommitId(commitId)
    if sigmaReturn != "":
        return jsonify({
              "code": -1,
              "errMsg": f"{sigmaReturn}"
        })

    base_dir = Path(__file__).parent.parent / "tmp"
    path = base_dir / filename
    if path.exists() and path.is_file():
        out_put_log("View file successfully");
        tree = ET.parse(str(path))
        root = tree.getroot()
        result = []

        for rule in root.findall("Rule"):
            sigmaFile = rule.findtext("SigmaFileName", "")
            sigmaRule = getSigmaRule(sigmaFile); 

            errMsg = rule.findtext("ErrMsg", "")

            ruleConstr = rule.findtext("PatternClause/SubPattern/SingleEvtConstr", "")
            format_rule_constr = ruleConstr
            if ruleConstr != "":
               ruleDict = generateDictFromExpression(ruleConstr);
               format_rule_constr = prettyConstr(ruleDict);

            result.append({
                "SigmaRule": sigmaRule,
                "ErrMsg": errMsg,
                "SingleEvtConstr": format_rule_constr

            })

        return jsonify({
            "code": 0,
            "rules": result
        })
    else:
        return jsonify({"code": -1, "errMsg": "File not found"})

@app.route("/upload_rule", methods=["POST"])
def upload_rule():
    TMP_DIR = Path("./tmp")
    TMP_DIR.mkdir(exist_ok=True)
    if "rule_file" not in request.files:
        return jsonify({"code": -1, "errMsg": "No rule_file"}) 

    file = request.files["rule_file"]

    if file.filename == "":
        return jsonify({"code": -1, "errMsg": "Empty filename"}) 

    now = datetime.now()
    time_str = now.strftime("%Y%m%d_%H%M%S")
    file.filename = file.filename.replace(".xml", "")
    tmp_name = f"{file.filename}_{time_str}.xml"
    tmp_path = TMP_DIR / tmp_name

    file.save(tmp_path)

    return jsonify({
        "code": 0,
        "filename": tmp_name
    })
       
@app.route("/compare")
def compare_rules():
    new_name = request.args.get("new")
    old_name = request.args.get("old")

    base_dir = Path(__file__).parent.parent / "tmp"
    new_path = base_dir / new_name
    old_path = base_dir / old_name

    if not new_path.exists() or not old_path.exists():
        return jsonify({
            "code": -1,
            "errMsg": "File not found"
        })  

    out_put_log("View file successfully");
    newTree = ET.parse(str(new_path))
    newRoot = newTree.getroot()
    oldTree = ET.parse(str(old_path))
    oldRoot = oldTree.getroot()

    result = []

    newDicts = {}
    oldDicts = {}
    for rule in newRoot.findall("Rule"):
        sigmaRuleId = rule.get("id") 
        newDicts[sigmaRuleId] = rule;
    for rule in oldRoot.findall("Rule"):
        sigmaRuleId = rule.get("id")
        oldDicts[sigmaRuleId] = rule;

    diffCount = 0;
    noChangeCount = 0;
    for oldSigmaRuleId, oldRule in oldDicts.items():
        newRule = newDicts.get(oldSigmaRuleId, None)
        newSigmaFile = None
        #formatedNewConstr = None 
        updateStatus = "NO Change"
        if diffRules(newRule, oldRule):
            updateStatus = "Modified"
            diffCount = diffCount + 1;
        else:
            noChangeCount = noChangeCount + 1;
            continue

        newRuleName = None
        if newRule is not None:
            newSigmaFile = newRule.findtext("SigmaFileName", "")
            newRuleName = newRule.findtext("Name", "")
            #newConstr = newRule.findtext("PatternClause/SubPattern/SingleEvtConstr")
            #ruleDict = generateDictFromExpression(newConstr)
            #formatedNewConstr = prettyConstr(ruleDict, "")

            #updateStatus = newRule.findtext("SIGMAUpdateStatus", "")
            if newSigmaFile.startswith(SIGMA_PREFIX):
               newSigmaFile = newSigmaFile[len(SIGMA_PREFIX):]

        oldSigmaFile = oldRule.findtext("SigmaFileName", "")
        #oldConstr = oldRule.findtext("PatternClause/SubPattern/SingleEvtConstr")
        #ruleDict = generateDictFromExpression(oldConstr)
        #formatedOldConstr = prettyConstr(ruleDict, "")
        oldRuleName = oldRule.findtext("Name", "")

        if oldSigmaFile.startswith(SIGMA_PREFIX):
           oldSigmaFile = oldSigmaFile[len(SIGMA_PREFIX):]

        item = {"OldSigmaFileName": oldSigmaFile, 
               #"OldSingleEvtConstr": formatedOldConstr, 
               "OldRuleName":  oldRuleName,
               "OldRuleFileName":  old_name,
               "UpdateStatus": updateStatus,
               "SigmaRuleId": oldSigmaRuleId,
               "NewSigmaFileName":newSigmaFile,
               #"NewSingleEvtConstr": formatedNewConstr,
               "NewRuleName": newRuleName,
               "NewRuleFileName":  new_name,
               }
        result.append(item)

    return jsonify({
            "code": 0,
            "modifiedNum":diffCount,
            "noChangeNum":noChangeCount,
            "diff": result
        })

def format_xml(rule_xml: str):
    try:
        rule = ET.fromstring(rule_xml)
        sigma_rule_Id =  rule.get("id", None)
        for elem in rule.iter("SingleEvtConstr"):
            ruleConstr = elem.text;
            ruleConstr = ruleConstr.replace('\r\n', ' ').replace('\r', ' ').replace('\n', ' ');
            ruleDict = generateDictFromExpression(ruleConstr);
            ruleConstr = ruleDictToConstr(ruleDict);
            elem.text = ruleConstr
        xmlstr = prettyXML(rule)
        xmlstr = xmlstr.replace('\r\n', '\n').replace('\r', '\n')
        return True, xmlstr, sigma_rule_Id, None

    except ET.ParseError as e:
        return False, None, None, f"Failed to parse XML ：{e}, place line: {e.position[0]} column: {e.position[1]}"


@app.route("/update_rule", methods=["POST"])
def update_rule():
    rule_xml = request.form.get("rule_xml")
    org_sigma_rule_Id = request.form.get("sigma_rule_Id")
    rule_file = request.form.get("rule_file")
    print(f"update_rule: filename: {rule_file}, ruleId: {org_sigma_rule_Id}")
    print(f"Orignal string: {rule_xml}");
    ok, rule_xml, sigma_rule_Id, errMsg = format_xml(rule_xml)
    if not ok:
        return jsonify({
            "code": -1,
            "errMsg": errMsg 
            });


    if sigma_rule_Id is None:
        return jsonify({
            "code": -1,
            "errMsg": "Please add rule id"
            });

    if org_sigma_rule_Id is not None and org_sigma_rule_Id != sigma_rule_Id:
        return jsonify({
            "code": -1,
            "errMsg": "The Rule Id in xml is not same with the one in box (Sigma Rule Id) "
            });

    print(f"Format string: {rule_xml}");
    base_dir = Path(__file__).parent.parent / "tmp"
    new_path = base_dir / rule_file
    if not new_path.exists():
        return jsonify({
            "code": -1,
            "errMsg": "File not found"
        })  

    newTree = ET.parse(str(new_path))
    newRoot = newTree.getroot()
    tmp_file, errFile, evtTypeFile = get_new_rule_filename(rule_file, "", "");
    out = open(tmp_file, "w", encoding='utf-8')
    success = 0;
    print("<Rules>", file=out)
    for rule in newRoot.findall("Rule"):
        sigmaRuleId = rule.get("id")
        if sigmaRuleId != sigma_rule_Id:
             xmlstr = prettyXML(rule)
             print(xmlstr, file=out)
             continue;
        else:
            print(rule_xml, file=out)
            success = 1;
     
    print("</Rules>", file=out)
    out.close()
    if success == 1: 
        os.replace(tmp_file, new_path)
        return jsonify({
            "code": 0,
            "result": ""
        })
    else:
        os.remove(tmp_file)
        return jsonify({
           "code": -1,
           "errMsg": "Not find SingleEvtConst in rule xml"
        })


@app.route("/query_sigma_rule")
def query_sigma_rule():
    sigma_rule_file = request.args.get("sigma_rule_file")
    sigma_commitId = request.args.get("sigma_commitId")
    sigmaReturn = setSigmaCommitId(sigma_commitId)
    if sigmaReturn != "":
        return sigmaReturn
    return getSigmaRule(sigma_rule_file)


@app.route("/query_rule")
def query_rule():
    sigma_rule_Id = request.args.get("sigma_rule_Id")
    rule_file_name = request.args.get("rule_file")

    print(f"query_rule: filename: {rule_file_name}, ruleId: {sigma_rule_Id}")
    base_dir = Path(__file__).parent.parent / "tmp"
    new_path = base_dir / rule_file_name

    if not new_path.exists():
        return jsonify({
            "code": -1,
            "errMsg": "File not found"
        })  

    newTree = ET.parse(str(new_path))
    newRoot = newTree.getroot()
    for rule in newRoot.findall("Rule"):
        sigmaRuleId = rule.get("id")
        if sigmaRuleId != sigma_rule_Id:
            continue;

        target_node = rule.find("PatternClause/SubPattern/SingleEvtConstr")
        if target_node is None:
            continue;
        ruleConstr = target_node.text
        ruleDict = generateDictFromExpression(ruleConstr);
        format_rule_constr = prettyConstr(ruleDict);
        target_node.text = "\n"+ format_rule_constr
        pretty_xml = prettyXML(rule)
        return jsonify({
              "code": 0,
              "rule": pretty_xml
        })

    return jsonify({
              "code": -1,
              "errMsg": "Not find SingleEvtConst in rule xml"
            })


def setSigmaCommitId(commitId):
     global current_commit_id
     print(f"current_commit_id: {current_commit_id}")
     try:
        base_dir = Path(SIGMA_DIR)
        if base_dir.exists() and current_commit_id == commitId:
            return ""
        
        rt = prepare_sigma_repo(CLONE_URL, commitId)
        if rt["code"] != 0:
               err = rt["errMsg"];
               print(f"Failed to set sigma to {commitId}")
               return f"Failed to prepare sigma repo: {err}"
       
        print(f"Set sigma to {commitId} successfully")
        current_commit_id = commitId
        return ""
     except Exception as e:
        return f"Failed to load Sigma rule: {e}"

def getSigmaRule(sigmaFileName):
    try:
        sigmaFileName = sigmaFileName.replace(SIGMA_PREFIX, "")
        base_dir = Path(__file__).parent.parent / "sigma"

        rule_path = base_dir / sigmaFileName
       
        if not rule_path.is_file():
            return "File not found"

        data = rule_path.read_text(encoding="utf-8")

        if data.strip():
            return data
        else:
            return "File is empty"

    except Exception as e:
        return f"Failed to load Sigma rule: {e}"

@app.route("/rules_detail")
def rules_detail():
    rule_file_name = request.args.get("rule_file")
    commitId = request.args.get("sigma_commitId")

    print(f"rules_detail: filename: {rule_file_name}, sigmaCommitId: {commitId}")
    base_dir = Path(__file__).parent.parent / "tmp"
    new_path = base_dir / rule_file_name

    sigmaReturn = setSigmaCommitId(commitId)
    if sigmaReturn != "":
        return jsonify({
              "code": -1,
              "errMsg": f"{sigmaReturn}"
        })

    if not new_path.exists():
        return jsonify({
            "code": -1,
            "errMsg": "File not found"
        })

    #print(str(new_path))
    newTree = ET.parse(str(new_path))
    newRoot = newTree.getroot()
    result = []
    for rule in newRoot.findall("Rule"):
        target_node = rule.find("PatternClause/SubPattern/SingleEvtConstr")
        pretty_xml = ""
        if target_node is not None:
            ruleConstr = target_node.text
            ruleDict = generateDictFromExpression(ruleConstr);
            format_rule_constr = prettyConstr(ruleDict);
            target_node.text = "\n"+ format_rule_constr
            
        pretty_xml = prettyXML(rule)
        #https://raw.githubusercontent.com/SigmaHQ/sigma/refs/heads/master/rules/network/firewall/net_firewall_cleartext_protocols.yml

        target_node = rule.find("SigmaFileName")

        sigmaRuleDetail = "Failed to get sigma rule"  


        if target_node is not None:
            sigmaRuleDetail = getSigmaRule(target_node.text)
        else:
            sigmaRuleDetail = "There is no SigmaFileName in FortiSIEM Rule"

        if sigmaRuleDetail == "" and pretty_xml == "":
            continue;

        item = (sigmaRuleDetail, pretty_xml);
        result.append(item)


    if len(result) != 0:
        return jsonify({
              "code": 0,
              "rules": result 
        })

    return jsonify({
              "code": -1,
              "errMsg": f"{rule_file_name} is empty"
            })

@app.route("/query_file_list")
def query_file_list():
    base_dir = Path(__file__).parent.parent / "tmp"
    xml_files = [f.name for f in base_dir.glob("*") if f.suffix in [".xml", ".csv"]]
    return jsonify({
           "code": 0,
           "fileLists": xml_files
    })


if __name__ == "__main__":
    init();
    t = threading.Thread(target=start_ws, daemon=True)
    t.start()

    app.run(host="0.0.0.0", port=7777, debug=True, use_reloader=False)

