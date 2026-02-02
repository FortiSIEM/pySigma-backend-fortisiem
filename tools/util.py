import os
import yaml
from sigma.collection import SigmaCollection
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
