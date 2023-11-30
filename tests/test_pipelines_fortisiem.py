import pytest
import sys
import os
import argparse
import yaml
import pathlib
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaValueError, SigmaConditionError
from sigma.pipelines.fortisiem.fortisiem import fortisiem_pipeline
from sigma.pipelines.fortisiem.config import FortisiemConfig
from sigma.backends.fortisiem.fortisiem import FortisemBackend
from sigma.backends.fortisiem.xmlRuleFormater import FortisiemXMLRuleFormater

def loadYml(file_path):
    with open(file_path, 'r') as file:
        file_content = file.read()
        ymlRule = SigmaCollection.from_yaml(file_content);
        return ymlRule;
    return None

def test_fortisiem_pipeline():
    sigmaFile = "tests/test.yml"
    sigmaCollection = loadYml(sigmaFile)
    config = FortisiemConfig();
    config.loadMitreAttackMatrixFile("tools/config/MITRE-Attack-matrix.csv");
    config = FortisiemConfig();
    config.loadMitreAttackMatrixFile("tools/config/MITRE-Attack-matrix.csv");
    config.loadFieldNameToFortiSIEMAttrNameMap("tools/config/winAttr2InternalAttr.csv");
    config.loadFieldValToFortiSIEMFieldValMap("tools/config/WinCode2ET.csv")
    for rule in sigmaCollection.rules:
        processing_pipeline = fortisiem_pipeline(config, rule)
        backend = FortisemBackend(processing_pipeline=processing_pipeline)

        ruleId = "PH_Rule_windows_SIGMA_1"
        formater = FortisiemXMLRuleFormater(config, sigmaFile, ruleId)
        xmlRules = backend.convert(rule, formater)
        print(xmlRules[0].strip(" "))
        file_content = None
        with open("tests/expectRuleFromPipelineTest.xml", 'r') as file:
            file_content = file.read()

        assert xmlRules[0].strip(" ") == file_content.strip(" ")

