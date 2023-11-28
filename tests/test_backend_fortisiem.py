import pytest
import sys
import os
import argparse
import yaml
import pathlib
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaValueError, SigmaConditionError

sigma_path = os.getcwd()
sys.path.insert(0, sigma_path)

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

def test_fortisiem_backend():
    sigmaFile = "tests/test.yml"
    sigmaCollection = loadYml(sigmaFile) 
    config = FortisiemConfig();
    config.loadMitreAttackMatrixFile("sigma/pipelines/fortisiem/config/MITRE-Attack-matrix.csv");
    for rule in sigmaCollection.rules:
        backend = FortisemBackend(processing_pipeline=None)
        ruleId = "PH_Rule_SIGMA_1" 
        ruleType = ""
        formater = FortisiemXMLRuleFormater(config, sigmaFile, ruleId, ruleType)
        xmlRules = backend.convert(rule, formater)
        file_content = None
        with open("tests/expectRule.xml", 'r') as file:
            file_content = file.read()
        assert xmlRules[0].strip(" ") == file_content.strip(" ")
