import pytest
from sigma.collection import SigmaCollection
from sigma.backends.fortisiem.fortisiem import FortisemBackend

@pytest.fixture
def test_fortisiem_backend():
    sigmaCollection = .from_yaml("""
title: Title name
id: 9a4ff3b8-6187-4fd2-8e8b-e0eae1129495
status: test
description: Description 
references:
   - https://threathunterplaybook.com/hunts/windows/190625-RegKeyAccessSyskey/notebook.html
author: test author
date: 2019/08/12
modified: 2021/11/27
tags:
   - attack.discovery
   - attack.t1012
logsource:
   product: windows
   service: security
detection:
   selection:
        EventID:
            - 4656
            - 4663
        ObjectStar: 'Object*Star'
        ObjectSkipStar: 'ObjectSkip\*Star'
        ObjectEndWith|endswith:
            - 'ObjectEndWithStr'
            - 'ObjectEndWithStr\\*\*AA'
        ObjectRe|re:
            - '^Object*Re$'
            - '^Object\\\*Re$'
        ObjectStartwith|startswith:
            - 'ObjectstartswithStr'
            - 'Objectstartswith\\*\*Str'
        ObjectContianAll|contains|all:
            - '/owa/'
            - '/powershell'
    condition: selection
falsepositives:
    - Unknown
level: high
    """);
    config = FortisiemConfig();
    config.loadMitreAttackMatrixFile("sigma/pipelines/fortisiem/config/MITRE-Attack-matrix.csv");
    config.loadFieldNameToFortiSIEMAttrNameMap("sigma/pipelines/fortisiem/config/winAttr2InternalAttr.csv");
    config.loadFieldValToFortiSIEMFieldValMap("sigma/pipelines/fortisiem/config/WinCode2ET.csv")
    for rule in sigmaCollection.rules:
        processing_pipeline = fortisiem_pipeline(config, rule)
        backend = FortisemBackend(processing_pipeline=processing_pipeline)

        ruleId = "PH_Rule_SIGMA_1" 
        formater = FortisiemXMLRuleFormater(config, sigmaFile, ruleId, cmdargs.ruleType)
        xmlRules = backend.convert(rule, formater)
        print(xmlRules)
        assert xmlRules == """
<Rule group="PH_SYS_RULE_THREAT_HUNTING" id="PH_Rule_SIGMA_1" phIncidentCategory="Server" function="Security" subFunction="Discovery" technique="T1012">
  <Name>Windows: Title name</Name>
  <IncidentTitle>Title name</IncidentTitle>
  <active>true</active>
  <Description>Description</Description>
  <SigmaFileName>test.yml</SigmaFileName>
  <SIGMAStatus>test</SIGMAStatus>
  <ignoreSIGMAUpdate>false</ignoreSIGMAUpdate>
  <CustomerScope groupByEachCustomer="true">
    <Include all="true"/>
    <Exclude/>
  </CustomerScope>
  <IncidentDef eventType="PH_RULE_Title_name" severity="1">
    <ArgList>ObjectContianAll = Filter.ObjectContianAll,ObjectEndWith = Filter.ObjectEndWith,ObjectRe = Filter.ObjectRe,ObjectSkipStar = Filter.ObjectSkipStar,ObjectStar = Filter.ObjectStar,ObjectStartwith = Filter.ObjectStartwith,hostName = Filter.hostName</ArgList>
  </IncidentDef>
  <PatternClause window="300">
    <SubPattern displayName="Filter" name="Filter">
      <SingleEvtConstr>((ObjectContianAll REGEXP "/owa/" AND ObjectContianAll REGEXP "/powershell") AND (ObjectRe REGEXP "^Object*Re$" OR ObjectRe REGEXP "^Object\\\*Re$") AND ObjectEndWith REGEXP "ObjectEndWithStr$|ObjectEndWithStr\\.*\*AA$" AND ObjectSkipStar = "ObjectSkip\*Star" AND ObjectStar REGEXP "Object.*Star" AND ObjectStartwith REGEXP "^ObjectstartswithStr|^Objectstartswith\\.*\*Str" AND eventType IN ("Win-Security-4656", "Win-Security-4663"))</SingleEvtConstr>
      <GroupByAttr>ObjectContianAll,ObjectEndWith,ObjectRe,ObjectSkipStar,ObjectStar,ObjectStartwith,hostName</GroupByAttr>
      <GroupEvtConstr>COUNT(*) &gt;= 1</GroupEvtConstr>
    </SubPattern>
  </PatternClause>
</Rule>
        """

