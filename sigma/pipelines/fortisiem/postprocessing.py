import sys
import csv 
import sigma
import yaml
import re
import copy
import xml.etree.ElementTree as ET
from lxml import etree
from sigma.rule import SigmaDetection
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaRule
from typing import ClassVar,Dict,Union,List

class QueryToFortisiemExpressionTransformation(QueryPostprocessingTransformation):
    def __init__(self):
        super().__init__();

    def __post_init__(self):
        return

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str
    ) -> str:
        super().apply(pipeline, rule, query)
        result = self.formatExpression(query)
        if not result:
            errMsg = "The format of condition is not right"
            print("condition: %s" % query)
            return result

        return result


    def getQuoteStr(self, conditionStr):
        nextIndex = 1;
        while(nextIndex < len(conditionStr)):
            if conditionStr[nextIndex]== '\\':
                nextIndex = nextIndex + 2
            elif conditionStr[nextIndex]== '"':
                return nextIndex
            else:
                nextIndex = nextIndex + 1
        print("ERROR: The condition format is wrong condition in getQuoteStr: ", conditionStr)
        return None;



    def formatParenthesesExpression(self, conditionStr, fullExpressionIsNot):
        #print("XXXX", conditionStr)
        count = 1;
        nextIndex = 1;
        remainStr = "";
        parenSubContition = None;
        while(nextIndex < len(conditionStr)):
            if conditionStr[nextIndex]== '"':
                #print("ZZZZ1", conditionStr[nextIndex:])
                nextQuoteIndex = self.getQuoteStr(conditionStr[nextIndex:])
                if not nextQuoteIndex:
                    return remainStr, None
                nextIndex = nextIndex + nextQuoteIndex 
                #print("ZZZZ2", conditionStr[nextIndex + 1:])
            elif conditionStr[nextIndex]== '(':
                count = count + 1
            elif conditionStr[nextIndex]== ')':
                count = count - 1;
                if count == 0:
                    substr = conditionStr[1:nextIndex];
                    remainStr = conditionStr[ nextIndex + 1:]
                    parenSubContition = self.formatExpression(conditionStr[1:nextIndex], fullExpressionIsNot)
                    break

            nextIndex = nextIndex + 1
        
        if count > 0:
            print("ERROR: The condition format is wrong condition in formatParenthesesExpression: ", conditionStr) 
            return remainStr, None
        
        return remainStr, parenSubContition
                   

    def formatExpression(self, conditionStr, fullExpressionIsNot = False):
        remainStr = str(conditionStr).strip(" ");
        if remainStr.startswith("AND") or remainStr.startswith("OR"):
           return None
        
        newRuleCondition = None
        countFilter = 0;
        while remainStr != "":
           token = ""
           countFilter += 1
           if remainStr.startswith("NOT "):
                token = "NOT"
                remainStr = remainStr[4:].strip(" ")
           elif remainStr.startswith("AND NOT "):
                token = "AND NOT"
                remainStr = remainStr[8:].strip(" ")
           elif remainStr.startswith("OR NOT "):
                token = "OR NOT"
                remainStr = remainStr[7:].strip(" ")
           elif remainStr.startswith("AND "):
                token = "AND"
                remainStr = remainStr[4:].strip(" ")
           elif remainStr.startswith("OR "):
                token = "OR"
                remainStr = remainStr[3:].strip(" ")
           else:
                token = ""

           partConditionIsNot = fullExpressionIsNot
           if "NOT" in token:
               partConditionIsNot  = not fullExpressionIsNot
               token = token.replace("NOT", "").strip(" ")
           
           if fullExpressionIsNot:
               if token == "AND":
                  token = "OR"
               elif token == "OR":
                   token == "AND"

           if remainStr[0] == '(':
                remainStr, subRuleCondition = self.formatParenthesesExpression(remainStr, partConditionIsNot)
                remainStr = remainStr.strip(" ")
                if subRuleCondition is None:
                    break;
                
                if newRuleCondition is None:
                    newRuleCondition = subRuleCondition
                else: 
                    newRuleCondition = newRuleCondition + " " + token + " " + subRuleCondition 
           else:
                x = re.split(" (?:AND|OR) ", remainStr)
                subRuleCondition = self.getAttOpVal(x[0], partConditionIsNot)
                if subRuleCondition is None:
                    break

                if newRuleCondition is None:
                    newRuleCondition = subRuleCondition
                else:
                    newRuleCondition = newRuleCondition + " " + token + " " + subRuleCondition

                if len(x) == 1:
                    remainStr = ""
                else:
                    remainStr = remainStr[len(x[0]):].strip(" ")


        if newRuleCondition is None:
            return None
        elif countFilter > 1: 
            return '(%s)' % newRuleCondition.strip(" ")
        else:
            return newRuleCondition.strip(" ")

    def getAttOpVal(self, conditionOrg, isNot):
        newCondition = conditionOrg
        part  = re.split("( = | CONTAIN | REGEXP | IN | IS )", newCondition)
        if part is None:
            print("ERROR: The condition format is wrong condition in getAttOpVal: ", conditionOrg) 
            return None

        attr = part[0].strip(" ")
        newCondition = newCondition[len(part[0]):].strip(" ")
        
        index = newCondition.find(" ")
        if index == -1:
            print("ERROR: The condition format is wrong condition in getAttOpVal: ", conditionOrg) 
            return None
        
        op = newCondition[0 : index].strip(" ")
        if isNot:
            if op == '=':
                op = '!='
            elif op == "IS":
                op = "IS NOT"
            else:
                op = "NOT " + op

        val = newCondition[index:].strip(" ")
        return "%s %s %s" % (attr, op, val) 
