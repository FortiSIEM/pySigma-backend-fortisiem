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
from sigma.pipelines.fortisiem.config import FortisiemConfig
from sigma.rule import SigmaRule
from typing import ClassVar,Dict,Union,List

class QueryToFortisiemExpressionTransformation(QueryPostprocessingTransformation):
    config = None
    def __init__(self, config):
        super().__init__();
        self.config = config

    def __post_init__(self):
        return

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str
    ) -> str:
        super().apply(pipeline, rule, query)
        try:
            result, mainToken = self.formatExpression(query, False, False)
            if not result:
                error = f"Query foramt is not right. query: {query}"
                raise NotImplementedError(error)
            return result
        except (NotImplementedError) as e:
            error = str(e) + f" query: {query}"
            raise NotImplementedError(error)




    def getQuoteStr(self, conditionStr):
        nextIndex = 1;
        while(nextIndex < len(conditionStr)):
            if conditionStr[nextIndex]== '\\':
                nextIndex = nextIndex + 2
            elif conditionStr[nextIndex]== '"':
                return nextIndex
            else:
                nextIndex = nextIndex + 1

        error = "Doubel quote doesn't match."
        raise NotImplementedError(error)



    def formatParenthesesExpression(self, conditionStr, fullExpressionIsNot):
        count = 1;
        nextIndex = 1;
        remainStr = "";
        parenSubContition = None;
        while(nextIndex < len(conditionStr)):
            if conditionStr[nextIndex]== '"':
                nextQuoteIndex = self.getQuoteStr(conditionStr[nextIndex:])
                if not nextQuoteIndex:
                    return remainStr, None
                nextIndex = nextIndex + nextQuoteIndex 
            elif conditionStr[nextIndex]== '(':
                count = count + 1
            elif conditionStr[nextIndex]== ')':
                count = count - 1;
                if count == 0:
                    remainStr = conditionStr[ nextIndex + 1:]
                    parenSubContition, subRuleToken = self.formatExpression(conditionStr[1:nextIndex], fullExpressionIsNot, True)
                    break

            nextIndex = nextIndex + 1
        
        if count > 0:
            error = "Parentheses doesn't match."
            raise NotImplementedError(error)


        return remainStr, parenSubContition, subRuleToken
                   

    def formatExpression(self, conditionStr, fullExpressionIsNot = False, needParentheses = False):
        remainStr = str(conditionStr).strip(" ");
        if remainStr.startswith("AND") or remainStr.startswith("OR"):
           return None, None
        
        newRuleCondition = None
        countFilter = 0;
        mainExpressionToken = "";
        subRuleConditionList = {}
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
                   token = "AND"


           if token != "":
               if mainExpressionToken != "" and mainExpressionToken != token:
                   error = "AND and  OR in same leave in one condition."
                   raise NotImplementedError(error)

               mainExpressionToken = token;

           if remainStr[0] == '(':
                remainStr, subRuleCondition, subRuleToken = self.formatParenthesesExpression(remainStr, partConditionIsNot)
                remainStr = remainStr.strip(" ")
                if subRuleCondition is None:
                    break;
                
                subRuleConditionList[subRuleCondition] = subRuleToken;
                '''                
                if ( newRuleCondition or remainStr ) and subRuleToken:
                    subRuleCondition = f"({subRuleCondition})"

                if newRuleCondition is None:
                    newRuleCondition = subRuleCondition
                else: 
                    newRuleCondition = newRuleCondition + " " + token + " " + subRuleCondition 
                '''
           else:
                oneCond, remainStr= self.getFilter(remainStr)
                subRuleCondition = self.getAttOpVal(oneCond, partConditionIsNot)
                if subRuleCondition is None:
                    break
                subRuleConditionList[subRuleCondition] = "";

                '''
                if newRuleCondition is None:
                    newRuleCondition = subRuleCondition
                else:
                    newRuleCondition = newRuleCondition + " " + token + " " + subRuleCondition
                '''
        if mainExpressionToken == "" and len(subRuleConditionList) > 1:
            error = "Wrong condition format."               
            raise NotImplementedError(error)

        if len(subRuleConditionList) == 1:
            newRuleCondition, mainExpressionToken = next(iter(subRuleConditionList.items()))
        else: 
            # mainExpressionToken should not be empty
            for subRuleCondition, subRuleToken in subRuleConditionList.items():
                if subRuleToken != '' and subRuleToken != mainExpressionToken:
                     subRuleCondition = f"({subRuleCondition})"

                if newRuleCondition is None:
                     newRuleCondition = subRuleCondition
                else:
                     newRuleCondition = newRuleCondition + " " + mainExpressionToken + " " + subRuleCondition

        if newRuleCondition is None:
            return None, mainExpressionToken
        else:
            return newRuleCondition.strip(" "), mainExpressionToken

    def getFilter(self, conditionStr):
       x = re.split(" (?:AND|OR) ", conditionStr)
       if len(x) == 1:
           return conditionStr, ""

       nextIndex = 0;
       inQuoteStr = False
       while(nextIndex < len(conditionStr)):
            if inQuoteStr:
                if conditionStr[nextIndex]== '\\':
                   nextIndex = nextIndex + 2
                   continue
                elif conditionStr[nextIndex]== '"':
                    inQuoteStr = False
                nextIndex = nextIndex +1
            else:
                if conditionStr[nextIndex]== '"':
                    inQuoteStr = True
                    nextIndex = nextIndex + 1
                    continue
                if conditionStr[nextIndex:].startswith(" AND ") or conditionStr[nextIndex:].startswith(" OR "):
                    return conditionStr[0: nextIndex], conditionStr[nextIndex:].strip(' ')

                nextIndex = nextIndex + 1
       return conditionStr, "";


    def getAttOpVal(self, conditionOrg, isNot):
        newCondition = conditionOrg
        part  = re.split("( = | CONTAIN | REGEXP | IN | IS )", newCondition)
        if part is None:
            error = "Key-value doesn't match."
            raise NotImplementedError(error)

        attr = part[0].strip(" ")
        newCondition = newCondition[len(part[0]):].strip(" ")
        
        index = newCondition.find(" ")
        if index == -1:
            error = "Key-value doesn't match."
            raise NotImplementedError(error)
        
        op = newCondition[0 : index].strip(" ")
        val = newCondition[index:].strip(" ")
        if val == "\"-\"":
            val = "NULL"
            op = "IS"

        if op == "REGEXP":
            if len(val) > 2048: 
                error = "Pattern too long."
                raise NotImplementedError(error)

        if isNot:
            if op == '=':
                op = '!='
            elif op == "IS":
                op = "IS NOT"
            else:
                op = "NOT " + op

           

        val = self.resetValByAttrType(attr, val, op)
        return self.formCondition(attr, op, val)
 
    #We parse the "User" field as domain\user, so we need to consider the domain.
    #If Sigma has 'user contain', we should convert to user contain OR domain contain
    #If Sigma has 'user endwith', we should convert to user endwith
    #If Sigma has 'user startwith', we should convert to user startwith OR domain startwith (in case the user field has no domain)
    def formCondition(self, attr, op, val):
       if attr != "user":
           if op == '=' or op == '!=':
              return f"{attr}{op}{val}";
           return f"{attr} {op} {val}";

       if op != "REGEXP" and op != "CONTAIN":
           if op == '=' or op == '!=':
              return f"{attr}{op}{val}";
           return f"{attr} {op} {val}";
       
       val.replace("\\\\", "#TEMP_TOKEN#")
       if val.strip('\"')[-1:] != '$' or val.strip('\"')[-2:] == '\\$':
           val.replace("#TEMP_TOKEN#", "\\\\")
           return f"({attr} {op} {val} OR domain {op} {val})"

       val.replace("#TEMP_TOKEN#", "\\\\")
       return f"{attr} {op} {val}";



    def resetValByAttrType(self, attrName, attrVal, op):
        if op not in ["=","!=","IN", "NOT IN"]:
            return attrVal

        attrType = self.config.getFortiSIEMAttrType(attrName)
        if attrType == "string":
            return attrVal
        vals = attrVal.strip(" ").strip("(").strip(")").split(",")
        vals = [ val.strip(" ").strip("\"") for val in vals]
        finalVal = ",".join(vals)
        if len(vals) > 1:
            return f"({finalVal})"
        return finalVal
        


