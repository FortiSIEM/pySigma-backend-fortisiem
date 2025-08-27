import re
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaValueError, SigmaConditionError,SigmaFeatureNotSupportedByBackendError
from sigma.conversion.state import ConversionState
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR, ConditionAND, ConditionNOT, ConditionItem, ConditionValueExpression
import sigma
#from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.fortisiem.fortisiem import fortisiem_pipeline
from sigma.backends.fortisiem.xmlRuleFormater import FortisiemXMLRuleFormater 
from typing import Callable, ClassVar, Dict, List, Optional, Pattern, Tuple, Union, Any
from sigma.types import (
    SigmaString,
    SigmaRegularExpression,
    SpecialChars,
    SigmaCIDRExpression,
    SigmaNumber
)

class FortisemBackend(TextQueryBackend):
    """FortiSIEM backend."""
    name : ClassVar[str] = "FortiSIEM"               # A descriptive name of the backend
    requires_pipeline : ClassVar[bool] = True             # Does the backend requires that a processing pipeline is provided?

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionOR, ConditionAND)
    group_expression : ClassVar[str] = "({expr})"

    or_token : ClassVar[str] = " OR "
    and_token : ClassVar[str] = " AND "
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = " = "

    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[Pattern] = re.compile("^[\\w.]+$")

    str_quote : ClassVar[str] = '"'
    escape_char : ClassVar[str] = "\\"
    wildcard_multi : ClassVar[str] = ".*"
    wildcard_single : ClassVar[str] = "?"
    add_escaped : ClassVar[str] = "\\"

    default_field_name: ClassVar[str] = "rawEventMsg"
    field_null_expression: ClassVar[str] = "{field} IS NULL"
    contain_expression : ClassVar[str] = "{field} CONTAIN \"{value}\"" 
    contain_expression1 : ClassVar[str] = "{field} CONTAIN {value}" 
    re_expression : ClassVar[str] = "{field} REGEXP \"{value}\""
    eq_expression : ClassVar[str] = "{field} = \"{value}\""
    re_escape_char : ClassVar[str] = "*\\.()[]|{}^$+!?"

    cidr_expression : ClassVar[str] = "{value}"

    convert_or_as_in : ClassVar[bool] = True
    convert_and_as_in : ClassVar[bool] = False

    in_expressions_allow_wildcards : ClassVar[bool] = True

    field_in_list_expression : ClassVar[str] = "{field} IN ({list})"
    list_separator : ClassVar[str] = ","
    reg_or_separator : ClassVar[str] = "|"

    unbound_value_str_expression : ClassVar[str] = '{value}'
    unbound_value_num_expression : ClassVar[str] = '{value}'
    unbound_value_re_expression : ClassVar[str] = '{value}'

    formater = None

    def __init__(self, processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None, collect_errors: bool = False, min_time : str = "-30d", max_time : str = "now", query_settings : Callable[[SigmaRule], Dict[str, str]] = lambda x: {}, output_settings : Dict = {}, **kwargs):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.query_settings = query_settings
        self.output_settings = {"dispatch.earliest_time": min_time, "dispatch.latest_time": max_time}
        self.output_settings.update(output_settings)
        self.field_equals_field_expression = "{field1} = {field2}"

    @staticmethod
    def _generate_settings(settings):
        """Format a settings dict into newline separated k=v string. Escape multi-line values."""
        output = ""
        for k, v in settings.items():
            output += f"\n{k} = " + " \\\n".join(v.split("\n"))  # cannot use \ in f-strings
        return output

    def finalize_query_default(self, rule : SigmaRule, query : str, index : int, state : ConversionState) -> str:
        return query 

    def finalize_query(
        self,
        rule: SigmaRule,
        query,
        index: int,
        state: ConversionState,
        output_format: str,
    ):
        """
        Finalize query. Dispatches to format-specific method. The index parameter enumerates generated queries if the
        conversion of a Sigma rule results in multiple queries.

        This is the place where syntactic elements of the target format for the specific query are added,
        e.g. adding query metadata.
        """
        backend_query = self.__getattribute__("finalize_query_" + output_format)(
            rule, query, index, state
        )

        return self.last_processing_pipeline.postprocess_query(rule, backend_query)


    def finalize(self, queries: List[Any], rule: SigmaRule, output_format: str, formater = None):
        """Finalize output. Dispatches to format-specific method."""
        output = self.__getattribute__("finalize_output_" + output_format)(queries, rule, formater)
        return self.last_processing_pipeline.finalize(output)

    def finalize_output_default(self, queries: List[Any], rule: SigmaRule, formater = None) -> Any:
        """
        Default finalization.

        This is the place where syntactic elements of the target format for the whole output are added,
        e.g. putting individual queries into a XML file.
        """
        if formater:
            return [
                formater.generateXMLRule(rule, query)
                for query in queries
            ]

        return queries

    def convert(self, rule: SigmaRule, xmlFormater: FortisiemXMLRuleFormater, output_format: Optional[str] = None):
        """
        Convert a Sigma rule into the target data structure. Usually the result are one or
        multiple queries, but might also be some arbitrary data structure required for further
        processing.
        """
        queries = self.convert_rule(rule, output_format or self.default_format)

        return self.finalize(queries, rule, output_format or self.default_format, xmlFormater)

    def convert_rule(self, rule: SigmaRule, output_format: Optional[str] = None):
        """
        Convert a single Sigma rule into the target data structure (usually query, see above).
        """
        try:
            self.last_processing_pipeline = (
                self.backend_processing_pipeline
                + self.processing_pipeline
                + self.output_format_processing_pipeline[output_format or self.default_format]
            )

            error_state = "applying processing pipeline on"
            self.last_processing_pipeline.apply(rule)  # 1. Apply transformations


            # 2. Convert conditions
            error_state = "converting"
            states = [
                ConversionState(processing_state=dict(self.last_processing_pipeline.state))
                for _ in rule.detection.parsed_condition
            ]
            queries = [
                self.convert_condition(cond.parsed, states[index])
                for index, cond in enumerate(rule.detection.parsed_condition)
            ]

            error_state = "finalizing query for"
            return [  # 3. Postprocess generated query
                self.finalize_query(
                    rule,
                    query,
                    index,
                    states[index],
                    output_format or self.default_format,
                )
                for index, query in enumerate(queries)
            ]
        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return []
            else:
                raise e
        except (
            Exception
        ) as e:  # enrich all other exceptions with Sigma-specific context information
            msg = f" (while {error_state} rule {str(rule.source)})"
            if len(e.args) > 1:
                e.args = (e.args[0] + msg,) + e.args[1:]
            else:
                e.args = (e.args[0] + msg,)
            raise

    def convert_value_to_str(self, value):
        s = ""
        for c in value:
            if c in self.str_quote + self.escape_char:
                s += self.escape_char
            s += c

        return s

    def convert_value_to_regstr(self, value):
        s = ""
        for c in value:
            if isinstance(c, SpecialChars):  # special handling for special characters
                if c == SpecialChars.WILDCARD_MULTI:
                    s += self.wildcard_multi
                    continue
                elif c == SpecialChars.WILDCARD_SINGLE:
                    s += self.escape_char 
                    s += self.wildcard_single
                    continue
            elif c in self.re_escape_char + self.str_quote:
                s += self.escape_char 
            s += c
        return s

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
        ): 
        """Conversion of field in value list conditions."""
       # Check for plain strings if wildcards are allowed for string expressions.
        isContainWildcards = False;
        value_str_list = []
        if self.in_expressions_allow_wildcards:
            for arg in cond.args:
                if not isinstance(arg.value, SigmaString):
                    val = "%s" % str(arg.value)
                    value_str_list.append(val)
                    continue
                isContainWildcards, val = self.convert_str_val(arg.value, state)
                value_str_list.append(val)


        value_str_list = sorted(value_str_list)
        if isinstance(cond, ConditionOR):
            if isContainWildcards:
                regex_value = self.reg_or_separator.join(value_str_list)
                return self.re_expression.format(
                   field = self.escape_and_quote_field(cond.args[0].field),
                   value = regex_value
                )
           
            else:
                return self.field_in_list_expression.format(
                     field=self.escape_and_quote_field(cond.args[0].field),  
                     list=self.list_separator.join(["\"%s\"" % item for item in value_str_list])
                )
        elif isinstance(cond, ConditionAND):
            if isContainWildcards:
                regex_value = self.and_token.join(
                    [
                       self.re_expression.format(
                            field = self.escape_and_quote_field(cond.args[0].field),
                            value =  value_str
                       )
                       for value_str in value_str_list
                    ]
                )
                return regex_value 
            else:
                regex_value = self.and_token.join(
                    [
                       self.contain_expression.format(
                            field = self.escape_and_quote_field(cond.args[0].field),
                            value = value_str
                       )
                       for value_str in value_str_list
                    ]
                )
                return regex_value


    def convert_condition_val(self, cond: ConditionValueExpression, state: ConversionState) -> Any:
        value =  super().convert_condition_val(cond, state)
        converted = self.contain_expression1.format(
                    field = self.escape_and_quote_field(self.default_field_name),
                    value = value)
        return converted


    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression, state : "sigma.conversion.state.ConversionState"):
        if not isinstance(cond.value, SigmaRegularExpression):
            error = "ERROR:  It's not SigmaRegularExpression when convert_condition_field_eq_val_re" 
            raise NotImplementedError(error)

        field = self.escape_and_quote_field(cond.field)
        value = cond.value.regexp 
        value = re.sub(r'(?<!\\)"', "\\\"", value)

        return self.re_expression.format(field = field, 
                             value = value)

    def convert_condition_field_eq_val_cidr(self, cond : ConditionFieldEqualsValueExpression, state : "sigma.conversion.state.ConversionState"):
        expr = "{field}" + self.eq_token + "\"{value}\""
        value = ""
        if type(cond.value) == SigmaCIDRExpression:
            value = cond.value.cidr
        else:
           value = cond.value
      
        value = self.escape_and_quote_field(value)
        if value is None:
           error = f"ERROR: Failed to quote value for {type(cond.value)} when convert_condition_field_eq_val_cidr"
           raise NotImplementedError(error)

        return  expr.format( field = self.escape_and_quote_field(cond.field), value = value)

    def convert_str_val(self, value: SigmaString, state: ConversionState):
        isContainWildcards = False
        val = ""
        if value.startswith(SpecialChars.WILDCARD_MULTI) and value.endswith(SpecialChars.WILDCARD_MULTI):
            val = value[1:-1]
            val = self.convert_value_to_regstr(val)
            isContainWildcards = True
        elif value.startswith(SpecialChars.WILDCARD_MULTI):
            val = value[1:]
            val = "%s$" % self.convert_value_to_regstr(val)
            isContainWildcards = True
        elif value.endswith(SpecialChars.WILDCARD_MULTI):
            val = value[:-1]
            val = "^%s" % self.convert_value_to_regstr(val)
            isContainWildcards = True
        elif value.contains_special():
            val = self.convert_value_to_regstr(value)
            isContainWildcards = True
        else:
            val = self.convert_value_to_str(value)
        return isContainWildcards, val



    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            isContainWildcards, val = self.convert_str_val(cond.value, state)
            if isContainWildcards:
                expr = self.re_expression
            else:
                expr = self.eq_expression

            field=self.escape_and_quote_field(cond.field)
            return expr.format(
                field=field,
                value= val,
            )

        except TypeError:  # pragma: no cover
            error = f"ERROR: Convert {cond.field}:{cond.value} failed in convert_condition_field_eq_val_str"
            raise NotImplementedError(error)

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions"""
        try:
           expr = "{field}" + self.eq_token + "\"{value}\""
           value = str(cond.value)
           return expr.format( field = self.escape_and_quote_field(cond.field), value = value)
        except TypeError:
           error = f"ERROR: Convert {cond.field}:{cond.value} failed in convert_condition_field_eq_val_num"
           raise NotImplementedError(error)

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR conditions."""
        try:
            converteds = []
            for arg in cond.args:
               converted = None 
               if arg is None:
                   continue
               if isinstance(arg, ConditionValueExpression):
                    if isinstance(arg.value, SigmaString) or isinstance(arg.value, SigmaNumber):
                       val = str(arg.value).replace('"', "\\\"");
                       converted = self.contain_expression.format(
                            field = self.escape_and_quote_field(self.default_field_name),
                            value = val)
                    else:
                        error = f"ERROR: Convert failed ConditionValueExpression in convert_condition_or."
                        raise NotImplementedError(error)
               elif self.compare_precedence(cond, arg):
                   converted = self.convert_condition(arg, state)
               else:
                   converted = self.convert_condition_group(arg, state)
               if converted is not None:
                    if type(converted) == tuple: 
                        for item in converted:
                            converteds.append(item)
                    elif type(converted) == str:
                        converteds.append(converted)
                    else:
                        error = f"{converted} is not tuple or str."
                        raise NotImplementedError(error)

            convertedStr = None
            if len(converteds) > 1:
                #converteds = sorted(converteds)
                convertedStr = self.or_token.join(converteds)
                convertedStr = "( %s )" % convertedStr
            else:
                convertedStr = self.or_token.join(converteds)
            return convertedStr 
        except TypeError:  # pragma: no cover
            error = f"ERROR: Convert failed in convert_condition_or."
            raise NotImplementedError(error)


    def convert_condition_and(
        self, cond: ConditionAND, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of AND conditions."""
        try:
            converteds = []
            for arg in cond.args:
               converted = None
               if arg is None:
                    continue
               elif isinstance(arg, ConditionValueExpression):
                    if isinstance(arg.value, SigmaString) or isinstance(arg.value, SigmaNumber):
                       val = str(arg.value).replace('"', "\\\"");
                       converted = self.contain_expression.format(
                            field = self.escape_and_quote_field(self.default_field_name),
                            value = val)
                    else:
                        error = f"ERROR: Convert failed ConditionValueExpression in convert_condition_and."
                        raise NotImplementedError(error)
               elif self.compare_precedence(cond, arg):
                   converted = self.convert_condition(arg, state)
               else:
                   converted = self.convert_condition_group(arg, state)

               if converted is not None:
                    if type(converted) == tuple:
                        for item in converted:
                            converteds.append(item)
                    elif type(converted) == str:
                        converteds.append(converted)
                    else:
                        error = f"{converted} is not tuple or str."
                        raise NotImplementedError(error)

            convertedStr = None
            if len(converteds) > 1:
                #converteds = sorted(converteds)
                convertedStr = self.and_token.join(converteds)
                convertedStr = "( %s )" % convertedStr
            else:
                convertedStr = self.and_token.join(converteds)
            return convertedStr
        except TypeError:  # pragma: no cover
            error = "Convert failed in convert_condition_and."
            raise NotImplementedError(error)

    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        if len(cond.args) == 0:
            return None
        return super().convert_condition_not(cond, state)


