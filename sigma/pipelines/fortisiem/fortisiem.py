from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation,DropDetectionItemTransformation 
from sigma.processing.conditions import IncludeFieldCondition 
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.pipelines.fortisiem.postprocessing import QueryToFortisiemExpressionTransformation
from sigma.pipelines.fortisiem.config import FortisiemConfig 
from sigma.pipelines.fortisiem.detectionItemTransformation import FortisiemReplaceDetectionItemTransformation
from sigma.rule import SigmaRule

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

@Pipeline
def fortisiem_pipeline(config: FortisiemConfig, rule: SigmaRule) -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    product, service, contition = config.shouldAppendCondition(rule)
    processingItemItems = []
    if contition:
        processingItem = ProcessingItem(
                identifier=f"fortisiem_windows_{service}",
                transformation=AddConditionTransformation(contition),
            )
        processingItemItems.append(processingItem)
    

    fieldProcessingItem = ProcessingItem(     # Field mappings
                identifier="fortisiem_field_mapping",
                transformation=FieldMappingTransformation(config.getFortiSIEMAttrDict(product, service)) 
                )
    processingItemItems.append(fieldProcessingItem)

    if product == "windows": 
        replaceProcessingItem = ProcessingItem(
                identifier=f"fortisiem_field_replace",
                transformation=FortisiemReplaceDetectionItemTransformation(config, product, service),
                field_name_conditions=[IncludeFieldCondition(["eventType", "EventID"])],
            )
        processingItemItems.append(replaceProcessingItem)

    dropProcessingItem = ProcessingItem(
                identifier=f"fortisiem_field_drop",
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[IncludeFieldCondition([".*_removed"], "re")],
            )
    processingItemItems.append(dropProcessingItem)

    return ProcessingPipeline(
        name="fortisiem pipeline",
        allowed_backends=frozenset(),                                               # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,            # The priority defines the order pipelines are applied. See documentation for common values.
        items=processingItemItems,
        postprocessing_items=[
            QueryPostprocessingItem(
                transformation=QueryToFortisiemExpressionTransformation(config),
                rule_condition_linking=any,
                rule_conditions=[
                ],
                identifier="to_fortisiem_rule_expression",
            )
        ],
        #finalizers=[ConcatenateQueriesFinalizer()],
    )

