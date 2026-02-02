from sigma.processing.transformations import DetectionItemTransformation, FieldMappingTransformation
from sigma.pipelines.fortisiem.config import FortisiemConfig
from typing import Any, Iterable, List, Dict, Optional, Set, Union, Pattern, Iterator,ClassVar 
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import (
    SigmaString,
    SigmaRegularExpression,
)
import string
from dataclasses import dataclass, InitVar, field

@dataclass
class FortisiemFieldMappingTransformation(FieldMappingTransformation):
    mapping: Dict[str, Union[str, List[str]]]
    extra_config: Optional[Dict] = None
    sigmaFile: str = None

    def __post_init__(self):
        if self.extra_config is not None:
            self.sigmaFile = self.extra_config.get("sigmaFile", None)

    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        if field not in self.mapping:
            return;

        mappings = self.mapping[field]
        if mappings is None:
            return;

        newAttr = mappings.get("default", None)
        if self.sigmaFile is not None:
           mapping = mappings.get(self.sigmaFile, None)
           if mapping is not None:
               newAttr = mapping
               print(f"XXXX{self.sigmaFile}: {field}---> {newAttr}")
        if newAttr is not None:
               return newAttr

class FortisiemReplaceDetectionItemTransformation(DetectionItemTransformation):
    """Deletes detection items. This should only used in combination with a detection item
    condition."""
    config: ClassVar[FortisiemConfig]
    product: str 
    service: str
    def __init__(self,config, product, service):
        self.config = config
        self.product = product
        self.service = service
        super().__init__();

    class ReplaceSigmaDetectionItem(SigmaDetectionItem):
        """Class is used to mark detection item as to be deleted. It's just for having all the
        detection item functionality available."""

        @classmethod
        def create(cls, detection_item):
            return cls(detection_item, [], [])

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[SigmaDetectionItem]:
        """This function only marks detection items for deletion."""
        return self.ReplaceSigmaDetectionItem.create(detection_item)

    def getValueByName(self, detection: SigmaDetection, attrName: str):
        values = []
        for d in detection.detection_items:
            if isinstance(d, SigmaDetection):
                for detection_item in d.detection_items:
                    if detection_item.field == attrName:
                        if type(detection_item.value) is list:
                            values = values + list(detection_item.value)
                        else:
                            values.append(detection_item.value)
            else:#sigmaDetectionItem
                if d.field == attrName:
                    if type(d.value) is list:
                        values = values + list(d.value)
                    else:
                        values.append(d.value)
        if len(values) == 0:
            return None 
        return values

    def apply_detection(self, detection: SigmaDetection):
        super().apply_detection(detection)
        newItems = []

        provider = self.getValueByName(detection, "_win_providerName_removed") 
        if provider and  len(provider) > 0:
            provider = provider[0]
                 
        for d in detection.detection_items:
            if not isinstance(d, self.ReplaceSigmaDetectionItem):
                 newItems.append(d)
                 continue

            detection_item = d.field
            if type(detection_item.value) is not list:
                error = "Unsupport this type %s to FortisiemReplaceDetectionItemTransformation." % type(detection_item.value)
                raise NotImplementedError(error)

            values = []
            for val in detection_item.value:
                newValues = self.config.convertDetectionItemValue(detection_item.field, val, self.product, self.service, provider)
                if newValues is None:
                    values.append(val)
                    continue

                if type(newValues) is str:
                    if ".*" in newValues:
                        values.append(SigmaRegularExpression(newValues))
                    else:
                        values.append(SigmaString(newValues))
                else:
                     for newVal in newValues:
                          if ".*" in newValues:
                              values.append(SigmaRegularExpression(newVal))
                          else:
                              values.append(SigmaString(newVal))

            detection_item.value = values;
            newItems.append(detection_item)

        detection.detection_items = newItems 
