from .fortisiem import fortisiem_pipeline
# TODO: add all pipelines that should be exposed to the user of your backend in the import statement above.

pipelines = {
    "fortisiem_pipeline": fortisiem_pipeline,   # TODO: adapt identifier to something approproiate
}