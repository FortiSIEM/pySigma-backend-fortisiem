![Tests](https://github.com/FortiSIEM/pySigma-backend-fortisiem/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/meiliumeiliu/d37be47299d1095351b315bd0725f6ba/raw/03d9dbf574d335fcef1435ac507d0b91c30be0b9/FortiSIEM-pySigma-backend-fortisiem.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma python Backend

This is the python backend for pySigma. It provides the package `sigma.backends.fortisiem` with the `FortisemBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.fortisiem`:

* fortisiem_pipeline: convert it to SingleEvtConstr in FortiSIEM XML Rule 

It supports the following output formats:

* default: plain Fortisiem XML Rule

This backend is currently maintained by:

* [Mei Liu](https://github.com/meiliu@fortinet.com/)
