"""ForensiX AI REST API layer (Phase 14).

This package exposes the already-built Phase 1-13 forensics functionality over a
FastAPI application. It contains only transport concerns -- request validation,
serialization, routing, error handling -- and never re-implements business
logic. Every route delegates to an existing module:

* events / timeline -> ``backend.database.db`` (parameterized reads)
* investigation      -> ``backend.ai.query_engine.InvestigationQueryEngine``
* reports            -> ``backend.ai.report_generator``
* integrity          -> ``backend.integrity.verifier``
* incidents          -> ``backend.ai.correlator``
* behavior anomalies -> ``backend.ai.behavior``

The FastAPI ``app`` instance itself is created in :mod:`backend.app`.
"""
