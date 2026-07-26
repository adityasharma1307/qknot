"""Attested signing for any artefact.

This package has NO dependency on `qresp.audit` and no knowledge of
HuggingFace, machine learning, or model files. It signs bytes, records where
the entropy came from, and verifies the result. That independence is
deliberate: the audit answers a research question about one registry, while
the signing pipeline is meant to be usable by anyone who needs
post-quantum-ready signatures with honest provenance.

The boundary is enforced by a test. If `qresp.signing` ever imports from
`qresp.audit`, tests/signing/test_package_boundary.py fails.
"""
