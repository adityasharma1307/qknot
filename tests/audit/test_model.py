"""Tests for qresp.model — classification rules from Table 4.1."""
from __future__ import annotations

import pytest

from qresp.audit.model import (
    QLabel,
    SigAlgorithm,
    classify_algorithm,
    reconcile_labels,
)


class TestClassifyAlgorithm:
    @pytest.mark.parametrize(
        "algo",
        [
            SigAlgorithm.RSA_2048, SigAlgorithm.RSA_3072, SigAlgorithm.RSA_4096,
            SigAlgorithm.RSA_OTHER,
            SigAlgorithm.ECDSA_P256, SigAlgorithm.ECDSA_P384, SigAlgorithm.ECDSA_OTHER,
            SigAlgorithm.ED25519, SigAlgorithm.ED448,
        ],
    )
    def test_classical_algos_are_vulnerable(self, algo: SigAlgorithm):
        assert classify_algorithm(algo) == QLabel.VULNERABLE

    @pytest.mark.parametrize(
        "algo",
        [
            SigAlgorithm.ML_DSA_44, SigAlgorithm.ML_DSA_65, SigAlgorithm.ML_DSA_87,
            SigAlgorithm.SLH_DSA,
        ],
    )
    def test_pqc_algos_are_safe(self, algo: SigAlgorithm):
        assert classify_algorithm(algo) == QLabel.SAFE

    def test_no_signature_is_unsigned(self):
        assert classify_algorithm(SigAlgorithm.NONE) == QLabel.UNSIGNED

    def test_unknown_is_error(self):
        # Unknown means we saw a signature file but could not parse it;
        # we flag it for review rather than guessing.
        assert classify_algorithm(SigAlgorithm.UNKNOWN) == QLabel.ERROR


class TestReconcileLabels:
    def test_empty_is_unsigned(self):
        assert reconcile_labels([]) == QLabel.UNSIGNED

    def test_single_label_passes_through(self):
        assert reconcile_labels([QLabel.SAFE]) == QLabel.SAFE
        assert reconcile_labels([QLabel.VULNERABLE]) == QLabel.VULNERABLE

    def test_agreeing_labels_pass_through(self):
        assert reconcile_labels([QLabel.SAFE, QLabel.SAFE]) == QLabel.SAFE
        assert reconcile_labels(
            [QLabel.VULNERABLE, QLabel.VULNERABLE, QLabel.VULNERABLE]
        ) == QLabel.VULNERABLE

    def test_safe_plus_vulnerable_is_mixed(self):
        assert reconcile_labels([QLabel.SAFE, QLabel.VULNERABLE]) == QLabel.MIXED

    def test_error_beats_safe(self):
        """A repo whose only readable signature is post-quantum, but which also
        carries something unreadable, has not been shown to be safe."""
        assert reconcile_labels([QLabel.SAFE, QLabel.ERROR]) == QLabel.ERROR

    def test_vulnerable_beats_error(self):
        """A confirmed vulnerable signature is not erased by an unrelated
        parse failure.

        The previous rule returned ERROR here, calling it conservative. For a
        vulnerability survey that is conservative in the wrong direction: we
        know the repo carries a signature Shor's algorithm breaks, and
        reporting `error` discards that established fact and understates the
        vulnerable count.
        """
        assert reconcile_labels([QLabel.VULNERABLE, QLabel.ERROR]) == QLabel.VULNERABLE
        assert reconcile_labels([QLabel.ERROR, QLabel.VULNERABLE]) == QLabel.VULNERABLE
        assert reconcile_labels(
            [QLabel.ERROR, QLabel.ERROR, QLabel.VULNERABLE, QLabel.ERROR]
        ) == QLabel.VULNERABLE

    def test_safe_and_vulnerable_together_stay_mixed_even_with_errors(self):
        """Disagreement between safe and vulnerable is the one case where
        `vulnerable` must not simply win: the repo genuinely has both."""
        assert reconcile_labels(
            [QLabel.SAFE, QLabel.VULNERABLE, QLabel.ERROR]
        ) == QLabel.MIXED

    def test_unsigned_plus_safe_resolves_to_safe(self):
        # If a model has one signed file and one unsigned candidate,
        # treat the signed verdict as authoritative.
        assert reconcile_labels([QLabel.SAFE, QLabel.UNSIGNED]) == QLabel.SAFE
        assert reconcile_labels([QLabel.UNSIGNED, QLabel.SAFE]) == QLabel.SAFE

    def test_unsigned_plus_vulnerable_resolves_to_vulnerable(self):
        assert reconcile_labels([QLabel.VULNERABLE, QLabel.UNSIGNED]) == QLabel.VULNERABLE
