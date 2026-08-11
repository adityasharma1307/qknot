"""Backends must satisfy SignatureBackend structurally, not by resemblance.

`Protocol` without `@runtime_checkable` binds nothing at runtime, and even with
it `isinstance` deliberately ignores signatures -- so a backend whose `sign`
grew a required argument would pass every check and fail at the first call
site. A second implementation of an interface is exactly where that drift
appears, and this project is adding one (liboqs).
"""
from __future__ import annotations

import pytest

from qknot.signing.backends import _BACKENDS, _assert_conforms, get_backend


class Good:
    algorithm = "ml-dsa-87"
    quantum_resistant = True
    side_channel_resistant = False
    signature_size = 4627

    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]: ...
    def sign(self, secret_key: bytes, message: bytes) -> bytes: ...
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...
    def describe(self) -> dict[str, object]: ...


class TestEveryRegisteredBackendConforms:
    @pytest.mark.parametrize("name", sorted(_BACKENDS))
    def test_registered_backend_satisfies_the_protocol(self, name):
        _assert_conforms(name, get_backend(name))

    def test_the_reference_shape_passes(self):
        _assert_conforms("good", Good())


class TestDriftIsCaught:
    def test_a_renamed_parameter_fails(self):
        """Renaming `message` to `data` breaks every keyword call site."""
        class Renamed(Good):
            def sign(self, secret_key: bytes, data: bytes) -> bytes: ...

        with pytest.raises(RuntimeError, match="requires"):
            _assert_conforms("renamed", Renamed())

    def test_an_added_required_parameter_fails(self):
        """The exact drift @runtime_checkable would NOT catch."""
        class Extra(Good):
            def sign(self, context: bytes, secret_key: bytes,
                     message: bytes) -> bytes: ...

        with pytest.raises(RuntimeError, match="signature drift|requires"):
            _assert_conforms("extra", Extra())

    def test_a_missing_method_fails(self):
        class NoDescribe(Good):
            describe = None

        with pytest.raises(RuntimeError, match="describe"):
            _assert_conforms("nodescribe", NoDescribe())

    def test_a_missing_attribute_fails(self):
        """Declared standalone: `del` on a subclass cannot remove an inherited
        attribute, so the first version of this test failed with AttributeError
        rather than testing anything."""
        class NoSize:
            algorithm = "x"
            quantum_resistant = True
            side_channel_resistant = False

            def keygen(self, seed: bytes | None = None): ...
            def sign(self, secret_key: bytes, message: bytes): ...
            def verify(self, public_key: bytes, message: bytes,
                       signature: bytes): ...
            def describe(self): ...

        with pytest.raises(RuntimeError, match="signature_size"):
            _assert_conforms("nosize", NoSize())

    def test_a_wrongly_typed_attribute_fails(self):
        """A string 'True' is truthy, so this would gate exposure the wrong way."""
        class Stringly(Good):
            side_channel_resistant = "yes"

        with pytest.raises(RuntimeError, match="side_channel_resistant"):
            _assert_conforms("stringly", Stringly())
