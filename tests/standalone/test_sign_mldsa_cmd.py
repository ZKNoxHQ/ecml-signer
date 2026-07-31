from Crypto.Hash import keccak
from cryptography.hazmat.primitives.asymmetric import mldsa
from ragger.backend.interface import BackendInterface
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import BoilerplateCommandSender
from application_client.boilerplate_response_unpacker import unpack_sign_tx_mldsa_response
from application_client.boilerplate_transaction import Transaction


# The device signs Keccak-256(raw_tx) with an ML-DSA-44 key derived from the
# device seed via SLIP-0010 (HMAC-SHA512 key = "mldsa-44"). We can't reproduce
# that key host-side without the device seed, so the test relies on the pk
# returned alongside the signature and just verifies signature validity.
def test_sign_tx_mldsa(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    client = BoilerplateCommandSender(backend)
    # SLIP-0010 ed25519-mode derivation requires all-hardened path components.
    path: str = "m/44'/1'/0'/0'/0'"

    transaction = Transaction(
        nonce=1,
        to="0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        value=666,
        memo="mldsa",
    ).serialize()

    with client.sign_tx_mldsa(path=path, transaction=transaction):
        scenario_navigator.review_approve()

    response = client.get_async_response().data
    pk_bytes, sig = unpack_sign_tx_mldsa_response(response)

    assert len(pk_bytes) == 1312, f"unexpected ML-DSA-44 pk length: {len(pk_bytes)}"
    assert len(sig) == 2420, f"unexpected ML-DSA-44 sig length: {len(sig)}"

    # Device hashes with Keccak-256 (not SHA3-256) before signing.
    k = keccak.new(digest_bits=256)
    k.update(transaction)
    m_hash = k.digest()

    # ML-DSA verify with an empty context matches the device call (ctx=NULL, ctx_len=0).
    pk = mldsa.MLDSA44PublicKey.from_public_bytes(pk_bytes)
    pk.verify(sig, m_hash)


# Same flow, but check that the derived key is stable across two signs of the
# same message: the pk must match, and both signatures must verify against it.
def test_sign_tx_mldsa_deterministic_pk(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    client = BoilerplateCommandSender(backend)
    # SLIP-0010 ed25519-mode derivation requires all-hardened path components.
    path: str = "m/44'/1'/0'/0'/0'"

    transaction = Transaction(
        nonce=2,
        to="0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        value=1,
        memo="mldsa-2",
    ).serialize()

    k = keccak.new(digest_bits=256)
    k.update(transaction)
    m_hash = k.digest()

    pks = []
    for _ in range(2):
        with client.sign_tx_mldsa(path=path, transaction=transaction):
            scenario_navigator.review_approve()
        pk_bytes, sig = unpack_sign_tx_mldsa_response(client.get_async_response().data)
        mldsa.MLDSA44PublicKey.from_public_bytes(pk_bytes).verify(sig, m_hash)
        pks.append(pk_bytes)

    assert pks[0] == pks[1], "ML-DSA public key must be deterministic across signs of the same path"
