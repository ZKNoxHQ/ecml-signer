from collections.abc import Generator
from contextlib import contextmanager
from enum import IntEnum

from ragger.backend.interface import RAPDU, BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import StatusWords

from .signing_partners import DYNAMIC_TOKEN_PARTNER
from .tlv import format_tlv

MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for maximum APDU number.
    P1_MAX = 0x03
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01


class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80


class MLDSAParam(IntEnum):
    """ML-DSA parameter set, carried in P2 of the ML-DSA INS (0x00 keeps the
    pre-existing ML-DSA-44 behaviour, so old clients are unaffected)."""

    MLDSA_44 = 0x00
    MLDSA_65 = 0x01

    @property
    def pk_bytes(self) -> int:
        return 1312 if self is MLDSAParam.MLDSA_44 else 1952

    @property
    def sig_bytes(self) -> int:
        return 2420 if self is MLDSAParam.MLDSA_44 else 3309

    @property
    def tau(self) -> int:
        return 39 if self is MLDSAParam.MLDSA_44 else 49

    @property
    def ctilde_bytes(self) -> int:
        return 32 if self is MLDSAParam.MLDSA_44 else 48

    def chunk_sizes(self, total: int) -> list[int]:
        """Split a length into the 255-byte chunks of GET_PK_CHUNK / GET_SIG_CHUNK."""
        full, rest = divmod(total, MAX_APDU_LEN)
        return [MAX_APDU_LEN] * full + ([rest] if rest else [])


class SettingId(IntEnum):
    """P1 values of SET_SETTING; mirrors src/handler/test_settings.c."""

    BLIND_SIGNING = 0x00


class InsType(IntEnum):
    GET_VERSION = 0x03
    GET_APP_NAME = 0x04
    GET_PUBLIC_KEY = 0x05
    SIGN_TX = 0x06
    SIGN_TOKEN_TX = 0x07
    SIGN_TX_MLDSA = 0x08
    DUMMY = 0x0A
    SAMPLE_IN_BALL = 0x0B
    KEYGEN_DILITHIUM_CORE = 0x0C
    SET_SETTING = 0x0D
    SIGN_DILITHIUM = 0x0F
    KEYGEN_DILITHIUM = 0x11
    GET_SIG_CHUNK = 0x12
    GET_PK_CHUNK = 0x13
    ECDSA_SIGN_HASH = 0x15
    HYBRID_SIGN_HASH = 0x16
    HYBRID_SIGN_USEROP = 0x17
    PROVIDE_TOKEN_INFO = 0x22


# Custom error codes specific to Boilerplate app
custom_errors = {
    "SW_INVALID_DYNAMIC_TOKEN": 0xB009,
    "SW_BLIND_SIGNING_DISABLED": 0xB00A,
}

# Build the combined dictionary first
_errors_dict = {m.name: m.value for m in StatusWords}
_errors_dict.update(custom_errors)

# Create the Errors enum
Errors = IntEnum("Errors", _errors_dict)  # type: ignore[misc]


def split_message(message: bytes, max_size: int) -> list[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


class BoilerplateCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=0xB0,  # specific CLA for BOLOS
            ins=0x01,  # specific INS for get_app_and_version
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=b"",
        )

    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_START, p2=P2.P2_LAST, data=b"")

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_APP_NAME, p1=P1.P1_START, p2=P2.P2_LAST, data=b"")

    def get_public_key(self, path: str) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=pack_derivation_path(path),
        )

    @contextmanager
    def get_public_key_with_confirmation(self, path: str) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_CONFIRM,
            p2=P2.P2_LAST,
            data=pack_derivation_path(path),
        ) as response:
            yield response

    @contextmanager
    def _sign_transaction(self, ins: InsType, path: str, transaction: bytes) -> Generator[None, None, None]:
        """Generic transaction signing handler (for SIGN_TX and SIGN_TOKEN_TX)."""
        self.backend.exchange(
            cla=CLA,
            ins=ins,
            p1=P1.P1_START,
            p2=P2.P2_MORE,
            data=pack_derivation_path(path),
        )
        messages = split_message(transaction, MAX_APDU_LEN)
        idx: int = P1.P1_START + 1

        for msg in messages[:-1]:
            self.backend.exchange(cla=CLA, ins=ins, p1=idx, p2=P2.P2_MORE, data=msg)
            idx += 1

        with self.backend.exchange_async(cla=CLA, ins=ins, p1=idx, p2=P2.P2_LAST, data=messages[-1]) as response:
            yield response

    # sign_tx and sign_token_tx are async functions that send the transaction to the device
    # Both functions yield in order to allow the caller to call the navigation functions
    @contextmanager
    def sign_tx(self, path: str, transaction: bytes) -> Generator[None, None, None]:
        with self._sign_transaction(InsType.SIGN_TX, path, transaction) as response:
            yield response

    @contextmanager
    def sign_token_tx(self, path: str, transaction: bytes) -> Generator[None, None, None]:
        with self._sign_transaction(InsType.SIGN_TOKEN_TX, path, transaction) as response:
            yield response

    @contextmanager
    def sign_tx_mldsa(
        self,
        path: str,
        transaction: bytes,
        param: MLDSAParam = MLDSAParam.MLDSA_44,
    ) -> Generator[None, None, None]:
        """SIGN_TX_MLDSA: the parameter set rides in the low bits of P2, beside
        the 0x80 more-flag (P2 = more | param)."""
        self.backend.exchange(
            cla=CLA,
            ins=InsType.SIGN_TX_MLDSA,
            p1=P1.P1_START,
            p2=P2.P2_MORE | param,
            data=pack_derivation_path(path),
        )
        messages = split_message(transaction, MAX_APDU_LEN)
        idx: int = P1.P1_START + 1

        for msg in messages[:-1]:
            self.backend.exchange(cla=CLA, ins=InsType.SIGN_TX_MLDSA, p1=idx, p2=P2.P2_MORE | param, data=msg)
            idx += 1

        with self.backend.exchange_async(
            cla=CLA, ins=InsType.SIGN_TX_MLDSA, p1=idx, p2=P2.P2_LAST | param, data=messages[-1]
        ) as response:
            yield response

    # ---------------------------------------------------------------- ML-DSA
    def keygen_mldsa_seed(self, seed: bytes, param: MLDSAParam = MLDSAParam.MLDSA_44) -> RAPDU:
        """KEYGEN_DILITHIUM_CORE (0x0c): deterministic keygen from a 32-byte seed."""
        return self.backend.exchange(cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=0, p2=param, data=seed)

    def keygen_mldsa_path(self, path: str, param: MLDSAParam = MLDSAParam.MLDSA_44) -> RAPDU:
        """KEYGEN_DILITHIUM (0x11): keygen from a BIP32 path (SLIP-0010)."""
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.KEYGEN_DILITHIUM,
            p1=0,
            p2=param,
            data=pack_derivation_path(path),
        )

    def _fetch_chunks(self, ins: InsType, total: int) -> bytes:
        out = b""
        for i, size in enumerate(MLDSAParam.MLDSA_44.chunk_sizes(total)):
            rapdu = self.backend.exchange(cla=CLA, ins=ins, p1=i, p2=size, data=b"")
            assert rapdu.status == StatusWords.SWO_SUCCESS
            assert len(rapdu.data) == size, f"chunk {i}: got {len(rapdu.data)}, expected {size}"
            out += rapdu.data
        return out

    def get_mldsa_pk(self, param: MLDSAParam = MLDSAParam.MLDSA_44) -> bytes:
        """GET_PK_CHUNK (0x13) over the whole public key of the parameter set."""
        return self._fetch_chunks(InsType.GET_PK_CHUNK, param.pk_bytes)

    def get_mldsa_sig(self, param: MLDSAParam = MLDSAParam.MLDSA_44) -> bytes:
        """GET_SIG_CHUNK (0x12) over the whole signature of the parameter set."""
        return self._fetch_chunks(InsType.GET_SIG_CHUNK, param.sig_bytes)

    def set_setting(self, setting: SettingId, enabled: bool) -> RAPDU:
        """Write an NVM setting directly (SET_SETTING, test builds only).

        Bypasses the Settings UI so a test can reach a known state on every
        device. The UI path has its own coverage in test_blind_signing.py.
        """
        return self.backend.exchange(cla=CLA, ins=InsType.SET_SETTING, p1=setting, p2=int(enabled), data=b"")

    def sample_in_ball(self, c_tilde: bytes, param: MLDSAParam = MLDSAParam.MLDSA_44) -> RAPDU:
        """SAMPLE_IN_BALL (0x0b) with the tau of the parameter set."""
        return self.backend.exchange(cla=CLA, ins=InsType.SAMPLE_IN_BALL, p1=0, p2=param, data=c_tilde)

    @contextmanager
    def hybrid_sign_hash(
        self,
        path: str,
        m_hash: bytes,
        param: MLDSAParam = MLDSAParam.MLDSA_44,
    ) -> Generator[None, None, None]:
        """HYBRID_SIGN_HASH (0x16): ECDSA inline, ML-DSA via the chunk INS."""
        assert len(m_hash) == 32
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.HYBRID_SIGN_HASH,
            p1=0,
            p2=param,
            data=pack_derivation_path(path) + m_hash,
        ) as response:
            yield response

    @contextmanager
    def hybrid_sign_userop(
        self,
        path: str,
        metadata: bytes,
        packed: bytes,
        call_data: bytes,
        param: MLDSAParam = MLDSAParam.MLDSA_44,
    ) -> Generator[None, None, None]:
        """HYBRID_SIGN_USEROP (0x17): the 4-step sequence, P2 = parameter set
        on every step."""
        for p1, data in (
            (0x00, pack_derivation_path(path)),
            (0x01, metadata),
            (0x02, packed),
        ):
            rapdu = self.backend.exchange(cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=p1, p2=param, data=data)
            assert rapdu.status == StatusWords.SWO_SUCCESS
        with self.backend.exchange_async(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=0x03, p2=param, data=call_data
        ) as response:
            yield response

    # Retrieve the last asynchronous response from the backend
    def get_async_response(self) -> RAPDU | None:
        return self.backend.last_async_response

    # Synchronous versions of sign_tx and sign_token_tx
    # These functions wait for the response after sending the transaction. They are particularly
    # useful for tests that expect the device to refuse the transaction before any review.
    def sign_tx_sync(self, path: str, transaction: bytes) -> RAPDU | None:
        with self.sign_tx(path, transaction):
            pass
        rapdu = self.get_async_response()
        assert isinstance(rapdu, RAPDU)
        return rapdu

    def sign_token_tx_sync(self, path: str, transaction: bytes) -> RAPDU | None:
        with self.sign_token_tx(path, transaction):
            pass
        rapdu = self.get_async_response()
        assert isinstance(rapdu, RAPDU)
        return rapdu

    def provide_dynamic_token(self, ticker: str, decimals: int, token_address: bytes, chain_id: int = 0x8001) -> RAPDU:
        """
        Provide a dynamic token descriptor signed with CAL test key.

        Args:
            ticker: Token ticker symbol (e.g., "USDC", "WETH")
            decimals: Number of decimal places (e.g., 6 for USDC, 18 for WETH)
            token_address: 32-byte token address for TUID
            chain_id: SLIP-44 coin type (default 0x8001 for boilerplate test coin)

        Returns:
            RAPDU response from the device
        """
        assert len(token_address) == 32, f"Token address must be 32 bytes, got {len(token_address)}"

        # Build TUID sub-TLV: tag 0x10 with 32-byte address (Boilerplate specific example)
        tuid = format_tlv(0x10, token_address)

        # Build payload WITHOUT signature for now
        payload = format_tlv(0x01, 0x90)  # STRUCTURE_TYPE: DYNAMIC_TOKEN
        payload += format_tlv(0x02, 0x01)  # VERSION: 1
        payload += format_tlv(0x03, chain_id)  # COIN_TYPE
        payload += format_tlv(0x04, "ECML-Signer")  # APP: application name
        payload += format_tlv(0x05, ticker)  # TICKER
        payload += format_tlv(0x06, decimals)  # MAGNITUDE (decimals)
        payload += format_tlv(0x07, tuid)  # TUID

        # Sign the crafted payload and append the signature to it
        payload += format_tlv(0x08, DYNAMIC_TOKEN_PARTNER.sign(payload))  # SIGNATURE

        # Before sending the mock CAL descriptor, we need to onboard our mock CAL using a PKI certificate
        self.backend.exchange_raw(DYNAMIC_TOKEN_PARTNER.get_certificate_payload(self.backend.device.type))

        # Send APDU with P1=0, P2=0 (no chunking for token descriptors)
        return self.backend.exchange(cla=CLA, ins=InsType.PROVIDE_TOKEN_INFO, p1=0x00, p2=0x00, data=payload)
