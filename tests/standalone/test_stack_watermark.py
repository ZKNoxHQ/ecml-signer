"""Peak stack depth of the ML-DSA paths, read back over the wire.

Only runs on a build made with DEBUG_STACK_WATERMARK=1 (src/debug), which
paints the free stack at start-up and appends [used:4 BE][total:4 BE] to the
DUMMY (INS 0x0a) response; on a normal build DUMMY echoes cdata unchanged and
this test skips.

ML-DSA-65 is the deepest path of the app (keygen expands a 6x5 matrix; the
signer keeps a 6-polynomial w vector across the rejection loop), and Nano X
has the smallest stack of the supported devices, so this is the figure that
decides whether the parameter set fits:

    make DEBUG_STACK_WATERMARK=1  (BOLOS_SDK / TARGET set for the device)
    pytest tests/standalone/test_stack_watermark.py -s --device nanox
"""

import pytest
from Crypto.Hash import keccak
from ragger.backend.interface import BackendInterface
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import (
    CLA,
    BoilerplateCommandSender,
    Errors,
    InsType,
    MLDSAParam,
)

PATH = "m/44'/1'/0'/0'/0'"
# Headroom we require between the peak and the top of the stack. The SDK's own
# I/O and UX frames run on the same stack outside the paths measured here.
MIN_FREE_BYTES = 512


def _watermark(backend: BackendInterface) -> tuple[int, int]:
    rapdu = backend.exchange(cla=CLA, ins=InsType.DUMMY, p1=0, p2=0, data=b"\x00")
    assert rapdu.status == Errors.SWO_SUCCESS
    if len(rapdu.data) != 9:
        pytest.skip("app not built with DEBUG_STACK_WATERMARK=1")
    used = int.from_bytes(rapdu.data[1:5], "big")
    total = int.from_bytes(rapdu.data[5:9], "big")
    return used, total


def test_stack_watermark_mldsa(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    client = BoilerplateCommandSender(backend)
    _watermark(backend)  # skips early when this is not an instrumented build

    report: list[str] = []

    # Deepest paths: keygen and sign, for both parameter sets.
    for param in (MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65):
        client.keygen_mldsa_path(PATH, param)
        used, total = _watermark(backend)
        report.append(f"keygen      {param.name}: {used} / {total} bytes")

    for param in (MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65):
        m_hash = keccak.new(digest_bits=256, data=param.name.encode()).digest()
        with client.hybrid_sign_hash(path=PATH, m_hash=m_hash, param=param):
            # Diagnostic run: navigate the review without comparing screens
            # (the golden snapshots belong to test_mldsa65.py, which signs
            # other hashes).
            scenario_navigator.review_approve_with_warning(
                test_name=f"stack_watermark_{param.name.lower()}", do_comparison=False
            )
        client.get_mldsa_sig(param)
        used, total = _watermark(backend)
        report.append(f"hybrid sign {param.name}: {used} / {total} bytes")

    used, total = _watermark(backend)
    free = total - used
    report.append(f"peak over all ML-DSA paths: {used} / {total} bytes ({free} free)")
    print("\n" + "\n".join(report))

    assert free >= MIN_FREE_BYTES, (
        f"only {free} bytes of stack left below the peak ({used} / {total}); "
        "the ML-DSA buffers do not fit on this device"
    )
