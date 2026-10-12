The `application_client` directory contains the minimalist python client for crafting and sending APDUs to the application.

The `standalone` directory contains the functional tests of the application, started from the Dashboard of the
device. They require a build made with `TEST_INS=1` (or `DEBUG=1`), which exposes the test-only instructions they
use; see "Test-only instructions" in `APP_SPECIFICATION.md`.

The application does not support the Exchange/swap flow, so there is no swap test suite.
