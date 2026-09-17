# ****************************************************************************
#    ZKNOX
#    (c) 2026.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "ECML-Signer"

# Application version
APPVERSION_M = 2
APPVERSION_N = 4
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Application source files
APP_SOURCE_PATH += src

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOX = icons/app_boilerplate_14px.gif
ICON_NANOSP = icons/app_boilerplate_14px.gif
ICON_STAX = icons/app_boilerplate_32px.gif
ICON_FLEX = icons/app_boilerplate_40px.gif
ICON_APEX_P = icons/app_boilerplate_32px_apex.png

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_NANOS2))
    # With the Nano NBGL Design, the Home Screen icon is the reverse of the App icon:
    # It should be on white background, with rounded corners.
    # This definition allows SDK Makefiles to automatically generate it based on the App icon.
    # Please note that the icon is dynamically generated, and declared in the .gitignore to avoid storing it.
    ICON_HOME_NANO = glyphs/home_boilerplate_14px.gif
endif

# Application allowed derivation curves.
# Possibles curves are: secp256k1, secp256r1, ed25519 and bls12381g1
# If your app needs it, you can specify multiple curves by using:
# `CURVE_APP_LOAD_PARAMS = <curve1> <curve2>`
# ed25519 is required by the SLIP-0010 mode used to derive the ML-DSA seed
# (see src/ui/action/validate.c). Not used for on-curve signing.
CURVE_APP_LOAD_PARAMS = secp256k1 ed25519

# Application allowed derivation paths.
# You should request a specific path for your app.
# This serve as an isolation mechanism.
# Most application will have to request a path according to the BIP-0044
# and SLIP-0044 standards.
# If your app needs it, you can specify multiple path by using:
# `PATH_APP_LOAD_PARAMS = "44'/1'" "45'/1'"`
PATH_APP_LOAD_PARAMS = "44'/60'" "44'/1'"   # Ethereum (60) + Testnet (1)

# Setting to allow building variant applications
# - <VARIANT_PARAM> is the name of the parameter which should be set
#   to specify the variant that should be build.
# - <VARIANT_VALUES> a list of variant that can be build using this app code.
#   * It must at least contains one value.
#   * Values can be the app ticker or anything else but should be unique.
VARIANT_PARAM = COIN
VARIANT_VALUES = BOL

# Enabling DEBUG flag will enable PRINTF for speculos
#DEBUG = 1

# Stack high-water mark printed on the Speculos console after every APDU
# (src/debug/stack_watermark.c). Keeps the release optimisation level (-Oz,
# not DEBUG's -Og) so the figure is the one of the production build; only
# PRINTF is enabled. Used to size the ML-DSA buffers: ML-DSA-65 keygen + sign
# is the deepest path of the app.
#DEBUG_STACK_WATERMARK = 1
ifeq ($(DEBUG_STACK_WATERMARK), 1)
    DEFINES += HAVE_PRINTF HAVE_STACK_WATERMARK
endif

# Enabling DEBUG_OVER_USB flag will enable PRINTF over USB
# This will force DISABLE_OS_IO_STACK_USE and add USB CDC profile
# The log can be displayed using a COM port terminal
#DEBUG_OVER_USB = 1

########################################
#     Application custom permissions   #
########################################
# See SDK `include/appflags.h` for the purpose of each permission
#HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
#HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
#HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
#HAVE_APPLICATION_FLAG_LIBRARY = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1
#ENABLE_NFC = 1
ENABLE_NBGL_FOR_NANO_DEVICES = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1
#ENABLE_NBGL_KEYBOARD = 1
#ENABLE_NBGL_KEYPAD = 1

########################################
#       SWAP FEATURE FLAG      		   #
# This flag enables the swap feature   #
# in the Boilerplate application.      #
########################################
# This is a smart documentation inclusion. The full documentation is available at https://ledgerhq.github.io/app-exchange/
# --8<-- [start:variables]
ifeq ($(APPNAME), "ECML-Signer")
# Two flags exist for enabling the SWAP
#   - ENABLE_SWAP           will lead to the enabling of the swap related C code of the standard_app
#                           AND will lead to the enabling of the APP_LOAD_PARAM required for os_lib_call working on device
#   - ENABLE_TESTING_SWAP:  will lead to the enabling of the swap related C code of the standard_app
#                           ONLY works on Speculos, not on device
# Testing only SWAP flag
ENABLE_TESTING_SWAP = 1
# Production enabled SWAP flag
# ENABLE_SWAP = 1
endif
# --8<-- [end:variables]

########################################
#          TLV & PKI features          #
########################################
# Both are used in the Dynamic Token example
ENABLE_TLV_LIBRARY = 1
ENABLE_PKI_LIBRARY = 1

########################################
#        Stack protection features     #
########################################
ENABLE_STACK_PROTECTOR = 1

########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
#DISABLE_STANDARD_APP_FILES = 1
#DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1 # To allow custom size declaration

# APDU I/O buffer.
#
# SIGN_TX_MLDSA (INS 0x08) answers pk_len(2) || pk || sig_len(2) || sig in a
# single response: 3736 B for ML-DSA-44 (1312 + 2420), 5265 B for ML-DSA-65
# (1952 + 3309). CUSTOM_IO_APDU_BUFFER_SIZE sizes BOTH G_io_rx_buffer and
# G_io_tx_buffer, so asking for 5376 costs ~10.5 KB of RAM.
#
# Nano X only has 28 KB of SRAM and the ML-DSA paths peak at ~9.3 KB of stack
# (measured, see tests/standalone/test_stack_watermark.py), so the large
# buffer does not fit there: on Nano X the app keeps the default buffer and
# SIGN_TX_MLDSA is limited to ML-DSA-44. ML-DSA-65 remains fully available on
# every device through the hybrid flows (HYBRID_SIGN_HASH 0x16 /
# HYBRID_SIGN_USEROP 0x17) and the KEYGEN + SIGN_DILITHIUM primitives, which
# return the ML-DSA half in 255-byte chunks (GET_PK_CHUNK / GET_SIG_CHUNK)
# and never need a large response.
ifeq ($(TARGET_NAME),TARGET_NANOX)
    # Nano X: 28 KB of SRAM total. A 5376-byte I/O buffer would leave ~9.4 KB
    # of stack, below the ~14.2 KB the review + ML-DSA signing path needs
    # (measured; see tests/standalone/test_stack_watermark.py), so the buffer
    # is sized for the largest CHUNKED response instead - SAMPLE_IN_BALL
    # returns a 1024-byte polynomial - and SIGN_TX_MLDSA, whose single
    # response does not fit, is unavailable (-1). Every ML-DSA feature stays
    # reachable there through HYBRID_SIGN_HASH / HYBRID_SIGN_USEROP and the
    # KEYGEN + SIGN_DILITHIUM primitives, which answer in 255-byte chunks.
    DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1
    DEFINES += CUSTOM_IO_APDU_BUFFER_SIZE=1280
    DEFINES += MLDSA_SIGN_TX_MAX_PARAM=-1
else
    DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1
    DEFINES += CUSTOM_IO_APDU_BUFFER_SIZE=5376
    DEFINES += MLDSA_SIGN_TX_MAX_PARAM=1
endif

# ML-DSA is provided as source in lib_cxng/src (not exported via cx.export),
# so pull the sources in and expose the internal headers.
# HAVE_MLDSA_OPTIMIZATION selects the SDK low-RAM signer/verifier (compressed
# challenge and w buffers, schoolbook c*t0 / c*t1 straight from the packed
# keys, streamed matrix expansion). The ML-DSA workspace dominates the stack of
# the review callback, and the small-RAM devices cannot host the plain one.
DEFINES += HAVE_MLDSA_OPTIMIZATION
SDK_SOURCE_FILES += $(wildcard $(BOLOS_SDK)/lib_cxng/src/cx_mldsa*.c)
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src
#DISABLE_STANDARD_APP_DEFINES = 1 # Will set all the following disablers
#DISABLE_STANDARD_SNPRINTF = 1
#DISABLE_STANDARD_USB = 1
#DISABLE_STANDARD_WEBUSB = 1
#DISABLE_DEBUG_LEDGER_ASSERT = 1
#DISABLE_DEBUG_THROW = 1

include $(BOLOS_SDK)/Makefile.standard_app
