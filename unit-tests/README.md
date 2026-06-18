# Unit tests

## Prerequisite

The following dependencies shall be installed :
- CMake >= 3.10
- lcov >= 1.14
- ruby >= 3.2 (Needed mock generation)

## Build, run unit tests and compute code coverage

In `unit-tests` folder, compile with

```shell
cmake -Bbuild -H. && make -C build
```

and run tests with

```shell
CTEST_OUTPUT_ON_FAILURE=1 make -C build test
```

To compute code coverage, execute in `unit-tests` folder

```shell
make generate_coverage
```

it will output `coverage.total` and `coverage/` folder with HTML details (in `coverage/index.html`).

## Unit tests - how to

### Introduction

This section describes how to write unit tests for ledger applications.

Ledger SDK provides with a CMake unit test module (`LedgerUT`). Under the hood, it uses ThrowTheSwitch's Unity framework and CMock mocking framework.

High coverages are typically ch allenging because testing a module usually requires dependencies to other app modules, to the SDK, and ultimately dependencies to OS.

Including all these dependencies is not desirable as unit tests of a module `A` should only test the logic of module `A`, not its integration with the rest of the app, nor its integration with the SDK or the OS. for example, when testing the APDU dispatcher, no actual apdu needs to transit, testing the dispatcher's logic is what is needed to validate its logic.

CMock makes it fairly easy to reach 100% code coverage as demonstrated in this app, by removing any dependency to other app modules, to the SDK or to the OS.

Previous unit tests implementation leveraged `cmocka`, which provides less flexibility :
- mocks are generated manually, they need to be maintained (i.e. when interfaces change)
- linker needs to be used to mock a function (-Wl,--wrap=my_func), which is challenging when a test suite supplants a functions with several callbacks in different tests.

Also current approach is that app-builder provides with cmocka, and leaving the app developer the ownership to design his UT. This can be improved by delegating UT design to the SDK, as to have a unified UT design across all apps.

Current tests, on the other hand, leverage Unity/CMock which :
- parse dependent headers and create mock implementation
- mocked implementation is programmable through `my_func_Expect`, `my_func_ExpectAndReturn` statements and alike
- when needed, custom behavior can still be achieved through `AddCallback`
- mocks are not versioned, they are part of the build.
- mocks do not need to be maintained upon interface changes, they are re-generated and part of the build.
- upon interface change, only the unit-tests need to be updated.

When a module depends on trivial other modules, it can be desirable to not mock these. `LedgerUT` still makes it possible to implement so-called *sociable* unit tests.

The following sections describe how to install `LedgerUT`, how to configure `LedgerUT`, and how to add unit tests and mocks.

### LedgerUT installation

To include LedgerUT, the following lines shall be added to the `CMakeLists.txt` of the `unit-tests` folder:

```cmake
set(SDK_DIR $ENV{BOLOS_SDK})
list(APPEND CMAKE_MODULE_PATH "${SDK_DIR}/CMake")
include(LedgerUT)
```

### Unit test configuration

Any tested code likely depends on the SDK and app modules. The include dependencies are satisfied like this :

```cmake
set(UT_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/apdu
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/handler
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/helper
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/swap
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/token
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/transaction
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/action
    ${CMAKE_CURRENT_SOURCE_DIR}/fakes/
)
```

The SDK itself provides with `${UT_INCLUDE_DIRS_SDK}` to resolve include dependencies on SDK headers.
It also provides with `${UT_COMPILE_DEFS_SDK}` to resolve compile definitions in SDK, that shall be added for some types to be defined (e.g. `cx_` types).

Unit tests may also define their own compile definitions, e.g.

```cmake
set(UT_COMPILE_DEFS
    APPNAME="Boilerplate"
    APPVERSION="9.9.9"
)
```

### Unit test and coverage initialization

The LedgerUT module is initialized through the following :

```cmake
ledger_unit_tests_init()
ledger_unit_tests_find_sources()

ledger_unit_tests_build_app_sources_as_lib(
    SOURCES      ${APP_SOURCES}
    INCLUDE_DIRS ${UT_INCLUDE_DIRS}
    COMPILE_DEFS ${UT_COMPILE_DEFS}
)
```
`ledger_unit_tests_init` will setup CMake, compiler flags and configure mock generation.

`ledger_unit_tests_find_sources` will find all sources in the tested app using CMake's `GLOB_RECURSE` feature.
This is to ensure all sources are compiled and have an associated `.gcno` file for code coverage computation.

A source that has not `.gcno` file will not be counted in coverage percentage, which introduces a bias in the coverage report.

The only exception is the application `(app_)?main.c` file, which is not counted in coverage report.

`ledger_unit_tests_build_app_sources_as_lib` will be the app sources in as a static library. It will never be used, it is for the sake of having `.gcno` files.

### Adding unit tests

In this section we discuss the ability to implement solitary unit tests for the app, as opposed to sociable unit tests. As a reminder :
- solitary unit tests are tests that do not depend on any other module actual implementation, they only rely on mocks.
- sociable unit tests on the other hand, depend on other modules actual implementation.
We follow the first, stricter approach to demonstrate the `LedgerUT` capabilities. `LedgerUT` remains compatible with sociable unit tests.

Solitary unit tests also make it possible to reach 100% code coverage and test the UI logic, as demonstrated in this app.

#### Example 1 - dispatcher.c

In this section, we take the example of `src/apdu/dispatcher.c` file, which has direct dependencies on :
- the SDK through `buffer.h`, `os.h`, `ledger_assert.h`;
- the app through `get_version.h`, `get_app_name.h`, `get_public_key.h`, `sign_tx.h`, `provide_token_info.h`.

We create a test that will automatically mock all these dependencies, using the following `LedgerUT` CMake function :

```cmake
ledger_unit_tests_add_test(
    NAME           test_dispatcher
    SOURCES        ${CMAKE_CURRENT_SOURCE_DIR}/../src/apdu/dispatcher.c
    MOCK_HEADERS   ${SDK_DIR}/lib_standard_app/buffer.h
                   ${SDK_DIR}/lib_standard_app/io.h
                   ${SDK_DIR}/include/ledger_assert_internals.h
                   ${CMAKE_CURRENT_SOURCE_DIR}/../src/handler/get_version.h
                   ${CMAKE_CURRENT_SOURCE_DIR}/../src/handler/get_app_name.h
                   ${CMAKE_CURRENT_SOURCE_DIR}/../src/handler/get_public_key.h
                   ${CMAKE_CURRENT_SOURCE_DIR}/../src/handler/sign_tx.h
                   ${CMAKE_CURRENT_SOURCE_DIR}/../src/handler/provide_token_info.h
    INCLUDE_DIRS   ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS   ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)
```

It will generate mocks for all headers listed in `MOCK_HEADERS` and compile the test with the app source `dispatcher.c`.
It will also include the necessary include directories and compile definitions listed in `INCLUDE_DIRS` and `COMPILE_DEFS`.

Mocks will be generated in `unit-tests/build/mocks`. All mocks are prefixed with `Mock`, e.g. `Mockbuffer.h`, `Mockget_version.h`, etc.

Mocks are wrappers to the original headers, the original function declarations and types still exist. 
The mock will provide with a set of functions that enable to control the behavior of the mocked functions.
For example, `get_version_ExpectAndReturn(...)` will set the expected return value of `get_version(...)` whenever `get_version` is called in the tested module.

`unit-tests/test_dispatcher.c` demonstrates how to use the generated mocks to test `dispatcher.c` in isolation.

#### Example 2 - menu_nbgl.c

In this section, we take the example of `src/ui/menu_nbgl.c` file, which has direct dependencies on :
- The SDK through `os.h`, `nbgl_use_case.h`, `os_nvm.h`, `os_helpers.h`;
- The app through `menu.h`, `display.h`.

