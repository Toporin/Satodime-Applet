# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Satochip applet full versions follows this format: vX.Y-Z.W where:
* X.Y refers to the PROTOCOL VERSION: changes that impact compatibility with the client side (e.g new functionalities, major patch...)
* Z.W refers to changes with no impact on compatibility of the client (e.g minor patches, optimizations...)


## [00.02-00.01]  (WIP)

Refactoring, CVC & NDEF support (WIP)

* Add card config through parameters during applet installation:
  * install parameters: `[ nb_slots(1b, optional) | is_coa(1b, optional) | rfu(2b, optional) | cvc_size(1b, optional) | cvc ]`

* Minor optimisation: return card status on card select

* Improve authentikey mgmt
    * In InitiateSecureChannel(), returns the coordx of authentikey to allow unambiguous recovery of authentiokey pubkey on client side

* Use transient AES key for secure channel encryption (Transient object do not wear flash memory)

* Use transient elliptic key for the ephemeral privkey used in secure channel

* Add support for fixed CVC
  * When enabled, the unlock secret is fixed during the lifetime of the applet and set during applet installation using a value provided in install parameters. 
  * As use case, the CVC can be engraved on the card.
  * The implementation of CVC is based on the same unlock secret mechanism and counter, the main difference is that CVC is fixed and provided externally, not generated randomly.
add command to check unlock secret
  * CVC is provided as install parameter during applet installation.

* Add command to check unlock secret:
  * INS 0x54
  * This function checks a given unlock counter and unlock_code and check validity.
  * This is useful for a client application to confirm their ownership is valid: if the applet returns SW_INCORRECT_UNLOCK_CODE, this probably means the cached unlock_secret in the application is wrong.

* Add APDU command to sign a transaction hash with the privkey for a given key slot
  * INS: 0x5B
  * This function is only available when slot status is 'unsealed'.

* Add NDEF support via the NDEFApplet and a data array shared with the Satodime applet.
  * NDEF data & policy can be changed through the Satodime applet, after ownership validation.

* Refactor cardNdef() command APDU
  * Check ownership for changing NDEF data
  * Support 3 NDEF policies: 0: No NDEF, 1: static NDEF, 2: dynamic NDEF
  * Change response format when getting current NDEF data.
  * Note that APDU format is not compatible with format used in seedkeeper applet

* Switch to gradle for building applet with NDEF support
  * based on https://github.com/fidesmo/gradle-javacard

## [0.1-0.2]

* refactor card-setup: allows to read info when setup is not done (changes are not allowed)

## [0.1-0.1]

* initial version