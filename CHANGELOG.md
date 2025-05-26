# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Satochip applet full versions follows this format: vX.Y-Z.W where:
* X.Y refers to the PROTOCOL VERSION: changes that impact compatibility with the client side (e.g new functionalities, major patch...)
* Z.W refers to changes with no impact on compatibility of the client (e.g minor patches, optimizations...)


## [FF.FF-FF-FF]  (WIP)

Refactoring, CVC & NDEF support (WIP)

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

* Add command to check unlock secret:
  * INS 0x54
  * This function check a given unlock counter and unlock_code and check validity.
  * This is useful for a client application to confirm their ownership is valid: if the applet returns SW_INCORRECT_UNLOCK_CODE, this probably means the cached unlock_secret in the application is wrong.



## [0.1-0.2]

* refactor card-setup: allows to read info when setup is not done (changes are not allowed)

## [0.1-0.1]

* initial version