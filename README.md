# Satodime-Applet
Open source javacard applet implementing a bearer crypto card. The bearer chip card that allows you to spend crypto assets like a banknote. Safely pass it along multiple times,  unseal anytime with ease, thanks to cryptography. Trustless, easy to verify and completly secure.

# Introduction

Satodime is a smartcard that stores cryptographic keypairs securely in a secure chip (also called Secure Element).
Each keypair can be associated with a specific address on a blockchain.

Each keypair is generated inside the secure chip and can be in any one of 3 states at any time:
- uninitialized: the keypair has not been generated yet
- sealed: the keypair has been generated securely inside the chip, only the public key is available
- unsealed: the private key has been revealed

Since the private key is generated inside the secure chip, a Satodime bearer can be certain that nobody (including himself) knows the private key until the key is unsealed.
In effect, a Satodime allows to physically transfer cryptocurrencies such as Bitcoin from one person to another, without having to trust the bearer of the Satodime, AS LONG AS THE KEY IS IN THE SEALED STATE.

Depending on the model, from 1 up to 3 keypairs can be stored simultaneously on a single Satodime.

# Security features

## Satodime authenticity:
The Satodime includes a cryptographic mechanism that allows to check whether the card is an authentic Satodime or a fake one. If the card is not authenticated, you should be extremely careful and avoid to store any valuable on it. The authentication mechanism is based on a unique digital certificate issued for each authentic Satodime and verified with a trusted Public Key Infrastructure.

## Secure key generation:
Private/public keypairs stored on the Satodime are always generated randomly inside the secure chip. As long as the keyslot is sealed, nobody has access to the private key. To prove that the private keys were not pre-generated during manufacturing and that no backdoor was inserted in the firmware, the user is prompted for a 64-hex random value during the sealing process. This random input is used to provide entropy during the key generation process. When the keyslot is unsealed and the private key is revealed, the entropy data (including user input) is provided and allows to ensure that the key generation process was indeed random.

## Transfer of ownership protection:
Satodime (and the SatodimeTool) supports communication through 2 interfaces: the NFC (Near Field Communication)  wireless interface and the wired interface through a standard smartcard reader.

It is important to note that the behavior of the Satodime is slightly different according to the interface used: the wired interface is considered 'trusted' while the NFC is not. In practice, this means that anyone can perform any operation via the wired (trusted) interface, while some sensitive operations can only be performed via the NFC interface by the legitimate owner. Sensitive operations include all operations that change the state of a keyslot (such as unsealing). This ensures that the current owner of a Satodime can confidently let a potential acquirer scan the card on his own device (e.g. to check the available balance) without the risk of unsealing and sweeping a private key.

To distinguish the legitimate owner of the card from other users, a pairing process is initiated when the card is transfered to a new owner. To initiate this transfer, the former owner simply click on the 'Transfer card' button in the 'Card info' tab in the main menu. Immediatly after, the card should be disconnected and provided the new owner to initiate new pairing. A message is then shown to confirm that a new pairing has been successfully established with the new owner through the SatodimeTool. If the transfer of ownership has not been initiated by the previous owner, the new owner SHOULD perform this transfer as soon as possible. The procedure is the same, except that in this case, it MUST be done via the 'trusted' wired interface (since pairing is a sensitive operation and it can only be done via the NFC interface by the legitimate owner).

# Satodime applications

Two applications are available to be use with a Satodime:
- Windows & Linux: [Satodime-Tool](https://github.com/Toporin/Satodime-Tool)
- Android: [Satodime-Android](https://github.com/Toporin/Satodime-Android)

Macos & IOS tools will be released later.

# Supported hardware

For supported hardware, refer to the [Satochip applet repository](https://github.com/Toporin/SatoChipApplet).

# Buidl & install

You can build the javacard CAP files or use the last [release](https://github.com/Toporin/SatochipApplet/releases).

To generate the CAP file from the sources, you can use the [ant-javacard](https://github.com/martinpaljak/ant-javacard) Ant task (see the instructions on the ant-javacard github repository).

For detailed build and installation, refer to the [Satochip applet repository](https://github.com/Toporin/SatoChipApplet). 

# License

This application is distributed under the GNU Affero General Public License version 3.

Some parts of the code may be licensed under a different (MIT-like) license. [Contact me](mailto:satochip.wallet@gmail.com) if you feel that some license combination is inappropriate.
