/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015-2019 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package org.satodime.applet;

import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacard.security.RandomData;

/**
 * SharedObject Class
 * <p>
 * This class uses a singleton pattern to share an object between the Satodime and NDEF applets.
 * The purpose is to provide up-to-date info about the card status through NDEF.
 * The NDEF record is signed and data includes a random nonce to provide some validity proof.
 * Info includes:
 * <ul>
 *   <li>Applet version</li>
 *   <li>Card type</li>
 *   <li>Number of slots</li>
 *   <li>Slot info: slot state, slip44 info, slot pubkey </li>
 * </ul>
 *
 */

public class SharedObject {

    /** singleton object shared with Satodime and NDEF applet **/
    private static SharedObject instance;

    private static byte[] tmpBuffer;

    /** base URL for dynamic url **/
    static final byte[] BASE_URL = {'e','x','a','m','p','l','e','.','c','o','m', '/'};

    /** for bytes to hex conversion **/
    static final byte[] HEX = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    /** NDEF file for dynamic url**/
    short ndefDataFileSize;
    byte[] ndefDataFile;

    /** number of slots **/
    byte nb_slots = 0;

    /** constants **/
    static final short SIZE_HEADER = 10;
    static final short SIZE_NONCE = 16; // 8-bytes hex-encoded
    static final short SIZE_CARD_TYPE = 1; // 1-hex
    static final short SIZE_VERSION = 8; // 4-byte hex-encoded
    static final short SIZE_PUBKEY = 66; // 33-byte hex-encoded
    static final short SIZE_NBSLOT = 1; // 1-hex
    static final short SIZE_SLOT = 75; // [state(1hex) | slip44(8hex) | pkey(66hex) ]
    static final short SIZE_STATE = 1; // 1-hex
    static final short SIZE_SLIP44 = 8; // 4-byte hex-encoded
    static final short SIZE_SIGNATURE = 144; // 72-byte hex-encoded

    /** offsets **/
    private short offset_nonce;
    private short offset_authentikey;
    private short offset_first_slot;
    private short offset_authentikey_sig_size;
    private short offset_authentikey_sig;

    private short size_message_to_sign;

    /** for nonce randomness **/
    private RandomData randomData;
    private Signature sigECDSA;

    /**
     * NDEF authentikey is used to authenticate key through NDEF tag.
     * For privacy, this authentikey should be shared between multiple cards.
     * By default, we use a dummy privkey, that should be updated during personalization.
     */
    private ECPrivateKey ndef_authentikey_private;

    /**
     * Constructor for the SharedObject class.
     * The SharedObject is a singleton shared between the Satodime and NDEF applet.
     * We use an empty constructor without parameters then use a initializer called from the Satodime class.
     */
    SharedObject() {

    }

    /**
     * SharedObject initializer called from the Satodime class.
     *
     * @param buffer
     *          shared temporary buffer used for intermediate operations
     * @param nb_slots
     *          Max number of slots
     *
     */
    void init(byte[] buffer, byte nb_slots) {

        tmpBuffer = buffer;

        this.nb_slots = nb_slots;
        //this.nb_slots = (byte)2; // todo!

        // cryptographic objects
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sigECDSA= Signature.getInstance(Satodime.ALG_ECDSA_SHA_256, false);

        // ndef_authentikey
        ndef_authentikey_private= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, Satodime.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(ndef_authentikey_private);
        //randomData.generateData(tmpBuffer, (short)0, Satodime.SIZE_ECPRIVKEY); // random, unique value may leak privacy
        Util.arrayFillNonAtomic(tmpBuffer, (short)0, Satodime.SIZE_ECPRIVKEY, (byte)1); // use dummy privkey by default, should be replace during personalization.
        ndef_authentikey_private.setS(tmpBuffer, (short)0, Satodime.SIZE_ECPRIVKEY);

        // offsets
        // [header(10b) | base_url() ] +
        // [nonce(8b) |  cardtype(1b) | version(4b) | authentikey(33b) | nb_slot(1b) ] +
        // [status(1b) | slip44(4b) | pubkey(33b) ] * nb_slot +
        // [authentikey_sig_size(1b) | authentikey_sig(70-72b) | padding(0-2b)]
        // total size: (10 + 12) + (16 + 1 + 8 + 66 + 1) + (75)*nb_slot + 145
        // for 1 slot: 22 + 92 + 75 + 145 = 334 (312 without the url & header)
        this.offset_nonce = (short)(SIZE_HEADER + BASE_URL.length);
        this.offset_authentikey = (short)(this.offset_nonce + SIZE_NONCE + SIZE_CARD_TYPE + SIZE_VERSION);
        this.offset_first_slot = (short)(offset_authentikey + SIZE_PUBKEY + SIZE_NBSLOT);
        this.offset_authentikey_sig_size = (short)(offset_first_slot + this.nb_slots * SIZE_SLOT);
        this.offset_authentikey_sig = (short)(offset_authentikey_sig_size+1);

        // size of msg to sign
        this.size_message_to_sign  = (short)(this.offset_authentikey_sig_size - this.offset_nonce);

        // Allocate the memory
        this.ndefDataFileSize = (short)(offset_authentikey_sig + SIZE_SIGNATURE);
        this.ndefDataFile = new byte[this.ndefDataFileSize];

        // populate ndef record with the fixed parts
        // header
        short offset = 0;
        Util.setShort(ndefDataFile, offset, (short)(this.ndefDataFileSize-2));
        offset += (short) 2;
        ndefDataFile[offset++] = (byte) 0xC1; // Header for Long URL
        ndefDataFile[offset++] = (byte) 0x01; // Type Length
        ndefDataFile[offset++] = (byte)0x00; // Short Payload Length (4b)
        ndefDataFile[offset++] = (byte)0x00; // Short Payload Length (4b)
        Util.setShort(ndefDataFile, offset, (short)(this.ndefDataFileSize-9));
        offset += (short) 2;
        ndefDataFile[offset++] = (byte) 0x55; // Record Type 'U'
        ndefDataFile[offset++] = (byte) 0x04;// URI Identifier Code (https://)
        // base URL
        Util.arrayCopy(BASE_URL, (short) (0), ndefDataFile, offset, (short) BASE_URL.length);
        offset += BASE_URL.length;
        // skip nonce
        offset += SIZE_NONCE;
        // cardtype
        ndefDataFile[offset++] = (byte) '2';

        // version
        ndefDataFile[offset++] = HEX[(short)((Satodime.PROTOCOL_MAJOR_VERSION>>4) & 0x0F)];
        ndefDataFile[offset++] = HEX[Satodime.PROTOCOL_MAJOR_VERSION & 0x0F];
        ndefDataFile[offset++] = HEX[(short)((Satodime.PROTOCOL_MINOR_VERSION>>4) & 0x0F)];
        ndefDataFile[offset++] = HEX[Satodime.PROTOCOL_MINOR_VERSION & 0x0F];
        ndefDataFile[offset++] = HEX[(short)((Satodime.APPLET_MAJOR_VERSION>>4) & 0x0F)];
        ndefDataFile[offset++] = HEX[Satodime.APPLET_MAJOR_VERSION & 0x0F];
        ndefDataFile[offset++] = HEX[(short)((Satodime.APPLET_MINOR_VERSION>>4) & 0x0F)];
        ndefDataFile[offset++] = HEX[Satodime.APPLET_MINOR_VERSION & 0x0F];

        // NDEF authentikey (dummy value until personalization)
        Util.arrayFillNonAtomic(ndefDataFile, offset, SIZE_PUBKEY, (byte)'0');
        offset += SIZE_PUBKEY;

        // nb_slots
        ndefDataFile[offset++] = HEX[this.nb_slots & 0x0F];// nb_slots should be <= 0x0F

        // save default slot info (to be populated)
        Util.arrayFillNonAtomic(ndefDataFile, this.offset_first_slot, (short)(this.nb_slots*SIZE_SLOT), (byte)'0');
    }

    /**
     * Package-private singleton access
     */
    static SharedObject getInstance() {
        if (instance == null) {
            instance = new SharedObject();
        }
        return instance;
    }

    void populateNdefDataFile() {

        // random nonce(8b)
        randomData.generateData(tmpBuffer, (short)0, (short)8);
        short offset = this.offset_nonce;
        byte tmpByte;
        for (short i=0; i<8; i++){
            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
            tmpByte = tmpBuffer[i];
            ndefDataFile[offset++] = HEX[(tmpByte >> 4) & 0x0F];
            ndefDataFile[offset++] = HEX[tmpByte & 0x0F];
        }

        // compute authentikey signature
        offset = this.offset_authentikey_sig;
        sigECDSA.init(ndef_authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(ndefDataFile, this.offset_nonce, this.size_message_to_sign, tmpBuffer, (short)0);
        // save signature, hex-encoded (todo: base64)
        for (short i=0; i<sign_size; i++){
            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
            tmpByte = tmpBuffer[i];
            ndefDataFile[offset++] = HEX[(tmpByte >> 4) & 0x0F];
            ndefDataFile[offset++] = HEX[tmpByte & 0x0F];
        }
        // '00' padding to reach 72-byte sig
        for (short i=0; i<(short)(72-sign_size); i++){
            ndefDataFile[offset++] = (byte)'0';
            ndefDataFile[offset++] = (byte)'0';
        }
        // save sig_size as the difference between the actual sig size (70-72 bytes) and the minimum size (70 bytes)
        sign_size -=(short)70;
        ndefDataFile[this.offset_authentikey_sig_size] = HEX[sign_size & 0x0F];// should be 0-2

        return;
    }

    void setSlotState(byte slot_index, byte slot_state) {
        short offset = (short)(this.offset_first_slot + slot_index * SIZE_SLOT);
        ndefDataFile[offset] = HEX[slot_state & 0x0F]; // should be 0, 1 or 2
    }

    void setSlotSlip44(byte slot_index, byte[] slip44_buffer, short slip44_offset, short slip44_size) {
        short offset = (short)(this.offset_first_slot + SIZE_STATE + slot_index * SIZE_SLOT);
        byte tmpByte;
        for (short i=0; i<slip44_size; i++){
            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
            tmpByte = slip44_buffer[(short)(slip44_offset+i)];
            ndefDataFile[offset++] = HEX[(tmpByte >> 4) & 0x0F];
            ndefDataFile[offset++] = HEX[tmpByte & 0x0F];
        }
    }

    void setSlotPubkey(byte slot_index, byte[] pubkey_buffer, short pubkey_offset, short pubkey_size) {
        short offset = (short)(this.offset_first_slot + SIZE_STATE + SIZE_SLIP44 + slot_index * SIZE_SLOT);
        byte tmpByte;
        // note: the pubkey is provided in uncompressed format, so we must compress it
        // compute compression byte
        if (pubkey_buffer[pubkey_offset]%2 == 0){
            tmpByte = (byte)0x02;
        } else {
            tmpByte = (byte)0x03;
        }
        ndefDataFile[offset++] = HEX[(tmpByte >> 4) & 0x0F];
        ndefDataFile[offset++] = HEX[tmpByte & 0x0F];
        // save coordx
        for (short i=1; i<=32; i++){
            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
            tmpByte = pubkey_buffer[(short)(pubkey_offset+i)];
            ndefDataFile[offset++] = HEX[(tmpByte >> 4) & 0x0F];
            ndefDataFile[offset++] = HEX[tmpByte & 0x0F];
        }
    }

    void resetSlot(byte slot_index){
        short offset = (short)(this.offset_first_slot + slot_index * SIZE_SLOT);
        Util.arrayFillNonAtomic(ndefDataFile, offset, SIZE_SLOT, (byte)'0');
    }

    void updateNdefAuthentikey(byte[] privkey_buffer, short privkey_offset, byte[] pubkey_buffer, short pubkey_offset){
        // update privkey
        ndef_authentikey_private.setS(privkey_buffer, privkey_offset, Satodime.SIZE_ECPRIVKEY);
        // update pubkey (must be in compressed format)
        byte tmpByte;
        short offset = this.offset_authentikey;
        for (short i=0; i<33; i++){
            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
            tmpByte = pubkey_buffer[(short)(pubkey_offset + i)];
            ndefDataFile[offset++] = HEX[(tmpByte >> 4) & 0x0F];
            ndefDataFile[offset++] = HEX[tmpByte & 0x0F];
        }

//        // pubkey recovery will be donne in the calling method in Satodime
//        keyAgreement.init(ndef_authentikey_private);
//        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, tmpBuffer, (short)0);
//        // compress pubkey
//        if (tmpBuffer[64]%2 == 0){
//            ndef_authentikey_public[0] = (byte)0x02;
//        } else {
//            ndef_authentikey_public[0] = (byte)0x03;
//        }
//        Util.arrayCopy(tmpBuffer, (short)1, ndef_authentikey_public, (short)1, (short)32);
    }

}
