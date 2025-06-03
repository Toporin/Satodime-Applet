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
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacard.security.RandomData;

/**
 * SharedObject Class
 * <p>
 *
 *
 */

public class SharedObject {

    private static SharedObject instance;

    private static byte[] tmpBuffer;

    /** The NDEF data file. Read through the NDEFApplet. **/
    //static final short MAX_NDEF_DATA_FILE_SIZE = 224;
    static final short MAX_NDEF_DATA_FILE_SIZE = 400;

    /** base URL for dynamic url **/
    static final byte[] BASE_URL = {'e','x','a','m','p','l','e','.','c','o','m', '/'};

    /** for bytes to hex conversion **/
    static final byte[] HEX = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};



    /** NDEF file for dynamic url**/
    short ndefDataFileSize;
    byte[] ndefDataFile;

    /** number of slots **/
    byte nb_slots = 0;
    static final short SLOT_SIZE = 76; // 38-byte hex-encoded

    /** constants **/
    static final short SIZE_ECPRIVKEY = 32;
    static final short SIZE_HEADER = (short)10;
    static final short SIZE_NONCE = (short)16; // 8-bytes hex-encoded
    static final short SIZE_CARD_TYPE = (short)1; // 1-char
    static final short SIZE_VERSION = (short)8; // 4-byte hex-encoded
    static final short SIZE_PUBKEY = (short)66; // 33-byte hex-encoded
    static final short SIZE_NBSLOT = (short)1; // 1-char
    static final short SIZE_SLOT = (short)76; // 38-byte hex-encoded
    static final short SIZE_STATUS = (short)1; // 1-char
    static final short SIZE_SLIP44 = (short)8; // 8-byte hex-encoded
    static final short SIZE_SIGNATURE = (short)144; // 72-byte hex-encoded!!

    /** offsets **/
    private short offset_nonce;
    private short offset_first_slot;
    private short offset_subca_sig_size;
    private short offset_subca_sig;
    private short offset_authentikey_sig_size;
    private short offset_authentikey_sig;

    private short size_message_to_sign;

    /** for nonce randomness **/
    private RandomData randomData;
    private KeyAgreement keyAgreement;
    private Signature sigECDSA;

    private ECPrivateKey authentikey_private;
    private byte[] authentikey_public;

    /** The list of pubkeys for each slot **/
    byte[] ecpubkeys;
    byte[] state_array;
    byte[] slip44_array;

    /** slot status **/

    /** slot slip44 **/

    /** authentikey pubkey (33b) **/

    /** authentikey signature **/

    /**
     * Constructor for the SharedObject class.
     * todo: use a constructor without parameters then use a initializer called from the Satodime class.
     *
     * @param nb_slots
     *          Max number of slots
     *
     */
    public SharedObject() {

    }
//    public SharedObject(byte[] buffer, byte nb_slots) {}

    //public SharedObject(byte[] buffer, byte nb_slots) {
    public void init(byte[] buffer, byte nb_slots) {

        tmpBuffer = buffer;

        //this.nb_slots = nb_slots;
        this.nb_slots = (byte)1; // debug

        // random object
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sigECDSA= Signature.getInstance(Satodime.ALG_ECDSA_SHA_256, false);
        try {
            keyAgreement = KeyAgreement.getInstance(Satodime.ALG_EC_SVDP_DH_PLAIN_XY, false);
        } catch (CryptoException e) {
            ISOException.throwIt(Satodime.SW_UNSUPPORTED_FEATURE);// unsupported feature => use a more recent card!
        }

        // authentikey
        authentikey_private= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, Satodime.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(authentikey_private);
        randomData.generateData(tmpBuffer, (short)0, SIZE_ECPRIVKEY);
        authentikey_private.setS(tmpBuffer, (short)0, SIZE_ECPRIVKEY); //random value first
        // recover pubkey
        keyAgreement.init(authentikey_private);
        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, tmpBuffer, (short)0);
        // compress pubkey
        authentikey_public = new byte[33];
        if (tmpBuffer[64]%2 == 0){
            authentikey_public[0] = (byte)0x02;
        } else {
            authentikey_public[0] = (byte)0x03;
        }
        Util.arrayCopy(tmpBuffer, (short)1, authentikey_public, (short)1, (short)32);

        // offsets
        // [header(10b) | base_url() ] +
        // [nonce(8b) |  cardtype(1b) | version(4b) | authentikey(33b) | nb_slot(1b) ] +
        // [status(1b) | slip44(4b) | pubkey(33b) ] * nb_slot +
        // [subca_sig_size(1b) | subca_sig(70-72b) | padding(0-2b)] +
        // [authentikey_sig_size(1b) | authentikey_sig(70-72b) | padding(0-2b)] +
        this.offset_nonce = (short)(SIZE_HEADER + BASE_URL.length);
        this.offset_first_slot = (short)(this.offset_nonce + SIZE_CARD_TYPE + SIZE_VERSION + SIZE_PUBKEY + SIZE_NBSLOT);
        this.offset_subca_sig_size = (short)(offset_first_slot + this.nb_slots * SIZE_SLOT);
        this.offset_subca_sig = (short)(this.offset_subca_sig_size + 1);
        this.offset_authentikey_sig_size = (short)(offset_subca_sig+SIZE_SIGNATURE);
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
        // authentikey
        byte tmpByte;
        for (short i=0; i<authentikey_public.length; i++){
            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
            tmpByte = authentikey_public[i];
            ndefDataFile[offset++] = HEX[(tmpByte >> 4) & 0x0F];
            ndefDataFile[offset++] = HEX[tmpByte & 0x0F];
        }
        // nb_slots
        ndefDataFile[offset++] = HEX[this.nb_slots & 0x0F];// nb_slots should be <= 0x0F

        // save default slot info (to be populated)
        Util.arrayFillNonAtomic(ndefDataFile, this.offset_first_slot, (short)(this.nb_slots*SLOT_SIZE), (byte)'0');

        // save dummy subca signature (to be be populated later)
        ndefDataFile[this.offset_subca_sig_size] = HEX[(short)2];// 2 for max sig size (72-byte), so no padding needed
        offset = this.offset_subca_sig;
        for (short i=0; i<72; i++){
            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
            ndefDataFile[offset++] = HEX[(byte)0];
            ndefDataFile[offset++] = HEX[(byte)0];
        }

    }

    // Package-private singleton access
//    static SharedObject getInstance(byte[] buffer, byte nb_slots) {
//        if (instance == null) {
//            instance = new SharedObject(buffer, nb_slots);
//        }
//        return instance;
//    }
    static SharedObject getInstance() {
        if (instance == null) {
            instance = new SharedObject();
        }
        return instance;
    }

    public short populateNdefDataFile() {

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
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
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

        return 0; // todo return void
    }

    /** OLD  **/

    public short getNdefDataSize(byte nb_slots){
        // [header(10b) | base_url() ] +
        // [nonce(8b) |  authentikey(33b) | nb_slot(1b) |  ] +
        // [status(1b) | slip44(4b) | pubkey(33b) ] * nb_slot +
        // [subca_sig_size(1b) | subca_sig(70-72b) | padding(0-2b)] +
        // [authentikey_sig_size(1b) | authentikey_sig(70-72b) | padding(0-2b)] +

        short size= 0;
        size+= (short) 10; //header
        size+= BASE_URL.length; // base URL
        size+= (short) (42 * 2); // card info, encoded in hex
        size+= (short) (nb_slots * SLOT_SIZE); // encoded in hex
        size+= (short) (146); //  signature +  size, encoded in hex, with 0-2b padding after each signature to have a fixed size
        size+= (short) (146); //  signature +  size, encoded in hex, with 0-2b padding after each signature to have a fixed size

        return size;
    }

    public short populateNdefDataFileDynamically(short offset_start, byte[] buffer) {

        short offset = 0;

        // todo move  to constructor?
        short offset_first_slot = (short)(10 + BASE_URL.length + 84);
        short offset_subca_sig = (short)(offset_first_slot + this.nb_slots * SLOT_SIZE);
        short offset_authentikey_sig = (short)(offset_subca_sig+146);


        if (offset_start == 0) {

            // header
            short ndef_size = getNdefDataSize(this.nb_slots);
            Util.setShort(buffer, offset, (short)(ndef_size-2));
            offset += (short) 2;
            buffer[offset++] = (byte) 0xC1; // Header for Long URL
            buffer[offset++] = (byte) 0x01; // Type Length
            buffer[offset++] = (byte)0x00; // Short Payload Length (4b)
            buffer[offset++] = (byte)0x00; // Short Payload Length (4b)
            Util.setShort(buffer, offset, (short)(ndef_size-9));
            offset += (short) 2;
            buffer[offset++] = (byte) 0x55; // Record Type 'U'
            buffer[offset++] = (byte) 0x04;// URI Identifier Code (https://)

            // base URL
            Util.arrayCopy(BASE_URL, (short) (0), buffer, offset, (short) BASE_URL.length);
            offset += BASE_URL.length;

            // nonce(8b)
            Util.arrayFillNonAtomic(buffer, offset, (short)16, (byte)'n');
            offset += (short)16;

            //authentikey(33b)
            Util.arrayFillNonAtomic(buffer, offset, (short)66, (byte)'a');
            offset += (short)66;

            // nb_slot(1b)
            buffer[offset++] = 'n';
            buffer[offset++] = 'n';

            return offset;

        }

        // slot data
        for (byte i=0; i<this.nb_slots; i++){

            short offset_slot_i = (short)(offset_first_slot + i*SLOT_SIZE);

            // for slot i
            if (offset_start == offset_slot_i){
                //[status(1b) | slip44(4b) | pubkey(33b) ]
                buffer[offset++] = 's';
                buffer[offset++] = 's';
                // slip
                Util.arrayFillNonAtomic(buffer, offset, (short)8, (byte)'c');
                offset += (short)8;
                // pubkey
                Util.arrayFillNonAtomic(buffer, offset, (short)66, (byte)'p');
                offset += (short)66;

                return offset;
            }
        }

        // subca sig
        if (offset_start == offset_subca_sig) {
            // sig length
            buffer[offset++] = 'l';
            buffer[offset++] = 'l';
            // sig + padding
            Util.arrayFillNonAtomic(buffer, offset, (short)144, (byte)'g'); // hex encoded
            offset += (short)144;

            return offset;
        }

        // authentikey sig
        if (offset_start == offset_authentikey_sig) {
            // sig length
            buffer[offset++] = 'l';
            buffer[offset++] = 'l';
            // sig + padding
            Util.arrayFillNonAtomic(buffer, offset, (short)144, (byte)'g'); // hex encoded
            offset += (short)144;

            return offset;
        }

        // should not happen
        return offset;
    }

    /*
     *  TEST 0-127 -> 256 hex
     * */

    public short getNdefDataSize4(byte nb_slot){
        // example.com/00010203...
        short size= 0;
        size+= 10; //header
        size+= BASE_URL.length; // base URL
        size+=256; // nb_slots

        return size;
    }

    public void populateNdefDataFile4(short offset_start) {

        short offset = (short)2;
        ndefDataFile[offset++] = (byte)0xC1; // Header for Long URL
        ndefDataFile[offset++] = (byte)0x01; // Type Length
        ndefDataFile[offset++] = (byte)0x00; // TODO Short Payload Length (4b)
        ndefDataFile[offset++] = (byte)0x00; // TODO Short Payload Length (4b)
        ndefDataFile[offset++] = (byte)0x00; // TODO Short Payload Length (4b)
        ndefDataFile[offset++] = (byte)0x00; // TODO Short Payload Length (4b)
        ndefDataFile[offset++] = (byte)0x55; // Record Type 'U'
        ndefDataFile[offset++] = (byte)0x04;// URI Identifier Code (https://)
        //ndefDataFile[offset++] = ;// URI

        // base URL
        Util.arrayCopy(BASE_URL, (short)(0), ndefDataFile, offset, (short)BASE_URL.length);
        offset+=BASE_URL.length;

        //
        byte tmpByte;
        for (short i=0; i<128; i++){
            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
            tmpByte = (byte)(i & 0xFF);
            ndefDataFile[offset++] = HEX[(tmpByte >> 4) & 0x0F];
            ndefDataFile[offset++] = HEX[tmpByte & 0x0F];
        }

        // update ndef length (2bytes)
        ndefDataFile[(short)0] = (byte) ((short)(offset-2)>>8); // file Length
        ndefDataFile[(short)1] = (byte) ((offset-2) & 0xFF); // file Length

        // update payload length
        ndefDataFile[(short)6] = (byte) ((short)(offset-9)>>8); // Payload Length
        ndefDataFile[(short)7] = (byte) ((offset-9) & 0xFF); // Payload Length

        return;
    }

/*
*  TEST 00-> 3F 12_ hex
* */

    public short getNdefDataSize3(){
        // example.com/00010203...
        short size= 0;
        size+= 7; //header
        size+= BASE_URL.length; // base URL
        size+=128; // nb_slots

        return size;
    }

    public void populateNdefDataFile3(short offset_start) {

        short offset = (short)2;
        ndefDataFile[offset++] = (byte)0xD1; // Header
        ndefDataFile[offset++] = (byte)0x01; // Type Length
        ndefDataFile[offset++] = (byte)0x00; // TODO Short Payload Length (1b)
        ndefDataFile[offset++] = (byte)0x55; // Record Type 'U'
        ndefDataFile[offset++] = (byte)0x04;// URI Identifier Code (https://)
        //ndefDataFile[offset++] = ;// URI

        // base URL
        Util.arrayCopy(BASE_URL, (short)(0), ndefDataFile, offset, (short)BASE_URL.length);
        offset+=BASE_URL.length;

        //
        byte tmpByte;
        for (short i=0; i<64; i++){
            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
            tmpByte = (byte)(i & 0xFF);
            ndefDataFile[offset++] = HEX[(tmpByte >> 4) & 0x0F];
            ndefDataFile[offset++] = HEX[tmpByte & 0x0F];
        }

        // update ndef length (2bytes)
        ndefDataFile[(short)0] = (byte) ((short)(offset-2)>>8); // file Length
        ndefDataFile[(short)1] = (byte) ((offset-2) & 0xFF); // file Length

        // update payload length
        ndefDataFile[(short)4] = (byte) (offset-6); // Payload Length

        return;
    }

/*
*       TEST NB_SLOT
* */

    public short getNdefDataSize_a(byte nb_slot){
        short size= 0;
        size+= 7; //header
        size+= BASE_URL.length; // base URL
        //size++; // nb_slots
        //size++; // nb_slots


        return size;
    }

    public void populateNdefDataFile_a(short offset_start) {


        short offset = (short)2;
        ndefDataFile[offset++] = (byte)0xD1; // Header
        ndefDataFile[offset++] = (byte)0x01; // Type Length
        ndefDataFile[offset++] = (byte)0x00; // TODO Short Payload Length (1b)
        ndefDataFile[offset++] = (byte)0x55; // Record Type 'U'
        ndefDataFile[offset++] = (byte)0x04;// URI Identifier Code (https://)
        //ndefDataFile[offset++] = ;// URI

        // base URL
        Util.arrayCopy(BASE_URL, (short)(0), ndefDataFile, offset, (short)BASE_URL.length);
        offset+=BASE_URL.length;

        // nb_slots as one hex character
        //ndefDataFile[offset++] = HEX[nb_slots & 0x0F]; // nb_slots should be <= 0x0F!

        // offset_start as 2 hex characters
        //ndefDataFile[offset++] = HEX[(short)((offset_start>>4) & 0x0F)]; // nb_slots should be <= 0x0F!
        //ndefDataFile[offset++] = HEX[offset_start & 0x0F]; // nb_slots should be <= 0x0F!

        // update ndef length (2bytes)
        ndefDataFile[(short)0] = (byte) ((short)(offset-2)>>8); // file Length
        ndefDataFile[(short)1] = (byte) ((offset-2) & 0xFF); // file Length

        // update payload length
        ndefDataFile[(short)4] = (byte) (offset-6); // Payload Length

        return;
    }


}
