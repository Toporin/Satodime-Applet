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

/**
 * SharedObject Class
 * <p>
 *
 *
 */

public class SharedObject {

    private static SharedObject instance;

    /** The NDEF data file. Read through the NDEFApplet. **/
    static final short MAX_NDEF_DATA_FILE_SIZE = 224;

    /** base URL for dynamic url **/
    static final byte[] BASE_URL = {'e','x','a','m','p','l','e','.','c','o','m', '/'};

    /** for bytes to hex conversion **/
    static final byte[] HEX = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    /** NDEF file for dynamic url**/
    byte[] ndefDataFile;

    /** number of slots **/
    byte nb_slots = 0;

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
     *
     * @param nb_slots
     *          Max number of slots
     *
     */
    public SharedObject(byte nb_slots) {

        // Allocate the memory
        this.ndefDataFile = new byte[MAX_NDEF_DATA_FILE_SIZE];
        this.nb_slots = nb_slots;
        this.ecpubkeys = new byte[(short)(nb_slots * Satodime.SIZE_ECPUBKEY)];
        this.state_array = new byte[nb_slots];
        this.slip44_array= new byte[(short)nb_slots * Satodime.SIZE_SLIP44];
    }

    // Package-private singleton access
    static SharedObject getInstance(byte nb_slots) {
        if (instance == null) {
            instance = new SharedObject(nb_slots);
        }
        return instance;
    }

    public void populateNdefDataFile() {

        byte payloadLength = 0;
        byte uriIdentifier = 0;


        short offset = (short)3;
        ndefDataFile[offset++] = (byte)0xD1; // Header
        ndefDataFile[offset++] = (byte)0x01; // Type Length
        ndefDataFile[offset++] = (byte)0x00; // TODO Payload Length
        ndefDataFile[offset++] = (byte)0x55; // Record Type 'U'
        ndefDataFile[offset++] = (byte)0x04;// URI Identifier Code (https://)
        //ndefDataFile[offset++] = ;// URI

        // base URL
        Util.arrayCopy(BASE_URL, (short)(0), ndefDataFile, offset, (short)BASE_URL.length);
        offset+=BASE_URL.length;

        // nb_slots as one hex character
        ndefDataFile[offset++] = HEX[nb_slots & 0x0F]; // nb_slots should be <= 0x0F!

        // ecpubkey
//        //Util.arrayCopy(ecpubkeys, (short)(0), ndefDataFile, offset, ecpubkeys.length);
//        byte tmpbyte;
//        for (short i=0; i<ecpubkeys.length; i++){
//            // For each byte, convert the two 4-bit nibbles to their hexadecimal value in ascii
//            tmpbyte = ecpubkeys[i];
//            ndefDataFile[offset++] = HEX[(tmpbyte >> 4) & 0x0F];
//            ndefDataFile[offset++] = HEX[tmpbyte & 0x0F];
//        }

        // update array length
        ndefDataFile[(short)0] = (byte) (offset-1); // file Length

        // update ndef length (2bytes)
        ndefDataFile[(short)1] = (byte) ((short)(offset-3)>>8); // file Length
        ndefDataFile[(short)2] = (byte) ((offset-3) & 0xFF); // file Length

        // update payload length
        ndefDataFile[(short)5] = (byte) (offset-7); // Payload Length

        return;
    }



}
