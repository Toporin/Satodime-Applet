/* Satodime: cryptocurrency physical bill, based on javacard
 * (c) 2021 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin                   
 *  
 * Based on the M.US.C.L.E framework:
 * see http://pcsclite.alioth.debian.org/musclecard.com/musclecard/
 * see https://github.com/martinpaljak/MuscleApplet/blob/d005f36209bdd7020bac0d783b228243126fd2f8/src/com/musclecard/CardEdge/CardEdge.java
 * 
 *  MUSCLE SmartCard Development
 *      Authors: Tommaso Cucinotta <cucinotta@sssup.it>
 *               David Corcoran    <corcoran@linuxnet.com>
 *      Description:      CardEdge implementation with JavaCard
 *      Protocol Authors: Tommaso Cucinotta <cucinotta@sssup.it>
 *                        David Corcoran <corcoran@linuxnet.com>
 *      
 * BEGIN LICENSE BLOCK
 * Copyright (C) 1999-2002 David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2021 Toporin 
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END LICENSE_BLOCK  
 */

package org.satodime.applet;

import org.satodime.applet.Biginteger;
import org.satodime.applet.HmacSha160;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
//import javacard.security.KeyPair;
import javacard.security.Signature;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * Implements MUSCLE's Card Edge Specification.
 */
public class Satodime extends javacard.framework.Applet { 

    /* constants declaration */
    
    /** 
     * VERSION HISTORY
     * PROTOCOL VERSION: changes that impact compatibility with the client side
     * APPLET VERSION:   changes with no impact on compatibility of the client
     */
    // 0.1-0.1: initial version
    private final static byte PROTOCOL_MAJOR_VERSION = (byte) 0; 
    private final static byte PROTOCOL_MINOR_VERSION = (byte) 1;
    private final static byte APPLET_MAJOR_VERSION = (byte) 0;
    private final static byte APPLET_MINOR_VERSION = (byte) 1;

    // Maximum number of keys handled by the Cardlet
    //private final static byte MAX_NUM_KEYS = (byte) 3;
    private static byte MAX_NUM_KEYS = (byte) 3;
    
        // Maximum size for the extended APDU buffer 
    private final static short EXT_APDU_BUFFER_SIZE = (short) 268;
    private final static short TMP_BUFFER_SIZE = (short) 256;

    // code of CLA byte in the command APDU header
    private final static byte CardEdge_CLA = (byte) 0xB0;

    /****************************************
     * Instruction codes *
     ****************************************/

    // Applet initialization
    private final static byte INS_SETUP = (byte) 0x2A;

    // Keys' use and management
    //private final static byte INS_IMPORT_KEY = (byte) 0x32;
    //private final static byte INS_RESET_KEY = (byte) 0x33;
    //private final static byte INS_GET_PUBLIC_FROM_PRIVATE= (byte)0x35;
    
    // Satodime
    private final static byte INS_GET_SATODIME_STATUS= (byte)0x50;
    private final static byte INS_GET_SATODIME_KEYSLOT_STATUS= (byte)0x51;
    private final static byte INS_SET_SATODIME_KEYSLOT_STATUS= (byte)0x52;
    //private final static byte INS_GET_SATODIME_UNLOCK_CODE= (byte)0x53; // deprecated
    private final static byte INS_GET_SATODIME_PUBKEY= (byte)0x55; // do not change state
    private final static byte INS_GET_SATODIME_PRIVKEY= (byte)0x56;// do not change state
    private final static byte INS_SEAL_SATODIME_KEY= (byte)0x57; // change key state from uninitialized to sealed
    private final static byte INS_UNSEAL_SATODIME_KEY= (byte)0x58; // change key state from sealed to unsealed 
    private final static byte INS_RESET_SATODIME_KEY= (byte)0x59; // change key state from unsealed to uninitialized
    private final static byte INS_INITIATE_SATODIME_TRANSFER= (byte)0x5A;
    // External authentication
    //private final static byte INS_CREATE_PIN = (byte) 0x40; 
    //private final static byte INS_VERIFY_PIN = (byte) 0x42;
    //private final static byte INS_CHANGE_PIN = (byte) 0x44;
    //private final static byte INS_UNBLOCK_PIN = (byte) 0x46;
    //private final static byte INS_LOGOUT_ALL = (byte) 0x60;
    
    // Status information
    //private final static byte INS_LIST_PINS = (byte) 0x48;
    private final static byte INS_GET_STATUS = (byte) 0x3C;
    private final static byte INS_CARD_LABEL = (byte) 0x3D;
    
    // HD wallet
    //private final static byte INS_BIP32_IMPORT_SEED= (byte) 0x6C;
    //private final static byte INS_BIP32_RESET_SEED= (byte) 0x77;
    //private final static byte INS_BIP32_GET_AUTHENTIKEY= (byte) 0x73;
    //private final static byte INS_BIP32_SET_AUTHENTIKEY_PUBKEY= (byte)0x75;
    //private final static byte INS_BIP32_GET_EXTENDED_KEY= (byte) 0x6D;
    //private final static byte INS_BIP32_SET_EXTENDED_PUBKEY= (byte) 0x74;
    //private final static byte INS_SIGN_MESSAGE= (byte) 0x6E;
    //private final static byte INS_SIGN_SHORT_MESSAGE= (byte) 0x72;
    //private final static byte INS_SIGN_TRANSACTION= (byte) 0x6F;
    //private final static byte INS_PARSE_TRANSACTION = (byte) 0x71;
    //private final static byte INS_CRYPT_TRANSACTION_2FA = (byte) 0x76;
    //private final static byte INS_SET_2FA_KEY = (byte) 0x79;    
    //private final static byte INS_RESET_2FA_KEY = (byte) 0x78;
    //private final static byte INS_SIGN_TRANSACTION_HASH= (byte) 0x7A;
    
    // secure channel
    private final static byte INS_INIT_SECURE_CHANNEL = (byte) 0x81;
    private final static byte INS_PROCESS_SECURE_CHANNEL = (byte) 0x82;
    
    // secure import from SeedKeeper
    //private final static byte INS_BIP32_IMPORT_ENCRYPTED_SEED = (byte) 0xAC; //deprecated
    //private final static byte INS_IMPORT_ENCRYPTED_SECRET = (byte) 0xAC;
    //private final static byte INS_IMPORT_TRUSTED_PUBKEY = (byte) 0xAA;
    //private final static byte INS_EXPORT_TRUSTED_PUBKEY = (byte) 0xAB;
    private final static byte INS_EXPORT_AUTHENTIKEY= (byte) 0xAD;
    
    // Personalization PKI support
    private final static byte INS_IMPORT_PKI_CERTIFICATE = (byte) 0x92;
    private final static byte INS_EXPORT_PKI_CERTIFICATE = (byte) 0x93;
    private final static byte INS_SIGN_PKI_CSR = (byte) 0x94;
    private final static byte INS_EXPORT_PKI_PUBKEY = (byte) 0x98;
    private final static byte INS_LOCK_PKI = (byte) 0x99;
    private final static byte INS_CHALLENGE_RESPONSE_PKI= (byte) 0x9A;
    
    // reset to factory settings
    //private final static byte INS_RESET_TO_FACTORY = (byte) 0xFF;
    
    /****************************************
     *          Error codes                 *
     ****************************************/
    
    /** Entered PIN is not correct */
    private final static short SW_PIN_FAILED = (short)0x63C0;// includes number of tries remaining
    ///** DEPRECATED - Entered PIN is not correct */
    //private final static short SW_AUTH_FAILED = (short) 0x9C02;
    /** Required operation is not allowed in actual circumstances */
    private final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
    /** Required setup is not not done */
    private final static short SW_SETUP_NOT_DONE = (short) 0x9C04;
    /** Required setup is already done */
    private final static short SW_SETUP_ALREADY_DONE = (short) 0x9C07;
    /** Required feature is not (yet) supported */
    final static short SW_UNSUPPORTED_FEATURE = (short) 0x9C05;
    /** Required operation was not authorized because of a lack of privileges */
    private final static short SW_UNAUTHORIZED = (short) 0x9C06;
    /** Algorithm specified is not correct */
    private final static short SW_INCORRECT_ALG = (short) 0x9C09;
    
    ///** There have been memory problems on the card */
    //private final static short SW_NO_MEMORY_LEFT = Bip32ObjectManager.SW_NO_MEMORY_LEFT;
    ///** DEPRECATED - Required object is missing */
    //private final static short SW_OBJECT_NOT_FOUND= (short) 0x9C07;

    /** Incorrect P1 parameter */
    private final static short SW_INCORRECT_P1 = (short) 0x9C10;
    /** Incorrect P2 parameter */
    private final static short SW_INCORRECT_P2 = (short) 0x9C11;
    /** Invalid input parameter to command */
    private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;
    
    /** Eckeys initialized */
    private final static short SW_ECKEYS_INITIALIZED_KEY = (short) 0x9C1A;
    
    /** Verify operation detected an invalid signature */
    private final static short SW_SIGNATURE_INVALID = (short) 0x9C0B;
    /** Operation has been blocked for security reason */
    private final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
    /** For debugging purposes */
    private final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
    /** Very low probability error */
    private final static short SW_BIP32_DERIVATION_ERROR = (short) 0x9C0E;
    /** Incorrect initialization of method */
    private final static short SW_INCORRECT_INITIALIZATION = (short) 0x9C13;
    /** Bip32 seed is not initialized*/
    private final static short SW_BIP32_UNINITIALIZED_SEED = (short) 0x9C14;
    /** Bip32 seed is already initialized (must be reset before change)*/
    private final static short SW_BIP32_INITIALIZED_SEED = (short) 0x9C17;
    //** DEPRECATED - Bip32 authentikey pubkey is not initialized*/
    //private final static short SW_BIP32_UNINITIALIZED_AUTHENTIKEY_PUBKEY= (short) 0x9C16;
    /** Incorrect transaction hash */
    private final static short SW_INCORRECT_TXHASH = (short) 0x9C15;
    
    /** 2FA already initialized*/
    private final static short SW_2FA_INITIALIZED_KEY = (short) 0x9C18;
    /** 2FA uninitialized*/
    private final static short SW_2FA_UNINITIALIZED_KEY = (short) 0x9C19;
        
    /** HMAC errors */
    static final short SW_HMAC_UNSUPPORTED_KEYSIZE = (short) 0x9c1E;
    static final short SW_HMAC_UNSUPPORTED_MSGSIZE = (short) 0x9c1F;
    
    /** Satodime */
    static final short SW_INCORRECT_UNLOCK_COUNTER = (short) 0x9c50;
    static final short SW_INCORRECT_UNLOCK_CODE = (short) 0x9c51;
    static final short SW_INCORRECT_KEYSLOT_STATE = (short) 0x9c52;
    static final short SW_INCORRECT_PROTOCOL_MEDIA = (short) 0x9c53;
    static final short SW_UNKNOWN_PROTOCOL_MEDIA = (short) 0x9c54;

//  /** SeedKeeper*/
//  /** Secret data is too long for import **/
//  private final static short SW_IMPORTED_DATA_TOO_LONG = (short) 0x9C32;
//  /** Wrong HMAC when importing Secret through Secure import **/
//  private final static short SW_SECURE_IMPORT_WRONG_MAC = (short) 0x9C33;
//  /** Wrong Fingerprint when importing Secret through Secure import **/
//  private final static short SW_SECURE_IMPORT_WRONG_FINGERPRINT = (short) 0x9C34;
//  /** No Trusted Pubkey when importing Secret through Secure import **/
//  private final static short SW_SECURE_IMPORT_NO_TRUSTEDPUBKEY = (short) 0x9C35;
    
    /** Secure channel */
    private final static short SW_SECURE_CHANNEL_REQUIRED = (short) 0x9C20;
    private final static short SW_SECURE_CHANNEL_UNINITIALIZED = (short) 0x9C21;
    private final static short SW_SECURE_CHANNEL_WRONG_IV= (short) 0x9C22;
    private final static short SW_SECURE_CHANNEL_WRONG_MAC= (short) 0x9C23;
    
    /** PKI perso error */
    private final static short SW_PKI_ALREADY_LOCKED = (short) 0x9C40;
    /** CARD HAS BEEN RESET TO FACTORY */
    private final static short SW_RESET_TO_FACTORY = (short) 0xFF00;
    /** For instructions that have been deprecated*/
    private final static short SW_INS_DEPRECATED = (short) 0x9C26;
    /** For debugging purposes 2 */
    private final static short SW_DEBUG_FLAG = (short) 0x9FFF;
    
    // KeyBlob Encoding in Key Blobs
    private final static byte BLOB_ENC_PLAIN = (byte) 0x00;

    // Cipher Operations admitted in ComputeCrypt()
    private final static byte OP_INIT = (byte) 0x01;
    private final static byte OP_PROCESS = (byte) 0x02;
    private final static byte OP_FINALIZE = (byte) 0x03;

    // JC API 2.2.2 does not define these constants:
    private final static byte ALG_ECDSA_SHA_256= (byte) 33;
    private final static byte ALG_EC_SVDP_DH_PLAIN= (byte) 3; //https://javacard.kenai.com/javadocs/connected/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN
    private final static byte ALG_EC_SVDP_DH_PLAIN_XY= (byte) 6; //https://docs.oracle.com/javacard/3.0.5/api/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN_XY
    private final static short LENGTH_EC_FP_256= (short) 256;
        
    /****************************************
     *    Instance variables declaration    *
     ****************************************/
    
    // card label
    private final static byte MAX_CARD_LABEL_SIZE = (byte) 64;
    private byte card_label_size = (byte) 0x00;
    private byte[] card_label;
    
    // Buffer for storing extended APDUs
    private byte[] recvBuffer;
    private byte[] tmpBuffer;

    /* For the setup function - should only be called once */
    private boolean setupDone = false;
    
    // shared cryptographic objects
    private RandomData randomData;
    private KeyAgreement keyAgreement;
    private Signature sigECDSA;
    private Cipher aes128;
    private MessageDigest sha256;  
        
    /*********************************************
     *               PKI objects                 *
     *********************************************/
    private static final byte[] PKI_CHALLENGE_MSG = {'C','h','a','l','l','e','n','g','e',':'};
    private boolean personalizationDone=false;
    private ECPrivateKey authentikey_private;
    private ECPublicKey authentikey_public;
    //private KeyPair authentikey_pair;
    private short authentikey_certificate_size=0;
    private byte[] authentikey_certificate;

    /*********************************************
     *                Satodime                   *
     *********************************************/
    
    // Key objects (allocated on demand)
    private short SIZE_ECPRIVKEY= (short)32;
    private short SIZE_ECPUBKEY= (short)65;
    private short SIZE_ECCOORDX= (short)32;
    private short SIZE_ENTROPY= (short)32;
    private ECPrivateKey[] ecprivkeys;
    private byte[] ecpubkeys; //private ECPublicKey[] ecpubkeys;
    private byte[] user_entropy_array;
    private byte[] card_entropy_array;
    short eckeys_flag=0x0000; //flag bit set to 1 when corresponding key is initialised 
    
    // unlock_code data
    private byte[] unlock_secret; 
    private byte[] unlock_counter;
    private static final byte SIZE_UNLOCK_SECRET=20;
    private static final byte SIZE_UNLOCK_COUNTER=4;
    
    // METADATA for each keypair
    //private byte[] unlock_code_array; // required for operations that change keystate via NFC
    private byte[] state_array;
    private byte[] type_array; // key type
    private byte[] asset_array; 
    private byte[] slip44_array;
    private byte[] contract_array;
    private byte[] tokenid_array;
    private byte[] data_array;
    
    private static final byte SIZE_SLIP44=4;
    private static final byte SIZE_CONTRACT=2+32;
    private static final byte SIZE_TOKENID=2+32;
    private static final byte SIZE_DATA=2+64;
    private static final byte SIZE_UNLOCK_CODE=20;
    //private static final short SIZE_KEY_METADATA= (short)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID + SIZE_DATA);
    private static final short SIZE_KEY_METADATA_0= (short)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID);
    private static final short SIZE_KEY_METADATA_1= (short)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + SIZE_DATA);
    
    // State values
    private static final byte STATE_UNINITIALIZED=0;
    private static final byte STATE_SEALED=1;
    private static final byte STATE_UNSEALED=2;
    // asset values
    //private static final byte ASSET_UNDEFINED=0x00;
    //private static final byte ASSET_COIN=0x01;
    //private static final byte ASSET_TOKEN=0x10; // [0x10,0x40[
    //private static final byte ASSET_ERC20=0x11;
    //private static final byte ASSET_BEP20=0x12;
    //private static final byte ASSET_NFT=0x40; // [0x40,0x70[
    //private static final byte ASSET_ERC721=0x41;
    //private static final byte ASSET_BEP721=0x42;
    //private static final byte ASSET_OTHER=(byte)0xff;
    
    
    /*********************************************
     *            Secure Channel                 *
     *********************************************/
    
    private static final byte[] CST_SC = {'s','c','_','k','e','y', 's','c','_','m','a','c'};
    private boolean needs_secure_channel= true;
    private boolean initialized_secure_channel= false;
    private ECPrivateKey sc_ephemeralkey; 
    private AESKey sc_sessionkey;
    private Cipher sc_aes128_cbc;
    private byte[] sc_buffer;
    private static final byte OFFSET_SC_IV=0;
    private static final byte OFFSET_SC_IV_RANDOM=OFFSET_SC_IV;
    private static final byte OFFSET_SC_IV_COUNTER=12;
    private static final byte OFFSET_SC_MACKEY=16;
    private static final byte SIZE_SC_MACKEY=20;
    private static final byte SIZE_SC_IV= 16;
    private static final byte SIZE_SC_IV_RANDOM=12;
    private static final byte SIZE_SC_IV_COUNTER=SIZE_SC_IV-SIZE_SC_IV_RANDOM;
    private static final byte SIZE_SC_BUFFER=SIZE_SC_MACKEY+SIZE_SC_IV;

    /*********************************************
     *        Other data instances               *
     *********************************************/

    
    /****************************************
     * Methods                              *
     ****************************************/
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // extract install parameters if any
        byte aidLength = bArray[bOffset];
        short controlLength = (short)(bArray[(short)(bOffset+1+aidLength)]&(short)0x00FF);
        short dataLength = (short)(bArray[(short)(bOffset+1+aidLength+1+controlLength)]&(short)0x00FF);
        new Satodime(bArray, (short) (bOffset+1+aidLength+1+controlLength+1), dataLength).register();
    }
    
    private Satodime(byte[] bArray, short bOffset, short bLength) {
        
        // recover MAX_NUM_KEYS from install params
        if (bLength>0){
            MAX_NUM_KEYS= bArray[bOffset];
        }else{
            MAX_NUM_KEYS=3; // default value
        }
        
        // Temporary working arrays
        try {
            tmpBuffer = JCSystem.makeTransientByteArray(TMP_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            tmpBuffer = new byte[TMP_BUFFER_SIZE];
        }
        // Initialize the extended APDU buffer
        try {
            // Try to allocate the extended APDU buffer on RAM memory
            recvBuffer = JCSystem.makeTransientByteArray(EXT_APDU_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            // Allocate the extended APDU buffer on EEPROM memory
            // This is the fallback method, but its usage is really not
            // recommended as after ~ 100000 writes it will kill the EEPROM cells...
            recvBuffer = new byte[EXT_APDU_BUFFER_SIZE];
        }
        
        // common cryptographic objects
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sigECDSA= Signature.getInstance(ALG_ECDSA_SHA_256, false); 
        sha256= MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        aes128= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        HmacSha160.init(tmpBuffer);
        try {
            keyAgreement = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false); 
        } catch (CryptoException e) {
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);// unsupported feature => use a more recent card!
        }
        
        //secure channel objects
        try {
            sc_buffer = JCSystem.makeTransientByteArray((short) SIZE_SC_BUFFER, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            sc_buffer = new byte[SIZE_SC_BUFFER];
        }
        
        // secure channel
        sc_sessionkey= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false); // todo: make transient?
        sc_ephemeralkey= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        sc_aes128_cbc= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false); 
                
        // perso PKI: generate public/private keypair
        authentikey_private= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(authentikey_private);
        authentikey_public= (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, LENGTH_EC_FP_256, false); 
        Secp256k1.setCommonCurveParameters(authentikey_public);
        //authentikey_pair= new KeyPair(authentikey_public, authentikey_private);
        //authentikey_pair.genKeyPair(); //=> cap file fails to load!
        randomData.generateData(recvBuffer, (short)0, SIZE_ECPRIVKEY);
        authentikey_private.setS(recvBuffer, (short)0, SIZE_ECPRIVKEY); //random value first
        keyAgreement.init(authentikey_private);   
        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, recvBuffer, (short)0); //pubkey in uncompressed form => silently fail after cap loaded
        authentikey_public.setW(recvBuffer, (short)0, (short)65);
        
        // private & public key arrays
        ecprivkeys = new ECPrivateKey[MAX_NUM_KEYS];
        for (byte key_nbr=(byte)0; key_nbr<MAX_NUM_KEYS; key_nbr++){
            ecprivkeys[key_nbr] = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
            Secp256k1.setCommonCurveParameters(ecprivkeys[key_nbr]);
        }
        ecpubkeys = new byte[(short)(MAX_NUM_KEYS*SIZE_ECPUBKEY)]; //new ECPublicKey[MAX_NUM_KEYS]; 
        user_entropy_array = new byte[(short)(MAX_NUM_KEYS*SIZE_ENTROPY)];
        card_entropy_array = new byte[(short)(MAX_NUM_KEYS*SIZE_ENTROPY)];
        
        // key metadata
        state_array= new byte[MAX_NUM_KEYS];
        type_array= new byte[MAX_NUM_KEYS];
        asset_array= new byte[MAX_NUM_KEYS];
        slip44_array= new byte[(short)MAX_NUM_KEYS*SIZE_SLIP44];
        contract_array= new byte[(short)MAX_NUM_KEYS*SIZE_CONTRACT];
        tokenid_array= new byte[(short)MAX_NUM_KEYS*SIZE_TOKENID];
        data_array= new byte[(short)MAX_NUM_KEYS*SIZE_DATA];
        //unlock_code_array= new byte[(short)MAX_NUM_KEYS*SIZE_UNLOCK_CODE];
        
        // unlock data
        unlock_secret= new byte[SIZE_UNLOCK_SECRET];
        unlock_counter= new byte[SIZE_UNLOCK_COUNTER];
        //Util.arrayFillNonAtomic(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER, (byte)0); //todo: use a random initial value?
        randomData.generateData(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);
        randomData.generateData(unlock_secret, (short)0, SIZE_UNLOCK_SECRET);
        
        // set keys state to uninitialized
        Util.arrayFillNonAtomic(state_array, (short)0, MAX_NUM_KEYS, STATE_UNINITIALIZED);
        
        // card label
        card_label = new byte[MAX_CARD_LABEL_SIZE];  
        
    } // end of constructor

    public boolean select() {
        /*
         * Application has been selected: Do session cleanup operation
         */
        
        //todo: clear secure channel values?
        initialized_secure_channel=false;
        
        return true;
    }

    public void deselect() {

    }

    public void process(APDU apdu) {
        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD

        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer
        
        if (selectingApplet())
            ISOException.throwIt(ISO7816.SW_NO_ERROR);

        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command
        if ((buffer[ISO7816.OFFSET_CLA] == 0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0xA4))
            return;
        // verify the rest of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != CardEdge_CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        byte ins = buffer[ISO7816.OFFSET_INS];
        
        // prepare APDU buffer
        if (ins != INS_GET_STATUS){
            short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
            if (bytesLeft != apdu.setIncomingAndReceive())
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        // only 3 commands are allowed, the others must be wrapped in a secure channel command
        // the 3 commands are: get_status, initialize_secure_channel & process_secure_channel
        short sizeout=(short)0;
        if (ins == INS_GET_STATUS){
            sizeout= GetStatus(apdu, buffer);
            apdu.setOutgoingAndSend((short) 0, sizeout);
            return;
        }
        else if (ins == INS_INIT_SECURE_CHANNEL){
            sizeout= InitiateSecureChannel(apdu, buffer);
            apdu.setOutgoingAndSend((short) 0, sizeout);
            return;
        }
        else if (ins == INS_PROCESS_SECURE_CHANNEL){
            sizeout= ProcessSecureChannel(apdu, buffer);
            //todo: check if sizeout and buffer[ISO7816.OFFSET_LC] matches...
            //if sizeout>4, buffer[ISO7816.OFFSET_LC] should be equal to (sizeout-5)
            //todo: remove padding ? (it is actually not used)          
        }
        else if (needs_secure_channel){
            ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
        }
        
        // at this point, the encrypted content has been deciphered in the buffer
        ins = buffer[ISO7816.OFFSET_INS];
        // check setup status
        if (!setupDone && (ins != INS_SETUP)){
            //before setup, only personalization is allowed
            if (personalizationDone ||
                    (  (ins != INS_EXPORT_PKI_PUBKEY)
                    && (ins != INS_IMPORT_PKI_CERTIFICATE)
                    && (ins != INS_SIGN_PKI_CSR)
                    && (ins != INS_LOCK_PKI)) ){
                ISOException.throwIt(SW_SETUP_NOT_DONE);
            } 
        }
        if (setupDone && (ins == INS_SETUP))
            ISOException.throwIt(SW_SETUP_ALREADY_DONE);
        
        switch (ins) {
        // common methods
        case INS_SETUP:
            sizeout= setup(apdu, buffer);
            break;
        case INS_GET_STATUS:
            sizeout= GetStatus(apdu, buffer);
            break;
        case INS_CARD_LABEL:
            sizeout = cardLabel(apdu, buffer);
            break;
        case INS_EXPORT_AUTHENTIKEY:
            sizeout= getAuthentikey(apdu, buffer);
            break;
        // Satodime
        case INS_GET_SATODIME_STATUS:
            sizeout= getSatodimeStatus(apdu, buffer);
            break;
        case INS_GET_SATODIME_KEYSLOT_STATUS:
            sizeout= getSatodimeKeyslotStatus(apdu, buffer);
            break;
        case INS_SET_SATODIME_KEYSLOT_STATUS:
            sizeout= setSatodimeKeyslotStatus(apdu, buffer);
            break;
//        case INS_GET_SATODIME_UNLOCK_CODE:
//            sizeout= getSatodimeUnlockCode(apdu, buffer);
//            break;
        case INS_GET_SATODIME_PUBKEY:
            sizeout= getSatodimePubkey(apdu, buffer);
            break;
        case INS_GET_SATODIME_PRIVKEY:
            sizeout= getSatodimePrivkey(apdu, buffer);
            break;
        case INS_SEAL_SATODIME_KEY:
            sizeout= sealSatodimeKey(apdu, buffer);
            break;
        case INS_UNSEAL_SATODIME_KEY:
            sizeout= unsealSatodimeKey(apdu, buffer);
            break;
        case INS_RESET_SATODIME_KEY:
            sizeout= resetSatodimeKey(apdu, buffer);
            break;
        case INS_INITIATE_SATODIME_TRANSFER:
            sizeout= initiateSatodimeTransfer(apdu, buffer);
            break;
        //PKI
        case INS_EXPORT_PKI_PUBKEY:
            sizeout= export_PKI_pubkey(apdu, buffer);
            break;
        case INS_SIGN_PKI_CSR:
            sizeout= sign_PKI_CSR(apdu, buffer);
            break;
        case INS_IMPORT_PKI_CERTIFICATE:
            sizeout= import_PKI_certificate(apdu, buffer);
            break;
        case INS_EXPORT_PKI_CERTIFICATE:
            sizeout= export_PKI_certificate(apdu, buffer);
            break;
        case INS_LOCK_PKI:
            sizeout= lock_PKI(apdu, buffer);
            break;
        case INS_CHALLENGE_RESPONSE_PKI:
            sizeout= challenge_response_pki(apdu, buffer);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }//end of switch
        
        // Prepare buffer for return
        if (sizeout==0){
            return;
        }
        else if ((ins == INS_GET_STATUS) || (ins == INS_INIT_SECURE_CHANNEL)) {
            apdu.setOutgoingAndSend((short) 0, sizeout);
        }
        else if (needs_secure_channel) { // encrypt response
            // buffer contains the data (sizeout)
            // for encryption, data is padded with PKCS#7
            short blocksize=(short)16;
            short padsize= (short) (blocksize - (sizeout%blocksize));
            
            Util.arrayCopy(buffer, (short)0, tmpBuffer, (short)0, sizeout);
            Util.arrayFillNonAtomic(tmpBuffer, sizeout, padsize, (byte)padsize);//padding
            Util.arrayCopy(sc_buffer, OFFSET_SC_IV, buffer, (short)0, SIZE_SC_IV);
            sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_ENCRYPT, sc_buffer, OFFSET_SC_IV, SIZE_SC_IV);
            short sizeoutCrypt=sc_aes128_cbc.doFinal(tmpBuffer, (short)0, (short)(sizeout+padsize), buffer, (short) (18));
            Util.setShort(buffer, (short)16, sizeoutCrypt);
            sizeout= (short)(18+sizeoutCrypt);
            //send back
            apdu.setOutgoingAndSend((short) 0, sizeout);
        }
        else {
            apdu.setOutgoingAndSend((short) 0, sizeout);
        }
        
    } // end of process method

    /** 
     * Setup APDU - initialize the applet and reserve memory
     * This is done only once during the lifetime of the applet
     * 
     * ins: INS_SETUP (0x2A) 
     * p1: 0x00
     * p2: 0x00
     * data: [default_pin_length(1b) | default_pin | 
     *        pin_tries0(1b) | ublk_tries0(1b) | pin0_length(1b) | pin0 | ublk0_length(1b) | ublk0 | 
     *        pin_tries1(1b) | ublk_tries1(1b) | pin1_length(1b) | pin1 | ublk1_length(1b) | ublk1 | 
     *        secmemsize(2b) | RFU(2b) | RFU(3b) |
     *        option_flags(2b) | 
     *        (option): hmacsha1_key(20b) | amount_limit(8b)
     *        ]
     * where: 
     *      default_pin: {0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30};
     *      pin_tries: max number of PIN try allowed before the corresponding PIN is blocked
     *      ublk_tries:  max number of UBLK(unblock) try allowed before the PUK is blocked
     *      secmemsize: number of bytes reserved for internal memory (storage of Bip32 objects)
     *      memsize: number of bytes reserved for memory with external access
     *      ACL: creation rights for objects - Key - PIN
     *      option_flags: flags to define up to 16 additional options:
     *      bit15 set: second factor authentication using hmac-sha1 challenge-response (v0.2-0.1)
     *          hmacsha1_key: 20-byte hmac key used for transaction authorization
     *          amount_limit: max amount (in satoshis) allowed without confirmation (this includes change value)
     *  
     * return: [ MAX_NUM_KEYS(2b) | size_unlock_secret(2b) | unlock_secret | size_unlock_counter(2b) | unlock_counter] (deprecated)
     * return: [ unlock_counter(4b) | unlock_secret(20b) ]
     */
    private short setup(APDU apdu, byte[] buffer) {
        personalizationDone=true;// perso PKI should be locked once setup is done
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short base = (short) (ISO7816.OFFSET_CDATA);
        
        // generate initial unlock_secret
        randomData.generateData(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);
        randomData.generateData(unlock_secret, (short)0, SIZE_UNLOCK_SECRET);
        // 
        setupDone = true;
        
        // return unlock data
        Util.arrayCopyNonAtomic(unlock_counter, (short)0, buffer, (short)0, SIZE_UNLOCK_COUNTER);
        Util.arrayCopyNonAtomic(unlock_secret, (short)0, buffer, (short)SIZE_UNLOCK_COUNTER, SIZE_UNLOCK_SECRET);
        return (short)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_SECRET); 
    }
        
    /****************************************
     * APDU handlers *
     ****************************************/  
    
    /**
     * This function retrieves general information about the Applet running on the smart
     * card, and useful information about the status of current session such as:
     *      - applet version (4b)
     *  
     *  ins: 0x3C
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: none
     *  return: [versions(4b) | PIN0-PUK0-PIN1-PUK1 tries (4b) | needs2FA (1b) | is_seeded(1b) | setupDone(1b) | needs_secure_channel(1b)]
     */
    private short GetStatus(APDU apdu, byte[] buffer) {
        // check that PIN[0] has been entered previously
        //if (!pins[0].isValidated())
        //  ISOException.throwIt(SW_UNAUTHORIZED);
        
        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        
        short pos = (short) 0;
        buffer[pos++] = PROTOCOL_MAJOR_VERSION; // Major Card Edge Protocol version n.
        buffer[pos++] = PROTOCOL_MINOR_VERSION; // Minor Card Edge Protocol version n.
        buffer[pos++] = APPLET_MAJOR_VERSION; // Major Applet version n.
        buffer[pos++] = APPLET_MINOR_VERSION; // Minor Applet version n.
        // PIN/PUK remaining tries available => send default
        if (setupDone){
            buffer[pos++] = (byte)1;
            buffer[pos++] = (byte)1;
            buffer[pos++] = (byte)1;
            buffer[pos++] = (byte)1;
        } else {
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
        }
        // needs_2FA: never
        buffer[pos++] = (byte)0x00;
        // bip32_seeded: never
        buffer[pos++] = (byte)0x00;
        if (setupDone)
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        if (needs_secure_channel)
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        
        return pos;
    }
    
    /**
     * This function allows to define or recover a short description of the card.
     * 
     * ins: 0x3D 
     * p1: 0x00 
     * p2: operation (0x00 to set label, 0x01 to get label)
     * data: [label_size(1b) | label ] if p2==0x00 else (none) 
     * return: [label_size(1b) | label ] if p2==0x01 else (none)
     */
    private short cardLabel(APDU apdu, byte[] buffer) {

        byte op = buffer[ISO7816.OFFSET_P2];
        switch (op) {
        case 0x00: // set label
            short bytes_left = Util.makeShort((byte) 0x00,
                    buffer[ISO7816.OFFSET_LC]);
            short buffer_offset = ISO7816.OFFSET_CDATA;
            if (bytes_left > 0) {
                short label_size = Util.makeShort((byte) 0x00,
                        buffer[buffer_offset]);
                if (label_size > bytes_left)
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                if (label_size > MAX_CARD_LABEL_SIZE)
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                card_label_size = buffer[buffer_offset];
                bytes_left--;
                buffer_offset++;
                Util.arrayCopyNonAtomic(buffer, buffer_offset, card_label,
                        (short) 0, label_size);
            } else if (bytes_left == 0) {// reset label
                card_label_size = (byte) 0x00;
            }
            return (short) 0;

        case 0x01: // get label
            buffer[(short) 0] = card_label_size;
            Util.arrayCopyNonAtomic(card_label, (short) 0, buffer, (short) 1,
                    card_label_size);
            return (short) (card_label_size + 1);

        default:
            ISOException.throwIt(SW_INCORRECT_P2);

        }// end switch()

        return (short) 0;
    }

        
    /**
     * This function returns the authentikey public key.
     * The function returns the x-coordinate of the authentikey, self-signed.
     * The authentikey full public key can be recovered from the signature.
     * 
     * Compared to getBIP32AuthentiKey(), this method returns the Authentikey even if the card is not seeded.
     * For SeedKeeper encrypted seed import, we use the authentikey as a Trusted Pubkey for the ECDH key exchange, 
     * thus the authentikey must be available before the Satochip is seeded. 
     * Before a seed is available, the authentiey is generated oncard randomly in the constructor
     * 
     *  ins: 0xAD
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: none
     *  return: [coordx_size(2b) | coordx | sig_size(2b) | sig]
     */
    private short getAuthentikey(APDU apdu, byte[] buffer){
        
        // compute the partial authentikey public key...
        authentikey_public.getW(buffer, (short)1);
        Util.setShort(buffer, (short)0, SIZE_ECCOORDX);
        // self signed public key
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(SIZE_ECCOORDX+2), buffer, (short)(SIZE_ECCOORDX+4));
        Util.setShort(buffer, (short)(SIZE_ECCOORDX+2), sign_size);
        
        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [coordx_size(2) | coordx | sigsize(2) | sig]
        return (short)(SIZE_ECCOORDX+sign_size+4);
        
    }
    
    /*********************************************
     *          Methods for Satodime             *
     *********************************************/
    
    /**
     * This function returns the satodime status of the card.
     * Info includes: number of key sots, nb slots used, nb slots available, 
     *  
     *  ins: 0x
     *  p1: 0x00
     *  p2: 0x00
     *  data: (none)
     *  return: [unlock_counter | nb_keys_slots(1b) | key_status(nb_key_slots bytes) ]
     */
    private short getSatodimeStatus(APDU apdu, byte[] buffer){
       
        short buffer_offset=(short)0;
        // unlock_counter
        Util.arrayCopyNonAtomic(unlock_counter, (short)0, buffer, buffer_offset, SIZE_UNLOCK_COUNTER);
        buffer_offset+=SIZE_UNLOCK_COUNTER;
        // nb_keys_slots
        buffer[buffer_offset]=  MAX_NUM_KEYS;
        buffer_offset++;
        // key_status
        for (byte i=0; i<MAX_NUM_KEYS; i++){
           buffer[buffer_offset++]= state_array[i];
        }
        return (short)(SIZE_UNLOCK_COUNTER + 1 + MAX_NUM_KEYS);
    }
    
    /**
     * This function returns the satodime status of a specific key slot.
     * Info includes: status,  
     * Unlock_code correct value is only returned when using a card reader (not via NFC) 
     * 
     *  ins: 0x
     *  p1: key slot (0x00-0x0F)
     *  p2: 0x00
     *  data: (none)
     *  return: [key_status(1b) | key_type(1b) | key_asset(1b) | key_slip44(4b) | key_contract(34b) | key_tokenid(34b) | key_data(66b) ]
     */
    private short getSatodimeKeyslotStatus(APDU apdu, byte[] buffer){
       
        byte key_nbr = buffer[ISO7816.OFFSET_P1];
        if ((key_nbr < 0) || (key_nbr >= MAX_NUM_KEYS) )
            ISOException.throwIt(SW_INCORRECT_P1);
        
        short buffer_offset=(short)0;
        
        // keystatus, key_type & key_asset
        buffer[buffer_offset++]=state_array[key_nbr];
        buffer[buffer_offset++]=type_array[key_nbr];
        buffer[buffer_offset++]=asset_array[key_nbr];
        // slip44
        Util.arrayCopyNonAtomic(slip44_array, (short)(key_nbr*SIZE_SLIP44), buffer, buffer_offset, SIZE_SLIP44);
        buffer_offset+=SIZE_SLIP44;
        // contract
        Util.arrayCopyNonAtomic(contract_array, (short)(key_nbr*SIZE_CONTRACT), buffer, buffer_offset, SIZE_CONTRACT);
        buffer_offset+=SIZE_CONTRACT;
        // tokenid
        Util.arrayCopyNonAtomic(tokenid_array, (short)(key_nbr*SIZE_TOKENID), buffer, buffer_offset, SIZE_TOKENID);
        buffer_offset+=SIZE_TOKENID;
        // data
        Util.arrayCopyNonAtomic(data_array, (short)(key_nbr*SIZE_DATA), buffer, buffer_offset, SIZE_DATA);
        buffer_offset+=SIZE_DATA;
        
        return buffer_offset;    
    }
    
    /**
     * This function set the satodime status of a specific key slot.
     * Info includes: status,  
     * This function is only allowed when the corresponding is in the 'sealed' state.
     * Unlock code is required to set or modify these data.
     *  
     *  ins: 0x
     *  p1: key slot (0x00-0x0F)
     *  p2: 0x00 or 0x01
     *  data: 
     *      p2==0x00: [unlock_counter(4b) | unlock_code(20b) | RFU(1b) | RFU(1b) | key_asset(1b) | key_slip44(4b) | key_contract(34b) | key_tokenid(34b)]
     *      p2==0x01: [unlock_counter(4b) | unlock_code(20b) | key_data(66b)]
     *  return: (none)
     */
    private short setSatodimeKeyslotStatus(APDU apdu, byte[] buffer){
        
        byte key_nbr = buffer[ISO7816.OFFSET_P1];
        if ((key_nbr < 0) || (key_nbr >= MAX_NUM_KEYS) )
            ISOException.throwIt(SW_INCORRECT_P1);
        
        byte p2 = buffer[ISO7816.OFFSET_P2];
        if ((p2 < 0x00) || (p2 > 0x01) )
            ISOException.throwIt(SW_INCORRECT_P2);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if ((p2==0x00) && (bytesLeft < SIZE_KEY_METADATA_0))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if ((p2==0x01) && (bytesLeft < SIZE_KEY_METADATA_1))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        
        short buffer_offset=ISO7816.OFFSET_CDATA;
        
        // check unlock_code
        // check which communication protocol is used
        byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        if (protocol == APDU.PROTOCOL_MEDIA_USB || protocol == APDU.PROTOCOL_MEDIA_DEFAULT) {
            // nothing to check...
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);  
        }
        // only check for contactless operation
        else if (protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
            // check counter
            if (Util.arrayCompare(unlock_counter, (short)0, buffer, buffer_offset, SIZE_UNLOCK_COUNTER) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_COUNTER);
            }
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            // compute & check hmac(counter_secret, apduheader | counter)
            HmacSha160.computeHmacSha160(unlock_secret, (short)0, SIZE_UNLOCK_SECRET, buffer, (short)0, buffer_offset, recvBuffer, (short)0);
            if (Util.arrayCompare(buffer, buffer_offset, recvBuffer, (short)0, SIZE_UNLOCK_CODE) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_CODE);
            }
            // increase counter
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);
        }
        else {
            ISOException.throwIt(SW_UNKNOWN_PROTOCOL_MEDIA);
        }
        buffer_offset+=SIZE_UNLOCK_CODE;
        
        if (p2==0x00){
            //RFU
            buffer_offset++;
            buffer_offset++;
            // key_asset
            asset_array[key_nbr]= buffer[buffer_offset++];
            // slip44
            Util.arrayCopyNonAtomic(buffer, buffer_offset, slip44_array, (short)(key_nbr*SIZE_SLIP44), SIZE_SLIP44);
            buffer_offset+=SIZE_SLIP44;
            // contract 
            Util.arrayCopyNonAtomic(buffer, buffer_offset, contract_array, (short)(key_nbr*SIZE_CONTRACT), SIZE_CONTRACT);
            buffer_offset+=SIZE_CONTRACT;
            // tokenid
            Util.arrayCopyNonAtomic(buffer, buffer_offset, tokenid_array, (short)(key_nbr*SIZE_TOKENID), SIZE_TOKENID);
            buffer_offset+=SIZE_TOKENID;
        }
        else if (p2==0x01){
            // data
            Util.arrayCopyNonAtomic(buffer, buffer_offset, data_array, (short)(key_nbr*SIZE_DATA), SIZE_DATA);
            buffer_offset+=SIZE_DATA;
        }
        return (short)0;
    }
            
    /**
     * This function returns the PUBLIC key for a given slot
     * This function is only available when slot status is 'sealed' or 'unsealed'
     * 
     *  ins: 0x
     *  p1: key slot (0x00-0x0F)
     *  p2: 0x00
     *  data: (none)
     *  return: [ pubkey_size(2b) | pubkey | sig_size(2b) | sig ]
     */
    private short getSatodimePubkey(APDU apdu, byte[] buffer){
        
        // check keyslot bounds
        byte key_nbr = buffer[ISO7816.OFFSET_P1];
        if ((key_nbr < 0) || (key_nbr >= MAX_NUM_KEYS) )
            ISOException.throwIt(SW_INCORRECT_P1);
        
        // check keyslot state
        if (state_array[key_nbr] == STATE_UNINITIALIZED)
            ISOException.throwIt(SW_INCORRECT_KEYSLOT_STATE);
        
        // returns pubkey, signed by authentikey
        short buffer_offset=0;
        // pubkey_size
        Util.setShort(buffer, buffer_offset, SIZE_ECPUBKEY);
        buffer_offset+=2;
        // pubkey
        Util.arrayCopyNonAtomic(ecpubkeys, (short)(key_nbr*SIZE_ECPUBKEY), buffer, buffer_offset, SIZE_ECPUBKEY);
        buffer_offset+=SIZE_ECPUBKEY;
        
        // key signed by authentikey
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, buffer_offset, buffer, (short)(buffer_offset+2));
        Util.setShort(buffer, buffer_offset, sign_size);
        buffer_offset+=2;
        buffer_offset+=sign_size;
        
        return buffer_offset;
    }
        
    /**
     * This function returns the PRIVATE key for a given slot.
     * This function is only available when slot status is 'unsealed'.
     * This function does NOT change the status of the corresponding key slot.
     * 
     *  ins: 0x
     *  p1: key slot (0x00-0x0F)
     *  p2: 0x00
     *  data: [ unlock_counter(4b) | unlock_code(20b) ]
     *  return: [ entropy_size(2b) | user_entropy + authentikey_coordx + card_entropy | privkey_size(2b) | privkey | sig_size(2b) | sig ]
     */
    private short getSatodimePrivkey(APDU apdu, byte[] buffer){
        
        // check keyslot bounds
        byte key_nbr = buffer[ISO7816.OFFSET_P1];
        if ((key_nbr < 0) || (key_nbr >= MAX_NUM_KEYS) )
            ISOException.throwIt(SW_INCORRECT_P1);
        
        // check keyslot state
        if (state_array[key_nbr] != STATE_UNSEALED)
            ISOException.throwIt(SW_INCORRECT_KEYSLOT_STATE);
        
        short buffer_offset=ISO7816.OFFSET_CDATA;
        
        // check unlock_code
        // check which communication protocol is used
        byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        if (protocol == APDU.PROTOCOL_MEDIA_USB || protocol == APDU.PROTOCOL_MEDIA_DEFAULT) {
            // nothing to check...
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);  
        }
        // only check for contactless operation
        else if (protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
            // check counter
            if (Util.arrayCompare(unlock_counter, (short)0, buffer, buffer_offset, SIZE_UNLOCK_COUNTER) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_COUNTER);
            }
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            // compute & check hmac(counter_secret, apduheader | counter)
            HmacSha160.computeHmacSha160(unlock_secret, (short)0, SIZE_UNLOCK_SECRET, buffer, (short)0, buffer_offset, recvBuffer, (short)0);
            if (Util.arrayCompare(buffer, buffer_offset, recvBuffer, (short)0, SIZE_UNLOCK_CODE) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_CODE);
            }
            // increase counter
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);
        }
        else {
            ISOException.throwIt(SW_UNKNOWN_PROTOCOL_MEDIA);
        }
        buffer_offset+=SIZE_UNLOCK_CODE;
        
        // entropy used to generate private key (proof that the key was indeed random)
        buffer_offset=0;
        Util.setShort(buffer, (short)0, (short)(2*SIZE_ENTROPY+SIZE_ECCOORDX) );
        buffer_offset+=2;
        authentikey_public.getW(buffer, (short)33); // pubkey starts with 0x65
        Util.arrayCopyNonAtomic(user_entropy_array, (short)(key_nbr*SIZE_ENTROPY), buffer, buffer_offset, SIZE_ENTROPY);
        buffer_offset+=SIZE_ENTROPY;
        buffer_offset+=SIZE_ECCOORDX;
        Util.arrayCopyNonAtomic(card_entropy_array, (short)(key_nbr*SIZE_ENTROPY), buffer, buffer_offset, SIZE_ENTROPY);
        buffer_offset+=SIZE_ENTROPY;
        
        // returns privkey
        short privkey_size= ecprivkeys[key_nbr].getS(buffer, (short)(buffer_offset+2));
        Util.setShort(buffer, buffer_offset, privkey_size);
        buffer_offset+=2;
        buffer_offset+= privkey_size;
         
        // key signed by authentikey
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, buffer_offset, buffer, (short)(buffer_offset+2));
        Util.setShort(buffer, buffer_offset, sign_size);
        buffer_offset+=2;
        buffer_offset+=sign_size;
        
        return buffer_offset;
    }    

    /**
     * This function SEAL the corresponding slot of a satodime.
     * This function is only available when slot status is 'unitialized'
     * This changes the status of the slot from 'unitialized' to 'sealed'.
     * Unlock code is only checked if used with NFC interface
     * 
     *  ins: 0x
     *  p1: key slot (0x00-0x0F)
     *  p2: 0x00
     *  data: [ unlock_counter(4b) | unlock_code(20b) | entropy_data(32b)]
     *  return: [ pubkey_size(2b) | pubkey | sig_size(2b) | sig ]
     */
    private short sealSatodimeKey(APDU apdu, byte[] buffer){
        
        // check keyslot bounds
        byte key_nbr = buffer[ISO7816.OFFSET_P1];
        if ((key_nbr < 0) || (key_nbr >= MAX_NUM_KEYS) )
            ISOException.throwIt(SW_INCORRECT_P1);
        
        // check keyslot state
        if (state_array[key_nbr] != STATE_UNINITIALIZED)
            ISOException.throwIt(SW_INCORRECT_KEYSLOT_STATE);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)(SIZE_UNLOCK_COUNTER+SIZE_UNLOCK_CODE+SIZE_ENTROPY))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        short buffer_offset=ISO7816.OFFSET_CDATA;
        
        // check unlock_code
        // check which communication protocol is used
        byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        if (protocol == APDU.PROTOCOL_MEDIA_USB || protocol == APDU.PROTOCOL_MEDIA_DEFAULT) {
            // nothing to check...
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);  
        }
        // only check for contactless operation
        else if (protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
            // check counter
            if (Util.arrayCompare(unlock_counter, (short)0, buffer, buffer_offset, SIZE_UNLOCK_COUNTER) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_COUNTER);
            }
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            // compute & check hmac(counter_secret, apduheader | counter)
            HmacSha160.computeHmacSha160(unlock_secret, (short)0, SIZE_UNLOCK_SECRET, buffer, (short)0, buffer_offset, recvBuffer, (short)0);
            if (Util.arrayCompare(buffer, buffer_offset, recvBuffer, (short)0, SIZE_UNLOCK_CODE) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_CODE);
            }
            // increase counter
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);
        }
        else {
            ISOException.throwIt(SW_UNKNOWN_PROTOCOL_MEDIA);
        }
        buffer_offset+=SIZE_UNLOCK_CODE;
        
        // get entropy from buffer
        Util.arrayCopyNonAtomic(buffer, buffer_offset, user_entropy_array, (short)(key_nbr*SIZE_ENTROPY), SIZE_ENTROPY);
        //buffer_offset+=SIZE_ENTROPY;
        sha256.reset();
        sha256.update(user_entropy_array, (short)(key_nbr*SIZE_ENTROPY), SIZE_ENTROPY);
        // hash authentikey coordx 
        authentikey_public.getW(recvBuffer, (short)0);
        sha256.update(recvBuffer, (short)(1), SIZE_ECCOORDX);
        
        // generate keypair
        // secret exponent is the SHA256(user_entropy + authentikey_coordx + card_entropy)
        randomData.generateData(card_entropy_array, (short)(key_nbr*SIZE_ENTROPY), SIZE_ENTROPY);
        short hash_size=sha256.doFinal(card_entropy_array, (short)(key_nbr*SIZE_ENTROPY), SIZE_ENTROPY, recvBuffer, (short)0);
        ecprivkeys[key_nbr].setS(recvBuffer, (short)0, SIZE_ECPRIVKEY); 
        Util.arrayFillNonAtomic(recvBuffer, (short)0, SIZE_ECPRIVKEY, (byte)0);// erase secret bytes
        
        // compute public key
        buffer_offset=(short)0;
        keyAgreement.init(ecprivkeys[key_nbr]);
        short pubkey_size= keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, SIZE_ECPUBKEY, ecpubkeys, (short)(key_nbr*SIZE_ECPUBKEY)); 
        Util.setShort(buffer, buffer_offset, pubkey_size);
        buffer_offset+=2;
        Util.arrayCopyNonAtomic(ecpubkeys, (short)(key_nbr*SIZE_ECPUBKEY), buffer, buffer_offset, pubkey_size);
        buffer_offset+=pubkey_size;
        
        // sign with authentikey
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, buffer_offset, buffer, (short)(buffer_offset+2));
        Util.setShort(buffer, buffer_offset, sign_size);
        buffer_offset+=2;
        buffer_offset+=sign_size;
        
        // change state
        state_array[key_nbr] = STATE_SEALED;
        
        return buffer_offset;
    } 

    /**
     * This function UNSEAL the corresponding slot of a satodime.
     * This function is only available when slot status is 'sealed'
     * This changes the status of the slot from 'sealed' to 'unsealed'.
     * Unlock code is only checked if used with NFC interface
     * 
     *  ins: 0x
     *  p1: key slot (0x00-0x0F)
     *  p2: 0x00
     *  data: [ unlock_counter(4b) | unlock_code(20b)]
     *  return: [ entropy_size(2b) | user_entropy + authentikey_coordx + card_entropy | privkey_size(2b) | privkey | sig_size(2b) | sig ]
     */
    private short unsealSatodimeKey(APDU apdu, byte[] buffer){
        
        // check keyslot bounds
        byte key_nbr = buffer[ISO7816.OFFSET_P1];
        if ((key_nbr < 0) || (key_nbr >= MAX_NUM_KEYS) )
            ISOException.throwIt(SW_INCORRECT_P1);
        
        // check keyslot state
        if (state_array[key_nbr] != STATE_SEALED)
            ISOException.throwIt(SW_INCORRECT_KEYSLOT_STATE);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)(SIZE_UNLOCK_COUNTER+SIZE_UNLOCK_CODE))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        short buffer_offset=ISO7816.OFFSET_CDATA;
        
        // check unlock_code
        // check which communication protocol is used
        byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        if (protocol == APDU.PROTOCOL_MEDIA_USB || protocol == APDU.PROTOCOL_MEDIA_DEFAULT) {
            // nothing to do...
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);  
        }
        // only check for contactless operation
        else if (protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
            // check counter
            if (Util.arrayCompare(unlock_counter, (short)0, buffer, buffer_offset, SIZE_UNLOCK_COUNTER) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_COUNTER);
            }
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            // compute & check hmac(counter_secret, apduheader | counter)
            HmacSha160.computeHmacSha160(unlock_secret, (short)0, SIZE_UNLOCK_SECRET, buffer, (short)0, buffer_offset, recvBuffer, (short)0);
            if (Util.arrayCompare(buffer, buffer_offset, recvBuffer, (short)0, SIZE_UNLOCK_CODE) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_CODE);
            }
            // increase counter
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);
        }
        else {
            ISOException.throwIt(SW_UNKNOWN_PROTOCOL_MEDIA);
        }
        buffer_offset+=SIZE_UNLOCK_CODE;
        
        // change state!
        state_array[key_nbr] = STATE_UNSEALED;
        
        // entropy used to generate private key (proof that the key was indeed random)
        buffer_offset=0;
        Util.setShort(buffer, (short)0, (short)(2*SIZE_ENTROPY+SIZE_ECCOORDX) );
        buffer_offset+=2;
        authentikey_public.getW(buffer, (short)33); // pubkey starts with 0x65
        Util.arrayCopyNonAtomic(user_entropy_array, (short)(key_nbr*SIZE_ENTROPY), buffer, buffer_offset, SIZE_ENTROPY);
        buffer_offset+=SIZE_ENTROPY;
        buffer_offset+=SIZE_ECCOORDX;
        Util.arrayCopyNonAtomic(card_entropy_array, (short)(key_nbr*SIZE_ENTROPY), buffer, buffer_offset, SIZE_ENTROPY);
        buffer_offset+=SIZE_ENTROPY;
        
        // returns privkey
        short privkey_size= ecprivkeys[key_nbr].getS(buffer, (short)(buffer_offset+2));
        Util.setShort(buffer, buffer_offset, privkey_size);
        buffer_offset+=2;
        buffer_offset+= privkey_size;
         
        // key signed by authentikey
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, buffer_offset, buffer, (short)(buffer_offset+2));
        Util.setShort(buffer, buffer_offset, sign_size);
        buffer_offset+=2;
        buffer_offset+=sign_size;
                
        return buffer_offset;
    } 
   
    /**
     * This function RESET the corresponding slot of a satodime.
     * This function is only available when slot status is 'unsealed'
     * This changes the status of the slot from 'unsealed' to 'uninitialized'.
     * Unlock code is only checked if used with NFC interface
     * 
     *  ins: 0x
     *  p1: key slot (0x00-0x0F)
     *  p2: 0x00
     *  data: [ unlock_counter(4b) | unlock_code(20b)]
     *  return: (none)
     */
    private short resetSatodimeKey(APDU apdu, byte[] buffer){
        
        // check keyslot bounds
        byte key_nbr = buffer[ISO7816.OFFSET_P1];
        if ((key_nbr < 0) || (key_nbr >= MAX_NUM_KEYS) )
            ISOException.throwIt(SW_INCORRECT_P1);
        
        // check keyslot state
        if (state_array[key_nbr] != STATE_UNSEALED)
            ISOException.throwIt(SW_INCORRECT_KEYSLOT_STATE);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)(SIZE_UNLOCK_COUNTER+SIZE_UNLOCK_CODE))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        short buffer_offset=ISO7816.OFFSET_CDATA;
        
        // check unlock_code
        // check which communication protocol is used
        byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        if (protocol == APDU.PROTOCOL_MEDIA_USB || protocol == APDU.PROTOCOL_MEDIA_DEFAULT) {
            // nothing to check...
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);  
        }
        // only check for contactless operation
        else if (protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
            // check counter
            if (Util.arrayCompare(unlock_counter, (short)0, buffer, buffer_offset, SIZE_UNLOCK_COUNTER) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_COUNTER);
            }
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            // compute & check hmac(counter_secret, apduheader | counter)
            HmacSha160.computeHmacSha160(unlock_secret, (short)0, SIZE_UNLOCK_SECRET, buffer, (short)0, buffer_offset, recvBuffer, (short)0);
            if (Util.arrayCompare(buffer, buffer_offset, recvBuffer, (short)0, SIZE_UNLOCK_CODE) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_CODE);
            }
            // increase counter
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);
        }
        else {
            ISOException.throwIt(SW_UNKNOWN_PROTOCOL_MEDIA);
        }
        buffer_offset+=SIZE_UNLOCK_CODE;
        
        // change state!
        state_array[key_nbr] = STATE_UNINITIALIZED;
        
        // reset privkey & entropy arrays
        ecprivkeys[key_nbr].clearKey();
        Secp256k1.setCommonCurveParameters(ecprivkeys[key_nbr]);// set default params
        Util.arrayFillNonAtomic(user_entropy_array, (short)(key_nbr*SIZE_ENTROPY), SIZE_ENTROPY, (byte)0);
        Util.arrayFillNonAtomic(card_entropy_array, (short)(key_nbr*SIZE_ENTROPY), SIZE_ENTROPY, (byte)0);
        // reset pubkey
        Util.arrayFillNonAtomic(ecpubkeys, (short)(key_nbr*SIZE_ECPUBKEY), SIZE_ECPUBKEY, (byte)0);
        
        // reset metadata
        type_array[key_nbr]= (byte)0;
        asset_array[key_nbr]= (byte)0;
        Util.arrayFillNonAtomic(slip44_array, (short)(key_nbr*SIZE_SLIP44), SIZE_SLIP44, (byte)0);
        Util.arrayFillNonAtomic(contract_array, (short)(key_nbr*SIZE_CONTRACT), SIZE_CONTRACT, (byte)0);
        Util.arrayFillNonAtomic(tokenid_array, (short)(key_nbr*SIZE_TOKENID), SIZE_TOKENID, (byte)0);
        Util.arrayFillNonAtomic(data_array, (short)(key_nbr*SIZE_DATA), SIZE_DATA, (byte)0);
        
        return (short)0;
    } 
    
    /**
     * This function initiates the transfert of the satodime to a new user.
     * This function forces setup of the Satodime, which generates fresh unlock_codes.
     * This ensures that previous owner cannot tamper cards (via NFC) after the transfer of ownership.
     * It is the responsibility of the new owner to verify the setup status of the card after transfer.
     * Unlock code is only checked if used with NFC interface
     * 
     *  ins: 0x
     *  p1: 0x00
     *  p2: 0x00
     *  data: [unlock_counter(4b) | unlock_code(20b)]
     *  return: (none)
     */
    private short initiateSatodimeTransfer(APDU apdu, byte[] buffer){
        
        short buffer_offset=ISO7816.OFFSET_CDATA;
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
       
        if (bytesLeft < (short)(SIZE_UNLOCK_COUNTER+SIZE_UNLOCK_CODE))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // check which communication protocol is used
        byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        if (protocol == APDU.PROTOCOL_MEDIA_USB || protocol == APDU.PROTOCOL_MEDIA_DEFAULT) {
            // nothing to check... increase counter
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);   
        }
        // only check for contactless operation
        else if (protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
            
            // check counter
            if (Util.arrayCompare(unlock_counter, (short)0, buffer, buffer_offset, SIZE_UNLOCK_COUNTER) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_COUNTER);
            }
            buffer_offset+=SIZE_UNLOCK_COUNTER;
            // compute & check hmac(counter_secret, apduheader | counter)
            HmacSha160.computeHmacSha160(unlock_secret, (short)0, SIZE_UNLOCK_SECRET, buffer, (short)0, buffer_offset, recvBuffer, (short)0);
            if (Util.arrayCompare(buffer, buffer_offset, recvBuffer, (short)0, SIZE_UNLOCK_CODE) != 0){
                ISOException.throwIt(SW_INCORRECT_UNLOCK_CODE);
            }
            // increase counter
            Biginteger.add1_carry(unlock_counter, (short)0, SIZE_UNLOCK_COUNTER);            
        }
        else {
            ISOException.throwIt(SW_UNKNOWN_PROTOCOL_MEDIA);
        }
        
        // force setup and generation of new unlock_code_array at next connection
        // New owner is reponsible to check that setup is indeed activated
        setupDone= false;
       
        return (short)0;
    }
    
    /*********************************************
     *      Methods for Secure Channel           *
     *********************************************/
        
    /**
     * This function allows to initiate a Secure Channel
     *  
     *  ins: 0x81
     *  p1: 0x00
     *  p2: 0x00
     *  data: [client-pubkey(65b)]
     *  return: [coordx_size(2b) | authentikey-coordx | sig_size(2b) | self-sig | sig2_size(optional) | authentikey-sig(optional)]
     */
    private short InitiateSecureChannel(APDU apdu, byte[] buffer){
        
        // get client pubkey
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)65)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (buffer[ISO7816.OFFSET_CDATA] != (byte)0x04)
            ISOException.throwIt(SW_INVALID_PARAMETER);
            
        // generate a new ephemeral key
        sc_ephemeralkey.clearKey(); //todo: simply generate new random S param instead?
        Secp256k1.setCommonCurveParameters(sc_ephemeralkey);// keep public params!
        randomData.generateData(recvBuffer, (short)0, SIZE_ECPRIVKEY);
        sc_ephemeralkey.setS(recvBuffer, (short)0, SIZE_ECPRIVKEY); //random value first
        
        // compute the shared secret...
        keyAgreement.init(sc_ephemeralkey);        
        keyAgreement.generateSecret(buffer, ISO7816.OFFSET_CDATA, (short) 65, recvBuffer, (short)0); //pubkey in uncompressed form
        // derive sc_sessionkey & sc_mackey
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, SIZE_ECCOORDX, CST_SC, (short)6, (short)6, recvBuffer, (short)33);
        Util.arrayCopyNonAtomic(recvBuffer, (short)33, sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY);
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, SIZE_ECCOORDX, CST_SC, (short)0, (short)6, recvBuffer, (short)33);
        sc_sessionkey.setKey(recvBuffer,(short)33); // AES-128: 16-bytes key!!       
   
        //reset IV counter
        Util.arrayFillNonAtomic(sc_buffer, OFFSET_SC_IV, SIZE_SC_IV, (byte) 0);
        
        // self signed ephemeral pubkey
        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)1); //pubkey in uncompressed form
        Util.setShort(buffer, (short)0, SIZE_ECCOORDX);
        sigECDSA.init(sc_ephemeralkey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(SIZE_ECCOORDX+2), buffer, (short)(SIZE_ECCOORDX+4));
        Util.setShort(buffer, (short)(SIZE_ECCOORDX+2), sign_size);
        
        // hash signed by authentikey
        short offset= (short)(2+SIZE_ECCOORDX+2+sign_size);
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign2_size= sigECDSA.sign(buffer, (short)0, offset, buffer, (short)(offset+2));
        Util.setShort(buffer, offset, sign2_size);
        offset+=(short)(2+sign2_size); 
        
        initialized_secure_channel= true;
        
        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [coordx_size(2) | coordx | sigsize(2) | sig | sig2_size(optional) | sig2(optional)]
        return offset;
    }
    
    /**
     * This function allows to decrypt a secure channel message
     *  
     *  ins: 0x82
     *  
     *  p1: 0x00 (RFU)
     *  p2: 0x00 (RFU)
     *  data: [IV(16b) | data_size(2b) | encrypted_command | mac_size(2b) | mac]
     *  
     *  return: [decrypted command]
     *   
     */
    private short ProcessSecureChannel(APDU apdu, byte[] buffer){
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short offset = ISO7816.OFFSET_CDATA;
        
        if (!initialized_secure_channel){
            ISOException.throwIt(SW_SECURE_CHANNEL_UNINITIALIZED);
        }
        
        // check hmac
        if (bytesLeft<18)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizein = Util.getShort(buffer, (short) (offset+SIZE_SC_IV));
        if (bytesLeft<(short)(SIZE_SC_IV+2+sizein+2))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizemac= Util.getShort(buffer, (short) (offset+SIZE_SC_IV+2+sizein));
        if (sizemac != (short)20)
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_MAC);
        if (bytesLeft<(short)(SIZE_SC_IV+2+sizein+2+sizemac))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        HmacSha160.computeHmacSha160(sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY, buffer, offset, (short)(SIZE_SC_IV+2+sizein), recvBuffer, (short)0);
        if ( Util.arrayCompare(recvBuffer, (short)0, buffer, (short)(offset+SIZE_SC_IV+2+sizein+2), (short)20) != (byte)0 )
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_MAC);
        
        // process IV
        // IV received from client should be odd and strictly greater than locally saved IV
        // IV should be random (the 12 first bytes), never reused (the last 4 bytes counter) and different for send and receive
        if ((buffer[(short)(offset+SIZE_SC_IV-(short)1)] & (byte)0x01)==0x00)// should be odd
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_IV);
        if ( !Biginteger.lessThan(sc_buffer, OFFSET_SC_IV_COUNTER, buffer, (short)(offset+SIZE_SC_IV_RANDOM), SIZE_SC_IV_COUNTER ) ) //and greater than local IV
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_IV);
        // update local IV
        Util.arrayCopy(buffer, (short)(offset+SIZE_SC_IV_RANDOM), sc_buffer, OFFSET_SC_IV_COUNTER, SIZE_SC_IV_COUNTER);
        Biginteger.add1_carry(sc_buffer, OFFSET_SC_IV_COUNTER, SIZE_SC_IV_COUNTER);
        randomData.generateData(sc_buffer, OFFSET_SC_IV_RANDOM, SIZE_SC_IV_RANDOM);
        sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_DECRYPT, buffer, offset, SIZE_SC_IV);
        offset+=SIZE_SC_IV;
        bytesLeft-=SIZE_SC_IV;
        
        //decrypt command
        offset+=2;
        bytesLeft-=2;
        if (bytesLeft<sizein)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizeout=sc_aes128_cbc.doFinal(buffer, offset, sizein, buffer, (short) (0));
        return sizeout;
    }
    
    /*********************************************
     *      Methods for PKI personalization      *
     *********************************************/
    
    /**
     * This function export the ECDSA secp256k1 public key that corresponds to the private key
     *  
     *  ins: 
     *  p1: 0x00
     *  p2: 0x00 
     *  data: [none]
     *  return: [ pubkey (65b) ]
     */
    private short export_PKI_pubkey(APDU apdu, byte[] buffer) {
        authentikey_public.getW(buffer, (short)0); 
        return (short)65;
    }
    
    /**
     * This function is used to self-sign the CSR of the device
     *  
     *  ins: 0x94
     *  p1: 0x00  
     *  p2: 0x00 
     *  data: [hash(32b)]
     *  return: [signature]
     */
    private short sign_PKI_CSR(APDU apdu, byte[] buffer) {

        if (personalizationDone)
            ISOException.throwIt(SW_PKI_ALREADY_LOCKED);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)32)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.signPreComputedHash(buffer, ISO7816.OFFSET_CDATA, MessageDigest.LENGTH_SHA_256, buffer, (short)0);
        return sign_size;
    }
    
    /**
     * This function imports the device certificate
     *  
     *  ins: 
     *  p1: 0x00
     *  p2: Init-Update 
     *  data(init): [ full_size(2b) ]
     *  data(update): [chunk_offset(2b) | chunk_size(2b) | chunk_data ]
     *  return: [none]
     */
    private short import_PKI_certificate(APDU apdu, byte[] buffer) {

        if (personalizationDone)
            ISOException.throwIt(SW_PKI_ALREADY_LOCKED);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short buffer_offset = (short) (ISO7816.OFFSET_CDATA);
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch(op){
            case OP_INIT:
                if (bytesLeft < (short)2)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
                short new_certificate_size=Util.getShort(buffer, buffer_offset);
                if (new_certificate_size < 0)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (authentikey_certificate==null){
                    // create array
                    authentikey_certificate= new byte[new_certificate_size];
                    authentikey_certificate_size=new_certificate_size;
                }else{
                    if (new_certificate_size>authentikey_certificate.length)
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    authentikey_certificate_size=new_certificate_size;
                }
                break;
                
            case OP_PROCESS: 
                if (bytesLeft < (short)4)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                short chunk_offset= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                short chunk_size= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                bytesLeft-=4;
                if (bytesLeft < chunk_size)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if ((chunk_offset<0) || (chunk_offset>=authentikey_certificate_size))
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (((short)(chunk_offset+chunk_size))>authentikey_certificate_size)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
                Util.arrayCopyNonAtomic(buffer, buffer_offset, authentikey_certificate, chunk_offset, chunk_size);
                break;
                
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
        }
        return (short)0;
    }
    
    /**
     * This function exports the device certificate
     *  
     *  ins: 
     *  p1: 0x00  
     *  p2: Init-Update 
     *  data(init): [ none ]
     *  return(init): [ full_size(2b) ]
     *  data(update): [ chunk_offset(2b) | chunk_size(2b) ]
     *  return(update): [ chunk_data ] 
     */
    private short export_PKI_certificate(APDU apdu, byte[] buffer) {
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch(op){
            case OP_INIT:
                Util.setShort(buffer, (short)0, authentikey_certificate_size);
                return (short)2; 
                
            case OP_PROCESS: 
                short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
                if (bytesLeft < (short)4)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
                short buffer_offset = (short) (ISO7816.OFFSET_CDATA);
                short chunk_offset= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                short chunk_size= Util.getShort(buffer, buffer_offset);
                
                if ((chunk_offset<0) || (chunk_offset>=authentikey_certificate_size))
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (((short)(chunk_offset+chunk_size))>authentikey_certificate_size)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                Util.arrayCopyNonAtomic(authentikey_certificate, chunk_offset, buffer, (short)0, chunk_size);
                return chunk_size; 
                
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
                return (short)0; 
        }
    }
    
    /**
     * This function locks the PKI config.
     * Once it is locked, it is not possible to modify private key, certificate or allowed_card_AID.
     *  
     *  ins: 
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: [none]
     *  return: [none]
     */
    private short lock_PKI(APDU apdu, byte[] buffer) {
        personalizationDone=true;
        return (short)0;
    }
    
    /**
     * This function performs a challenge-response to verify the authenticity of the device.
     * The challenge is made of three parts: 
     *          - a constant header
     *          - a 32-byte challenge provided by the requester
     *          - a 32-byte random nonce generated by the device
     * The response is the signature over this challenge. 
     * This signature can be verified with the certificate stored in the device.
     * 
     *  ins: 
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: [challenge1(32b)]
     *  return: [challenge2(32b) | sig_size(2b) | sig]
     */
    private short challenge_response_pki(APDU apdu, byte[] buffer) {
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)32)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        //copy all data into array
        short offset=(short)0;
        Util.arrayCopyNonAtomic(PKI_CHALLENGE_MSG, (short)0, recvBuffer, offset, (short)PKI_CHALLENGE_MSG.length);
        offset+=PKI_CHALLENGE_MSG.length;
        randomData.generateData(recvBuffer, offset, (short)32);
        offset+=(short)32;
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, recvBuffer, offset, (short)32);
        offset+=(short)32;
         
        //sign challenge
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(recvBuffer, (short)0, offset, buffer, (short)34);
        Util.setShort(buffer, (short)32, sign_size);
        Util.arrayCopyNonAtomic(recvBuffer, (short)PKI_CHALLENGE_MSG.length, buffer, (short)0, (short)32);
        
        // verify response
        sigECDSA.init(authentikey_public, Signature.MODE_VERIFY);
        boolean is_valid= sigECDSA.verify(recvBuffer, (short)0, offset, buffer, (short)(34), sign_size);
        if (!is_valid)
            ISOException.throwIt(SW_SIGNATURE_INVALID);
        
        return (short)(32+2+sign_size);
    }
    
} // end of class JAVA_APPLET
