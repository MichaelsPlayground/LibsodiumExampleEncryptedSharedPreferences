package de.androidcrypto.libsodiumexample;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;

import com.goterl.lazysodium.LazySodiumAndroid;
import com.goterl.lazysodium.SodiumAndroid;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.SecretBox;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Date;


public class LibsodiumUtils {

    /**
     * This class is using Lazysodium for Libsodium CryptoBox encryption
     */

    private static final String TAG = "LibsodiumUtils";

    private boolean libsodiumUtilsAvailable = false;
    private String masterKeyAlias;
    public SharedPreferences sharedPreferences;
    private Context mContext;
    private int lastCryptoBoxKeyPairNumber = 0;

    private final String PRIVATE_KEY_NAME = "private_key_";
    private final String PUBLIC_KEY_NAME = "public_key_";
    private final String KEY_GENERATION_TIMESTAMP = "key_timestamp_";
    private final String KEY_GENERATION_TIMESTAMP_STRING = "key_timestamp_string_";
    private final String LAST_KEYPAIR_NUMBER = "last_keypair_number";

    protected LazySodiumAndroid ls;

    public LibsodiumUtils(Context context) {
        Log.d(TAG, "LibsodiumUtils construction");
        this.mContext = context;
        try {
            masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);
            sharedPreferences = EncryptedSharedPreferences.create(
                    "secret_shared_prefs",
                    masterKeyAlias,
                    mContext,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
            // init Lazysodium
            ls = new LazySodiumAndroid(new SodiumAndroid());
            // get the last generated keyPair number
            lastCryptoBoxKeyPairNumber = getLastCryptoBoxKeyPairNumberFromPreferences();

            libsodiumUtilsAvailable = true;
            Log.d(TAG, "LibsodiumUtils available");
        } catch (GeneralSecurityException | IOException e) {
            Log.e(TAG, "Error on initialization of LibsodiumUtils: " + e.getMessage());
            libsodiumUtilsAvailable = false;
            e.printStackTrace();
        }
    }

    public boolean isLibsodiumUtilsAvailable() {
        Log.d(TAG, "isLibsodiumUtilsAvailable");
        return libsodiumUtilsAvailable;
    }

    public int getLastCryptoBoxKeyPairNumber() {
        Log.d(TAG, "getLastCryptoBoxKeyPairNumber");
        return lastCryptoBoxKeyPairNumber;
    }

    public int generateNewKeyPair() {
        Log.d(TAG, "generate new KeyPair");
        KeyPair newKeyPair = generateCryptoBoxKeypairLazysodium();
        if (newKeyPair == null) {
            Log.e(TAG, "The keyPair could not get generated");
            return -1;
        }
        try {
            long actualTime = new Date().getTime();
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String actualTimeString = dateFormat.format(actualTime);
            String privateKeyBase64 = getCryptoBoxPrivateKeyBase64Lazysodium(newKeyPair);
            String publicKeyBase64 = getCryptoBoxPublicKeyBase64Lazysodium(newKeyPair);
            // we are going to store the data
            lastCryptoBoxKeyPairNumber++;
            sharedPreferences.edit().putString(PRIVATE_KEY_NAME + "_" + String.valueOf(lastCryptoBoxKeyPairNumber), privateKeyBase64).apply();
            sharedPreferences.edit().putString(PUBLIC_KEY_NAME + "_" + String.valueOf(lastCryptoBoxKeyPairNumber), publicKeyBase64).apply();
            sharedPreferences.edit().putString(KEY_GENERATION_TIMESTAMP + "_" + String.valueOf(lastCryptoBoxKeyPairNumber), String.valueOf(actualTime)).apply();
            sharedPreferences.edit().putString(KEY_GENERATION_TIMESTAMP_STRING + "_" + String.valueOf(lastCryptoBoxKeyPairNumber), actualTimeString).apply();
            sharedPreferences.edit().putInt(LAST_KEYPAIR_NUMBER, lastCryptoBoxKeyPairNumber).apply();
            Log.d(TAG, "new keyPair generated and stored, number: " + String.valueOf(lastCryptoBoxKeyPairNumber));
            return lastCryptoBoxKeyPairNumber;
        } catch (Exception e) {
            Log.e(TAG, "Error on key generation and storage: " + e.getMessage());
            return -1;
        }
    }

    private int getLastCryptoBoxKeyPairNumberFromPreferences() {
        Log.d(TAG, "getLastCryptoBoxKeyPairNumberFromPreferences");
        return sharedPreferences.getInt(LAST_KEYPAIR_NUMBER, 0);
    }

    public String getPublicKeyBase64(int keyNumber) {
        Log.d(TAG, "getPublicKeyBase64");
        if (keyNumber < 1) {
            Log.e(TAG, "asking for an invalid key (key number is smaller than 1)");
            return null;
        }
        if (keyNumber > lastCryptoBoxKeyPairNumber) {
            Log.e(TAG, "asking for an invalid key (key number larger than lastCryptoBoxKeyPairNumber)");
            return null;
        }
        return sharedPreferences.getString(PUBLIC_KEY_NAME + "_" + String.valueOf(keyNumber), "");
    }

    /**
     *
     * @param plaintext String to encrypt
     * @param privateKeyNumber own = senders private key
     * @param publicKeyBase64 receipients public key in Base64 encoding
     * @return nonce:ciphertext in hex encoding
     */
    public String encryptCryptoBox(String plaintext, int privateKeyNumber, String publicKeyBase64) {
        Log.d(TAG, "encryptCryptoBox");
        if (TextUtils.isEmpty(plaintext)) {
            Log.e(TAG, "plaintext is empty");
            return "";
        }
        if (TextUtils.isEmpty(publicKeyBase64)) {
            Log.e(TAG, "publicKeyBase64 is empty");
            return "";
        }
        if (privateKeyNumber < 1) {
            Log.e(TAG, "asking for an invalid key (key number is smaller than 1)");
            return "";
        }
        if (privateKeyNumber > lastCryptoBoxKeyPairNumber) {
            Log.e(TAG, "asking for an invalid key (key number larger than lastCryptoBoxKeyPairNumber)");
            return null;
        }
        try {
            String privateKeyBase64 = sharedPreferences.getString(PRIVATE_KEY_NAME, "");
            if (privateKeyBase64.equals("")) {
                Log.e(TAG, "no privateKey found for privateKeyNumber " + privateKeyNumber);
                return "";
            }
            return encryptCryptoBoxHexLazysodium(privateKeyBase64, publicKeyBase64, plaintext);
        } catch (Exception e) {
            Log.e(TAG, "Error on encryption");
            return "";
        }
    }

    /**
     *
     * @param ciphertext String to decrypt
     * @param privateKeyNumber own = receivers private key
     * @param publicKeyBase64 senders public key in Base64 encoding
     * @return decryptedtext
     */
    public String decryptCryptoBox(String ciphertext, int privateKeyNumber, String publicKeyBase64) {
        Log.d(TAG, "decryptCryptoBox");
        if (TextUtils.isEmpty(ciphertext)) {
            Log.e(TAG, "ciphertext is empty");
            return "";
        }
        if (TextUtils.isEmpty(publicKeyBase64)) {
            Log.e(TAG, "publicKeyBase64 is empty");
            return "";
        }
        if (privateKeyNumber < 1) {
            Log.e(TAG, "asking for an invalid key (key number is smaller than 1)");
            return "";
        }
        if (privateKeyNumber > lastCryptoBoxKeyPairNumber) {
            Log.e(TAG, "asking for an invalid key (key number larger than lastCryptoBoxKeyPairNumber)");
            return null;
        }
        try {
            String privateKeyBase64 = sharedPreferences.getString(PRIVATE_KEY_NAME, "");
            if (privateKeyBase64.equals("")) {
                Log.e(TAG, "no privateKey found for privateKeyNumber " + privateKeyNumber);
                return "";
            }
            return decryptCryptoBoxHexLazysodium(privateKeyBase64, publicKeyBase64, ciphertext);
        } catch (Exception e) {
            Log.e(TAG, "Error on decryption");
            return "";
        }
    }

    /**
     * section for Lazysodium
     */

    private KeyPair generateCryptoBoxKeypairLazysodium() {
        try {
            Box.Lazy box = (Box.Lazy) ls;
            return box.cryptoBoxKeypair();
        } catch (SodiumException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String getCryptoBoxPrivateKeyBase64Lazysodium(com.goterl.lazysodium.utils.KeyPair keyPair) {
        return base64Encoding(keyPair.getSecretKey().getAsBytes());
    }

    private String getCryptoBoxPublicKeyBase64Lazysodium(com.goterl.lazysodium.utils.KeyPair keyPair) {
        return base64Encoding(keyPair.getPublicKey().getAsBytes());
    }


    /**
     * This is the CryptoBox encryption, it needs the publicKeyA from receipient and privateKeyB from sender (both in Base64 encoding)
     *
     * @param privateKeyB from sender in Base64 encoding
     * @param publicKeyA from receipient in Base64 encoding
     * @param plaintext
     * @return the nonce and ciphertext in hex encoding, separated by ":" (nonce:ciphertext)
     */
    private String encryptCryptoBoxHexLazysodium(String privateKeyB, String publicKeyA, String plaintext) {
        try {
            Box.Lazy box = (Box.Lazy) ls;
            // get the keys
            com.goterl.lazysodium.utils.Key keyA = Key.fromBytes(base64Decoding(publicKeyA));
            com.goterl.lazysodium.utils.Key keyB = Key.fromBytes(base64Decoding(privateKeyB));
            KeyPair encryptionKeyPair = new KeyPair(keyA, keyB);
            byte[] nonce = ls.randomBytesBuf(SecretBox.NONCEBYTES);
            // box.cryptoBoxEasy returns a hex encoded string but not a Base64 encoded one
            return bytesToHex(nonce) + ":" + box.cryptoBoxEasy(plaintext, nonce, encryptionKeyPair);
        } catch (SodiumException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * This is the CryptoBox decryption, it needs the publicKeyB from sender and privateKeyA from receipient (both in Base64 encoding)
     *
     * @param privateKeyA        from ReceipientSender
     * @param publicKeyB
     * @param completeCiphertext as nonce:ciphertext (each in hex encoding)
     * @return the decrypted value
     */
    private String decryptCryptoBoxHexLazysodium(String privateKeyA, String publicKeyB, String completeCiphertext) {
        try {
            String[] parts = completeCiphertext.split(":", 0);
            if (parts.length != 2) return "";
            Box.Lazy box = (Box.Lazy) ls;
            // get the keys
            com.goterl.lazysodium.utils.Key keyA = Key.fromBytes(base64Decoding(privateKeyA));
            com.goterl.lazysodium.utils.Key keyB = Key.fromBytes(base64Decoding(publicKeyB));
            KeyPair decryptionKeyPair = new KeyPair(keyB, keyA);
            return box.cryptoBoxOpenEasy(parts[1], hexToBytes(parts[0]), decryptionKeyPair);
        } catch (SodiumException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * section for utils
     */

    private static String base64Encoding(byte[] input) {
        return Base64.encodeToString(input, Base64.NO_WRAP);
    }

    private static byte[] base64Decoding(String input) {
        return Base64.decode(input, Base64.NO_WRAP);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private static byte[] hexToBytes(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(str.substring(2 * i, 2 * i + 2),
                    16);
        }
        return bytes;
    }

    private static String hexToBase64(String hexString) {
        return base64Encoding(hexToBytes(hexString));
    }

    private static String base64ToHex(String base64String) {
        return bytesToHex(base64Decoding(base64String));
    }
}