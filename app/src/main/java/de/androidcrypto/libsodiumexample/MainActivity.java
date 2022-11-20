package de.androidcrypto.libsodiumexample;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import androidx.appcompat.app.AppCompatActivity;

import com.goterl.lazysodium.LazySodiumAndroid;
import com.goterl.lazysodium.SodiumAndroid;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.SecretBox;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;
import com.iwebpp.crypto.TweetNacl;
import com.iwebpp.crypto.TweetNaclFast;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "LibsodiumExample";
    protected LazySodiumAndroid ls;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        EditText privateKeyA, publicKeyA, privateKeyB, publicKeyB;
        EditText plaintext, ciphertext, decryptedtext;

        privateKeyA = findViewById(R.id.etCryptoBoxPrivateKeyA);
        publicKeyA = findViewById(R.id.etCryptoBoxPublicKeyA);
        privateKeyB = findViewById(R.id.etCryptoBoxPrivateKeyB);
        publicKeyB = findViewById(R.id.etCryptoBoxPublicKeyB);
        plaintext = findViewById(R.id.etCryptoBoxPlaintext);
        ciphertext = findViewById(R.id.etCryptoBoxCiphertext);
        decryptedtext = findViewById(R.id.etCryptoBoxDecryptedtext);

        // init Lazysodium
        ls = new LazySodiumAndroid(new SodiumAndroid());

        Button runCryptoBoxLazysodium = findViewById(R.id.btnCryptoBoxRunLazysodium);
        runCryptoBoxLazysodium.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String plaintextLazysodium = plaintext.getText().toString();
                com.goterl.lazysodium.utils.KeyPair keyPairALazysodium = generateCryptoBoxKeypairLazysodium();
                com.goterl.lazysodium.utils.KeyPair keyPairBLazysodium = generateCryptoBoxKeypairLazysodium();
                String privateKeyABase64Lazysodium = getCryptoBoxPrivateKeyBase64Lazysodium(keyPairALazysodium);
                String publicKeyABase64Lazysodium = getCryptoBoxPublicKeyBase64Lazysodium(keyPairALazysodium);
                String privateKeyBBase64Lazysodium = getCryptoBoxPrivateKeyBase64Lazysodium(keyPairBLazysodium);
                String publicKeyBBase64Lazysodium = getCryptoBoxPublicKeyBase64Lazysodium(keyPairBLazysodium);
                String completeCiphertextBase64Lazysodium = encryptCryptoBoxHexLazysodium(privateKeyBBase64Lazysodium, publicKeyABase64Lazysodium, plaintextLazysodium);
                String decryptedtextLazasodium = decryptCryptoBoxHexLazysodium(privateKeyABase64Lazysodium, publicKeyBBase64Lazysodium, completeCiphertextBase64Lazysodium);

                privateKeyA.setText(privateKeyABase64Lazysodium);
                publicKeyA.setText(publicKeyABase64Lazysodium);
                privateKeyB.setText(privateKeyBBase64Lazysodium);
                publicKeyB.setText(publicKeyBBase64Lazysodium);
                ciphertext.setText(completeCiphertextBase64Lazysodium);
                decryptedtext.setText(decryptedtextLazasodium);
            }
        });

        Button runCryptoBoxTweetNacl = findViewById(R.id.btnCryptoBoxRunTweetNacl);
        runCryptoBoxTweetNacl.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String plaintextTweetNacl = plaintext.getText().toString();
                TweetNaclFast.Box.KeyPair keyPairATweetNacl = generateCryptoBoxKeypairTweetNacl();
                TweetNaclFast.Box.KeyPair keyPairBTweetNacl = generateCryptoBoxKeypairTweetNacl();
                String privateKeyABase64TweetNacl = getCryptoBoxPrivateKeyBase64TweetNacl(keyPairATweetNacl);
                String publicKeyABase64TweetNacl = getCryptoBoxPublicKeyBase64TweetNacl(keyPairATweetNacl);
                String privateKeyBBase64TweetNacl = getCryptoBoxPrivateKeyBase64TweetNacl(keyPairBTweetNacl);
                String publicKeyBBase64TweetNacl = getCryptoBoxPublicKeyBase64TweetNacl(keyPairBTweetNacl);
                String completeCiphertextBase64TweetNacl = encryptCryptoBoxBase64TweetNacl(privateKeyBBase64TweetNacl, publicKeyABase64TweetNacl, plaintextTweetNacl);
                String decryptedtextTweetNacl = decryptCryptoBoxBase64TweetNacl(privateKeyABase64TweetNacl, publicKeyBBase64TweetNacl, completeCiphertextBase64TweetNacl);

                privateKeyA.setText(privateKeyABase64TweetNacl);
                publicKeyA.setText(publicKeyABase64TweetNacl);
                privateKeyB.setText(privateKeyBBase64TweetNacl);
                publicKeyB.setText(publicKeyBBase64TweetNacl);
                ciphertext.setText(completeCiphertextBase64TweetNacl);
                decryptedtext.setText(decryptedtextTweetNacl);
            }
        });

        Button runCryptoBoxLazysodiumSpeed = findViewById(R.id.btnCryptoBoxRunSpeedLazysodium);
        runCryptoBoxLazysodiumSpeed.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String plaintext = "The lazy dog jumps over the quick brown fox";
                int nrRounds = 1000;
                long timeKeygenerationTotal = 0;
                long timeEncryptionTotal = 0;
                long timeDecryptionTotal = 0;
                for (int i = 0; i < nrRounds; i++) {
                    // key generation
                    long startTimeKeygeneration = System.currentTimeMillis();
                    com.goterl.lazysodium.utils.KeyPair keyPairALazysodium = generateCryptoBoxKeypairLazysodium();
                    com.goterl.lazysodium.utils.KeyPair keyPairBLazysodium = generateCryptoBoxKeypairLazysodium();
                    String privateKeyABase64Lazysodium = getCryptoBoxPrivateKeyBase64Lazysodium(keyPairALazysodium);
                    String publicKeyABase64Lazysodium = getCryptoBoxPublicKeyBase64Lazysodium(keyPairALazysodium);
                    String privateKeyBBase64Lazysodium = getCryptoBoxPrivateKeyBase64Lazysodium(keyPairBLazysodium);
                    String publicKeyBBase64Lazysodium = getCryptoBoxPublicKeyBase64Lazysodium(keyPairBLazysodium);
                    long stopTimeKeygeneration = System.currentTimeMillis();
                    long elapsedTimeKeygeneration = stopTimeKeygeneration - startTimeKeygeneration;
                    timeKeygenerationTotal += elapsedTimeKeygeneration;

                    // encryption
                    String completeCiphertextHexLazysodium = "";
                    long startTimeEncryption = System.currentTimeMillis();
                    completeCiphertextHexLazysodium = encryptCryptoBoxHexLazysodium(privateKeyBBase64Lazysodium, publicKeyABase64Lazysodium, plaintext);
                    long stopTimeEncryption = System.currentTimeMillis();
                    long elapsedTimeEncryption = stopTimeEncryption - startTimeEncryption;
                    timeEncryptionTotal += elapsedTimeEncryption;

                    // decryption
                    String decryptedtextLazysodium = "";
                    long startTimeDecryption = System.currentTimeMillis();
                    decryptedtextLazysodium = decryptCryptoBoxHexLazysodium(privateKeyABase64Lazysodium, publicKeyBBase64Lazysodium, completeCiphertextHexLazysodium);
                    long stopTimeDecryption = System.currentTimeMillis();
                    long elapsedTimeDecryption = stopTimeDecryption - startTimeDecryption;
                    timeDecryptionTotal += elapsedTimeDecryption;
                    Log.i(TAG, "Decryptedtext: " + decryptedtextLazysodium);
                }
                // sum
                EditText speedResult = findViewById(R.id.etCryptoBoxLazysodiumSpeed);
                String resultString = "Time in milliseconds for nrRounds: " + nrRounds;
                resultString += "\nkey generation: " + timeKeygenerationTotal;
                resultString += "\nencryption: " + timeEncryptionTotal;
                resultString += "\ndecryption: " + timeDecryptionTotal;
                speedResult.setText(resultString);
            }
        });

        Button runCryptoBoxTweetNaclSpeed = findViewById(R.id.btnCryptoBoxRunSpeedTweetNacl);
        runCryptoBoxTweetNaclSpeed.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String plaintext = "The lazy dog jumps over the quick brown fox";
                int nrRounds = 100;
                long timeKeygenerationTotal = 0;
                long timeEncryptionTotal = 0;
                long timeDecryptionTotal = 0;
                for (int i = 0; i < nrRounds; i++) {
                    // key generation
                    long startTimeKeygeneration = System.currentTimeMillis();
                    TweetNaclFast.Box.KeyPair keyPairATweetNacl = generateCryptoBoxKeypairTweetNacl();
                    TweetNaclFast.Box.KeyPair keyPairBTweetNacl = generateCryptoBoxKeypairTweetNacl();
                    String privateKeyABase64TweetNacl = getCryptoBoxPrivateKeyBase64TweetNacl(keyPairATweetNacl);
                    String publicKeyABase64TweetNacl = getCryptoBoxPublicKeyBase64TweetNacl(keyPairATweetNacl);
                    String privateKeyBBase64TweetNacl = getCryptoBoxPrivateKeyBase64TweetNacl(keyPairBTweetNacl);
                    String publicKeyBBase64TweetNacl = getCryptoBoxPublicKeyBase64TweetNacl(keyPairBTweetNacl);
                    long stopTimeKeygeneration = System.currentTimeMillis();
                    long elapsedTimeKeygeneration = stopTimeKeygeneration - startTimeKeygeneration;
                    timeKeygenerationTotal += elapsedTimeKeygeneration;

                    // encryption
                    String completeCiphertextBase64TweetNacl = "";
                    long startTimeEncryption = System.currentTimeMillis();
                    completeCiphertextBase64TweetNacl = encryptCryptoBoxBase64TweetNacl(privateKeyBBase64TweetNacl, publicKeyABase64TweetNacl, plaintext);
                    long stopTimeEncryption = System.currentTimeMillis();
                    long elapsedTimeEncryption = stopTimeEncryption - startTimeEncryption;
                    timeEncryptionTotal += elapsedTimeEncryption;

                    // decryption
                    String decryptedtextTweetNacl = "";
                    long startTimeDecryption = System.currentTimeMillis();
                    decryptedtextTweetNacl = decryptCryptoBoxBase64TweetNacl(privateKeyABase64TweetNacl, publicKeyBBase64TweetNacl, completeCiphertextBase64TweetNacl);
                    long stopTimeDecryption = System.currentTimeMillis();
                    long elapsedTimeDecryption = stopTimeDecryption - startTimeDecryption;
                    timeDecryptionTotal += elapsedTimeDecryption;
                    Log.i(TAG, "Decryptedtext: " + decryptedtextTweetNacl);
                }
                // sum
                EditText speedResult = findViewById(R.id.etCryptoBoxTweetNaclSpeed);
                String resultString = "Time in milliseconds for nrRounds: " + nrRounds;
                resultString += "\nkey generation: " + timeKeygenerationTotal;
                resultString += "\nencryption: " + timeEncryptionTotal;
                resultString += "\ndecryption: " + timeDecryptionTotal;
                speedResult.setText(resultString);
            }
        });
    }

    /**
     * section for TweetNacl
     */

    private TweetNaclFast.Box.KeyPair generateCryptoBoxKeypairTweetNacl() {
        return TweetNaclFast.Box.keyPair();
    }

    private String getCryptoBoxPrivateKeyBase64TweetNacl(TweetNaclFast.Box.KeyPair keyPair) {
        return base64Encoding(keyPair.getSecretKey());
    }

    private String getCryptoBoxPublicKeyBase64TweetNacl(TweetNaclFast.Box.KeyPair keyPair) {
        return base64Encoding(keyPair.getPublicKey());
    }

    /**
     * This is the CryptoBox encryption, it needs the publicKeyA from receipient and privateKeyB from sender (both in Base64 encoding)
     *
     * @param privateKeyB from Sender
     * @param publicKeyA
     * @param plaintext
     * @return the nonce and ciphertext in Base64 encoding, separated by ":" (nonce:ciphertext)
     */
    private String encryptCryptoBoxBase64TweetNacl(String privateKeyB, String publicKeyA, String plaintext) {
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] nonce = generateRandomNonce();
        TweetNaclFast.Box box = new TweetNaclFast.Box(base64Decoding(publicKeyA), base64Decoding(privateKeyB));
        return base64Encoding(nonce) + ":" + base64Encoding(box.box(data, nonce));
    }

    private static byte[] generateRandomNonce() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[24];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    /**
     * This is the CryptoBox decryption, it needs the publicKeyB from sender and privateKeyA from receipient (both in Base64 encoding)
     *
     * @param privateKeyA        from ReceipientSender
     * @param publicKeyB
     * @param completeCiphertext as nonce:ciphertext (each in Base64 encoding)
     * @return the decrypted value
     */
    private static String decryptCryptoBoxBase64TweetNacl(String privateKeyA, String publicKeyB, String completeCiphertext) {
        String[] parts = completeCiphertext.split(":", 0);
        if (parts.length != 2) return "";
        byte[] nonce = base64Decoding(parts[0]);
        byte[] ciphertext = base64Decoding(parts[1]);
        TweetNaclFast.Box box = new TweetNaclFast.Box(base64Decoding(publicKeyB), base64Decoding(privateKeyA));
        return new String(box.open(ciphertext, nonce), StandardCharsets.UTF_8);
    }

    /**
     * section for Lazysodium
     */

    private com.goterl.lazysodium.utils.KeyPair generateCryptoBoxKeypairLazysodium() {
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
     * @param privateKeyB from Sender
     * @param publicKeyA
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