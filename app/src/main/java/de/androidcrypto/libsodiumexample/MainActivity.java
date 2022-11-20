package de.androidcrypto.libsodiumexample;

import android.os.Bundle;
import android.util.Base64;
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

public class MainActivity extends AppCompatActivity {

    protected LazySodiumAndroid ls;
    private static byte[] nonceS;

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
                String ciphertextBase64Lazysodium = encryptCryptoBoxBase64Lazysodium(privateKeyBBase64Lazysodium, publicKeyABase64Lazysodium, plaintextLazysodium);
                String decryptedtextLazasodium = decryptCryptoBoxBase64Lazysodium(privateKeyABase64Lazysodium, publicKeyBBase64Lazysodium, ciphertextBase64Lazysodium);
                
                privateKeyA.setText(privateKeyABase64Lazysodium);
                publicKeyA.setText(publicKeyABase64Lazysodium);
                privateKeyB.setText(privateKeyBBase64Lazysodium);
                publicKeyB.setText(publicKeyBBase64Lazysodium);
                ciphertext.setText(ciphertextBase64Lazysodium);
                decryptedtext.setText(decryptedtextLazasodium);
            }
        });
        
    }

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
     * @param privateKeyB from Sender
     * @param publicKeyA
     * @param plaintext
     * @return the ciphertext in Base64 encoding
     */
    private String encryptCryptoBoxBase64Lazysodium(String privateKeyB, String publicKeyA, String plaintext) {
        try {
            Box.Lazy box = (Box.Lazy) ls;
            // get the keys
            com.goterl.lazysodium.utils.Key keyA = Key.fromBytes(base64Decoding(publicKeyA));
            com.goterl.lazysodium.utils.Key keyB = Key.fromBytes(base64Decoding(privateKeyB));
            KeyPair encryptionKeyPair = new KeyPair(keyA, keyB);
            //byte[] nonce = ls.randomBytesBuf(SecretBox.NONCEBYTES);
            nonceS = ls.randomBytesBuf(SecretBox.NONCEBYTES);
            // box.cryptoBoxEasy return a hex encoded string but not a Base64 encoded one
            return base64Encoding(hexToBytes(box.cryptoBoxEasy(plaintext, nonceS, encryptionKeyPair)));
        } catch (SodiumException e) {
            e.printStackTrace();
            return "";
        }
    }

    private String decryptCryptoBoxBase64Lazysodium(String privateKeyA, String publicKeyB, String ciphertext) {

        try {
            Box.Lazy box = (Box.Lazy) ls;
            // get the keys
            com.goterl.lazysodium.utils.Key keyA = Key.fromBytes(base64Decoding(privateKeyA));
            com.goterl.lazysodium.utils.Key keyB = Key.fromBytes(base64Decoding(publicKeyB));
            KeyPair decryptionKeyPair = new KeyPair(keyB, keyA);
            return box.cryptoBoxOpenEasy(bytesToHex(base64Decoding(ciphertext)), nonceS, decryptionKeyPair);
        } catch (SodiumException e) {
            e.printStackTrace();
            return "";
        }
    }

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

    public static byte[] hexToBytes(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(str.substring(2 * i, 2 * i + 2),
                    16);
        }
        return bytes;
    }


}