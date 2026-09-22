package com.authio.unity;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import com.unity3d.player.UnityPlayer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class AuthioKeystore {
    private static final String ALIAS = "com.authio.unity.v1";
    private static final String PREFS = "com.authio.unity";

    private AuthioKeystore() {}

    public static String get(String key) throws Exception {
        String blob = prefs().getString(key, "");
        if (blob == null || blob.length() == 0) return "";
        byte[] packed = Base64.decode(blob, Base64.NO_WRAP);
        ByteBuffer buf = ByteBuffer.wrap(packed);
        int ivLen = buf.getInt();
        if (ivLen < 0 || ivLen > buf.remaining()) return "";
        byte[] iv = new byte[ivLen];
        buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()];
        buf.get(cipherText);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secret(), new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }

    public static void set(String key, String value) throws Exception {
        if (value == null) {
            delete(key);
            return;
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secret());
        byte[] iv = cipher.getIV();
        byte[] cipherText = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        ByteBuffer buf = ByteBuffer.allocate(4 + iv.length + cipherText.length);
        buf.putInt(iv.length);
        buf.put(iv);
        buf.put(cipherText);
        prefs().edit().putString(key, Base64.encodeToString(buf.array(), Base64.NO_WRAP)).apply();
    }

    public static void delete(String key) {
        prefs().edit().remove(key).apply();
    }

    private static SharedPreferences prefs() {
        return UnityPlayer.currentActivity.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static SecretKey secret() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias(ALIAS)) {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build());
            generator.generateKey();
        }
        return ((KeyStore.SecretKeyEntry) store.getEntry(ALIAS, null)).getSecretKey();
    }
}
