package com.fikua.dss.keys;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MasterKeysTest {

    static String key(int fill) {
        var bytes = new byte[32];
        java.util.Arrays.fill(bytes, (byte) fill);
        return Base64.getEncoder().encodeToString(bytes);
    }

    @Test
    void decryptsWhatItEncryptsOnlyInItsContext() {
        var keys = new MasterKeys(key(1), null);
        var encrypted = keys.encrypt("data".getBytes(), "a");
        assertArrayEquals("data".getBytes(), keys.decrypt(keys.currentId(), encrypted, "a"));
        var id = keys.currentId();
        assertThrows(IllegalStateException.class, () -> keys.decrypt(id, encrypted, "b"));
    }

    @Test
    void aPreviousKeyDecryptsAndAnUnknownOneDoesNot() {
        var old = new MasterKeys(key(1), null);
        var encrypted = old.encrypt("data".getBytes(), "a");
        var current = new MasterKeys(key(2), key(1));
        assertNotEquals(old.currentId(), current.currentId());
        assertArrayEquals("data".getBytes(), current.decrypt(old.currentId(), encrypted, "a"));
        var other = new MasterKeys(key(3), "");
        var oldId = old.currentId();
        assertThrows(IllegalStateException.class, () -> other.decrypt(oldId, encrypted, "a"));
    }

    @Test
    void refusesAMasterKeyOfAnotherSizeWithoutWritingIt() {
        var tooShort = Base64.getEncoder().encodeToString(new byte[16]);
        assertThrows(IllegalStateException.class, () -> new MasterKeys(tooShort, null));
        assertThrows(IllegalStateException.class, () -> new MasterKeys(null, null));
        var error = assertThrows(IllegalStateException.class, () -> new MasterKeys("no-es-base64!!", null));
        assertFalse(error.toString().contains("no-es"));
        assertEquals(null, error.getCause());
    }
}
