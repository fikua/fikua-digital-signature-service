package com.fikua.dss.service;

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Es256Test {

    @Test
    void recognisesOnlyP256() throws Exception {
        assertTrue(Es256.isP256(params("secp256r1")));
        assertFalse(Es256.isP256(params("secp384r1")));
        assertFalse(Es256.isP256(params("secp521r1")));
    }

    private static java.security.spec.ECParameterSpec params(String curve) throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return ((ECPublicKey) generator.generateKeyPair().getPublic()).getParams();
    }
}
