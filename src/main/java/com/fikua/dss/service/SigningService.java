package com.fikua.dss.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class SigningService {

    private static final Logger log = LoggerFactory.getLogger(SigningService.class);

    // DigestInfo prefix for SHA-256 (DER-encoded ASN.1: SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING })
    private static final byte[] SHA256_DIGEST_INFO_PREFIX = {
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20
    };

    private final CertificateService certificateService;

    public SigningService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    public List<String> signHashes(List<String> hashesBase64) {
        var signatures = new ArrayList<String>();
        for (var hashB64 : hashesBase64) {
            var hashBytes = Base64.getUrlDecoder().decode(hashB64);
            var signatureBytes = rawSign(hashBytes);
            signatures.add(Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes));
        }
        log.info("Signed {} hash(es)", hashesBase64.size());
        return signatures;
    }

    public List<String> signDocuments(List<byte[]> documents) {
        var signatures = new ArrayList<String>();
        for (var doc : documents) {
            var signatureBytes = signWithDigest(doc);
            signatures.add(Base64.getEncoder().encodeToString(signatureBytes));
        }
        log.info("Signed {} document(s)", documents.size());
        return signatures;
    }

    private byte[] rawSign(byte[] precomputedHash) {
        try {
            var algo = certificateService.getPrivateKey().getAlgorithm();
            var sigAlgo = switch (algo) {
                case "EC" -> "NONEwithECDSA";
                case "RSA" -> "NONEwithRSA";
                default -> throw new IllegalStateException("Unsupported: " + algo);
            };

            byte[] dataToSign;
            if ("RSA".equals(algo)) {
                // RSASSA-PKCS1-v1_5 requires DigestInfo wrapping around the hash.
                // NONEwithRSA does raw RSA, so we prepend the SHA-256 DigestInfo prefix.
                dataToSign = new byte[SHA256_DIGEST_INFO_PREFIX.length + precomputedHash.length];
                System.arraycopy(SHA256_DIGEST_INFO_PREFIX, 0, dataToSign, 0, SHA256_DIGEST_INFO_PREFIX.length);
                System.arraycopy(precomputedHash, 0, dataToSign, SHA256_DIGEST_INFO_PREFIX.length, precomputedHash.length);
            } else {
                dataToSign = precomputedHash;
            }

            var sig = Signature.getInstance(sigAlgo, "BC");
            sig.initSign(certificateService.getPrivateKey());
            sig.update(dataToSign);
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign hash", e);
        }
    }

    private byte[] signWithDigest(byte[] data) {
        try {
            var sigAlgo = certificateService.getSignatureAlgorithm();
            var sig = Signature.getInstance(sigAlgo, "BC");
            sig.initSign(certificateService.getPrivateKey());
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign document", e);
        }
    }
}
