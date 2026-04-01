package es.in2.mockqtsp.service;

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
            var sig = Signature.getInstance(sigAlgo, "BC");
            sig.initSign(certificateService.getPrivateKey());
            sig.update(precomputedHash);
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
