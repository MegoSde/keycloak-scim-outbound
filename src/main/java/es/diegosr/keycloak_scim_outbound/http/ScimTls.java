package es.diegosr.keycloak_scim_outbound.http;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Target-scoped trust. Never changes the JVM default SSL context. */
public final class ScimTls {
    public static final int MAX_PEM_LENGTH = 131072;
    public static final int MAX_CERTIFICATES = 16;
    private static final Pattern CERTIFICATE = Pattern.compile(
            "-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\\s]+)-----END CERTIFICATE-----");

    private ScimTls() { }

    public static String normalize(String pem) {
        StringBuilder result = new StringBuilder();
        for (X509Certificate certificate : parse(pem)) {
            try {
                result.append("-----BEGIN CERTIFICATE-----\n")
                        .append(Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(certificate.getEncoded()))
                        .append("\n-----END CERTIFICATE-----\n");
            } catch (Exception e) {
                throw new IllegalArgumentException("Unable to encode trusted certificate", e);
            }
        }
        return result.toString();
    }

    static List<X509Certificate> parse(String pem) {
        if (pem == null || pem.isBlank()) return List.of();
        if (pem.length() > MAX_PEM_LENGTH) {
            throw new IllegalArgumentException("Trusted certificates must not exceed 128 KiB");
        }
        List<X509Certificate> certificates = new ArrayList<>();
        var matcher = CERTIFICATE.matcher(pem);
        int end = 0;
        try {
            var factory = CertificateFactory.getInstance("X.509");
            while (matcher.find()) {
                if (!pem.substring(end, matcher.start()).isBlank()) {
                    throw new IllegalArgumentException("Only PEM CERTIFICATE blocks are allowed; do not upload private keys");
                }
                if (certificates.size() >= MAX_CERTIFICATES) {
                    throw new IllegalArgumentException("Upload at most 16 trusted certificates");
                }
                byte[] der = Base64.getDecoder().decode(matcher.group(1).replaceAll("\\s", ""));
                var input = new ByteArrayInputStream(der);
                var certificate = (X509Certificate) factory.generateCertificate(input);
                if (input.available() != 0) throw new IllegalArgumentException("Unexpected data in certificate");
                certificate.checkValidity();
                certificates.add(certificate);
                end = matcher.end();
            }
            if (certificates.isEmpty() || !pem.substring(end).isBlank()) {
                throw new IllegalArgumentException("Upload valid PEM certificates only; private keys and other formats are not supported");
            }
            return certificates;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Trusted certificate is invalid, expired, or not yet valid", e);
        }
    }

    public static SSLContext context(String pem) {
        var certificates = parse(pem);
        if (certificates.isEmpty()) return null;
        try {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            for (int i = 0; i < certificates.size(); i++) {
                trustStore.setCertificateEntry("scim-ca-" + i, certificates.get(i));
            }
            TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            managers.init(trustStore);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, managers.getTrustManagers(), null);
            return context;
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to initialize SCIM certificate trust", e);
        }
    }
}
