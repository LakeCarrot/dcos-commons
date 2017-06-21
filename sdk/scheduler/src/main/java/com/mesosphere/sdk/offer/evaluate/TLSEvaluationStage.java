package com.mesosphere.sdk.offer.evaluate;

import com.mesosphere.sdk.dcos.CertificateAuthorityClient;
import com.mesosphere.sdk.dcos.DcosConstants;
import com.mesosphere.sdk.dcos.SecretsClient;
import com.mesosphere.sdk.dcos.auth.CachedTokenProvider;
import com.mesosphere.sdk.dcos.auth.ServiceAccountIAMTokenProvider;
import com.mesosphere.sdk.dcos.auth.TokenProvider;
import com.mesosphere.sdk.dcos.ca.CSRBuilder;
import com.mesosphere.sdk.dcos.ca.DefaultCAClient;
import com.mesosphere.sdk.dcos.http.HttpClientBuilder;
import com.mesosphere.sdk.dcos.http.URLHelper;
import com.mesosphere.sdk.dcos.secrets.DefaultSecretsClient;
import com.mesosphere.sdk.dcos.secrets.Secret;
import com.mesosphere.sdk.dcos.secrets.SecretsException;
import com.mesosphere.sdk.offer.MesosResourcePool;
import com.mesosphere.sdk.scheduler.SchedulerFlags;
import com.mesosphere.sdk.specification.SecretSpec;
import org.apache.http.client.fluent.Executor;
import org.apache.mesos.Protos;
import sun.security.pkcs10.PKCS10;
import sun.security.provider.X509Factory;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.DNSName;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X500Name;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class TLSEvaluationStage implements OfferEvaluationStage {

    private String serviceName;
    private CertificateAuthorityClient certificateAuthorityClient;
    private SecretsClient secretsClient;
    private KeyPairGenerator keyPairGenerator;

    public TLSEvaluationStage(
            String serviceName, CertificateAuthorityClient certificateAuthorityClient, SecretsClient secretsClient, KeyPairGenerator keyPairGenerator) {
        this.serviceName = serviceName;
        this.certificateAuthorityClient = certificateAuthorityClient;
        this.secretsClient = secretsClient;
        this.keyPairGenerator = keyPairGenerator;
    }

    public static TLSEvaluationStage fromEnvironmentForService(String serviceName) throws InvalidKeySpecException {

        SchedulerFlags flags = SchedulerFlags.fromEnv();

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        String privateKeyStr = flags.getServiceAccountPrivateKeyPEM()
                .replaceAll("-----BEGIN (.* )?PRIVATE KEY-----\n", "")
                .replaceAll("-----END (.* )?PRIVATE KEY-----\n?", "")
                .replaceAll("\n", "");
        byte[] privateKeyBytes  = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(spec);

        ServiceAccountIAMTokenProvider serviceAccountIAMTokenProvider = new ServiceAccountIAMTokenProvider.Builder()
                .setIamUrl(URLHelper.fromUnchecked(DcosConstants.IAM_AUTH_URL))
                .setUid(flags.getServiceAccountUid())
                .setPrivateKey((RSAPrivateKey) privateKey)
                .build();
        TokenProvider tokenProvider = new CachedTokenProvider(serviceAccountIAMTokenProvider);

        Executor executor = Executor.newInstance(
                new HttpClientBuilder()
                        .setTokenProvider(tokenProvider)
                        .build());

        CertificateAuthorityClient certificateAuthorityClient = new DefaultCAClient(executor);
        SecretsClient secretsClient = new DefaultSecretsClient(executor);

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return new TLSEvaluationStage(serviceName, certificateAuthorityClient, secretsClient, keyPairGenerator);

    }

    @Override
    public EvaluationOutcome evaluate(MesosResourcePool mesosResourcePool, PodInfoBuilder podInfoBuilder) {

        if (!podInfoBuilder.getPodInstance().getPod().getTransportEncryption().isPresent()) {
            return EvaluationOutcome.pass(this, "Not requested TLS certificate.");
        }

        // Generate new private key and encode it to PEM
        // Generate new CSR, sign it, encode certificate to PEM
        try {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509Certificate certificate = certificateAuthorityClient.sign(generateCSR(keyPair));

            String certPEM = certificateToPem(certificate);
            String privateKeyPEM = privateKeyToPem(keyPair.getPrivate());

            storeSecrets(podInfoBuilder, certPEM, privateKeyPEM);

        }
        catch (Exception e) {
            return EvaluationOutcome.fail(this, "Failed because of exception: %s", e);
        }

        Collection<Protos.Volume> volumes = getExecutorInfoSecretVolumes(podInfoBuilder);

        // Share keys to the container
        podInfoBuilder.getTaskBuilders().stream()
                .forEach(builder -> builder
                        .getExecutorBuilder()
                        .getContainerBuilder()
                        .addAllVolumes(volumes));

        return EvaluationOutcome.pass(this, "TLS certificate created and exposed");

    }

    private Collection<Protos.Volume> getExecutorInfoSecretVolumes(PodInfoBuilder podInfoBuilder) {
        String filenameInContainer = podInfoBuilder
                .getPodInstance()
                .getPod()
                .getTransportEncryption()
                .get()
                .getName();

        HashMap<String, String> tlsSecrets = new HashMap<>();
        tlsSecrets.put(
                getSecretPath(podInfoBuilder, "certificate.crt"),
                String.format("/%s.cert", filenameInContainer));

        tlsSecrets.put(
                getSecretPath(podInfoBuilder, "private.key"),
                String.format("/%s.key", filenameInContainer));

        Collection<Protos.Volume> volumes = new ArrayList<>();

        for (Map.Entry<String, String> entry : tlsSecrets.entrySet()) {

            volumes.add(Protos.Volume.newBuilder()
                    .setSource(Protos.Volume.Source.newBuilder()
                            .setType(Protos.Volume.Source.Type.SECRET)
                            .setSecret(getReferenceSecret(entry.getKey()))
                            .build())
                    .setContainerPath(entry.getValue())
                    .setMode(Protos.Volume.Mode.RO)
                    .build());

        }

        return volumes;
    }

    private static Protos.Secret getReferenceSecret(String secretPath) {
        return Protos.Secret.newBuilder()
                .setType(Protos.Secret.Type.REFERENCE)
                .setReference(Protos.Secret.Reference.newBuilder().setName(secretPath))
                .build();
    }

    private void storeSecrets(
            PodInfoBuilder podInfoBuilder, String certPEM, String privateKeyPEM) throws IOException, SecretsException {
        secretsClient.create(
                getSecretPath(podInfoBuilder, "certificate.crt"),
                buildSecret(certPEM, "PEM encoded certificate"));

        secretsClient.create(
                getSecretPath(podInfoBuilder, "private.key"),
                buildSecret(privateKeyPEM, "PEM encoded private key"));
    }

    private Secret buildSecret(String value, String description) {
        return new Secret.Builder()
                .value(value)
                .author(serviceName)
                .description(description)
                .build();
    }

    private String getSecretPath(PodInfoBuilder podInfoBuilder, String name) {
        return String.format("%s/%s/%s", serviceName, podInfoBuilder.getPodInstance().getName(), name);
    }

    private String privateKeyToPem(PrivateKey privateKey) {

        StringBuilder sb = new StringBuilder();

        sb.append("-----BEGIN PRIVATE KEY-----\n");
        Base64.getEncoder().encodeToString(privateKey.getEncoded());
        sb.append("-----END PRIVATE KEY-----\n");

        return sb.toString();

    }

    private String certificateToPem(X509Certificate certificate) throws CertificateEncodingException {

        StringBuilder sb = new StringBuilder();

        sb.append(X509Factory.BEGIN_CERT + "\n");
        sb.append(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        sb.append(X509Factory.END_CERT + "\n");

        return sb.toString();

    }

    private byte[] generateCSR(KeyPair keyPair) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        KeyUsageExtension keyUsage = new KeyUsageExtension();
        keyUsage.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);

        int[] serverAuthOidData = new int[]{1, 3, 6, 1, 5, 5, 7, 3, 1};
        int[] clientAuthOidData = new int[]{1, 3, 6, 1, 5, 5, 7, 3, 2};
        Vector<ObjectIdentifier> extendedKeyUsages = new Vector<>(Arrays.asList(
                new ObjectIdentifier(clientAuthOidData),
                new ObjectIdentifier(serverAuthOidData)
        ));
        ExtendedKeyUsageExtension extendedKeyUsage = new ExtendedKeyUsageExtension(
                extendedKeyUsages);

        PKCS10 csr = new CSRBuilder(keyPair.getPublic())
                .addSubject(new X500Name("CN=martin"))
                .addSubjectAlternativeName(new DNSName("test.com"))
                .addExtension(KeyUsageExtension.NAME, keyUsage)
                .addExtension(ExtendedKeyUsageExtension.NAME, extendedKeyUsage)
                .buildAndSign(keyPair.getPrivate());

        // Encode it to PEM format
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(os);
        csr.print(ps);

        return os.toByteArray();

    }
}
