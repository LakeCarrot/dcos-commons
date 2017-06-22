package com.mesosphere.sdk.offer.evaluate;

import com.mesosphere.sdk.dcos.CertificateAuthorityClient;
import com.mesosphere.sdk.dcos.DcosConstants;
import com.mesosphere.sdk.dcos.SecretsClient;
import com.mesosphere.sdk.dcos.auth.CachedTokenProvider;
import com.mesosphere.sdk.dcos.auth.ServiceAccountIAMTokenProvider;
import com.mesosphere.sdk.dcos.auth.TokenProvider;
import com.mesosphere.sdk.dcos.ca.DefaultCAClient;
import com.mesosphere.sdk.dcos.http.HttpClientBuilder;
import com.mesosphere.sdk.dcos.http.URLHelper;
import com.mesosphere.sdk.dcos.secrets.DefaultSecretsClient;
import com.mesosphere.sdk.dcos.secrets.Secret;
import com.mesosphere.sdk.dcos.secrets.SecretsException;
import com.mesosphere.sdk.offer.MesosResourcePool;
import com.mesosphere.sdk.scheduler.SchedulerFlags;
import org.apache.http.client.fluent.Executor;
import org.apache.mesos.Protos;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
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

    public static TLSEvaluationStage fromEnvironmentForService(String serviceName) throws IOException, InvalidKeySpecException {

        SchedulerFlags flags = SchedulerFlags.fromEnv();

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        PemReader pemReader = new PemReader(new StringReader(flags.getServiceAccountPrivateKeyPEM()));
        PrivateKey privateKey = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent()));

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

    private String privateKeyToPem(PrivateKey privateKey) throws IOException {

        StringWriter stringWriter = new StringWriter();

        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(new JcaMiscPEMGenerator(privateKey));
        pemWriter.flush();

        return stringWriter.toString();

    }

    private String certificateToPem(X509Certificate certificate) throws CertificateEncodingException, IOException {

        StringWriter stringWriter = new StringWriter();

        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(new JcaMiscPEMGenerator(certificate));
        pemWriter.flush();

        return stringWriter.toString();

    }

    private byte[] generateCSR(KeyPair keyPair) throws IOException, OperatorCreationException {

        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.CN, "testing");
        X500Name name = nameBuilder.build();

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        extensionsGenerator.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));


        extensionsGenerator.addExtension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(
                        new KeyPurposeId[] {
                                KeyPurposeId.id_kp_clientAuth,
                                KeyPurposeId.id_kp_serverAuth }
                ));

        GeneralNames subAtlNames = new GeneralNames(
                new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, "test.com"),
                        new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                }
        );
        extensionsGenerator.addExtension(
                Extension.subjectAlternativeName, true, subAtlNames);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(name, keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        return csr.getEncoded();

    }
}
