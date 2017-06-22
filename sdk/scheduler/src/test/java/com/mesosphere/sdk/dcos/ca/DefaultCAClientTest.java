package com.mesosphere.sdk.dcos.ca;

import com.mesosphere.sdk.dcos.auth.StaticTokenProvider;
import com.mesosphere.sdk.dcos.http.HttpClientBuilder;
import org.apache.http.client.HttpClient;
import org.apache.http.client.fluent.Executor;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

public class DefaultCAClientTest {

    private String TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJhZG1pbiIsImV4cCI6MTQ5ODU1NjQ2Mn0.n7w8gDYUwEjSR6g-uk-Xk0SFuMjSEC4otVAdjn5i1rA4L7WFjy3G9n3e6dojSNXpm6kgLrRyUCWE1BcUfl0f-Zev49NGARbHgOMZjJSFoNly0W1Bo2QoeccuyqcKpqSZl4JNWeTyJRmc_r2lFzUcM67WwQMLNHA9eFdy6PkwPSSz1jpFpE3fu49sFkLdYA8v5PIxqQ3WExznpS5837qK8KQlfypo4xslwOvtF_nOhbduG4bLNu500IWIvT8_Ul3FdXVfR_t5FSnbe0M61rTy4IKik-lGTwMJQKjaMF248RxR-lhH6OrF6kmV0d8he9z9fFuZAPEC2wAJMS-3_FU7Bg";

    private KeyPairGenerator KEY_PAIR_GENERATOR;
    private int RSA_KEY_SIZE = 2048;

    private URL CA_BASE_URL;

    @Before
    public void init() throws NoSuchAlgorithmException, MalformedURLException {
        KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("RSA");
        KEY_PAIR_GENERATOR.initialize(RSA_KEY_SIZE);
        CA_BASE_URL = new URL("https://172.17.0.2/ca/api/v2/");
    }

    public Executor createAuthenticatedExecutor() {

        HttpClient httpClient = new HttpClientBuilder()
                .disableTLSVerification()
                .setTokenProvider(new StaticTokenProvider(TOKEN))
                .build();
        return Executor.newInstance(httpClient);

    }

    // TODO(mh): Run with a CA container?
    @Ignore
    @Test
    public void testSign() throws Exception {
        DefaultCAClient client = new DefaultCAClient(CA_BASE_URL, createAuthenticatedExecutor());

        KeyPair keyPair = KEY_PAIR_GENERATOR.generateKeyPair();

        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.CN, "testing");
        org.bouncycastle.asn1.x500.X500Name name = nameBuilder.build();

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

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PemWriter writer = new PemWriter(new OutputStreamWriter(os));
        writer.writeObject(new JcaMiscPEMGenerator(csr));
        writer.flush();

        X509Certificate certificate = client.sign(os.toByteArray());
        Assert.assertNotNull(certificate);

    }
}