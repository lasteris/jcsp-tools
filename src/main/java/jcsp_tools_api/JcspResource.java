package jcsp_tools_api;

import com.objsys.asn1j.runtime.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.jboss.resteasy.reactive.RestQuery;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Attribute;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Attribute_values;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.params.OID;

import java.io.IOException;
import java.security.*;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static ru.CryptoPro.JCSP.JCSP.PROVIDER_NAME;


@Path("/")
public class JcspResource {

    @Path("/aliases")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public List<String> listCertAliasesOfContainer(@RestQuery String keyStoreType, @RestQuery String keyStorePass)
            throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException {
        //REGISTRY, как понять какие еще ?
        KeyStore ks = KeyStore.getInstance(keyStoreType, PROVIDER_NAME);
        ks.load(null, keyStorePass.toCharArray());
        return Collections.list(ks.aliases());
    }

    @Path("/cms")
    @POST
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public byte[] cms(
            byte[] data, @RestQuery String keyStoreType, @RestQuery String keyStorePass, @RestQuery String certAlias
            ) throws KeyStoreException, NoSuchProviderException, CertificateException, IOException, NoSuchAlgorithmException,
            Asn1Exception, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        KeyStore ks = KeyStore.getInstance(keyStoreType, PROVIDER_NAME);
        ks.load(null, keyStorePass.toCharArray());

        X509Certificate certificate = (X509Certificate) ks.getCertificate(certAlias);

        var contentInfo = new ContentInfo();
        contentInfo.contentType = new Asn1ObjectIdentifier(
                new OID("1.2.840.113549.1.7.2").value);
        var signedData = new SignedData();
        signedData.version = new CMSVersion(1);
        contentInfo.content = signedData;

        signedData.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(
                new OID(JCP.GOST_DIGEST_2012_256_OID).value);

        a.parameters = new Asn1Null();
        signedData.digestAlgorithms.elements[0] = a;

        signedData.encapContentInfo = new EncapsulatedContentInfo(
                new Asn1ObjectIdentifier(
                        new OID("1.2.840.113549.1.7.1").value), null);

        // certificate
        signedData.certificates = new CertificateSet(1);
        final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate crt =
                new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();
        final Asn1BerDecodeBuffer decodeBuffer =
                new Asn1BerDecodeBuffer(certificate.getEncoded());
        crt.decode(decodeBuffer);

        signedData.certificates.elements = new CertificateChoices[1];
        signedData.certificates.elements[0] = new CertificateChoices();
        signedData.certificates.elements[0].set_certificate(crt);

        // signer info
        signedData.signerInfos = new SignerInfos(1);
        signedData.signerInfos.elements[0] = new SignerInfo();
        signedData.signerInfos.elements[0].version = new CMSVersion(1);
        signedData.signerInfos.elements[0].sid = new SignerIdentifier();

        final byte[] encodedName = certificate
                .getIssuerX500Principal().getEncoded();
        final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
        final Name name = new Name();
        name.decode(nameBuf);

        final CertificateSerialNumber num = new CertificateSerialNumber(
                certificate.getSerialNumber());
        signedData.signerInfos.elements[0].sid.set_issuerAndSerialNumber(
                new IssuerAndSerialNumber(name, num));
        signedData.signerInfos.elements[0].digestAlgorithm =
                new DigestAlgorithmIdentifier(
                        new OID(JCP.GOST_DIGEST_2012_256_OID).value);
        signedData.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
        signedData.signerInfos.elements[0].signatureAlgorithm =
                new SignatureAlgorithmIdentifier(
                        new OID(JCP.GOST_SIGN_2012_256_OID).value);
        signedData.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();

        //region digestAttr

        //signedAttributes
        signedData.signerInfos.elements[0].signedAttrs = new SignedAttributes(2);

        //contentType
        signedData.signerInfos.elements[0].signedAttrs.elements[0] =
                new Attribute(new OID("1.2.840.113549.1.9.3").value,
                        new Attribute_values(1));

        final Asn1Type conttype = new Asn1ObjectIdentifier(
                new OID("1.2.840.113549.1.7.1").value);
        signedData.signerInfos.elements[0].signedAttrs.elements[0].values.elements[0] =
                conttype;

        //message digest
        signedData.signerInfos.elements[0].signedAttrs.elements[1] =
                new Attribute(new OID("1.2.840.113549.1.9.4").value,
                        new Attribute_values(1));

        final Asn1Type messageDigest = new Asn1OctetString(digest(data));
        signedData.signerInfos.elements[0].signedAttrs.elements[1].values.elements[0] =
                messageDigest;

        //endregion digestAttr

        //signature
        Asn1BerEncodeBuffer encBufSignedAttr = new Asn1BerEncodeBuffer();
        signedData.signerInfos.elements[0].signedAttrs
                .encode(encBufSignedAttr);
        final byte[] _sign = encBufSignedAttr.getMsgCopy();
        signedData.signerInfos.elements[0].signature = new SignatureValue(sign(_sign, ks, certAlias, keyStorePass.toCharArray()));

        // encode
        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        contentInfo.encode(asnBuf, true);
        return asnBuf.getMsgCopy();
    }

    public byte[] digest(byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest messageDigest = MessageDigest.getInstance(JCP.GOST_DIGEST_2012_256_OID, PROVIDER_NAME);
        return messageDigest.digest(data);
    }

    public byte[] sign(byte[] data, KeyStore ks, String alias, char[] password)
            throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, KeyStoreException,
            InvalidKeyException, SignatureException {
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password);
        Signature signature = Signature.getInstance(JCP.GOST_SIGN_2012_256_OID, PROVIDER_NAME);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}
