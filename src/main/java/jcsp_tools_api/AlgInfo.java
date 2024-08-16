package jcsp_tools_api;

import java.security.cert.X509Certificate;

public class AlgInfo {

    private final String algOid;

    public AlgInfo(X509Certificate certificate) {
        this.algOid = certificate.getSigAlgOID();
    }

    public String getDigestAlg() {
        switch (algOid) {
            case "1.2.643.2.2.3":
                return "GOST3411-94";
            case "1.2.643.7.1.1.3.2":
                return "GOST3411-2012-256";
            default:
                throw new RuntimeException(String.format("Алгоритм с oid %s не поддерживается", algOid));
        }
    }

    public String getSignatureAlg() {
        switch (algOid) {
            case "1.2.643.2.2.3":
                return "GOST3411-94withGOST3410-2001";
            case "1.2.643.7.1.1.3.2":
                return "GOST3411-2012-256withGOST3410-2012-256";
            default:
                throw new RuntimeException(String.format("Алгоритм с oid %s не поддерживается", algOid));
        }
    }

    public String getDigestXmlAlg() {
        switch (algOid) {
            case "1.2.643.2.2.3":
                return "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
            //return "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";
            case "1.2.643.7.1.1.3.2":
                return "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
            default:
                throw new RuntimeException(String.format("Алгоритм с oid %s не поддерживается", algOid));
        }
    }

    public String getSignatureXmlAlg() {
        switch (algOid) {
            case "1.2.643.2.2.3":
                return "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
            // return "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";
            case "1.2.643.7.1.1.3.2":
                return "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
            default:
                throw new RuntimeException(String.format("Алгоритм с oid %s не поддерживается", algOid));
        }
    }
}
