import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.print.event.PrintJobListener;
import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.parser.XMLParserException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import utils.Utils;

public class App {
    public static void main(String[] args) throws Exception {
        new App().validateFiles();
    }
    Boolean valid = false;

    ArrayList<String> msgs = new ArrayList<>();
    String[] supportedSignatureAlgos = new String[]{"Algorithm=\"http://www.w3.org/2000/09/xmldsig#dsa-sha1\"", "Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"", "Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"", "Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384\"", "Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512\""};

    String[] supportedDigitalPrintAlgos = new String[]{"Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"", "Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#sha224\"", "Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"", "Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#sha384\"", "Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\""};

    private static final Map<String, String> DIGEST_ALG;

    static {
        DIGEST_ALG = new HashMap<String, String>();
        DIGEST_ALG.put("http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1");
        DIGEST_ALG.put("http://www.w3.org/2001/04/xmldsig-more#sha224", "SHA-224");
        DIGEST_ALG.put("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256");
        DIGEST_ALG.put("http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384");
        DIGEST_ALG.put("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");
    }

    private static final Map<String, String> TRANSORM_ALG;
    static {
        TRANSORM_ALG = new HashMap<String, String>();
        TRANSORM_ALG.put("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", "REC");
        TRANSORM_ALG.put("http://www.w3.org/2000/09/xmldsig#base64", "base64");
    }

    private static final Map<String, String> SIGN_ALG;

    static {
        SIGN_ALG = new HashMap<String, String>();
        SIGN_ALG.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "SHA1withDSA");
        SIGN_ALG.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA1withRSA/ISO9796-2");
        SIGN_ALG.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA");
        SIGN_ALG.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA");
        SIGN_ALG.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA");
    }

    void validateFiles() {

        try {
            var files = loadFilesToVerify();

            for (File file : files) {
                msgs.add("# Subor: " + file.getName());
                if (validateFile(file)) {
                    System.out.println("was right");
                    msgs.add("\n#### Subor: " + file.getName() + " má platný XADES-T podpis");
                } else {
                    System.out.println("was not right");
                    msgs.add("\n#### Subor: " + file.getName() + " nie je platný");
                }
                msgs.add("\n");

            }

            // VYPIS DO MARKDOWN
            var file_writer_md = new FileWriter("./resources/output_files/outputValidation.md");
            for (String msg : msgs) {
                if (msg.contains("# "))
                    file_writer_md.write(msg + " \n");
                else {
                    file_writer_md.write(msg + " ");
                }
            }
            file_writer_md.close();

            // VYPIS DO TXT
            var file_writer_txt = new FileWriter("./resources/output_files/outputValidation.txt");
            for (String msg : msgs) {
                file_writer_txt.write(msg + "\n");

            }

            file_writer_txt.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private boolean validateFile(File file) {
        Document parsedXml = buildXml(file);
        if (!isValidTimestampCerfificate(parsedXml)) return false;
        
        if (!isValidDatovaObalka(parsedXml)) return false;

        if (!isValidSignatureMethodAndCanonicalizationMethod(parsedXml)) return false;

        if (!isValidTransformsAndDigestMethod(parsedXml)) return false;

        if (!isValidCoreReferencesAndDigestValue(parsedXml)) return false;

        if (!isValidSignedInfoAndKeyInfo(parsedXml)) return false;

        if (!isValidSignatureElements(parsedXml)) return false;

        if (!isValidSignatureValueId(parsedXml)) return false;

        if (!isValidKeyInfoContent(parsedXml)) return false;

        if (!isValidSignaturePropertiesContent(parsedXml)) return false;
        
        if (!isValidSignedInfoReferences(parsedXml)) return false;

        if (!isValidManifest(parsedXml)) return false;

        if (!isValidMessageImprint(parsedXml)) return false;
        
        if (!isValidCertificate(parsedXml)) return false;
        
        return true;
    }

    private boolean isValidSignedInfoReferences(Document parsedXml) {

        return true;
    }
    private boolean isValidManifest(Document parsedXml) {
        NodeList referencesElements = findAllNodes(parsedXml, "ds:Manifest");
        for (int i = 0; i < referencesElements.getLength(); i++) {
            Node referenceNode = referencesElements.item(i);
        
			 // každý ds:Manifest element musí mať Id atribút,
             Node IdNode = null;
             String IdValueObtained = "";
             IdNode = referenceNode.getAttributes().getNamedItem("Id");
             
             //ziskane hodnoty
             if (IdNode != null) {
                 IdValueObtained = IdNode.getTextContent();
             } else {
                 msgs.add("Element ds:Manifest nemá atribút Id");
                 return false;
             }
			
			// každý ds:Manifest element musí obsahovať práve jednu referenciu na ds:Object
            
            List<Node> dsObj = findChildNodesWithName(referenceNode, "ds:Reference");
            
			if (dsObj.size() != 1) {
				msgs.add("ds:Manifest element neobsahuje prave jednu referenciu na objekt");
                return false;
			} else {
                Node temp = dsObj.get(0);
                String uri_obj = temp.getAttributes().getNamedItem("Type").getTextContent();
                if(!uri_obj.equals("http://www.w3.org/2000/09/xmldsig#Object")) {
                    msgs.add("ds:Manifest nema referenciu na objekt");
                    return false;
                }
            }

            List<Node> transformsElements = findChildNodesWithName(referenceNode, "ds:Transforms");
            if (transformsElements.size() == 1) {
                List<Node> transformElements = findChildNodesWithName(transformsElements.get(0), "ds:Transform"); 
                String transformMethod = null;
                if (transformElements != null) {
                    transformMethod = transformElements.get(0).getAttributes().getNamedItem("Algorithm").getTextContent();
                } else {
                    msgs.add("reference Node neobsahuje ds:Transform");
                    return false;
                }
                transformMethod = TRANSORM_ALG.get(transformMethod);
                if (transformMethod == null) {
                    msgs.add("ds:Transform s nepodporovaným algoritmom");
                    return false;
                }
            } else {
                msgs.add("reference Node neobsahuje ds:Transforms");
                return false;
            }

            List<Node> digestMethodElement = findChildNodesWithName(referenceNode, "ds:DigestMethod");
            if (digestMethodElement.size() == 1 ) {
                String digestMethod = null;
                digestMethod = digestMethodElement.get(0).getAttributes().getNamedItem("Algorithm").getTextContent();
                digestMethod = DIGEST_ALG.get(digestMethod);
                if (digestMethod == null) {
                    msgs.add("ds:DigestMethod s nepodporovaným algoritmom");
                    return false;
                }
            } else {
                msgs.add("reference Node neobsahuje ds:DigestMethod");
                return false;
            }
            
		}
        return true;
    }

    private X500Name toBouncyX500Name( X500Principal principal) {
        String name = principal.getName();
    
        String[] RDN = name.split(",");
    
        StringBuffer buf = new StringBuffer(name.length());
        buf.append(RDN[3]);
        buf.append(',');
        buf.append(RDN[1]);
        buf.append(',');
        buf.append(RDN[2]);
        buf.append(',');
        buf.append(RDN[0]);

        return new X500Name(buf.toString());
    }

	public boolean isValidTimestampCerfificate(Document parsedXml) {
        var crl = Utils.getCRL();
        if (crl == null){
            msgs.add("could not load crl");
            return false;
        }
        TimeStampToken ts_token = Utils.getTimestampToken(parsedXml);
        
        ArrayList<X509CertificateHolder> collection = (ArrayList<X509CertificateHolder>) ts_token.getCertificates().getMatches(null);

		BigInteger serialNumToken = ts_token.getSID().getSerialNumber();
		X500Name issuerToken = toBouncyX500Name(ts_token.getSID().getIssuer());
        
		X509CertificateHolder signer = null;
		for (X509CertificateHolder certHolder : collection) {
			if (certHolder.getSerialNumber().equals(serialNumToken) && (certHolder.getIssuer().equals(issuerToken))){
				signer = certHolder;
				break;
			}
		}

		if (signer == null){
            msgs.add("V dokumente sa nenachadza certifikat casovej peciatky.");
            return false;
		}
        
		if (!signer.isValidOn(new Date())){
            msgs.add("Podpisový certifikát časovej pečiatky nie je platný voči aktuálnemu času.");
            return false;
		}
        
		if (crl.getRevokedCertificate(signer.getSerialNumber()) != null){
            msgs.add("Podpisový certifikát časovej pečiatky nie je platný voči platnému poslednému CRL.");
            return false;
		}

		return true;
	}

	public boolean isValidMessageImprint(Document parsedXml) {
        TimeStampToken ts_token = Utils.getTimestampToken(parsedXml);

		byte[] messageImprint = ts_token.getTimeStampInfo().getMessageImprintDigest();
		String hashAlg = ts_token.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString();
		Node signatureValueNode = null;
        signatureValueNode = findNode(parsedXml, "ds:SignatureValue");

		if (signatureValueNode == null){
            msgs.add("Element ds:SignatureValue nenájdený.");
            return false;
        }

		byte[] signatureValue = Base64.decode(signatureValueNode.getTextContent().getBytes());

		MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance(hashAlg, "SUN");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			msgs.add("Nepodporovaný algoritmus v message digest.");
            return false;
        }

		if (!Arrays.equals(messageImprint, messageDigest.digest(signatureValue))){
			msgs.add("MessageImprint z časovej pečiatky a podpis ds:SignatureValue sa nezhodujú.");
            return false;
        }

        return true;
	}

	public boolean isValidCertificate(Document parsedXml) {
        var crl = Utils.getCRL();
        if (crl == null){
            msgs.add("could not load crl");
        }
        TimeStampToken ts_token = Utils.getTimestampToken(parsedXml);
        
		Node certificateNode = null;

        certificateNode = findNode(parsedXml, "ds:X509Certificate");
		

		if (certificateNode == null){
			msgs.add("Element ds:X509Certificate nenájdený.");
		}

		X509CertificateObject cert = null;
		ASN1InputStream asn1is = null;

		try {
			asn1is = new ASN1InputStream(new ByteArrayInputStream(Base64.decode(certificateNode.getTextContent())));
			ASN1Sequence sq = (ASN1Sequence) asn1is.readObject();
			cert = new X509CertificateObject(X509CertificateStructure.getInstance(sq));
		} catch (IOException | CertificateParsingException e) {
			e.printStackTrace();
		} finally {
			if (asn1is != null) {
				try {
					asn1is.close();
				} catch (IOException e) {
					msgs.add("Nie je možné prečítať certifikát dokumentu.");
				}
			}
		}

		try {
			cert.checkValidity(ts_token.getTimeStampInfo().getGenTime());
		} catch (CertificateExpiredException e) {
			msgs.add("Certifikát dokumentu bol pri podpise expirovaný.");
		} catch (CertificateNotYetValidException e) {
			msgs.add("Certifikát dokumentu ešte nebol platný v čase podpisovania.");
		}

		X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
		if (entry != null && entry.getRevocationDate().before(ts_token.getTimeStampInfo().getGenTime())) {
			msgs.add("Certifikát bol zrušený v čase podpisovania.");
		}

		return true;
	}

    private boolean isValidSignaturePropertiesContent(Document parsedXml) {

        //najst ds:SignatureProperties element (ma byt ulozeny pod ds:Object)
        Node signatureNode = findNode(parsedXml, "ds:Signature");
        NodeList objectElements = findAllNodes(parsedXml, "ds:Object");
        // List<Node> objectElements = findChildNodesWithName(signatureNode, "ds:Object");
        Node signaturePropertiesNode = null;
        //hladam element signatureProperties pod ds:Object
        if (objectElements == null) {
            msgs.add("Element ds:Signature neobsahuje žiadne ds:Object elementy.");
            return false;
        }

        //TODO - prave jeden Signature properties element
        Boolean propertiesFound = false;
        Node propNode = null;
        for (int i = 0; i < objectElements.getLength(); i++) {
            Node objectElement = objectElements.item(i);
            propNode = findChildNodeOf(objectElement, "ds:SignatureProperties");
            if (propNode != null) {
                propertiesFound = true;
                signaturePropertiesNode = propNode;
                break;
            }
        }

        if (propertiesFound == false)  {
            msgs.add("Element ds:SignatureProperties sa nenachádza v žiadnom ds:Object elemente.");
            return false;
        }
        
        //overenie Id
/*         element ds:SignatureProperties musí byť referencovany z príslušného ds:Reference elementu v rámci ds:SignedInfo.  */

        Node IdNode = null;
        String IdValueObtained = "";
        IdNode = signaturePropertiesNode.getAttributes().getNamedItem("Id");

        //ziskane hodnoty
        if (IdNode != null) {
            IdValueObtained = IdNode.getTextContent();
        } else {
            msgs.add("Element ds:SignatureProperties nemá atribút Id");
            return false;
        }

        //ocakavane hodnoty Id - signed info reference
        String IdValueExpected = "";
        Node signedInfoNode = findNode(parsedXml, "ds:SignedInfo");
        List<Node> referenceElements = null;
        if (signedInfoNode != null) {
            referenceElements = findChildNodesWithName(signedInfoNode, "ds:Reference");
        } else {
            msgs.add("Element ds:SignedInfo neexistuje.");
            return false;
        }

        if (referenceElements == null) {
            msgs.add("Element ds:SignedIndfo neobsahuje žiadne ds:Reference elementy.");
            return false;
        }

        Node refNode = null;
        Node referenceIddNode = null;
        String idContent = "";
        Boolean propertiesIdFound = false;
        for (Node referenceElement : referenceElements) {
            referenceIddNode = referenceElement.getAttributes().getNamedItem("Id");
            if (referenceIddNode != null) {
                idContent = referenceIddNode.getTextContent();
                if (idContent.contains("SignatureProperties")) {
                    IdValueExpected = idContent.replace("Reference", "");
                    propertiesIdFound = true;
                    break;
                }
            }
        }

        if (propertiesIdFound == false)  {
            msgs.add("Element ds:SignatureProperties nie je referencovaný v žiadnom ds:Reference (Id).");
            return false;
        }

        Boolean IdSignaturePropertiesValid = false;
        if (IdValueObtained != "") {
            if (IdValueExpected != "") {
                if (IdValueExpected.equals(IdValueObtained)) {
                    IdSignaturePropertiesValid = true; //este musia byt splnene dalsie podmienky
                } else {
                    msgs.add("Id atribút v ds:SignatureProperties nemá rovnakú hodnotu ako Id atribút v príslušnom ds:Reference.");
                    return false;
                }
            } else {
                msgs.add("Atribút Id v ds:Reference pre ds:SignatureProperties element neexistuje.");
                return false;
            }
        } else {
            msgs.add("Atribút Id elementu ds:SignatureProperties neobsahuje žiadnu hodnotu");
            return false;
        }

        //najst pod properies element xzep:SignatureVersion a xzep:ProductInfos (asi tak) 
        //najdu vsetky signature property
        List<Node> signaturePropertyElements = findChildNodesWithName(signaturePropertiesNode, "ds:SignatureProperty");
        Node signatureVersionNode = null;
        Node productInfosNode = null;
        Node targetNode = null;
        Node tempVersionNode = null;
        Node tempProductNode = null;
        Node targetVersionNode = null;
        Node targetProductNode = null;
        for (Node signaturePropertyElement : signaturePropertyElements) {
            tempVersionNode = findChildNodeOf(signaturePropertyElement, "xzep:SignatureVersion");
            tempProductNode = findChildNodeOf(signaturePropertyElement, "xzep:ProductInfos");
            if (tempVersionNode != null) {
                signatureVersionNode = tempVersionNode;
                targetVersionNode = signaturePropertyElement.getAttributes().getNamedItem("Target");
            }

            if (tempProductNode != null) {
                productInfosNode = tempProductNode;
                targetProductNode = signaturePropertyElement.getAttributes().getNamedItem("Target");
            }
            //najdi atribut target
            //najdi node
        }

        if (signatureVersionNode == null) {
            msgs.add("Element xzep:SignatureVersion v ds:SignatureProperty neexistuje.");
            return false;
        }

        if (productInfosNode == null) {
            msgs.add("Element xzep:ProductInfos v ds:SignatureProperty neexistuje.");
            return false;
        }
        //pre kazdu vyhladaj node xzep:SignatureVersion a xzep:ProductInfos
        //vyhladaj pre kazdu target

        //oba musia obsahvat atribut Target  - URI referencia na Id atribut prislusneho ds:signature elementu
        //TODO - skontroluj obsah target, ci nie je prazdny
         //target zbavit #
        String targetVersion = "";
        String targetProduct = "";
        if (targetVersionNode != null) {
            targetVersion = targetVersionNode.getTextContent();
            if (targetVersion != null) {
                targetVersion = targetVersion.replace("#", "");
            } else {
                msgs.add("Target atribút v elemente ds:SignatureProperty neobsahuje žiadnu hodnotu (xzep:SignatureVersion)");
                return false;
            }
        } else {
            msgs.add("Element ds:SignatureProperty neobsahuje Target atribút (xzep:SignatureVersion)");
            return false;
        }


        if (targetProductNode != null) {
            targetProduct = targetProductNode.getTextContent();
            if (targetProduct != null) {
                targetProduct = targetProduct.replace("#", "");
            } else {
                msgs.add("Target atribút v elemente ds:SignatureProperty neobsahuje žiadnu hodnotu (xzep:ProductInfos)");
                return false;
            }
        } else {
            msgs.add("Element ds:SignatureProperty neobsahuje Target atribút (xzep:ProductInfos)");
            return false;
        }

        
       
        //
        Node IdSignatureNode = null;
        String IdSignatureValueExpected = "";
        IdSignatureNode = signatureNode.getAttributes().getNamedItem("Id");
        if (IdSignatureNode != null) {
            IdSignatureValueExpected = IdSignatureNode.getTextContent();
            if (IdSignatureValueExpected != null) {
                //todo, Id pripravene na porovnanie s targetmi
                if (!(targetProduct.equals(IdSignatureValueExpected))) {
                    msgs.add("Target v elemente ds:SignatureProperty a Id ds:Signature sa nezhodujú (xzep:ProductInfos).");
                    return false;
                }

                if (!(targetVersion.equals(IdSignatureValueExpected))) {
                    msgs.add("Target v elemente ds:SignatureProperty a Id ds:Signature sa nezhodujú (xzep:SignatureVersion).");
                    return false;
                }

                //na konci vsetky splnene podmienky
                //tieto referencie na target su ok, este musi byt splnena podmienka vyssie, id signature properties je valid
                if (IdSignaturePropertiesValid == true) {
                    return true;
                }
            } else {
                msgs.add("Atribút Id elementu ds:Signature neobsahuje žiadnu hodnotu.");
                return false;
            }
        } else {
            msgs.add("Element ds:Signature nemá atribút Id");
            return false;
        }
        
        return false;
    }


    private boolean isValidKeyInfoContent(Document parsedXml) {

        //najst element ds:KeyInfo

        //predpokladam na zaklade predchadzajucej vykonanej metody(ifu), ze signature Node existuje
        Node signatureNode = findNode(parsedXml, "ds:Signature");
        Node keyInfoNode = findChildNodeOf(signatureNode, "ds:KeyInfo");

        if (keyInfoNode == null) {
            msgs.add("Element ds:KeyInfo neexistuje");
            return false;
        }

         //id atribut v keyinfo, referencia v elemente ds:SignedInfo
         //ziskane hodnoty
        Node IdNode = null;
        String IdValueObtained = "";
        IdNode = keyInfoNode.getAttributes().getNamedItem("Id");

        if (IdNode != null) {
            IdValueObtained = IdNode.getTextContent();
        } else {
            msgs.add("Element ds:KeyInfo nemá atribút Id");
            return false;
        }
       
        //TODO- kde v signedinfo je referencia na Id? 
        //ocakavane hodnoty Id
        String IdValueExpected = "";
        Node signatureTimeStampNode = findNode(parsedXml, "ds:SignedInfo");
        Node IdNodeTimeStamp = null;
        /* if (signatureTimeStampNode != null) {
            IdNodeTimeStamp = signatureTimeStampNode.getAttributes().getNamedItem("Id");
            if (IdNodeTimeStamp != null) {
                IdValueExpected = IdNodeTimeStamp.getTextContent();
            } else {
                msgs.add("Element xades:SignatureTimeStamp nemá atribút Id");
                return false;
            }
        } else {
            msgs.add("Element xades:SignatureTimeStamp neexistuje.");
            return false;
        } */

        //keyinfo ma element ds:X509Data
        Node X509DataNode = findChildNodeOf(keyInfoNode, "ds:X509Data");
        if (X509DataNode == null) {
            msgs.add("Element ds:X509Data neexistuje");
            return false;
        }

        // element ds:X509Data ma elementy ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName
        Node X509CertificateNode = findChildNodeOf(X509DataNode, "ds:X509Certificate");
        Node X509IssuerSerialNode = findChildNodeOf(X509DataNode, "ds:X509IssuerSerial");
        Node X509SubjectNameNode = findChildNodeOf(X509DataNode, "ds:X509SubjectName");

        String X509CertficateValue = "";
        String issuerName = "";
        String serialNumber = "";
        String subjectName = "";
        Node X509IssuerNameNode = null;
        Node X509SerialNumberNode = null;

        if ((X509CertificateNode != null) && (X509IssuerSerialNode != null) && (X509SubjectNameNode != null)) {
            X509CertficateValue = X509CertificateNode.getTextContent();
            X509IssuerNameNode = findChildNodeOf(X509IssuerSerialNode, "ds:X509IssuerName");
            if (X509IssuerNameNode != null) {
                issuerName = X509IssuerNameNode.getTextContent();
            } else {
                msgs.add("Element ds:X509IssuerSerial neobsahuje element ds:X509IssuerName.");
                return false;
            }
            X509SerialNumberNode = findChildNodeOf(X509IssuerSerialNode, "ds:X509SerialNumber");
            if (X509SerialNumberNode != null) {
                serialNumber = X509SerialNumberNode.getTextContent();
            } else {
                msgs.add("Element ds:X509IssuerSerial neobsahuje element ds:X509SerialNumber.");
                return false;
            }
            subjectName = X509SubjectNameNode.getTextContent();
            //X509Certificate certificate = generateCertificateFromString(X509CertficateValue);
        } else {
            msgs.add("Element ds:X509Data neobsahuje všetky elementy (ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName)");
            return false;
        }
        //X509CertficateValue = X509CertificateNode.getTextContent();
        //TODO certificate value je null???
        X509Certificate certificate = generateCertificateFromString(X509CertficateValue);
        String certfIssuerName = certificate.getIssuerX500Principal().toString().replaceAll("ST=", "S=");
		String certfSerialNumber = certificate.getSerialNumber().toString();
		String certfSubjectName = certificate.getSubjectX500Principal().toString();

        //issuer a subject sedi s certificate
        //if (xIssuerNameElement.getTextContent().equals(certifIssuerName) == false)
        //overenie issuer Name
        if (issuerName != null) {
            if (issuerName.equals(certfIssuerName) == false) {
                msgs.add("Element ds:X509IssuerName sa nezhoduje s hodnotou na certifikáte");
                return false;
            }
        } else {
            msgs.add("Element ds:X509IssuerName neobsahuje žiadnu hodnotu.");
            return false;
        }

        //overenie serial number
        if (serialNumber != null) {
            if (serialNumber.equals(certfSerialNumber) == false) {
                msgs.add("Element ds:X509SerialNumber sa nezhoduje s hodnotou na certifikáte");
                return false;
            }
        } else {
            msgs.add("Element ds:X509SerialNumber neobsahuje žiadnu hodnotu.");
            return false;
        }

        //overenie subject name
        if (subjectName != null) {
            if (subjectName.equals(certfSubjectName) == false) {
                msgs.add("Element ds:X509SubjectName sa nezhoduje s hodnotou na certifikáte");
                return false;
            }
        } else {
            msgs.add("Element ds:X509SubjectName neobsahuje žiadnu hodnotu.");
            return false;
        }

        return true;

    }

    private boolean isValidSignatureValueId(Document parsedXml) {
        //        parsedXml.getDocumentURI()

        //predpokladam na zaklade predchadzajucej vykonanej metody(ifu), ze signature Node existuje
        Node signatureNode = findNode(parsedXml, "ds:Signature");
        Node signatureValueNode = findChildNodeOf(signatureNode, "ds:SignatureValue");
        Node IdNode = null;
        String IdValueObtained = "";

        //ziskane hodnoty
        if (signatureValueNode != null) {
            IdNode = signatureValueNode.getAttributes().getNamedItem("Id");
            if (IdNode != null) {
                IdValueObtained = IdNode.getTextContent();
            } else {
                msgs.add("Element ds:SignatureValue nemá atribút Id");
                return false;
            }
        } else {
            msgs.add("Element ds:SignatureValue neexistuje");
            return false;
        }

        //ocakavane hodnoty Id
        String IdValueExpected = "";
        Node signatureTimeStampNode = findNode(parsedXml, "xades:SignatureTimeStamp");
        Node IdNodeTimeStamp = null;
        if (signatureTimeStampNode != null) {
            IdNodeTimeStamp = signatureTimeStampNode.getAttributes().getNamedItem("Id");
            if (IdNodeTimeStamp != null) {
                IdValueExpected = IdNodeTimeStamp.getTextContent();
            } else {
                msgs.add("Element xades:SignatureTimeStamp nemá atribút Id");
                return false;
            }
        } else {
            msgs.add("Element xades:SignatureTimeStamp neexistuje.");
            return false;
        }

        //v expected vyhodit SignatureTimeStamp
        //v obtained vyhodit SignatureValue
        if (IdValueObtained != "") {
            if (IdValueExpected != "") {
                //konecne overenie Id atributu
                IdValueExpected = IdValueExpected.replace("SignatureTimeStamp", ""); //navyse na konci SignatureTimeStamp
                IdValueObtained = IdValueObtained.replace("SignatureValue", ""); //navyse na konci SignatureValue
                if (IdValueExpected.equals(IdValueObtained)) {
                    return true;
                } else {
                    msgs.add("Id atribút v ds:SignatureValue nemá rovnakú hodnotu ako Id atribút v xades:SignatureTimeStamp.");
                    return false;
                }
            } else {
                msgs.add("Atribút Id elementu ds:SignatureValue nemáme ako overiť. Chýba hodnota Id v elemente xades:SignatureTimeStamp.");
                return false;
            }
        } else {
            msgs.add("Atribút Id elementu ds:SignatureValue neobsahuje žiadnu hodnotu");
            return false;
        }

    }

    
    private boolean isValidSignatureElements(Document parsedXml) {
        //        parsedXml.getDocumentURI()
/* 
        Node signatureNode = findNode(parsedXml, "df:Signature");
        Node signatureNodeChild = findChildNodeOf(signatureNode, "Id"); */

        //1/2 Id atribut + overenie hodnoty
        //Id - ds:signature element je referencovaný z elementu xades:QualifyingProperties, atribút Target

        Node signatureNode = findNode(parsedXml, "ds:Signature");
        Node IdNode = null;
        String IdValueObtained = "";
        if (signatureNode != null) {
            IdNode = signatureNode.getAttributes().getNamedItem("Id");
            if (IdNode != null) {
                IdValueObtained = IdNode.getTextContent();
            } else {
                msgs.add("Element ds:Signature nemá atribút Id");
                return false;
            }
        } else {
            msgs.add("Element ds:Signature neexistuje");
            return false;
        }

        //ocakavane hodnoty Id
        String IdValueExpected = "";
        Node qualifyingPropertiesNode = findNode(parsedXml, "xades:QualifyingProperties");
        Node qualifyingPropertiesTargetNode = null;
        if (qualifyingPropertiesNode != null) {
            qualifyingPropertiesTargetNode = qualifyingPropertiesNode.getAttributes().getNamedItem("Target");
            if (qualifyingPropertiesTargetNode != null) {
                IdValueExpected = qualifyingPropertiesTargetNode.getTextContent();
            } else {
                msgs.add("Element Target v elemente xades:QualifyingProperties neexistuje.");
                return false;
            }
        } else {
            msgs.add("Element xades:QualifyingProperties neexistuje.");
            return false;
        }


        Boolean IdValueIsValid = false;
        if (IdValueObtained != "") {
            if (IdValueExpected != "") {
                //konecne overenie Id atributu
                IdValueExpected = IdValueExpected.replace("#", ""); //v targete je pred Idckom este navyse #
                if (IdValueExpected.equals(IdValueObtained)) {
                    //return true; //TODO - najprv aj druha podmienka pre namespace musi byt splnena, az potom true
                    IdValueIsValid = true;
                } else {
                    msgs.add("Id atribút v ds:Signature nemá rovnakú hodnotu ako Target atribút v xades:QualifyingProperties.");
                    return false;
                }
            } else {
                msgs.add("Atribút Id elementu ds:Signature nemáme ako overiť. Chýba hodnota Id v Target atribúte v xades:QualifyingProperties.");
                return false;
            }
        } else {
            msgs.add("Atribút Id elementu ds:Signature neobsahuje žiadnu hodnotu");
            return false;
        }

        //msgs.add("Element xades:QualifyingProperties nemá atribút Target. Nemáme ako overit Id v ds:Signature");


        //2/2 namespace
        //overenie, ze Signature Node existuje je uz vyssie
        String namespaceValueObtained = "";
        String namespaceExpected = "http://www.w3.org/2000/09/xmldsig#";
        Node namespaceNode = signatureNode.getAttributes().getNamedItem("xmlns:ds");
        if (namespaceNode != null) {
            namespaceValueObtained = namespaceNode.getTextContent();
        } else {
            msgs.add("Element ds:Signature nemá atribút xmlns:ds");
            return false;
        }
        
        if (namespaceValueObtained != "") {
            if (namespaceValueObtained.equals(namespaceExpected)) {
                if (IdValueIsValid == true) {
                    return true;
                } 
            } else {
                msgs.add("Namespace xmlns:ds v ds:Signature nemá správnu hodnotu.");
                return false;
            }
        } else {
            msgs.add("Namespace xmlns:ds v ds:Signature neobsahuje žiadnu hodnotu");
            return false;
        }

		return false;
    }



    private boolean isValidSignedInfoAndKeyInfo(Document parsedXml) {

        Node signatureNode = findNode(parsedXml, "ds:Signature");
        Node signedInfoNode = findChildNodeOf(signatureNode, "ds:SignedInfo");
        Node canonicalMethodNode = null;
        if (signedInfoNode != null) {
            canonicalMethodNode = findChildNodeOf(signedInfoNode, "ds:CanonicalizationMethod");
        } else {
            msgs.add("CanonicalizationMethod element nebol v signed info najdeny");
            return false;
        }

        Node signatureMethodNode = findChildNodeOf(signedInfoNode, "ds:SignatureMethod");
        Node signatureValueNode = findChildNodeOf(signatureNode, "ds:SignatureValue");

        byte[] signedInfoElementBytes = fromElementToString(signedInfoNode).getBytes();
        String canonicalizationMethod = "";
        if (canonicalMethodNode != null) {
            canonicalizationMethod = canonicalMethodNode.getAttributes().getNamedItem("Algorithm").getTextContent();
        } else {
            msgs.add("CanonicalizationMethod element nema atribut algorithm");
            return false;
        }

        Canonicalizer canonicalizer = null;
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            canonicalizer = Canonicalizer.getInstance(canonicalizationMethod);
            try {
                canonicalizer.canonicalize(signedInfoElementBytes, stream, true);
                signedInfoElementBytes = stream.toByteArray();
            } catch ( IOException | CanonicalizationException | XMLParserException e) {
                throw new RuntimeException(e);
            }
        } catch (InvalidCanonicalizerException e) {
            throw new RuntimeException(e);
        }

        Node keyInfoNode = findNode(parsedXml, "ds:KeyInfo");
        Node x509Data = findChildNodeOf(keyInfoNode, "ds:X509Data");
        Node x509Certificate = null;
        if (x509Data != null) {
            x509Certificate = findChildNodeOf(x509Data, "ds:X509Certificate");
        } else {
            msgs.add("Element ds:X509Certificate neexistuje");
            return false;
        }
        String X509CertficateValue = null;
        if (x509Certificate != null) {
            X509CertficateValue = x509Certificate.getTextContent();
        } else {
            msgs.add("Element ds:X509Certificate nema hodnotu");
            return false;
        }

        String signatureMethod = "";

        if (signatureMethodNode != null) {
            signatureMethod = signatureMethodNode.getAttributes().getNamedItem("Algorithm").getTextContent();
        } else {
            msgs.add("signature Method nema atribut algorithm");
            return false;
        }

        signatureMethod = SIGN_ALG.get(signatureMethod);

        X509Certificate certificate = generateCertificateFromString(X509CertficateValue);
        Signature signer = null;


        try {
            signer = Signature.getInstance(signatureMethod);
            signer.initVerify(certificate.getPublicKey());
            signer.update(signedInfoElementBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            msgs.add("Chyba pri inicializacii podpisovaca: " + e);
            return false;
        }

        byte[] signatureValueBytes = new byte[0];
        if (signatureValueNode != null) {
            signatureValueBytes = signatureValueNode.getTextContent().getBytes();
        } else {
            msgs.add("signature value nema hodnotu");
            return false;
        }


        byte[] decodedSignatureValueBytes = Base64.decode(signatureValueBytes);

        boolean verificationResult = false;

        try {
            verificationResult = signer.verify(decodedSignatureValueBytes);
        } catch (SignatureException e) {
            msgs.add("Chyba pri verifikacii digitalneho podpisu");
            return false;
        }

        if (!verificationResult) {
            msgs.add("Podpisana hodnota ds:SignedInfo sa nezhoduje s hodnotou v elemente ds:SignatureValue");
            return false;

        }
        return true;

    }

    private X509Certificate generateCertificateFromString(String x509CertficateValue) {
        CertificateFactory cf = null;
        X509Certificate cert = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(x509CertficateValue)));
        } catch (CertificateException e) {
            msgs.add("Nepodarilo sa vytvorit cerfikat " + e);
            throw new RuntimeException(e);
        }

        return cert;
    }

    public boolean isValidCoreReferencesAndDigestValue(Document parsedXml) {

        List<Node> referencesElements = findChildNodesWithName(Objects.requireNonNull(findChildNodeOf(findNode(parsedXml, "ds:Signature"), "ds:SignedInfo")), "ds:Reference");

        for (Node referenceNode : referencesElements) {
            Node uriNode = referenceNode.getAttributes().getNamedItem("URI");

            if (uriNode == null) {
                msgs.add("Reference node nema URI atribut");
                return false;
            }
            String uri = referenceNode.getAttributes().getNamedItem("URI").getTextContent();

            Node manifestNode = findByAttributeValue(parsedXml, "ds:Manifest", "Id", uri);

            if (manifestNode == null) {
                continue;
//                msgs.add("Ziadny ds:Manifest neobsahuje hodnotu uri: " + uri );
//                return false;
            }

            Node digestValueElement = findChildNodeOf(referenceNode, "ds:DigestValue");
            String expectedDigestValue = null;
            if (digestValueElement != null) {
                expectedDigestValue = digestValueElement.getTextContent();
            } else {
                msgs.add("reference Node neobsahuje digestValue");
                return false;
            }

            Node digestMethodElement = findChildNodeOf(referenceNode, "ds:DigestMethod");

            String digestMethod = null;
            if (digestMethodElement != null) {
                digestMethod = digestMethodElement.getAttributes().getNamedItem("Algorithm").getTextContent();
            } else {
                msgs.add("reference Node neobsahuje DigestMethod algorithm");
                return false;
            }
            digestMethod = DIGEST_ALG.get(digestMethod);


            byte[] manifestElementBytes = fromElementToString(manifestNode).getBytes();
            List<Node> transformsElements = findChildNodesWithName(manifestNode, "ds:Transforms");
            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            for (int j = 0; j < transformsElements.size(); j++) {

                Node transformsElement = transformsElements.get(j);

                Node transformElement = findChildNodeOf(transformsElement, "ds:Transform");
                String transformMethod = null;
                if (transformElement != null) {
                    transformMethod = transformElement.getAttributes().getNamedItem("Algorithm").getTextContent();
                } else {
                    msgs.add("transform element nema algorithm");
                    return false;
                }

                if ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315".equals(transformMethod)) {
                    Canonicalizer canonicalizer = null;
                    try {
                        org.apache.xml.security.Init.init();
                        canonicalizer = Canonicalizer.getInstance(transformMethod);
                        canonicalizer.canonicalize(manifestElementBytes, stream, false);
                        manifestElementBytes = stream.toByteArray();
                    } catch (InvalidCanonicalizerException | XMLParserException | IOException |
                             CanonicalizationException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

            MessageDigest messageDigest = null;

            try {
                messageDigest = MessageDigest.getInstance(digestMethod);
            } catch (NoSuchAlgorithmException e) {
                msgs.add("Neznamy digest algoritmus");
                return false;
            }
            String actualDigestValue = new String(Base64.encode(messageDigest.digest(manifestElementBytes)));


            if (!expectedDigestValue.equals(actualDigestValue)) {
                msgs.add(expectedDigestValue);
                msgs.add(actualDigestValue);
                msgs.add("Core validation zlyhala, hodnota ds:DigestValue elementu ds:Reference sa nezhoduje s hodnotou elementu ds:Manifest");
                return false;
            }
        }

        return true;
    }

    public static String fromElementToString(Node element) {

        StreamResult result = new StreamResult(new StringWriter());

        Transformer transformer = null;
        try {
            transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(element), result);
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }

        return result.getWriter().toString();
    }

    private Node findByAttributeValue(Document parsedXml, String elementName, String atribudeName, String AttributeValue) {
        NodeList nodeList = findAllNodes(parsedXml, elementName);
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node element = nodeList.item(i);
            NamedNodeMap atrNodes = element.getAttributes();
            for (int j = 0; j < atrNodes.getLength(); j++) {
                Node atr = atrNodes.item(i);
                if (atribudeName.equals(atr.getNodeName())) {
                    if (AttributeValue.substring(1).equals(atr.getTextContent())) {
                        return element;
                    }
                }

            }
        }

        return null;
    }

    private boolean isValidTransformsAndDigestMethod(Document parsedXml) {
        String atr1Valid = "Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"";

        NodeList nodeList1 = findAllNodes(parsedXml, "ds:Transform");
        NodeList nodeList2 = findAllNodes(parsedXml, "ds:DigestMethod");


        for (int i = 0; i < nodeList1.getLength(); i++) {
            Node nodeAtr1 = nodeList1.item(i).getAttributes().getNamedItem("Algorithm");
            if (nodeAtr1 == null) {
                msgs.add("Súbor neobsahuje atribut ds:Transforms");
                return false;
            }
            String atr1 = nodeAtr1.toString();


            if (!atr1Valid.equals(atr1)) {
                msgs.add(atr1);
                msgs.add(atr1Valid);
                msgs.add("Súbor má neplatnú hodnotu obsahu ds:Transforms");
                return false;
            }
        }

        for (int i = 0; i < nodeList2.getLength(); i++) {
            Node nodeAtr2 = nodeList2.item(i).getAttributes().getNamedItem("Algorithm");
            if (nodeAtr2 == null) {
                msgs.add("Súbor neobsahuje atribut ds:DigestMethod");
                return false;
            }
            String atr2 = nodeAtr2.toString();


            if (!Arrays.asList(supportedDigitalPrintAlgos).contains(atr2)) {
                msgs.add(atr2);
                msgs.add("\n");
                msgs.add("Podporovane algo: ");

                msgs.addAll(Arrays.asList(supportedDigitalPrintAlgos));
                msgs.add("Súbor má neplatnú hodnotu obsahu ds:DigestMethod");
                return false;
            }
        }

        return true;
    }

    private boolean isValidSignatureMethodAndCanonicalizationMethod(Document parsedXml) {
        String atr1 = findNode(parsedXml, "ds:SignatureMethod").getAttributes().getNamedItem("Algorithm").toString();
        String atr2 = findNode(parsedXml, "ds:CanonicalizationMethod").getAttributes().getNamedItem("Algorithm").toString();

        String atr2Valid = "Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"";


        if (Arrays.asList(supportedSignatureAlgos).contains(atr1)) {
            if (atr2Valid.equals(atr2)) {
                return true;
            } else {
                msgs.add(atr2);
                msgs.add(atr2Valid);
                msgs.add("Súbor má neplatnú hodnotu obsahu ds:CanonicalizationMethod");
                return false;
            }
        } else {
            msgs.add(atr1);
            msgs.add("\n");
            msgs.add("Podporovane algo: ");

            msgs.addAll(Arrays.asList(supportedSignatureAlgos));
            msgs.add(String.valueOf(Arrays.asList(supportedSignatureAlgos).contains(atr1)));
            msgs.add("Súbor má neplatnú hodnotu obsahu ds:SignatureMethod");
            return false;
        }


    }

    private boolean isValidDatovaObalka(Document parsedXml) {
//        parsedXml.getDocumentURI()
        String atr1 = findNode(parsedXml, "xzep:DataEnvelope").getAttributes().getNamedItem("xmlns:xzep").toString();
        String atr2 = findNode(parsedXml, "xzep:DataEnvelope").getAttributes().getNamedItem("xmlns:ds").toString();

        String atr1Valid = "xmlns:xzep=\"http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0\"";
        String atr2Valid = "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"";


        if (atr1.equals(atr1Valid)) if (atr2.equals(atr2Valid)) {
            return true;
        }

        msgs.add(atr1);
        msgs.add(atr1Valid);
        msgs.add(String.valueOf(atr1.equals(atr1Valid)));

        msgs.add(atr2);
        msgs.add(atr2Valid);
        msgs.add(String.valueOf(atr2.equals(atr2Valid)));
        msgs.add("Súbor má neplatnú hodnotu koreňových elementov xmlns:xzep a xmlns:ds");
        return false;
    }

    private Node findNode(Document parsedXml, String elementName) {
        return parsedXml.getElementsByTagName(elementName).item(0);
    }

    private Node findChildNodeOf(Node node, String elementName) {
        NodeList nodeList = node.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node childNode = nodeList.item(i);
            if (childNode.getNodeName().equals(elementName)) {
                return childNode;
            }
        }
        //TODO tento vypis zakmentovat na konci, ked bude hotovo. Nesedi to v output file
        msgs.add("Chyba pri ziskavani elementu " + elementName + ". Element nebol v dokumente najdeny");
        return null;
    }

    private List<Node> findChildNodesWithName(Node node, String elementName) {
        NodeList nodeList = node.getChildNodes();
        List<Node> childNodeList = new ArrayList<>();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node childNode = nodeList.item(i);

            if (childNode.getNodeName().equals(elementName)) {
                childNodeList.add(childNode);
            } else {
                childNodeList.addAll(findChildNodesWithName(childNode, elementName));
            }
        }
        return childNodeList;
    }

    private NodeList findAllNodes(Document parsedXml, String elementName) {
        return parsedXml.getElementsByTagName(elementName);
    }

    private void debugNodeValues(Document parsedXml, String elementName, String atrName) {
        Node node = parsedXml.getElementsByTagName(elementName).item(0);
        if (node != null) {
            msgs.add(node.toString());
            msgs.add("node text: " + node.getTextContent());
            msgs.add("node name: " + node.getNodeName());
            msgs.add("node value: " + node.getNodeValue());
            msgs.add("namespace: " + node.getNamespaceURI());
            msgs.add("Attr: " + node.getAttributes());
            msgs.add("Attr2: " + node.getAttributes().getNamedItem(atrName));
        }

    }

    private Document buildXml(File xmlFile) {
        DocumentBuilder documentBuilder = null;
        try {
            documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            return documentBuilder.parse(xmlFile);
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new RuntimeException(e);
        }

    }


    private ArrayList<File> loadFilesToVerify() {
        String rootPath = "./resources/input_files/";
        ArrayList<File> files = new ArrayList<>();
        try {
            Files.walk(Paths.get(rootPath)).filter(Files::isRegularFile).forEach(p -> {
                files.add(new File(p.toUri()));
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return files;
    }
}
