package assinaturaxml;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.crypto.MarshalException;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class AssinaturaXML {

    public static void main(String[] args) throws Exception {
        
        // Definição das variáveis usadas como parâmetro na função assinar().
        final String localDocumento = "src/arquivos/purchaseOrder.xml";
        final String localKeystore = "src/arquivos/keystore";
        final String senhaKeystore = "changeit";
        final String nomePrivateKey = "mykey";
        final String senhaPrivateKey = "changeit";
        final String localDocumentoAssinado = "src/arquivos/signedPurchaseOrder.xml";
        
        AssinaturaXML sign = new AssinaturaXML();
        sign.assinar(localDocumento, localKeystore, senhaKeystore, nomePrivateKey, senhaPrivateKey, localDocumentoAssinado);
    }
    
    public void assinar(String localDocumento, String localKeystore, String senhaKeystore, 
        String nomePrivateKey, String senhaPrivateKey, String localDocumentoAssinado) 
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, 
        ParserConfigurationException, FileNotFoundException, SAXException, IOException, 
        KeyStoreException, CertificateException, UnrecoverableEntryException, MarshalException, 
        XMLSignatureException, TransformerConfigurationException, TransformerException, Exception{
        
        // Crie um XMLSignatureFactory que será usado para gerar a assinatura.
        XMLSignatureFactory fabrica = XMLSignatureFactory.getInstance();
        
        // Crie uma referência ao documento envelopado com "" assinando o documento inteiro.
        Reference referencia = fabrica.newReference("", fabrica.newDigestMethod(DigestMethod.SHA256, null),
            Collections.singletonList(fabrica.newTransform(Transform.ENVELOPED, 
            (TransformParameterSpec) null)), null, null);

        // Cria a SingnedInfo com os métodos utilizados pela assinatura.
        SignedInfo infoAssinatura = fabrica.newSignedInfo(fabrica.newCanonicalizationMethod
            (CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
            fabrica.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null), 
            Collections.singletonList(referencia));

        // Instancia o documento.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document documento = dbf.newDocumentBuilder().parse (new FileInputStream(localDocumento));
        
        // Carrega a KeyStore a Chave Privada e o Certificado.
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(localKeystore), senhaKeystore.toCharArray());
        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry
            (nomePrivateKey, new KeyStore.PasswordProtection(senhaPrivateKey.toCharArray()));
        X509Certificate certificado = (X509Certificate) keyEntry.getCertificate();
        
        // Cria o KeyInfo com as informações do Certificado.
        KeyInfoFactory kif = fabrica.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(certificado.getSubjectX500Principal().getName());
        x509Content.add(certificado);
        X509Data xdata = kif.newX509Data(x509Content);
        KeyInfo infoKey = kif.newKeyInfo(Collections.singletonList(xdata));
            
        // Cria um DOMSignContext especificando a Chave Privada e o Documento.
        DOMSignContext contexto = new DOMSignContext(keyEntry.getPrivateKey(), documento.getDocumentElement());

        // Cria a AssinaturaXML.
        XMLSignature signature = fabrica.newXMLSignature(infoAssinatura, infoKey);
        signature.sign(contexto);
        System.out.println("O documento foi assinado.");

        // Cria o documento assinado no local designado.
        OutputStream documentoAssinado = new FileOutputStream(localDocumentoAssinado);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer();
        t.transform(new DOMSource(documento), new StreamResult(documentoAssinado));
        
        // Função para verificar a validade da assinatura utilizando a Chave Pública.
        PublicKey pubkey = certificado.getPublicKey();
        AssinaturaXML verif = new AssinaturaXML();
        verif.verificar(pubkey, localDocumentoAssinado);    
    }    
    
    public void verificar(PublicKey pubKey, String localDocumentoAssinado) throws Exception {
			
	// Carrega o documento assinado.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document documentoAssinado = dbf.newDocumentBuilder().parse(new FileInputStream(localDocumentoAssinado));

        // Seleciona a TAG Signature do arquivo de XML.
        boolean valido;
        NodeList node = documentoAssinado.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (node.getLength() == 0) {
            valido = false;
        } else {
            XMLSignatureFactory fabrica = XMLSignatureFactory.getInstance();
            DOMValidateContext contextoValido = new DOMValidateContext(pubKey, node.item(0));

            // Unmarshal a AssinaturaXML e verifica sua validade.
            XMLSignature signatureVal = fabrica.unmarshalXMLSignature(contextoValido);
            valido = signatureVal.validate(contextoValido);
        }
        if (valido == true){
            System.out.println("Assinatura Válida");
        }else{
            System.out.println("Assinatura Inválida");
        }
    }
}