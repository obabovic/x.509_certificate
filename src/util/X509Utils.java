/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package util;

import implementation.MyCode;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import model.UIParameters;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import static org.bouncycastle.asn1.x509.X509Extensions.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import sun.security.x509.X509CertImpl;

/**
 *
 * @author obabovic
 */
public class X509Utils {
  private static KeyStore keyStore;
  private static X509Utils instance = null;
  private static String keyStorePassword = "123";
  private static String keyStoreFileName = "keystore";
  
  public X509Utils() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    keyStore = KeyStore.getInstance("BKS", "BC");
  }
  
  public KeyStore loadKeyStore() {
    try {
      keyStore = X509Utils.getInstance().getKeyStore();
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
      return null;
    }
    
    try {
      InputStream readStream = new FileInputStream(X509Utils.getKeyStoreFileName());
      keyStore.load(readStream, X509Utils.getKeyStorePassword().toCharArray());
      readStream.close();
    } catch (Exception ex) {
      try {
        keyStore.load(null,null);
      } catch (Exception ex1) {
        Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex1);
      }
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return keyStore;
  }
  
  public void storeKeyStore() {
    OutputStream writeStream;
    try {
      writeStream = new FileOutputStream(keyStoreFileName);
      keyStore.store(writeStream, keyStorePassword.toCharArray());
      writeStream.close();
    } catch (Exception ex) {
      Logger.getLogger(X509Utils.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  //issuerDN is passed only if the certificate is not being self signed
  public X509Certificate generateCertificate(UIParameters uiParams, PublicKey pubKey, PrivateKey privKey, boolean selfSigned, Principal issuerDN) throws GeneralSecurityException, IOException, Exception {
    X509Certificate result = null;
    X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
    X500Principal xp = new X500Principal(uiParams.getDn());
    
    certGen.setSerialNumber(uiParams.getSerialNumber());
    certGen.setIssuerDN(selfSigned?xp:new X500Principal(issuerDN.toString()));
    certGen.setNotBefore(uiParams.getNotBefore());
    certGen.setNotAfter(uiParams.getNotAfter());
    certGen.setSubjectDN(xp);
    certGen.setPublicKey(pubKey);
//    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find();
    //adding extensions
    //key ids
    if(uiParams.isExtensionKeyIdentifier()) {
      //converting a string into valid format for authorityKeyIdentifier
      List<GeneralName> names = new ArrayList();
      GeneralName altName = new GeneralName(GeneralName.dNSName, uiParams.getCommonName());
      names.add(altName);
      GeneralName [] listToArray = new GeneralName[names.size()];
      names.toArray(listToArray);
      GeneralNames authorityName = new GeneralNames(listToArray);
      
      SubjectKeyIdentifier sKID = new SubjectKeyIdentifier(pubKey.getEncoded());
      AuthorityKeyIdentifier aKID = new AuthorityKeyIdentifier(authorityName, uiParams.getSerialNumber());
      
      //sKID and aKID must not be critical, fro mdocumentation
      certGen.addExtension(Extension.subjectKeyIdentifier, false, sKID);
      certGen.addExtension(Extension.authorityKeyIdentifier, false, aKID);
    }
    
    //Alternative names
    if(uiParams.getExtensionsubjectAlternativeName().length > 0) {
      List<GeneralName> names = new ArrayList();
      for(String name: uiParams.getExtensionsubjectAlternativeName()) {
        GeneralName altName = new GeneralName(GeneralName.dNSName, name);
        names.add(altName);
      }
      GeneralName [] listToArray = new GeneralName[names.size()];
      names.toArray(listToArray);
      GeneralNames subjectAltName = new GeneralNames(listToArray);
      certGen.addExtension(Extension.subjectAlternativeName, uiParams.isExtensionSubjectAlternativeNameIsCritical(), subjectAltName); 
    }
    
    
    //Basic constraints
    BasicConstraints basicConstraint;
    if(uiParams.isExtensionIsCertificateAuthority()) {
      Integer pathLen = 0;
      if(uiParams.getExtensionPathLength().compareTo("") != 0) 
        pathLen = Integer.parseInt(uiParams.getExtensionPathLength());
        
      basicConstraint = new BasicConstraints(pathLen);
    } else {
      basicConstraint = new BasicConstraints(false);
    }
    
    certGen.addExtension(X509Extensions.BasicConstraints, uiParams.isExtensionBasicConstraintsIsCritical(), basicConstraint);
    
    certGen.setSignatureAlgorithm(uiParams.getSignatureAlgorithm());
    result = certGen.generateX509Certificate(privKey, "BC");
    return result;
  }
  
  public static X509Certificate sign(PKCS10CertificationRequest inputCSR, KeyStore.PrivateKeyEntry subjectEntry, KeyStore.PrivateKeyEntry issuerEntry)
        throws InvalidKeyException, NoSuchAlgorithmException,
        NoSuchProviderException, SignatureException, IOException,CertificateException, Exception {   
    PrivateKey caPrivate = issuerEntry.getPrivateKey();
    KeyPair pair = new KeyPair(subjectEntry.getCertificate().getPublicKey(), subjectEntry.getPrivateKey());
    X509Certificate issuerCert = (X509Certificate) issuerEntry.getCertificate();
    X509Certificate subjectCert = (X509Certificate) subjectEntry.getCertificate();
    String issuerSigAlgName = (issuerCert.getPublicKey().getAlgorithm().compareTo("DSA")==0)?"SHA1withDSA":issuerCert.getSigAlgName();
    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(issuerSigAlgName);
    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

    AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivate.getEncoded());
    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
    
    //in newer version of BC such as 1.51, this is 
    PKCS10CertificationRequest pk10Holder = inputCSR;
    
    X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(new X500Name(issuerCert.getSubjectDN().toString()), subjectCert.getSerialNumber(), subjectCert.getNotBefore(), subjectCert.getNotAfter(), pk10Holder.getCertificationRequestInfo().getSubject(), keyInfo);
    
    ContentSigner sigGen = null;
    String alg = issuerCert.getPublicKey().getAlgorithm();
    if((alg.contains("RSA"))||(alg.compareTo("RSA") == 0))
      sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(foo);
    else if((alg.contains("DSA"))||(alg.compareTo("DSA") == 0)) 
      sigGen = new BcDSAContentSignerBuilder(sigAlgId, digAlgId).build(foo);
    else if((alg.contains("EC"))||(alg.compareTo("EC") == 0)) 
      sigGen = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(foo);
    else throw new Exception("Invalid algorithm.");
    
    
    boolean subjectAndAuthorityExists = false;
    boolean isCriticalAltNames = false, isCriticalBasicConstraints = false;
    
    
    
    //checks what's critical
    Set<String> criticals = subjectCert.getCriticalExtensionOIDs();
    for(String item: criticals){
      if(item.compareTo(Extension.subjectAlternativeName.toString()) == 0) {
        isCriticalAltNames = true;
      } else if (item.compareTo(Extension.basicConstraints.toString()) == 0) {
        isCriticalBasicConstraints = true;
      }
    }
    
    //set key identifier
    //converting a string into valid format for authorityKeyIdentifier
    LdapName ln = new LdapName(subjectCert.getSubjectDN().toString());
    String CN = null;
    
    int i = 1; // used for mapping DN attributes to fields
    for(Rdn rdn : ln.getRdns()) {
        if(rdn.getType().compareTo("CN") == 0)
          CN = (String) rdn.getValue();
    }
    List<GeneralName> names = new ArrayList();
    GeneralName altName = new GeneralName(GeneralName.dNSName, CN.toString());
    names.add(altName);
    GeneralName [] listToArray = new GeneralName[names.size()];
    names.toArray(listToArray);
    GeneralNames authorityName = new GeneralNames(listToArray);

    SubjectKeyIdentifier sKID = new SubjectKeyIdentifier(pair.getPublic().getEncoded());
    AuthorityKeyIdentifier aKID = new AuthorityKeyIdentifier(authorityName, subjectCert.getSerialNumber());

    //sKID and aKID must not be critical, from documentation
    certGen.addExtension(Extension.subjectKeyIdentifier, false, sKID);
    certGen.addExtension(Extension.authorityKeyIdentifier, false, aKID);
    
    
    //set sub alt names
    i=0;
    Collection sANsCollection = subjectCert.getSubjectAlternativeNames();
    names = new ArrayList();
    
    if(sANsCollection != null) {
      for (Iterator iterator = sANsCollection.iterator(); iterator.hasNext();) {
        List<Object> nameTypePair = (List<Object>) iterator.next();   
        Integer typeOfAlternativeName = (Integer)nameTypePair.get(0);
        String alternativeName = (String) nameTypePair.get(1);

        altName = new GeneralName(GeneralName.dNSName, alternativeName);
        names.add(altName);
      }
      listToArray = new GeneralName[names.size()];
      names.toArray(listToArray);
      GeneralNames subjectAltName = new GeneralNames(listToArray);
      certGen.addExtension(Extension.subjectAlternativeName, isCriticalAltNames, subjectAltName); 
    }
    
    
    
    
    byte sKIDb[] = subjectCert.getExtensionValue(Extension.subjectKeyIdentifier.toString());
    
    //checks if key identifier exists
    if(sKIDb != null) {
      subjectAndAuthorityExists = true;
    }
    
    //set the certs basic constraint
    BasicConstraints basicConstraints = null;
    byte[] extVal = subjectCert.getExtensionValue(Extension.basicConstraints.toString());
    
    Object obj = new ASN1InputStream(extVal).readObject();
    extVal = ((DEROctetString) obj).getOctets();
    obj = new ASN1InputStream(extVal).readObject();
    basicConstraints = BasicConstraints.getInstance((ASN1Sequence) obj);
    
    certGen.addExtension(Extension.basicConstraints, isCriticalBasicConstraints, basicConstraints.getEncoded());
    
    
    
    
    X509CertificateHolder holder = certGen.build(sigGen);
    Certificate eeX509CertificateStructure = holder.toASN1Structure(); 

    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
    
    // Read Certificate
    InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
    X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
    is1.close();
    return theCert;
    //return null;
}

  public static X509Utils getInstance() throws Exception {
    if(instance == null)
      instance = new X509Utils();
    return instance;
  }
  
  public KeyStore getKeyStore() {
    return instance.keyStore;
  }

  public static String getKeyStorePassword() {
    return keyStorePassword;
  }

  public static String getKeyStoreFileName() {
    return keyStoreFileName;
  }
}
