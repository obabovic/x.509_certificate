/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package util;

import implementation.MyCode;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import model.UIParameters;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;


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
  
  public X509Certificate generateCertificate(UIParameters uiParams, KeyPair pair) throws GeneralSecurityException, IOException, Exception {
    X509Certificate result = null;
    X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
    X500Principal xp = new X500Principal(uiParams.getDn());
            
    certGen.setSerialNumber(uiParams.getSerialNumber());
    certGen.setIssuerDN(xp);
    certGen.setNotBefore(uiParams.getNotBefore());
    certGen.setNotAfter(uiParams.getNotAfter());
    certGen.setSubjectDN(xp);
    certGen.setPublicKey(pair.getPublic());
    certGen.setSignatureAlgorithm(uiParams.getSignatureAlgorithm());
    
    //adding extensions
    //Key usage
    if(uiParams.isExtensionKeyIdentifier()) {
      X509KeyUsage keyuse = new X509KeyUsage(X509KeyUsage.dataEncipherment | X509KeyUsage.nonRepudiation);
      certGen.addExtension(X509Extensions.KeyUsage, uiParams.isExtensionKeyIdentifierIsCritical(), keyuse);
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
      certGen.addExtension(X509Extensions.SubjectAlternativeName, uiParams.isExtensionSubjectAlternativeNameIsCritical(), subjectAltName); 
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
    
    
    result = certGen.generateX509Certificate(pair.getPrivate(), "BC");
    return result;
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
