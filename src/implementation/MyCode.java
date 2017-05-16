/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;
import code.GuiException;
import gui.KeyStorePanel;
import gui.ToolbarPanel;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import model.UIParameters;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import static org.bouncycastle.asn1.x509.X509Extensions.SubjectAlternativeName;
import static org.bouncycastle.asn1.x509.X509Extensions.SubjectKeyIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.pkcs.EncryptedPrivateKeyInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import util.UIUtils;
import util.X509Utils;
import x509.v3.CodeV3;
import x509.v3.GuiV3;
/**
 *
 * @author obabovic
 */
public class MyCode extends CodeV3 {
  private KeyPairGenerator keyGen;
  private KeyPair keyPair;
  
  public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
    super(algorithm_conf, extensions_conf);
  }
  
  public GuiV3 getAccess() {
    return access;
  }

  @Override
  public Enumeration<String> loadLocalKeystore() {
    try {
      KeyStore ks = X509Utils.getInstance().loadKeyStore();
      return ks.aliases();
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
    return null;
  }

  @Override
  public void resetLocalKeystore() {
    try {
      X509Utils.getInstance().getKeyStore().load(null,null);
      File keyStoreFile = new File(X509Utils.getKeyStoreFileName());
      keyStoreFile.delete();
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
  }

  @Override
  public int loadKeypair(String string) {
    int result = -1;
    
    try {
      Certificate[] certs = X509Utils.getInstance().getKeyStore().getCertificateChain(string);
      X509Certificate cert = (X509Certificate) certs[0];
      
      result = UIUtils.mapCertificateToUI(access, cert);
      
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
    return result;
  }
  
  @Override
  public boolean saveKeypair(String string) {
    boolean res = true;
    
    UIParameters uiParams = UIUtils.mapUIToModel(access, string);
    
    try {
      keyGen = KeyPairGenerator.getInstance("DSA");
      keyGen.initialize(Integer.parseInt(uiParams.getKeyLength()));
      keyPair = keyGen.generateKeyPair();
      X509Certificate cert = X509Utils.getInstance().generateCertificate(uiParams, keyPair);
      Certificate certs [] = {cert};
      
      X509Utils.getInstance().getKeyStore().setKeyEntry(uiParams.getName(), keyPair.getPrivate(), X509Utils.getKeyStorePassword().toCharArray(), certs);
      X509Utils.getInstance().storeKeyStore();
    } catch (IOException ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return res;
  }

  @Override
  public boolean removeKeypair(String string) {
    boolean result = false;
    
    try {
      if(X509Utils.getInstance().getKeyStore().containsAlias(string)) {
         X509Utils.getInstance().getKeyStore().deleteEntry(string);
         X509Utils.getInstance().storeKeyStore();
         result = true;
      }
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return result;
  }

  //String keypair_name, String file_name, String password
  @Override
  public boolean importKeypair(String string, String string1, String string2) {
    boolean result = false;
    
    try {
      KeyStore ks = KeyStore.getInstance("pkcs12");
      InputStream readStream = new FileInputStream(string1);
      ks.load(readStream, string2.toCharArray());
      readStream.close();
      X509Certificate cert = (X509Certificate) ks.getCertificate(string);
      Key pKey = ks.getKey(string, string2.toCharArray());
      if((cert!=null)&&(pKey!=null)) {
        Certificate certs[] = {cert};
        if(!X509Utils.getInstance().getKeyStore().containsAlias(string)) {
          X509Utils.getInstance().getKeyStore().setKeyEntry(string, pKey, X509Utils.getKeyStorePassword().toCharArray(), certs);
          X509Utils.getInstance().storeKeyStore();
          result = true;
        }
      }
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return result;
  }

  //String keypair_name, String file_name, String password
  @Override
  public boolean exportKeypair(String string, String string1, String string2) {
    boolean result = false;
    
    try {
      ProtectionParameter pp = new KeyStore.PasswordProtection(X509Utils.getKeyStorePassword().toCharArray()); 
      KeyStore ks = KeyStore.getInstance("pkcs12");
      ks.load(null,null);
      PrivateKeyEntry entry = (PrivateKeyEntry) X509Utils.getInstance().getKeyStore().getEntry(string, pp);
      Certificate certs[] = {entry.getCertificateChain()[0]};
      PrivateKey pKey = entry.getPrivateKey();
      ks.setKeyEntry(string, pKey, string2.toCharArray(), certs);
      OutputStream writeStream;
    
      writeStream = new FileOutputStream(string1+".p12");
      ks.store(writeStream, string2.toCharArray());
      writeStream.close();
      
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return result;
  }

  @Override
  public boolean signCertificate(String string, String string1) {
    return true;
  }

  @Override
  public boolean importCertificate(File file, String string) {
    return false;
  }

  @Override
  public boolean exportCertificate(File file, int i) {
    return false;
  }

  @Override
  public String getIssuer(String string) {
    return null;
  }

  @Override
  public String getIssuerPublicKeyAlgorithm(String string) {
    return null;
  }

  @Override
  public int getRSAKeyLength(String string) {
    return -1;
  }

  @Override
  public List<String> getIssuers(String string) {
    return null;
  }

  @Override
  public boolean generateCSR(String string) {
    return true;
  }
  
}
