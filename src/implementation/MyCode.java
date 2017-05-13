/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;
import code.GuiException;
import gui.KeyStorePanel;
import gui.ToolbarPanel;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import model.UIParameters;
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
    
  }

  @Override
  public int loadKeypair(String string) {
    return 0;
  }

  @Override
  public boolean saveKeypair(String string) {
    boolean res = true;
    
    String name = string;
    String subjectCountry = access.getSubjectCountry();
    String subjectState = access.getSubjectState();
    String subjectLocality = access.getSubjectLocality();
    String subjectOrganization = access.getSubjectOrganization();
    String subjectOrganizationUnit = access.getSubjectOrganizationUnit();
    String subjectCommonName = access.getSubjectCommonName();
    String subjectSignatureAlgorithm = access.getPublicKeySignatureAlgorithm();
    int subjectCertificateVersion = access.getVersion();
    BigInteger subjectSerialNumber = new BigInteger(access.getSerialNumber());
    Date notBefore = access.getNotBefore();
    Date notAfter = access.getNotAfter();
    String keyLength = access.getPublicKeyParameter();
    String publicKeyAlgorithm = access.getPublicKeyAlgorithm();
    boolean extensionKeyIdentifier = access.getEnabledKeyIdentifiers();
    String[] extensionsubjectAlternativeName = access.getAlternativeName(5);
    String pathLength = access.getPathLen();
    boolean extensionKeyIdentifierIsCritical = access.isCritical(0);
    boolean extensionSubjectAlternativeNameIsCritical = access.isCritical(5);
    boolean extensionBasicConstraintsIsCritical = access.isCritical(8);
    boolean extensionIsCertificateAuthority = access.isCA();
    
    
    UIParameters uiParams = new UIParameters(name,subjectCountry,subjectState,subjectLocality,subjectOrganization,subjectOrganizationUnit,subjectCommonName,subjectSignatureAlgorithm, subjectCertificateVersion,subjectSerialNumber,notBefore,notAfter, keyLength, publicKeyAlgorithm, extensionKeyIdentifier,extensionsubjectAlternativeName, pathLength, extensionKeyIdentifierIsCritical, extensionSubjectAlternativeNameIsCritical, extensionBasicConstraintsIsCritical, extensionIsCertificateAuthority);
    
    try {
      keyGen = KeyPairGenerator.getInstance("DSA");
      keyPair = keyGen.generateKeyPair();
      X509Certificate cert = X509Utils.getInstance().generateCertificate(uiParams, keyPair);
      Certificate certs [] = {cert};
      X509Utils.getInstance().getKeyStore().setKeyEntry(name, keyPair.getPrivate().getEncoded(), certs);
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
    return true;
  }

  @Override
  public boolean importKeypair(String string, String string1, String string2) {
    return true;
  }

  @Override
  public boolean exportKeypair(String string, String string1, String string2) {
    return false;
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
