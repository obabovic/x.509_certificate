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
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import x509.v3.CodeV3;
import x509.v3.GuiV3;
/**
 *
 * @author obabovic
 */
public class MyCode extends CodeV3 {
  

  public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
    super(algorithm_conf, extensions_conf);
    
  }
  
  public GuiV3 getAccess() {
    return access;
  }

  @Override
  public Enumeration<String> loadLocalKeystore() {
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
    
    return true;
  }

  @Override
  public boolean removeKeypair(String string) {
    return true;
  }

  @Override
  public boolean importKeypair(String string, String string1, String string2) {
    return false;
  }

  @Override
  public boolean exportKeypair(String string, String string1, String string2) {
    return false;
  }

  @Override
  public boolean signCertificate(String string, String string1) {
    return false;
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
    return false;
  }
  
}
