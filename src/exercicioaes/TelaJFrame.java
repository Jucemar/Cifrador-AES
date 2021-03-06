package exercicioaes;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 *
 * @author Guiche-03
 */
public class TelaJFrame extends javax.swing.JFrame {

    /**
     * Creates new form TelaJFrame
     */
   
    public static int tamanhoKey;
    public static CifradorAES c;

    public TelaJFrame() {
        initComponents();
        setResizable(false);
        setLocationRelativeTo(null);
        tamanhoKey=0;
        c=new CifradorAES();

    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        radioGroupButton = new javax.swing.ButtonGroup();
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        rbutton128 = new javax.swing.JRadioButton();
        rButton192 = new javax.swing.JRadioButton();
        rButton256 = new javax.swing.JRadioButton();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        txtAreaMsgPlain = new javax.swing.JTextArea();
        txtAreaKey = new javax.swing.JTextArea();
        txtAreaMsgEncrypet = new javax.swing.JTextArea();
        descriptar = new javax.swing.JButton();
        encriptar = new javax.swing.JButton();
        llimpar = new javax.swing.JButton();
        labelErro = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder("Encriptar"));

        jLabel1.setText("Mensagem plana:");

        radioGroupButton.add(rbutton128);
        rbutton128.setText("128 bits");
        rbutton128.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rbutton128ActionPerformed(evt);
            }
        });

        radioGroupButton.add(rButton192);
        rButton192.setText("192 bits");
        rButton192.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rButton192ActionPerformed(evt);
            }
        });

        radioGroupButton.add(rButton256);
        rButton256.setText("256 bits");
        rButton256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rButton256ActionPerformed(evt);
            }
        });

        jLabel2.setText("Tamanho da chave:");

        jLabel3.setText("Chave gerada:");

        jLabel4.setText("Mensagem criptografada:");

        txtAreaMsgPlain.setColumns(20);
        txtAreaMsgPlain.setLineWrap(true);
        txtAreaMsgPlain.setRows(5);
        txtAreaMsgPlain.setWrapStyleWord(true);

        txtAreaKey.setColumns(20);
        txtAreaKey.setRows(5);

        txtAreaMsgEncrypet.setColumns(20);
        txtAreaMsgEncrypet.setLineWrap(true);
        txtAreaMsgEncrypet.setRows(5);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(txtAreaMsgPlain)
                    .addComponent(txtAreaKey)
                    .addComponent(txtAreaMsgEncrypet)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2)
                            .addComponent(jLabel3)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(rbutton128)
                                .addGap(18, 18, 18)
                                .addComponent(rButton192)
                                .addGap(18, 18, 18)
                                .addComponent(rButton256))
                            .addComponent(jLabel4))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel1Layout.createSequentialGroup()
                    .addGap(10, 10, 10)
                    .addComponent(jLabel1)
                    .addContainerGap(382, Short.MAX_VALUE)))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(28, 28, 28)
                .addComponent(txtAreaMsgPlain, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(rbutton128)
                    .addComponent(rButton192)
                    .addComponent(rButton256))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(txtAreaKey, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(txtAreaMsgEncrypet, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel1Layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(jLabel1)
                    .addContainerGap(286, Short.MAX_VALUE)))
        );

        descriptar.setText("Decriptar");
        descriptar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                descriptarActionPerformed(evt);
            }
        });

        encriptar.setText("Encriptar");
        encriptar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encriptarActionPerformed(evt);
            }
        });

        llimpar.setText("Limpar");
        llimpar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                llimparActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(labelErro, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGap(18, 18, 18)
                        .addComponent(llimpar)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(encriptar)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(descriptar)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(descriptar)
                        .addComponent(encriptar)
                        .addComponent(llimpar))
                    .addComponent(labelErro))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void rbutton128ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rbutton128ActionPerformed
        tamanhoKey = 128;
        System.out.println(tamanhoKey);
    }//GEN-LAST:event_rbutton128ActionPerformed

    private void rButton192ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rButton192ActionPerformed
        tamanhoKey = 192;
        System.out.println(tamanhoKey);
    }//GEN-LAST:event_rButton192ActionPerformed

    private void descriptarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_descriptarActionPerformed
       
        if(txtAreaKey.getText().length()>0 && txtAreaMsgEncrypet.getText().length()>0){
            labelErro.setText("");
        String encripted=txtAreaMsgEncrypet.getText().trim();
        char[] ca=encripted.toCharArray();
         byte[] ba = null;
        
         try {
             ba = Hex.decodeHex(ca);
         } catch (DecoderException ex) {
             Logger.getLogger(TelaJFrame.class.getName()).log(Level.SEVERE, null, ex);
         }
        
         
         
         
        byte[] retr = null;
        try {
           
            
            
            byte[] decodedKey = Base64.getDecoder().decode(txtAreaKey.getText().trim());

            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
            c.setChaveSecreta(originalKey);
            
            retr = c.decrypt(ba);
        } catch (DataLengthException ex) {

        } catch (InvalidCipherTextException ex) {

        }

//        if (retr.length == ba.length) {
//            ba = retr;
//        } else {
//            System.arraycopy(retr, 0, ba, 0, ba.length);
//        }

        ba = retr;
        String decrypted = null;
        try {
            decrypted = new String(ba, "UTF-8");
        } catch (UnsupportedEncodingException ex) {

        }
        System.out.println(decrypted);
        System.out.println( Base64.getEncoder().encodeToString(c.getChaveSecreta().getEncoded()));
        txtAreaMsgPlain.setText(decrypted);
        }else{
            labelErro.setText("Falta a mensagem cifrada e a key");
        }
        
    }//GEN-LAST:event_descriptarActionPerformed

    private void encriptarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encriptarActionPerformed

        if(txtAreaMsgPlain.getText().length()>0 && tamanhoKey>0){
            labelErro.setText("");
        
       

        try {
            c.gerarChave(tamanhoKey);
            String encodedKey = Base64.getEncoder().encodeToString(c.getChaveSecreta().getEncoded());
            txtAreaKey.setText(encodedKey);
            
        } catch (NoSuchAlgorithmException ex) {
           
        }

        String secret = txtAreaMsgPlain.getText().trim();
        System.out.println(secret);
        byte[] ba = null;
        try {
            ba = secret.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
           
        }

        
        byte[] encr = null;
        try {
            encr = c.encrypt(ba);
        } catch (DataLengthException ex) {

        } catch (InvalidCipherTextException ex) {

        }
        System.out.println("Encrypted : "+ Hex.encodeHexString(encr));
        
        txtAreaMsgEncrypet.setText(Hex.encodeHexString(encr));
        }else{
            labelErro.setText("Falta a mensagem limpa e o tamanho da chave");
        }
    }//GEN-LAST:event_encriptarActionPerformed

    private void rButton256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rButton256ActionPerformed
        tamanhoKey = 256;
        System.out.println(tamanhoKey);
    }//GEN-LAST:event_rButton256ActionPerformed

    private void llimparActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_llimparActionPerformed
txtAreaKey.setText("");
txtAreaMsgEncrypet.setText("");// TODO add your handling code here:
txtAreaMsgPlain.setText("");
tamanhoKey=0;
 c=new CifradorAES();
 radioGroupButton.clearSelection();
  labelErro.setText("");

    }//GEN-LAST:event_llimparActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Windows".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(TelaJFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(TelaJFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(TelaJFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(TelaJFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new TelaJFrame().setVisible(true);
            }
        });

        
    
}

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton descriptar;
    private javax.swing.JButton encriptar;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JLabel labelErro;
    private javax.swing.JButton llimpar;
    private javax.swing.JRadioButton rButton192;
    private javax.swing.JRadioButton rButton256;
    private javax.swing.ButtonGroup radioGroupButton;
    private javax.swing.JRadioButton rbutton128;
    private javax.swing.JTextArea txtAreaKey;
    private javax.swing.JTextArea txtAreaMsgEncrypet;
    private javax.swing.JTextArea txtAreaMsgPlain;
    // End of variables declaration//GEN-END:variables
}
