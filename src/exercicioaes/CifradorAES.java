
package exercicioaes;

import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;


public class CifradorAES {

    private SecretKey chaveSecreta;

    public void setChaveSecreta(SecretKey sk) {
        this.chaveSecreta = sk;
        this.key = new KeyParameter(sk.getEncoded());
    }



    public SecretKey getChaveSecreta() {
        return chaveSecreta;
    }
    private final BlockCipher AESCipher; 
    private PaddedBufferedBlockCipher pbbc;
    private KeyParameter key;

    public CifradorAES() {
        this.AESCipher = new AESEngine();
        
         this.pbbc = new PaddedBufferedBlockCipher(AESCipher);
        
    }
    

    
    
     public byte[] encrypt(byte[] input)
            throws DataLengthException, InvalidCipherTextException {
        return processar(input, true);
    }
 
    public byte[] decrypt(byte[] input)
            throws DataLengthException, InvalidCipherTextException {
        return processar(input, false);
    }
 
    private byte[] processar(byte[] input, boolean encrypt)
            throws DataLengthException, InvalidCipherTextException {
 
        pbbc.init(encrypt, key);
 
        byte[] output = new byte[pbbc.getOutputSize(input.length)];
        int bytesWrittenOut = pbbc.processBytes(
            input, 0, input.length, output, 0);
 
        pbbc.doFinal(output, bytesWrittenOut);
 
        return output;
 
    }

    public void gerarChave(int tamanho) throws NoSuchAlgorithmException {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        
        

        kg.init(tamanho);
        chaveSecreta = kg.generateKey();
        this.key = new KeyParameter(chaveSecreta.getEncoded());
    }

}
