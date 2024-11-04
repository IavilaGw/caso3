import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.math.BigInteger;

public class Cliente {

    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 3400;
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private SecretKey aesKey;
    private KeyPair dhKeyPair;
    private Mac hmac;

    public Cliente() throws Exception {
   
        this.socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        this.out = new ObjectOutputStream(socket.getOutputStream());
        this.in = new ObjectInputStream(socket.getInputStream());

        initDHKeyExchange();
        
        this.hmac = Mac.getInstance("HmacSHA384");
        hmac.init(aesKey);  

        System.out.println("Cliente conectado al servidor en " + SERVER_ADDRESS + ":" + SERVER_PORT);
    }

    private void initDHKeyExchange() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(1024);
        this.dhKeyPair = keyPairGen.generateKeyPair();

        out.writeObject(dhKeyPair.getPublic());

        PublicKey serverPubKey = (PublicKey) in.readObject();
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(dhKeyPair.getPrivate());
        keyAgree.doPhase(serverPubKey, true);

        byte[] sharedSecret = keyAgree.generateSecret();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-512");
        byte[] keyDigest = sha256.digest(sharedSecret);

        this.aesKey = new SecretKeySpec(keyDigest, 0, 32, "AES"); 
    }

    public void sendEncryptedMessage(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getIV();
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

        byte[] hmacValue = hmac.doFinal(encryptedMessage);

        out.writeObject(iv);
        out.writeObject(encryptedMessage);
        out.writeObject(hmacValue);
    }

    public void receiveAndValidateResponse() throws Exception {
        byte[] iv = (byte[]) in.readObject();
        byte[] encryptedResponse = (byte[]) in.readObject();
        byte[] hmacValue = (byte[]) in.readObject();

        byte[] calculatedHmac = hmac.doFinal(encryptedResponse);
        if (!MessageDigest.isEqual(calculatedHmac, hmacValue)) {
            System.err.println("Error en la consulta: HMAC no coincide.");
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] decryptedResponse = cipher.doFinal(encryptedResponse);

        System.out.println("Respuesta del servidor: " + new String(decryptedResponse));
    }

    public static void main(String[] args) {
        try {
            Cliente cliente = new Cliente();
            cliente.sendEncryptedMessage("Consulta estado del paquete 123");
            cliente.receiveAndValidateResponse();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
