import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.util.Map;

public class ClientHandler extends Thread {

    private Socket clientSocket;
    private KeyPair rsaKeyPair;
    private SecretKey aesKey;
    private Map<String, String> packageStatusTable;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private Mac hmac;

    public ClientHandler(Socket socket, KeyPair rsaKeyPair, Map<String, String> packageStatusTable) {
        this.clientSocket = socket;
        this.rsaKeyPair = rsaKeyPair;
        this.packageStatusTable = packageStatusTable;
    }

    @Override
    public void run() {
        try {
            this.out = new ObjectOutputStream(clientSocket.getOutputStream());
            this.in = new ObjectInputStream(clientSocket.getInputStream());

            establishSessionKey();
            while (true) {
                receiveAndProcessRequest();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void establishSessionKey() throws Exception {
        PublicKey clientPubKey = (PublicKey) in.readObject();

        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(rsaKeyPair.getPrivate());
        keyAgree.doPhase(clientPubKey, true);

        byte[] sharedSecret = keyAgree.generateSecret();
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] keyDigest = sha512.digest(sharedSecret);

        this.aesKey = new SecretKeySpec(keyDigest, 0, 32, "AES");

        this.hmac = Mac.getInstance("HmacSHA384");
        hmac.init(aesKey);

        System.out.println("Clave de sesión AES establecida con el cliente.");
    }

    private void receiveAndProcessRequest() throws Exception {
        byte[] iv = (byte[]) in.readObject();
        byte[] encryptedRequest = (byte[]) in.readObject();
        byte[] hmacValue = (byte[]) in.readObject();

        byte[] calculatedHmac = hmac.doFinal(encryptedRequest);
        if (!MessageDigest.isEqual(calculatedHmac, hmacValue)) {
            System.err.println("Error en la consulta: HMAC no coincide.");
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        String request = new String(cipher.doFinal(encryptedRequest));

        String response = processRequest(request);

        sendEncryptedResponse(response);
    }

    private String processRequest(String request) {
        String packageId = request.split(" ")[1];  
        return packageStatusTable.getOrDefault(packageId, "DESCONOCIDO");
    }

    private void sendEncryptedResponse(String response) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getIV();
        byte[] encryptedResponse = cipher.doFinal(response.getBytes());

        byte[] hmacValue = hmac.doFinal(encryptedResponse);

        out.writeObject(iv);
        out.writeObject(encryptedResponse);
        out.writeObject(hmacValue);
    }
}
