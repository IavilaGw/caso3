import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.math.BigInteger;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class Cliente {

    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 3400;
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private SecretKey aesKey;
    private Mac hmac;

    public Cliente() throws Exception {
        this.socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        this.out = new ObjectOutputStream(socket.getOutputStream());
        this.in = new ObjectInputStream(socket.getInputStream());

        initDHKeyExchange();
    }

    /**
     * Realiza el intercambio de claves usando Diffie-Hellman (DH) y establece
     * claves compartidas para AES y HMAC.
     */
    private void initDHKeyExchange() throws Exception {
        PublicKey serverPubKey = readServerPublicKey("publicKey.key");
        sendInitialHandshake();

        // Generar y enviar un reto cifrado
        String challenge = generateRandomChallenge();
        byte[] encryptedChallenge = encryptWithRSA(challenge.getBytes(), serverPubKey);
        out.writeObject(encryptedChallenge);

        // Verificar respuesta del servidor
        String serverResponse = (String) in.readObject();
        if (serverResponse.equals(challenge)) {
            out.writeObject("OK");
            validateAndExchangeDHKeys(serverPubKey);
        } else {
            System.out.println("La respuesta fue incorrecta");
            out.writeObject("ERROR");
        }
    }

    /**
     * Lee la clave pública del servidor desde un archivo.
     */
    private PublicKey readServerPublicKey(String filePath) throws Exception {
        // byte[] pubKeyBytes = new byte[1024];
        // try (FileInputStream fis = new FileInputStream(filePath)) {
        // fis.read(pubKeyBytes);
        // }

        // KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // return keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

        // Lee el archivo como bytes (formato DER)
        byte[] pubKeyBytes = Files.readAllBytes(Paths.get(filePath));

        // Genera la clave pública usando X.509
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));
    }

    /**
     * Envía una señal de inicio de sesión segura al servidor.
     */
    private void sendInitialHandshake() throws Exception {
        out.writeObject("SECINIT");
        System.out.println("Palabra 'SECINIT' enviada");
    }

    /**
     * Genera un reto aleatorio como parte de la autenticación.
     */
    private String generateRandomChallenge() {
        int min = 100000000;
        int randomInt = new Random().nextInt() + min;
        String challenge = String.valueOf(randomInt);
        System.out.println("Reto generado: " + challenge);
        return challenge;
    }

    /**
     * Cifra datos usando RSA y la clave pública del servidor.
     */
    private byte[] encryptWithRSA(byte[] data, PublicKey pubKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return rsaCipher.doFinal(data);
    }

    /**
     * Valida la firma del servidor y realiza el intercambio de claves
     * Diffie-Hellman (DH).
     */
    private void validateAndExchangeDHKeys(PublicKey serverPubKey) throws Exception {
        BigInteger p = (BigInteger) in.readObject();
        BigInteger g = (BigInteger) in.readObject();
        BigInteger serverResult = (BigInteger) in.readObject();
        byte[] receivedSignature = (byte[]) in.readObject();

        if (verifyServerSignature(p, g, serverResult, receivedSignature, serverPubKey)) {
            System.out.println("Firma verificada exitosamente.");
            out.writeObject("OK");

            BigInteger sharedSecret = performDHExchange(p, g, serverResult);
            deriveAESAndHMACKeys(sharedSecret);
        } else {
            System.out.println("La firma no coincide con el mensaje.");
            out.writeObject("ERROR");
        }
    }

    /**
     * Verifica la firma del servidor para autenticar el intercambio de claves DH.
     */
    private boolean verifyServerSignature(BigInteger p, BigInteger g, BigInteger result, byte[] signature,
            PublicKey pubKey) throws Exception {
        ByteBuffer buffer = ByteBuffer
                .allocate(p.toByteArray().length + g.toByteArray().length + result.toByteArray().length);
        buffer.put(p.toByteArray()).put(g.toByteArray()).put(result.toByteArray());

        Signature sigVerify = Signature.getInstance("SHA1withRSA");
        sigVerify.initVerify(pubKey);
        sigVerify.update(buffer.array());
        return sigVerify.verify(signature);
    }

    /**
     * Realiza el cálculo de Diffie-Hellman y genera la clave secreta compartida.
     */
    private BigInteger performDHExchange(BigInteger p, BigInteger g, BigInteger serverResult) throws Exception {
        BigInteger y = new BigInteger(p.subtract(BigInteger.ONE).bitLength(), new SecureRandom());
        BigInteger clientResult = g.modPow(y, p);
        out.writeObject(clientResult);
        return serverResult.modPow(y, p);
    }

    /**
     * Deriva las claves para AES y HMAC usando SHA-512 sobre el secreto compartido.
     */
    private void deriveAESAndHMACKeys(BigInteger sharedSecret) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(sharedSecret.toByteArray());

        byte[] encryptionKey = new byte[32];
        byte[] hmacKey = new byte[32];
        System.arraycopy(digest, 0, encryptionKey, 0, 32);
        System.arraycopy(digest, 32, hmacKey, 0, 32);

        aesKey = new SecretKeySpec(encryptionKey, "AES");
        hmac = Mac.getInstance("HmacSHA384");
        hmac.init(new SecretKeySpec(hmacKey, "HmacSHA384"));

        System.out.println("Clave para cifrado (256 bits): " + bytesToHex(encryptionKey));
        System.out.println("Clave para HMAC (256 bits): " + bytesToHex(hmacKey));
    }

    /**
     * Inicializa el IV, cifra y firma datos de usuario, y los envía al servidor.
     */
    private void initializeIVAndSendSecureData() throws Exception {
        byte[] iv = (byte[]) in.readObject();
        System.out.println("IV recibido: " + bytesToHex(iv));

        System.out.println("Cliente conectado al servidor en " + SERVER_ADDRESS + ":" + SERVER_PORT);

        Random random = new Random();
        String uId = String.valueOf(random.nextInt(10));
        String packageId = "00" + random.nextInt(1, 8);

        byte[] uIdEncrypted = encryptWithAES(uId.getBytes(), iv);
        byte[] uIdHmac = hmac.doFinal(uId.getBytes());

        byte[] packageIdEncrypted = encryptWithAES(packageId.getBytes(), iv);
        byte[] packageIdHmac = hmac.doFinal(packageId.getBytes());

        sendEncryptedAndSignedData(uIdEncrypted, uIdHmac, packageIdEncrypted, packageIdHmac);
        receiveAndValidateResponse(iv);
    }

    /**
     * Cifra datos usando AES.
     */
    private byte[] encryptWithAES(byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    /**
     * Envía los datos cifrados y firmados al servidor.
     */
    private void sendEncryptedAndSignedData(byte[] uIdEncrypted, byte[] uIdHmac, byte[] packageIdEncrypted,
            byte[] packageIdHmac) throws Exception {
        out.writeObject(uIdEncrypted);
        out.writeObject(uIdHmac);
        out.writeObject(packageIdEncrypted);
        out.writeObject(packageIdHmac);
    }

    /**
     * Convierte un arreglo de bytes a una representación hexadecimal.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Recibe la respuesta del servidor y la valida
     */
    public void receiveAndValidateResponse(byte[] iv) throws Exception {
        byte[] encryptedResponse = (byte[]) in.readObject();
        byte[] hmacValue = (byte[]) in.readObject();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] decryptedResponse = cipher.doFinal(encryptedResponse);

        byte[] calculatedHmac = hmac.doFinal(decryptedResponse);
        if (!MessageDigest.isEqual(calculatedHmac, hmacValue)) {
            System.err.println("Error en la consulta: HMAC no coincide.");
            return;
        }
        String fin = "TERMINAR";
        out.writeObject(fin);
        System.out.println("Respuesta del servidor: " + new String(decryptedResponse));
    }

     public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Seleccione el número de delegados para el cliente (4, 8, o 32): ");
            int numDelegados = scanner.nextInt();
            scanner.close();

            ExecutorService executor = Executors.newFixedThreadPool(numDelegados);

            for (int i = 0; i < numDelegados; i++) {
                executor.execute(() -> {
                    try {
                        Cliente cliente = new Cliente();
                        cliente.initializeIVAndSendSecureData();
                    } catch (Exception e) {
                        System.err.println("Error en la conexión del cliente delegado.");
                        e.printStackTrace();
                    }
                });
            }

            executor.shutdown();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
