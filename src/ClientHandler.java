import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.sql.Time;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ClientHandler extends Thread {

    private Socket clientSocket;
    private KeyPair rsaKeyPair;
    private Map<String, String> packageStatusTable;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private long tiempoReto;
    private long tiempoDH;

    // Constructor de la clase
    public ClientHandler(Socket socket, KeyPair rsaKeyPair, Map<String, String> packageStatusTable) {
        this.clientSocket = socket;
        this.rsaKeyPair = rsaKeyPair;
        this.packageStatusTable = packageStatusTable;
    }

    // Método principal del hilo
    @Override
    public void run() {
        try {
            this.out = new ObjectOutputStream(clientSocket.getOutputStream());
            this.in = new ObjectInputStream(clientSocket.getInputStream());

            establishSessionKey();
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

    /**
     * Establece la clave de sesión mediante un intercambio de claves Diffie-Hellman
     * y RSA.
     */
    private void establishSessionKey() throws Exception {
        PrivateKey serverPriKey = rsaKeyPair.getPrivate();

        // Leer y mostrar la palabra enviada por el cliente
        String palabra = (String) in.readObject();
        System.out.println(palabra);

        long tiempoRetoInit = System.currentTimeMillis();
        // Leer y descifrar el reto recibido del cliente
        byte[] retoCifrado = (byte[]) in.readObject();
        String mensajeDescifrado = decryptRSA(retoCifrado, serverPriKey);
        System.out.println("Reto descifrado: " + mensajeDescifrado);
        long tiempoRetoFin = System.currentTimeMillis();
        tiempoReto = tiempoRetoFin - tiempoRetoInit;
        // Enviar el reto descifrado de vuelta al cliente
        out.writeObject(mensajeDescifrado);

        // Leer respuesta del cliente
        String respuesta = (String) in.readObject();
        if ("OK".equals(respuesta)) {
            long tiempoDHInit = System.currentTimeMillis();
            // Proceso de generación y envío de parámetros Diffie-Hellman (P y G)
            BigInteger[] dhParameters = generateDHParameters();
            BigInteger p = dhParameters[0];
            BigInteger g = dhParameters[1];

            // Generación y envío del valor público del servidor G^x mod P
            BigInteger x = generateRandomExponent(p);
            BigInteger result = g.modPow(x, p);
            long tiempoDHFin = System.currentTimeMillis();
            tiempoDH = tiempoDHFin - tiempoDHInit;
            out.writeObject(p);
            out.writeObject(g);
            out.writeObject(result);

            // Firmar y enviar P, G, y el resultado (G^x mod P) al cliente
            sendDigitalSignature(p, g, result, serverPriKey);

            // Leer respuesta del cliente y calcular clave compartida
            String respuesta2 = (String) in.readObject();
            if ("OK".equals(respuesta2)) {
                BigInteger respuestaGy = (BigInteger) in.readObject();
                BigInteger sharedSecret = respuestaGy.modPow(x, p);

                // Generar claves de cifrado y HMAC
                byte[] encryptionKey = deriveKey(sharedSecret, 0, 32);
                byte[] hmacKey = deriveKey(sharedSecret, 32, 32);

                // Mostrar las claves derivadas
                System.out.println("Clave para cifrado (256 bits): " + bytesToHex(encryptionKey));
                System.out.println("Clave para HMAC (256 bits): " + bytesToHex(hmacKey));

                // Enviar un IV aleatorio al cliente
                byte[] iv = generateIV();

                // Mostrar el IV en formato hexadecimal
                System.out.println("IV generado: " + bytesToHex(iv));
                out.writeObject(iv);

                // Procesar solicitud cifrada del cliente y verificar su integridad
                processEncryptedRequest(encryptionKey, hmacKey, iv);
                String fin = (String) in.readObject();
                System.out.println(fin);
            } else {
                System.out.println("Error en la verificación de la firma enviada.");
            }
        } else {
            System.out.println("Respuesta incorrecta al reto enviado.");
        }
    }

    /**
     * Desencripta un mensaje usando RSA.
     */
    private String decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }

    /**
     * Genera parámetros Diffie-Hellman P y G utilizando OpenSSL.
     */
    private BigInteger[] generateDHParameters() throws Exception {
        Process process = Runtime.getRuntime().exec("OpenSSL-1.1.1h_win32\\openssl dhparam -text 1024");
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();

        // Leer la salida de OpenSSL y cerrar el proceso
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        reader.close();
        process.waitFor();

        // Extraer P y G usando expresiones regulares
        Pattern pPattern = Pattern.compile("prime:[\\s]*((?:[0-9A-Fa-f]{2}:?\\s*)+)", Pattern.MULTILINE);
        Pattern gPattern = Pattern.compile("generator:\\s*(\\d+)", Pattern.MULTILINE);
        Matcher pMatcher = pPattern.matcher(output);
        Matcher gMatcher = gPattern.matcher(output);

        BigInteger p = pMatcher.find() ? new BigInteger(pMatcher.group(1).replaceAll("[:\\s]", ""), 16) : null;
        BigInteger g = gMatcher.find() ? new BigInteger(gMatcher.group(1)) : null;

        return new BigInteger[] { p, g };
    }

    /**
     * Genera un exponente aleatorio dentro del rango seguro.
     */
    private BigInteger generateRandomExponent(BigInteger p) {
        BigInteger min = BigInteger.ZERO;
        BigInteger max = p.subtract(BigInteger.ONE);
        SecureRandom random = new SecureRandom();
        BigInteger x;
        do {
            x = new BigInteger(max.bitLength(), random);
        } while (x.compareTo(min) < 0 || x.compareTo(max) >= 0);
        return x;
    }

    /**
     * Genera y envía una firma digital usando SHA1 con RSA.
     */
    private void sendDigitalSignature(BigInteger p, BigInteger g, BigInteger result, PrivateKey privateKey)
            throws Exception {
        byte[] messageBytes = ByteBuffer
                .allocate(p.toByteArray().length + g.toByteArray().length + result.toByteArray().length)
                .put(p.toByteArray()).put(g.toByteArray()).put(result.toByteArray()).array();

        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(messageBytes);
        byte[] digitalSignature = signature.sign();
        out.writeObject(digitalSignature);
    }

    /**
     * Deriva claves de cifrado y HMAC a partir del secreto compartido.
     */
    private byte[] deriveKey(BigInteger sharedSecret, int offset, int length) throws NoSuchAlgorithmException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret.toByteArray());
        byte[] key = new byte[length];
        System.arraycopy(digest, offset, key, 0, length);
        return key;
    }

    /**
     * Genera un IV aleatorio de 128 bits.
     */
    private byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * Procesa la solicitud cifrada del cliente y verifica HMAC.
     */
    private void processEncryptedRequest(byte[] encryptionKey, byte[] hmacKey, byte[] iv) throws Exception {
        byte[] uIdCifradoAES = (byte[]) in.readObject();
        byte[] uIdCifradoHMAC = (byte[]) in.readObject();
        byte[] paqueteIdCifradoAES = (byte[]) in.readObject();
        byte[] paqueteIdCifradoHMAC = (byte[]) in.readObject();

        long tiempoVeriConsulInit = System.currentTimeMillis();
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new IvParameterSpec(iv));
        byte[] decryptedUId = aesCipher.doFinal(uIdCifradoAES);
        byte[] decryptedPaqueteId = aesCipher.doFinal(paqueteIdCifradoAES);

        boolean isHMACValidForUId = verifyHMAC(decryptedUId, hmacKey, uIdCifradoHMAC);
        boolean isHMACValidForPaqueteId = verifyHMAC(decryptedPaqueteId, hmacKey, paqueteIdCifradoHMAC);
        long tiempoVeriConsulFin = System.currentTimeMillis();

        
        if (isHMACValidForUId && isHMACValidForPaqueteId) {
            String response = processRequest(new String(decryptedPaqueteId));
            aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new IvParameterSpec(iv));
            byte[] encryptedResponse = aesCipher.doFinal(response.getBytes());
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(new SecretKeySpec(hmacKey, "HmacSHA384"));
            byte[] hmacValue = hmac.doFinal(response.getBytes());
            out.writeObject(encryptedResponse);
            out.writeObject(hmacValue);
        } else {
            throw new SecurityException("El HMAC no coincide, los datos pueden haber sido modificados.");
        }
    }

    /**
     * Verifica un HMAC calculado contra un valor esperado.
     */
    public static boolean verifyHMAC(byte[] data, byte[] hmacKey, byte[] expectedHmac) throws Exception {
        byte[] hmac = generateHMAC(data, hmacKey);
        return MessageDigest.isEqual(hmac, expectedHmac);
    }

    /**
     * Genera un HMAC con SHA-384.
     */
    public static byte[] generateHMAC(byte[] data, byte[] hmacKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(new SecretKeySpec(hmacKey, "HmacSHA384"));
        return mac.doFinal(data);
    }

    /**
     * Convierte un arreglo de bytes a una representación en hexadecimal.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Procesa la solicitud de consulta de estado de un paquete.
     */
    private String processRequest(String request) {
        return packageStatusTable.getOrDefault(request, "DESCONOCIDO");
    }
}
