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
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ClientHandler2 extends Thread {

    private Socket clientSocket;
    private KeyPair rsaKeyPair;
    private Map<String, String> packageStatusTable;
    private ObjectOutputStream out;
    private ObjectInputStream in;

    public ClientHandler2(Socket socket, KeyPair rsaKeyPair, Map<String, String> packageStatusTable) {
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
        PrivateKey serverPriKey = (PrivateKey) rsaKeyPair.getPrivate();

        // Leer la palabra enviada por el cliente
        String palabra = (String) in.readObject();
        System.out.println(palabra);

        // Leer el mensaje cifrado
        byte[] retoCifrado = (byte[]) in.readObject(); // Leer el reto cifrado
        System.out.println("Reto cifrado recibido");

        // Ahora descifrar el reto
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, serverPriKey);
        byte[] textoDescifrado = cipher.doFinal(retoCifrado); // Descifrar el mensaje cifrado
        String mensajeDescifrado = new String(textoDescifrado);
        System.out.println("Reto descifrado: " + mensajeDescifrado);

        out.writeObject(mensajeDescifrado);
        System.out.println("RTa enviada");

        String respuesta = (String) in.readObject();
        System.out.println(respuesta);

        if (respuesta.equals("OK")) {
            try {
                // Ejecutar el comando OpenSSL para generar parámetros DH de 1024 bits
                Process process = Runtime.getRuntime().exec("OpenSSL-1.1.1h_win32\\openssl dhparam -text 1024");

                // Leer la salida del comando
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                StringBuilder output = new StringBuilder();

                // Almacena toda la salida en un StringBuilder
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                reader.close();

                // Esperar a que el proceso termine
                process.waitFor();

                // Imprimir la salida completa, que incluye los valores P y G
                System.out.println("Parámetros DH generados:");
                String outputStr = output.toString();
                System.out.println(outputStr);

                // Utilizar regex para encontrar el valor de P (prime) y G (generator)
                Pattern pPattern = Pattern.compile("prime:[\\s]*((?:[0-9A-Fa-f]{2}:?\\s*)+)", Pattern.MULTILINE);
                Pattern gPattern = Pattern.compile("generator:\\s*(\\d+)", Pattern.MULTILINE);

                Matcher pMatcher = pPattern.matcher(outputStr);
                Matcher gMatcher = gPattern.matcher(outputStr);

                BigInteger p = null;
                BigInteger g = null;

                // Extraer P y G si están presentes
                if (pMatcher.find()) {
                    String primeHex = pMatcher.group(1).replaceAll("[:\\s]", "");
                    p = new BigInteger(primeHex, 16); // P en hexadecimal
                } else {
                    System.out.println("No se encontró el valor de P en la salida de OpenSSL.");
                }
                if (gMatcher.find()) {
                    g = new BigInteger(gMatcher.group(1)); // G es en decimal
                } else {
                    System.out.println("No se encontró el valor de G en la salida de OpenSSL.");
                }

                System.out.println("Valor de P: " + p);
                System.out.println("Valor de G: " + g);

                // Definir el rango (por ejemplo, entre 1000 y 10000)
                BigInteger min = new BigInteger("0");
                BigInteger max = p.subtract(new BigInteger("1"));

                // Crear un objeto SecureRandom
                SecureRandom random = new SecureRandom();

                // Generar un BigInteger aleatorio dentro del rango
                BigInteger x;
                do {
                    // Generamos un BigInteger aleatorio con el mismo número de bits que el máximo
                    x = new BigInteger(max.bitLength(), random);
                } while (x.compareTo(min) < 0 || x.compareTo(max) >= 0); // Verificar que esté dentro del rango

                BigInteger result = g.modPow(x, p);

                System.out.println("G^x mod P: " + result);
                out.writeObject(p);
                out.writeObject(g);
                out.writeObject(result);

                // Convertir cada elemento a bytes y concatenarlos
                byte[] bytesP = p.toByteArray();
                byte[] bytesG = g.toByteArray();
                byte[] bytesResult = result.toByteArray();

                // Concatenar todos los bytes en un solo arreglo
                ByteBuffer buffer = ByteBuffer.allocate(bytesP.length + bytesG.length + bytesResult.length);
                buffer.put(bytesP);
                buffer.put(bytesG);
                buffer.put(bytesResult);
                byte[] mensajeBytes = buffer.array();

                // Firmar el mensaje combinado
                Signature signature = Signature.getInstance("SHA1withRSA");
                signature.initSign(serverPriKey);
                signature.update(mensajeBytes);
                byte[] digitalSignature = signature.sign();

                out.writeObject(digitalSignature);
                System.out.println("Se envio P, G, G^x y firma");

                String respuesta2 = (String) in.readObject();
                System.out.println(respuesta2);

                if (respuesta2.equals("OK")) {
                    BigInteger respuestaGy = (BigInteger) in.readObject();

                    // Calcular (G^y)^x
                    BigInteger resultadoLlave = respuestaGy.modPow(x, p);

                    BigInteger sharedSecret = resultadoLlave;

                    // Convertimos la clave compartida a un arreglo de bytes
                    byte[] sharedSecretBytes = sharedSecret.toByteArray();

                    // Usamos SHA-512 para generar un digest
                    MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                    byte[] digest = sha512.digest(sharedSecretBytes);

                    // Dividir el digest en dos mitades de 256 bits (32 bytes)
                    byte[] encryptionKey = new byte[32]; // Primeros 256 bits (32 bytes)
                    byte[] hmacKey = new byte[32]; // Últimos 256 bits (32 bytes)

                    System.arraycopy(digest, 0, encryptionKey, 0, 32); // Los primeros 256 bits para cifrado
                    System.arraycopy(digest, 32, hmacKey, 0, 32); // Los últimos 256 bits para HMAC

                    // Mostrar las claves derivadas
                    System.out.println("Clave para cifrado (256 bits): " + bytesToHex(encryptionKey));
                    System.out.println("Clave para HMAC (256 bits): " + bytesToHex(hmacKey));

                    SecretKeySpec aesKey = new SecretKeySpec(encryptionKey, "AES");

                    SecretKeySpec secretKeyHMAC = new SecretKeySpec(hmacKey, "HmacSHA384");
                    Mac hmac = Mac.getInstance("HmacSHA384");
                    hmac.init(secretKeyHMAC);

                    // Crear una instancia de SecureRandom
                    SecureRandom secureRandom = new SecureRandom();

                    // Crear un arreglo de 16 bytes (128 bits) para el IV
                    byte[] iv = new byte[16];

                    // Llenar el arreglo con datos aleatorios
                    secureRandom.nextBytes(iv);

                    // Mostrar el IV en formato hexadecimal
                    System.out.println("IV generado: " + bytesToHex(iv));

                    out.writeObject(iv);
                    System.out.println("iv enviado");

                    byte[] uIdCifradoAES = (byte[]) in.readObject();
                    byte[] uIdCifradoHMAC = (byte[]) in.readObject();
                    byte[] paqueteIdCifradoAES = (byte[]) in.readObject();
                    byte[] paqueteIdCifradoHMAC = (byte[]) in.readObject();

                    Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher2.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
                    byte[] decryptedResponse1 = cipher2.doFinal(uIdCifradoAES);
                    byte[] decryptedResponse2 = cipher2.doFinal(paqueteIdCifradoAES);

                    boolean isHMACValidForUId = verifyHMAC(decryptedResponse1, hmacKey, uIdCifradoHMAC);
                    boolean isHMACValidForPaqueteId = verifyHMAC(decryptedResponse2, hmacKey, paqueteIdCifradoHMAC);
                    if (!isHMACValidForPaqueteId && !isHMACValidForUId) {
                        throw new SecurityException("El HMAC no coincide, los datos pueden haber sido modificados.");
                    } else {
                        System.out.println("HMACs coinciden");
                        String response = processRequest(new String(decryptedResponse2));
                        cipher2.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
                        byte[] encryptedResponse = cipher2.doFinal(response.getBytes());

                        byte[] hmacValue = hmac.doFinal(response.getBytes());

                        out.writeObject(encryptedResponse);
                        out.writeObject(hmacValue);

                        String fin = (String) in.readObject();
                        System.out.println(fin);
                    }

                } else {
                    System.out.println(respuesta2 + " Se mando una firma que no coincide con el mensaje.");
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

        } else {
            System.out.println(respuesta + " Se mando una respuesta incorrecta.");
        }
    }

    // Función para verificar HMAC
    public static boolean verifyHMAC(byte[] data, byte[] hmacKey, byte[] expectedHmac) throws Exception {
        byte[] hmac = generateHMAC(data, hmacKey);
        return MessageDigest.isEqual(hmac, expectedHmac);
    }

    // Función para generar HMAC con SHA-384
    public static byte[] generateHMAC(byte[] data, byte[] hmacKey) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(hmacKey, "HmacSHA384");
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(secretKey);
        return mac.doFinal(data);
    }

    // Función auxiliar para convertir un arreglo de bytes a hexadecimal
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private String processRequest(String request) {
        String packageId = request;
        return packageStatusTable.getOrDefault(packageId, "DESCONOCIDO");
    }
}
