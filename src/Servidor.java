import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Servidor {

    private static final int SERVER_PORT = 3400;
    private KeyPair rsaKeyPair;
    private Map<String, String> packageStatusTable;

    public Servidor() throws Exception {
        packageStatusTable = new HashMap<>();
        initPackageStatusTable();
    }

    private void initPackageStatusTable() {
        packageStatusTable.put("001", "ENOFICINA");
        packageStatusTable.put("002", "RECOGIDO");
        packageStatusTable.put("003", "ENENTREGA");
        packageStatusTable.put("004","ENCLASIFICADO");
        packageStatusTable.put("005","DESPACHADO");
        packageStatusTable.put("006","ENTREGADO");
        packageStatusTable.put("007","DESCONOCIDO");
    }

    public void start() throws Exception {
        ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
        System.out.println("Servidor iniciado en el puerto " + SERVER_PORT);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Cliente conectado: " + clientSocket.getInetAddress());
            new Thread(new ClientHandler(clientSocket, rsaKeyPair, packageStatusTable)).start();
        }
    }

    private void generateAndSaveKeys() throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024);
        rsaKeyPair = keyPairGen.generateKeyPair();

        try (FileOutputStream fos = new FileOutputStream("publicKey.key")) {
            fos.write(rsaKeyPair.getPublic().getEncoded());
        }

        try (FileOutputStream fos = new FileOutputStream("privateKey.key")) {
            fos.write(rsaKeyPair.getPrivate().getEncoded());
        }

        System.out.println("Llaves RSA generadas y guardadas en archivos.");
        System.out.println("La llave pública está en 'publicKey.key' y la llave privada en 'privateKey.key'.");
    }

    public static void main(String[] args) {
        try {
            Servidor servidor = new Servidor();
            Scanner scanner = new Scanner(System.in);

            while (true) {
                System.out.println("Menú del Servidor:");
                System.out.println("1. Generar llaves RSA y guardarlas en archivos");
                System.out.println("2. Iniciar servidor");
                System.out.print("Seleccione una opción: ");
                int opcion = scanner.nextInt();

                if (opcion == 1) {
                    servidor.generateAndSaveKeys();
                } else if (opcion == 2) {
                    servidor.generateAndSaveKeys();
                    servidor.start();
                } else {
                    System.out.println("Opción inválida. Por favor, seleccione nuevamente.");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}



