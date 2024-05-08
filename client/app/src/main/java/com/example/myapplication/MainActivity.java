package com.example.myapplication;

import android.content.res.Resources;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import android.util.Base64;
import java.net.Socket;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.KeyStore;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLSocketFactory;


public class MainActivity extends AppCompatActivity {

    // Setup Server information
    protected static String server = "192.168.0.22";
    protected static int port = 7070;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Capturamos el boton de Enviar
        View button = findViewById(R.id.button_send);

        // Llama al listener del boton Enviar
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                showDialog();
            }
        });


    }

    // Creación de un cuadro de dialogo para confirmar pedido
    private void showDialog() throws Resources.NotFoundException {
        EditText beds = (EditText) findViewById(R.id.bedInput);
        EditText tables = (EditText) findViewById(R.id.tableInput);
        EditText chairs = (EditText) findViewById(R.id.chairInput);
        EditText armchairs = (EditText) findViewById(R.id.armchairInput);
        EditText client = (EditText) findViewById(R.id.clientInput);
        new AlertDialog.Builder(this)
            .setTitle("Enviar")
            .setMessage("Se va a proceder al envio")
            .setIcon(android.R.drawable.ic_dialog_alert)
            .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    String nBeds =  beds.getText().toString();
                    String nTables =  tables.getText().toString();
                    String nChairs =  chairs.getText().toString();
                    String nArmchairs =  armchairs.getText().toString();
                    String nClient =  client.getText().toString();
                    if  ((nBeds.isEmpty() && nTables.isEmpty() && nChairs.isEmpty() && nArmchairs.isEmpty()) || nClient.isEmpty()) {
                        Toast.makeText(getApplicationContext(), "Debe introducir al menos un elemento y el Número de cliente", Toast.LENGTH_SHORT).show();
                    }   else if ((Integer.parseInt(nBeds) > 300) || (Integer.parseInt(nTables) > 300) || (Integer.parseInt(nChairs) > 300) || (Integer.parseInt(nArmchairs) > 300)) {
                        Toast.makeText(getApplicationContext(), "No se pueden pedir más de 300 unidades de cada material", Toast.LENGTH_SHORT).show();
                    }   else {
                        String data = nBeds + '-' + nTables + '-' +nChairs + '-' +nArmchairs + '-' + nClient;
                        try {
                            String signature = signData(data, nClient);
                            String signedData = data + "--|--" + signature;
                            sendToServer(signedData);
                        } catch (Exception e) {
                            e.printStackTrace();
                            Toast.makeText(MainActivity.this, "Error while signing data:\n" + e, Toast.LENGTH_SHORT).show();
                        }
                    }
                }
            }
            )
            .setNegativeButton(android.R.string.no, null)
            .show();
        }

    private String signData(String data, String nClient) throws Exception {
        String fileName = "private_key_" + nClient + ".pem";
        InputStream keyInputStream = getAssets().open(fileName);
        byte[] keyBytes = readAllBytes(keyInputStream);
        String keyString = new String(keyBytes).replaceAll("-----\\w+ PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] decodedKey = Base64.decode(keyString, Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
        return Base64.encodeToString(signedData, Base64.DEFAULT);
    }

    private byte[] readAllBytes(InputStream inputStream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
            return stringBuilder.toString().getBytes();
        }
    }

    private void sendToServer(String data) {
        new AsyncTask<String, Void, String>() {
            @Override
            protected String doInBackground(String... params) {
                String serverResponse = "";
                SSLContext sslContext;
                try {
                    sslContext = SSLContext.getInstance("TLSv1.3");
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    InputStream caInput = getResources().openRawResource(R.raw.server);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    Certificate ca;
                    try {
                        ca = cf.generateCertificate(caInput);
                    } finally {
                        caInput.close();
                    }
                    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                    keyStore.load(null, null);
                    keyStore.setCertificateEntry("server", ca);
                    tmf.init(keyStore);
                    sslContext.init(null, tmf.getTrustManagers(), null);

                    SSLSocketFactory socketFactory = sslContext.getSocketFactory();
                    try (Socket socket = socketFactory.createSocket(server, port);
                         DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                         BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                        output.writeUTF(params[0]);
                        output.flush();
                        serverResponse = input.readLine();
                    }
                } catch (Exception e) {
                    if (e.getMessage() != "Socket is closed") {
                        e.printStackTrace();
                        serverResponse = "Error: " + e.getMessage();
                    }
                }
                return serverResponse;
            }

            @Override
            protected void onPostExecute(String result) {
                Toast.makeText(MainActivity.this, result, Toast.LENGTH_LONG).show();
            }
        }.execute(data);
    }
    }
