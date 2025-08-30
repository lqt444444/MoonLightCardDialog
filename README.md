### Principle
1.  In the traditional `client-server-database` license key verification architecture, there are specific requirements for the server and database, which can easily become targets for attacks. This article was written to address the shortcomings of setting up a network-based license key verification system.
2.  The entire system uses two pairs of public and private keys with the ES256 algorithm, a common digital signature algorithm in JWT. It combines hashing and elliptic curves to provide better security with shorter keys.
3.  Since we are moving away from data storage, we naturally need to decrypt the ciphertext. Local decryption is absolutely insecure, so Cloudflare is used for decryption. To ensure that a man-in-the-middle cannot tamper with the data, elliptic curves are also used for signing and verifying the public and private keys at both ends.

This system has three key roles:

4.  **Administrator**:
    *   **Assets**: Possesses the **admin private key**.
    *   **Responsibilities**: Uses the private key to issue tokens containing authorization information (device ID, expiration time).

5.  **Cloudflare Worker**:
    *   **Assets**: Possesses the **admin public key** (to verify the authenticity of tokens) and its own **Worker private key** (to prove its own identity).
    *   **Responsibilities**: Acts as a stateless verification endpoint. It receives requests from the app, verifies their authenticity and validity, and then signs a trusted receipt for the app with its own private key.

6.  **Android Application (Consumer)**:
    *   **Assets**: Possesses the **Worker public key**.
    *   **Responsibilities**: Asks the user for the license key, submits it to the Worker for verification, and uses its public key to verify whether the Worker's receipt is authentic.

Let's start the tutorial.
:::tip
We need a simple Node.js environment.
:::
First, initialize the project and install the `jose` library:
`npm init -y`
`npm install jose`
> The Jose library needs to be installed locally, so the TypeScript in this project cannot be directly copied to CF Workers. Therefore, the entire build process requires a computer environment. This is a necessary sacrifice for a low-cost solution. If any expert can create a script that runs without a computer, please help.

> Appendix: Jose is the core for implementing JWT. If you are not familiar with it, you can search for it on Baidu. We won't go into detail here.

We need two pairs of ECDSA P-256 keys: one for the administrator and one for the Worker.
Modify `package.json` and add `"type": "module",`.
### License Key Generation and Issuance
:::tip
If you don't have a package.json, create one.
:::
Here is the JavaScript code:
**`generate-keys.js`**
```javascript
import { generateKeyPair, exportSPKI, exportPKCS8 } from 'jose';
import { promises as fs } from 'fs';

async function generateKeys(prefix) {
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    const spkiPem = await exportSPKI(publicKey);
    const pkcs8Pem = await exportPKCS8(privateKey);

    await fs.writeFile(`${prefix}_public_key.pem`, spkiPem);
    await fs.writeFile(`${prefix}_private_key.pem`, pkcs8Pem);
    
    console.log(`--- ${prefix}_public_key.pem ---`);
    console.log(spkiPem);
}

console.log('Generating admin key pair...');
await generateKeys('admin');
console.log('\nGenerating Worker key pair...');
await generateKeys('worker');
console.log('\nAll key pairs have been generated!');
```

Run `node generate-keys.js` in the terminal, and you will get four files. Please keep them safe:
*   `admin_private_key.pem`: Protect this well; it's used to generate license keys.
*   `admin_public_key.pem`: Will be deployed to the Worker.
*   `worker_private_key.pem`: Will be deployed to the Worker.
*   `worker_public_key.pem`: Will be hardcoded into the Android App.

**`issue-token.js`**
```javascript
import { SignJWT, importPKCS8 } from 'jose';
import { promises as fs } from 'fs';

async function issueGoldenToken(deviceId, validityInDays) {
    const privateKeyPem = await fs.readFile('admin_private_key.pem', 'utf-8');
    const privateKey = await importPKCS8(privateKeyPem, 'ES256');
    const expiresAt = Math.floor(Date.now() / 1000) + (validityInDays * 24 * 60 * 60);

    const goldenToken = await new SignJWT({ deviceId, expiresAt })
        .setProtectedHeader({ alg: 'ES256' })
        .sign(privateKey);

    console.log('License key generated ---');
    console.log(`Device ID: ${deviceId}`);
    console.log(`Expires at: ${new Date(expiresAt * 1000).toLocaleString()}`);
    console.log('Please send the following string to the user:');
    console.log(goldenToken);
}

const userDeviceId = process.argv[2];
const days = parseInt(process.argv[3], 10);
if (!userDeviceId || !days) {
    console.log('Usage: node issue-token.js <Device ID> <Validity in days>');
} else {
    issueGoldenToken(userDeviceId, days);
}
```
**Usage**: `node issue-token.js <User's Device ID> <Validity in days>` (e.g., `30` days). The long string generated is the license key to be sent to the user.

### Web End
We will use the Wrangler CLI tool to create and deploy the Worker.

1.  **Create project**: `npx wrangler init my-license-worker` (choose the `Worker only` template).
2.  **Install dependencies**: `cd my-license-worker` then `npm install jose`
3.  **Upload secrets**: Use the `wrangler secret put` command to upload the contents of `admin_public_key.pem` and `worker_private_key.pem` to environment variables named `ADMIN_PUBLIC_KEY` and `WORKER_PRIVATE_KEY` respectively (this might get stuck, remember to use a VPN).

**`src/index.ts`**
```typescript
import { importSPKI, jwtVerify, SignJWT, importPKCS8 } from 'jose';

export interface Env {
    ADMIN_PUBLIC_KEY: string;
    WORKER_PRIVATE_KEY: string;
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        if (request.method !== 'POST') {
            return jsonResponse({ error: 'Expected POST' }, 405);
        }

        try {
            const { deviceId, token }: { deviceId?: string; token?: string } = await request.json();

            if (!deviceId || !token) {
                return jsonResponse({ isValid: false, reason: 'Missing parameters' }, 400);
            }
            
            // 1. Verify the golden token with the admin public key
            const adminPublicKey = await importSPKI(env.ADMIN_PUBLIC_KEY, 'ES256');
            const { payload: tokenPayload } = await jwtVerify(token, adminPublicKey);

            // 2. Validate business logic
            if (tokenPayload.deviceId !== deviceId) {
                return jsonResponse({ isValid: false, reason: 'Device ID mismatch' });
            }
            if (Math.floor(Date.now() / 1000) > (tokenPayload.expiresAt as number)) {
                return jsonResponse({ isValid: false, reason: 'Token expired' });
            }

            // 3. All validations passed, prepare a success receipt
            const responseData = {
                isValid: true,
                deviceId: tokenPayload.deviceId,
                expiresAt: tokenPayload.expiresAt,
                validatedAt: Math.floor(Date.now() / 1000),
            };

            // 4. Sign the receipt with the Worker private key to generate a response JWT
            const workerPrivateKey = await importPKCS8(env.WORKER_PRIVATE_KEY, 'ES256');
            const signedJwtResponse = await new SignJWT(responseData)
                .setProtectedHeader({ alg: 'ES256' })
                .sign(workerPrivateKey);
            
            // 5. Return the signed JWT as the final result
            return jsonResponse({ responseToken: signedJwtResponse });

        } catch (error: any) {
            // If jwtVerify fails (invalid signature), it will be caught here
            const reason = error.code || error.message || 'Internal Server Error';
            console.error(`Validation failed: ${reason}`);
            return jsonResponse({ isValid: false, reason });
        }
    },
};

function jsonResponse(data: object, status: number = 200): Response {
    return new Response(JSON.stringify(data), { status: status, headers: { 'Content-Type': 'application/json' }});
}
```

Finally, run `npx wrangler deploy` to deploy it globally.

### Next is the Android layer integration

The finished product is written in MoonLightAPP, but has not been submitted yet.

Class Name: SecurityManager

Related Code
```Java
package bbs.yuchen.icu;  
  
import android.util.Base64;  
import android.util.Log;  
  
import com.nimbusds.jose.JWSVerifier;  
import com.nimbusds.jose.crypto.ECDSAVerifier;  
import com.nimbusds.jwt.SignedJWT;  
  
import org.json.JSONObject;  
  
import java.io.BufferedReader;  
import java.io.InputStream;  
import java.io.InputStreamReader;  
import java.io.OutputStream;  
import java.net.HttpURLConnection;  
import java.net.URL;  
import java.nio.charset.StandardCharsets;  
import java.security.KeyFactory;  
import java.security.PublicKey;  
import java.security.interfaces.ECPublicKey;  
import java.security.spec.X509EncodedKeySpec;  
  
public class SecurityManager {  
    private static final String TAG = "SecurityManagerDebug";  
  
  
    private static final String WORKER_PUBLIC_KEY_STRING = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";  // Fill in your own key
  
    /**  
     * Verifies the JWT response from the Cloudflare Worker.  
     * @param responseToken The JWS string received from the Worker.  
     * @return true if the signature is valid, otherwise false.  
     */  
    private static boolean verifyResponse(String responseToken) {  
        try {  
            Log.d(TAG, "Verifying response token: " + responseToken);  
  
            // 1. Parse the received JWS string using the Nimbus library  
            SignedJWT signedJWT = SignedJWT.parse(responseToken);  
  
            // 2. Load the Worker public key that we hardcoded in the App  
            PublicKey publicKey = loadPublicKey(WORKER_PUBLIC_KEY_STRING);  
            if (!(publicKey instanceof ECPublicKey)) {  
                Log.e(TAG, "Public key is not an EC public key, cannot verify.");  
                return false;  
            }  
  
            // 3. Create a Nimbus verifier suitable for ECDSA signatures  
            JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);  
  
            // 4. Perform the verification! This will return true if the token's signature matches the public key            
            boolean isSignatureValid = signedJWT.verify(verifier);  
            Log.d(TAG, "Is worker signature on JWT valid? -> " + isSignatureValid);  
  
            return isSignatureValid;  
  
        } catch (Exception e) {  
            Log.e(TAG, "Exception during JWT verification", e);  
            return false;  
        }  
    }  
  
    /**  
     * Initiates a validation request to the Cloudflare Worker.  
     * @param deviceId The ID of the current device.  
     * @param goldenToken The authorization token (license key) entered by the user.  
     * @return true if the license is valid, otherwise false.  
     */  
    public static boolean validateLicense(String deviceId, String goldenToken) {  
        
        // Please replace this with your actual Worker URL.  
        String workerUrl = "https://card.342191.xyz";  // Feel free to hit it
  
        Log.d(TAG, "\n--- Starting License Validation ---");  
        Log.d(TAG, "Worker URL: " + workerUrl);  
        Log.d(TAG, "Device ID: " + deviceId);  
        Log.d(TAG, "Golden Token: " + goldenToken);  
  
        HttpURLConnection conn = null;  
        try {  
            URL url = new URL(workerUrl);  
            conn = (HttpURLConnection) url.openConnection();  
            conn.setRequestMethod("POST");  
            conn.setRequestProperty("Content-Type", "application/json; utf-8");  
            conn.setConnectTimeout(15000);  
            conn.setReadTimeout(15000);  
            conn.setDoOutput(true);  
  
            // 1. Create the request body  
            JSONObject requestPayload = new JSONObject();  
            requestPayload.put("deviceId", deviceId);  
            requestPayload.put("token", goldenToken);  
            String jsonInputString = requestPayload.toString();  
            Log.d(TAG, "Sending request payload: " + jsonInputString);  
  
            // 2. Send the request  
            try (OutputStream os = conn.getOutputStream()) {  
                os.write(jsonInputString.getBytes(StandardCharsets.UTF_8));  
            }  
  
            // 3. Get the response  
            int responseCode = conn.getResponseCode();  
            String responseMessage = conn.getResponseMessage();  
            Log.d(TAG, "Received HTTP Response: " + responseCode + " " + responseMessage);  
  
            InputStream inputStream = (responseCode >= 200 && responseCode <= 299) ? conn.getInputStream() : conn.getErrorStream();  
            if (inputStream == null) {  
                Log.e(TAG, "Response input stream is null.");  
                return false;  
            }  
  
            // 4. Read the response body  
            try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {  
                StringBuilder response = new StringBuilder();  
                String responseLine;  
                while ((responseLine = br.readLine()) != null) {  
                    response.append(responseLine.trim());  
                }  
                String rawResponse = response.toString();  
                Log.d(TAG, "Raw response body: " + rawResponse);  
  
                if (responseCode != 200) {  
                    Log.e(TAG, "Validation failed due to non-200 response code.");  
                    return false;  
                }  
  
                JSONObject jsonResponse = new JSONObject(rawResponse);  
  
                // Check if the Worker returned a business logic error  
                if (jsonResponse.has("isValid") && !jsonResponse.getBoolean("isValid")) {  
                    Log.e(TAG, "Worker returned a validation failure: " + jsonResponse.optString("reason"));  
                    return false;  
                }  
  
                // 5. [Corrected] Extract and verify the JWT token returned by the Worker  
                if (!jsonResponse.has("responseToken")) {  
                    Log.e(TAG, "Response does not contain 'responseToken'");  
                    return false;  
                }  
                String responseToken = jsonResponse.getString("responseToken");  
  
                // 6. Verify the signature of this JWT token  
                if (!verifyResponse(responseToken)) {  
                    // If the signature is invalid, fail immediately  
                    return false;  
                }  
  
                // 7. Because the signature has been verified, we can [fully trust] the content within the token  
                SignedJWT signedJWT = SignedJWT.parse(responseToken);  
                JSONObject payload = new JSONObject(signedJWT.getPayload().toString());  
  
                boolean isLicenseValid = payload.getBoolean("isValid");  
                Log.d(TAG, "Is license valid according to TRUSTED payload? -> " + isLicenseValid);  
  
                return isLicenseValid;  
            }  
  
        } catch (Exception e) {  
            Log.e(TAG, "An exception occurred during validation", e);  
            return false;  
        } finally {  
            if (conn != null) {  
                conn.disconnect();  
            }  
            Log.d(TAG, "--- License Validation Finished ---");  
        }  
    }  
  
    /**  
     * Helper method to load a public key from a PEM formatted string.  
     * @param key The PEM string of the public key.  
     * @return PublicKey object.  
     * @throws Exception  
     */    
    private static PublicKey loadPublicKey(String key) throws Exception {  
        String publicKeyPEM = key  
                .replace("-----BEGIN PUBLIC KEY-----", "")  
                .replaceAll("\n", "")  
                .replace("-----END PUBLIC KEY-----", "");  
        byte[] encoded = Base64.decode(publicKeyPEM, Base64.DEFAULT);  
        KeyFactory keyFactory = KeyFactory.getInstance("EC");  
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);  
        return keyFactory.generatePublic(keySpec);  
    }  
}
```

Since it's already encapsulated, there's no point in posting the UI layer code. Write it yourself.
