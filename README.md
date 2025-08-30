# MoonLightCardDialog
### 原理
1. 传统当中`客户端-服务器-数据库`的卡密验证架构，对于服务器，数据库存在一定需求，很容易成为攻击目标，为了弥补搭建网络卡密验证方面的缺点，写了本文章
2. 全文分为两个公钥私钥，算法为ES256，是JWT当中常见的数字签名算法，结合与哈希与椭圆曲线，更短的密钥可以有更好的安全性
3. 我们脱离了数据存储，自然是需要将密文解密的，本地的解密是绝对不安全的，因此需要Cloudflare进行解密，为了保证中间人不会篡改，同样用了椭圆曲线进行了前后公私密钥的签名校验
这个系统有三个关键角色：

4.  **管理员**:
    *   **资产**：拥有**管理员私钥**
    *   **职责**：使用私钥签发包含授权信息（设备ID、过期时间）的令牌

5.  **Cloudflare Worker**:
    *   **资产**：拥有**管理员公钥**（用于验证令牌真伪）和自己的 **Worker 私钥**（用于证明自身身份）。
    *   **职责**：作为一个无状态的验证端点，它接收 App 的请求，验证真实性和有效性，然后用自己的私key签名，给 App 一个可信的回执。

6.  **安卓应用（消费者）**:
    *   **资产**：拥有 **Worker 公钥**。
    *   **职责**：向用户索要卡密，提交给 Worker 验证，并用自己的公钥验证 Worker 的回执是否真实。

下面开始教学
:::tip
我们需要一个简单的 Node.js 环境
:::
首先，初始化项目并安装 `jose` 库：
`npm init -y`
`npm install jose`
> Jose库需要在本地安装，因此本项目的ts并不能直接复制到CFworkers，因此全程构建需要电脑环境，低成本必须要求的牺牲，没办法，如果有大佬可以构建出脱离电脑的运行脚本，还请多多帮助


> 附录Jose是实现JWT的核心，有不会的可以去百度搜索，不做赘述了


我们需要两对 ECDSA P-256 密钥：一对用于管理员，一对用于 Worker。
修改 `package.json`，添加 `"type": "module",`。
### 卡密的生成与签发
:::tip
package.json没有就创建一个
:::
 下面是js代码
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

console.log('正在生成管理员密钥对...');
await generateKeys('admin');
console.log('\n正在生成 Worker 密钥对...');
await generateKeys('worker');
console.log('\n密钥对已全部生成！');
```

在终端运行 `node generate-keys.js`，你将得到四个文件。请妥善保管它们：
*   `admin_private_key.pem`: 保护好了哦，用来生成卡密的
*   `admin_public_key.pem`: 将部署到 Worker。
*   `worker_private_key.pem`: 将部署到 Worker。
*   `worker_public_key.pem`: 将硬编码到安卓 App 中

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

    console.log('卡密已生成 ---');
    console.log(`设备ID: ${deviceId}`);
    console.log(`有效期至: ${new Date(expiresAt * 1000).toLocaleString()}`);
    console.log('请将下面的字符串发给用户:');
    console.log(goldenToken);
}

const userDeviceId = process.argv[2];
const days = parseInt(process.argv[3], 10);
if (!userDeviceId || !days) {
    console.log('用法: node issue-token.js <设备ID> <有效天数>');
} else {
    issueGoldenToken(userDeviceId, days);
}
```
**使用**: `node issue-token.js <用户的设备ID> <有效天数>` (例如 `30` 天)。生成的长字符串就是发给用户的卡密。

### 网络端
我们将使用 Wrangler CLI 工具来创建和部署 Worker。

1.  **创建项目**: `npx wrangler init my-license-worker` (选择 `Worker only` 模板)。
2.  **安装依赖**: `cd my-license-worker` 然后 `npm install jose`
3.  **上传密钥**: 使用 `wrangler secret put` 命令，将 `admin_public_key.pem` 和 `worker_private_key.pem` 的内容分别上传到名为 `ADMIN_PUBLIC_KEY` 和 `WORKER_PRIVATE_KEY` 的环境变量中（这里可能会卡，记得挂梯子）

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
            
            // 1. 用管理员公钥验证黄金令牌
            const adminPublicKey = await importSPKI(env.ADMIN_PUBLIC_KEY, 'ES256');
            const { payload: tokenPayload } = await jwtVerify(token, adminPublicKey);

            // 2. 验证业务逻辑
            if (tokenPayload.deviceId !== deviceId) {
                return jsonResponse({ isValid: false, reason: 'Device ID mismatch' });
            }
            if (Math.floor(Date.now() / 1000) > (tokenPayload.expiresAt as number)) {
                return jsonResponse({ isValid: false, reason: 'Token expired' });
            }

            // 3. 所有验证通过，准备成功回执
            const responseData = {
                isValid: true,
                deviceId: tokenPayload.deviceId,
                expiresAt: tokenPayload.expiresAt,
                validatedAt: Math.floor(Date.now() / 1000),
            };

            // 4. 用 Worker 私钥签名回执，生成一个响应JWT
            const workerPrivateKey = await importPKCS8(env.WORKER_PRIVATE_KEY, 'ES256');
            const signedJwtResponse = await new SignJWT(responseData)
                .setProtectedHeader({ alg: 'ES256' })
                .sign(workerPrivateKey);
            
            // 5. 将签好名的 JWT 作为最终结果返回
            return jsonResponse({ responseToken: signedJwtResponse });

        } catch (error: any) {
            // 如果 jwtVerify 失败 (签名无效)，也会在这里捕获
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

最后，运行 `npx wrangler deploy` 将其部署到全球。

### 接下来是安卓层面对接了

成品写在MoonLightAPP了，目前还没有提交

类名：SecurityManager

相关代码
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
  
  
    private static final String WORKER_PUBLIC_KEY_STRING = "-----BEGIN PUBLIC KEY-----\-----END PUBLIC KEY-----";  //填写自己的密钥
  
    /**  
     *验证来自 Cloudflare Worker 的 JWT 响应。  
     * @param responseToken 从 Worker 收到的 JWS 字符串。  
     * @return 如果签名有效则返回 true，否则返回 false。  
     */  
    private static boolean verifyResponse(String responseToken) {  
        try {  
            Log.d(TAG, "Verifying response token: " + responseToken);  
  
            // 1. 使用 Nimbus 库解析收到的 JWS 字符串  
            SignedJWT signedJWT = SignedJWT.parse(responseToken);  
  
            // 2. 加载我们硬编码在 App 中的 Worker 公钥  
            PublicKey publicKey = loadPublicKey(WORKER_PUBLIC_KEY_STRING);  
            if (!(publicKey instanceof ECPublicKey)) {  
                Log.e(TAG, "Public key is not an EC public key, cannot verify.");  
                return false;  
            }  
  
            // 3. 创建一个适用于 ECDSA 签名的 Nimbus 验签器  
            JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);  
  
            // 4. 执行验签！如果令牌的签名与公钥匹配，这里会返回 true            boolean isSignatureValid = signedJWT.verify(verifier);  
            Log.d(TAG, "Is worker signature on JWT valid? -> " + isSignatureValid);  
  
            return isSignatureValid;  
  
        } catch (Exception e) {  
            Log.e(TAG, "Exception during JWT verification", e);  
            return false;  
        }  
    }  
  
    /**  
     * 向 Cloudflare Worker 发起验证请求。  
     * @param deviceId 当前设备的ID。  
     * @param goldenToken 用户输入的授权令牌（卡密）。  
     * @return 如果授权有效则返回 true，否则返回 false。  
     */  
    public static boolean validateLicense(String deviceId, String goldenToken) {  
        
        // 请将这里替换为您真实的 Worker URL。  
        String workerUrl = "https://card.342191.xyz";  //欢迎打
  
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
  
            // 1. 创建请求体  
            JSONObject requestPayload = new JSONObject();  
            requestPayload.put("deviceId", deviceId);  
            requestPayload.put("token", goldenToken);  
            String jsonInputString = requestPayload.toString();  
            Log.d(TAG, "Sending request payload: " + jsonInputString);  
  
            // 2. 发送请求  
            try (OutputStream os = conn.getOutputStream()) {  
                os.write(jsonInputString.getBytes(StandardCharsets.UTF_8));  
            }  
  
            // 3. 获取响应  
            int responseCode = conn.getResponseCode();  
            String responseMessage = conn.getResponseMessage();  
            Log.d(TAG, "Received HTTP Response: " + responseCode + " " + responseMessage);  
  
            InputStream inputStream = (responseCode >= 200 && responseCode <= 299) ? conn.getInputStream() : conn.getErrorStream();  
            if (inputStream == null) {  
                Log.e(TAG, "Response input stream is null.");  
                return false;  
            }  
  
            // 4. 读取响应体  
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
  
                // 检查 Worker 是否返回了业务逻辑错误  
                if (jsonResponse.has("isValid") && !jsonResponse.getBoolean("isValid")) {  
                    Log.e(TAG, "Worker returned a validation failure: " + jsonResponse.optString("reason"));  
                    return false;  
                }  
  
                // 5. [已修正] 提取并验证 Worker 返回的 JWT 令牌  
                if (!jsonResponse.has("responseToken")) {  
                    Log.e(TAG, "Response does not contain 'responseToken'");  
                    return false;  
                }  
                String responseToken = jsonResponse.getString("responseToken");  
  
                // 6. 验证这个 JWT 令牌的签名  
                if (!verifyResponse(responseToken)) {  
                    // 如果签名无效，直接失败  
                    return false;  
                }  
  
                // 7. 因为签名已经验证通过，所以我们可以【完全信任】令牌内的内容  
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
     * 辅助方法，从 PEM 格式的字符串加载公钥。  
     * @param key 公钥的 PEM 字符串。  
     * @return PublicKey 对象。  
     * @throws Exception  
     */    private static PublicKey loadPublicKey(String key) throws Exception {  
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

由于原本就封装好了，UI层面代码发出来没用，自己写吧
- 
