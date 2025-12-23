import { Database } from "bun:sqlite";
import { CLIENT_ID, CLIENT_SECRET } from "./config";

// Helper functions to decode base64 values
const decodeBase64 = (value: string): string => {
  return Buffer.from(value, "base64").toString("utf-8");
};

const DECODED_CLIENT_ID = decodeBase64(CLIENT_ID);
const DECODED_CLIENT_SECRET = decodeBase64(CLIENT_SECRET);
import { mkdirSync, accessSync, constants, existsSync, unlinkSync } from "fs";
import { dirname } from "path";

// Function to ensure database path exists and is read/writable
function ensureDatabasePath(dbPath: string): void {
  try {
    const dir = dbPath.includes("/") ? dirname(dbPath) : ".";

    if (dir !== ".") {
      mkdirSync(dir, { recursive: true });
    }

    if (existsSync(dbPath)) {
      try {
        accessSync(dbPath, constants.R_OK | constants.W_OK);
      } catch (error) {
        throw new Error(
          `Database file ${dbPath} is not readable/writable: ${error}`
        );
      }
    } else {
      try {
        const testPath = dir !== "." ? `${dir}/.dbtest.tmp` : ".dbtest.tmp";
        Bun.write(testPath, "");
        unlinkSync(testPath);
      } catch (error) {
        throw new Error(`Cannot write to database directory: ${error}`);
      }
    }
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(
        `Failed to ensure database path ${dbPath}: ${error.message}`
      );
    }
    throw new Error(`Failed to ensure database path ${dbPath}: ${error}`);
  }
}

const dbPath = process.env.DATABASE_PATH || "tokens.db";
ensureDatabasePath(dbPath);
const db = new Database(dbPath);

const WATERFALL_HOSTNAME = atob("YXBpcy5pZmxvdy5jbg");
const WATERFALL_INFO = atob(
  "aHR0cHM6Ly9pZmxvdy5jbi9hcGkvb2F1dGgvZ2V0VXNlckluZm8/YWNjZXNzVG9rZW49"
);
const WATERFALL_TOKEN = atob("aHR0cHM6Ly9pZmxvdy5jbi9vYXV0aC90b2tlbg");
const WATERFALL_AUTH = atob(
  "aHR0cHM6Ly9pZmxvdy5jbi9vYXV0aD9sb2dpbk1ldGhvZD1waG9uZSZ0eXBlPXBob25lJnJlZGlyZWN0PQ"
);
const WATERFALL_CB_PATH = atob("L29hdXRoMmNhbGxiYWNr");
const WATERFALL_LIST = atob(
  "aHR0cHM6Ly9pZmxvdy5jbi9hcGkvcGxhdGZvcm0vbW9kZWxzL2xpc3Q"
);

const WATERFALL_AUTHORIZE_PATH = atob(
  "aHR0cHM6Ly9pZmxvdy5jbi9vYXV0aC9hdXRob3JpemU"
);

// Create table for key-value storage
db.run(`
  CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT
  )
`);

// Prepare statements for performance
const getKvStmt = db.prepare<{ value: string }, [string]>(
  "SELECT value FROM kv WHERE key = ?"
);
const saveKvStmt = db.prepare<{}, [string, string]>(
  "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)"
);

type TokenData = Token & (TokenDataOAuth | TokenDataUid);

interface Token {
  access_token: string;
  expiry_date: number;
}

interface TokenDataUid {
  type: "uid";
  uid: string;
}

interface TokenDataOAuth {
  type: "oauth";
  refresh_token: string;
}

// Function to get current token
function getCurrentToken(): TokenData | null {
  try {
    const result = getKvStmt.get("token");
    if (result && typeof result === "object" && "value" in result) {
      const tokenData = JSON.parse(result.value as string);
      if (
        tokenData &&
        typeof tokenData === "object" &&
        tokenData.access_token
      ) {
        return tokenData;
      }
    }
  } catch (error) {
    console.error("Error getting token from database:", error);
  }
  return null;
}

// Function to save token
function saveToken(token: TokenData) {
  const tokenJson = JSON.stringify(token);
  saveKvStmt.run("token", tokenJson);
}

// Function to get API key
async function getApiKey(accessToken: string): Promise<string> {
  const storedApiKey = getStoredApiKey();
  if (storedApiKey) {
    return storedApiKey;
  }

  const response = await fetch(`${WATERFALL_INFO}${accessToken}`);

  if (!response.ok) {
    throw new Error("API Not Available");
  }

  const data = await response.json();

  if (data && typeof data === "object" && !data.success) {
    const errorMessage = data.message || "API Error";
    const errorCode = data.code || "UNKNOWN_ERROR";
    throw new Error(`[${errorCode}] ${errorMessage}`);
  }

  const apiKey = data.data?.apiKey as string;
  if (!apiKey) {
    throw new Error("API key not found in response");
  }

  saveApiKey(apiKey);
  return apiKey;
}

// Function to get stored API key
function getStoredApiKey(): string | null {
  try {
    const result = getKvStmt.get("apiKey");
    if (result && typeof result === "object" && "value" in result) {
      return result.value as string;
    }
  } catch (error) {
    console.error("Error getting API key from database:", error);
  }
  return null;
}

function clearStoredApiKey() {
  db.run(`DELETE FROM kv WHERE key = 'apiKey'`);
}

// Function to clear all stored authentication data
function clearAuthData() {
  db.run(`DELETE FROM kv WHERE key = 'token'`);
  db.run(`DELETE FROM kv WHERE key = 'apiKey'`);
  db.run(`DELETE FROM kv WHERE key = 'uid'`);
}

// Function to save API key
function saveApiKey(apiKey: string) {
  saveKvStmt.run("apiKey", apiKey);
}

// Function to refresh token
async function refreshToken() {
  const currentToken = getCurrentToken();
  if (!currentToken) return false;

  if (currentToken.type == "oauth") {
    const response = await fetch(WATERFALL_TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(
          `${DECODED_CLIENT_ID}:${DECODED_CLIENT_SECRET}`
        ).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: currentToken.refresh_token,
        client_id: DECODED_CLIENT_ID,
        client_secret: DECODED_CLIENT_SECRET,
      }).toString(),
    });

    console.log(`Refresh response: ${response.status} ${response.statusText}`);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    console.log("Refresh response data:");
    console.log(JSON.stringify(data));

    if (data && typeof data === "object" && "code" in data) {
      if (data.code != 200) {
        throw new Error(`WEB_ERROR ${data.code}: ${data.message || "UNKNOWN"}`);
      }
    }

    if (
      !data ||
      !data.access_token ||
      !data.refresh_token ||
      !data.expires_in
    ) {
      throw new Error("Invalid token response: missing required fields");
    }

    const newToken: TokenData = {
      type: "oauth",
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expiry_date: Date.now() + data.expires_in * 1000,
    };

    saveToken(newToken);
    return true;
  }

  if (currentToken.type == "uid") {
    const uid = currentToken.uid;

    const url = new URL(WATERFALL_AUTHORIZE_PATH);
    const state = crypto
      .getRandomValues(new Uint8Array(32))
      .reduce((acc, byte) => acc + byte.toString(16).padStart(2, "0"), "");
    url.searchParams.append("response_type", "code");
    url.searchParams.append("client_id", DECODED_CLIENT_ID);
    url.searchParams.append(
      "redirect_uri",
      `http://localhost:${PORT}${WATERFALL_CB_PATH}`
    );
    url.searchParams.append("uid", uid);
    url.searchParams.append("state", state);

    const authorize = await fetch(url, {
      redirect: "manual",
    });

    const location = authorize.headers.get("location");
    if (!location) {
      throw new Error("UID: No location header");
    }

    const decode = new URL(location);
    const code = decode.searchParams.get("code");
    const receivedState = decode.searchParams.get("state");
    if (state !== receivedState) {
      throw new Error("UID: State mismatch");
    }

    if (!code) {
      throw new Error("UID: No code");
    }

    const response = await fetch(WATERFALL_TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(
          `${DECODED_CLIENT_ID}:${DECODED_CLIENT_SECRET}`
        ).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: `http://localhost:${PORT}${WATERFALL_CB_PATH}`,
        client_id: DECODED_CLIENT_ID,
        client_secret: DECODED_CLIENT_SECRET,
      }).toString(),
    });

    const data = await response.json();
    const token: TokenData = {
      type: "uid",
      access_token: data.access_token,
      uid,
      expiry_date: Date.now() + data.expires_in * 1000,
    };

    saveToken(token);
    return true;
  }
}

let retryCount = 0;

// If the token expires within 24 hours, refresh it
const TOKEN_EXPIRE_MARGIN = 24 * 60 * 60 * 1000;

// Function to check and validate existing token on startup
async function checkExistingToken() {
  const currentToken = getCurrentToken();
  if (currentToken) {
    if (Date.now() > currentToken.expiry_date - TOKEN_EXPIRE_MARGIN) {
      // token expired
      try {
        if (await refreshToken()) {
          console.log("Expired token was refreshed, user is authenticated");
        } else {
          console.log("Token refresh failed, user needs to re-authenticate");
        }
      } catch (error: any) {
        console.error(
          "Token refresh failed, assuming user is still authenticated but will retry next time"
        );
        console.error(error?.message || String(error));
        return true;
      }
    } else {
      console.log("Existing token is valid, user is authenticated");
    }
  } else {
    console.log("No existing token, user need to authenticate");
  }
  return false;
}

// Check existing token on startup
const needRetry = await checkExistingToken();

// Refresh every hour
const TOKEN_REFRESH_INTERVAL = 60 * 60 * 1000;

// Retry every 10 minutes
const TOKEN_RETRY_INTERVAL = 10 * 60 * 1000;

const refreshTokenRoutine = async () => {
  const currentToken = getCurrentToken();
  if (currentToken) {
    if (currentToken.type == "oauth") {
      if (Date.now() > currentToken.expiry_date - TOKEN_EXPIRE_MARGIN) {
        try {
          if (await refreshToken()) {
            console.log("Token refreshed successfully");
            retryCount = 0;
          } else {
            console.log("Token refresh failed, user needs to re-authenticate");
            retryCount = 0;
          }
        } catch (error: any) {
          retryCount++;
          if (retryCount > 3) {
            console.error(
              "Token refresh failed too many times, user needs to re-authenticate"
            );
            clearAuthData();
            retryCount = 0;
            return false;
          }

          console.log("Token refresh failed, will retry in 10 minutes");
          console.error(error?.message || String(error));
          setTimeout(refreshTokenRoutine, TOKEN_RETRY_INTERVAL);
        }
      }
    }
  }

  setTimeout(refreshTokenRoutine, TOKEN_REFRESH_INTERVAL);
};

// Set up token refresh interval
setTimeout(
  refreshTokenRoutine,
  needRetry ? TOKEN_RETRY_INTERVAL : TOKEN_REFRESH_INTERVAL
);

let PORT = parseInt(process.env.PORT || "34007");
if (isNaN(PORT)) {
  PORT = 34007;
}

let PENDING_STATE: string | null = null;

// Function to handle root route
async function handleRoot(): Promise<Response> {
  const currentToken = getCurrentToken();
  if (!currentToken) {
    PENDING_STATE = crypto
      .getRandomValues(new Uint8Array(32))
      .reduce((acc, byte) => acc + byte.toString(16).padStart(2, "0"), "");
    const loginUrl = `${WATERFALL_AUTH}${encodeURIComponent(
      `http://localhost:${PORT}/${WATERFALL_CB_PATH}`
    )}&state=${PENDING_STATE}&client_id=${DECODED_CLIENT_ID}`;
    return new Response(
      `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Waterfall Login Portal</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
          }
          .container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
            width: 90%;
          }
          h1 {
            color: #333;
            margin-bottom: 1.5rem;
          }
          .login-btn, .uid-btn {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 25px;
            font-weight: bold;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            border: none;
            cursor: pointer;
            font-size: 16px;
            margin: 5px;
          }
          .login-btn:hover, .uid-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.25);
          }
          .divider {
            margin: 1.5rem 0;
            text-align: center;
            position: relative;
          }
          .divider::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: #ddd;
          }
          .divider span {
            background: white;
            padding: 0 1rem;
            color: #666;
            position: relative;
          }
          .uid-form {
            margin-top: 1rem;
          }
          .uid-input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 1rem;
            font-size: 16px;
            box-sizing: border-box;
          }
          .uid-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.2);
          }
          .error-message {
            color: #e74c3c;
            margin-top: 0.5rem;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Login Portal</h1>
          <a href="${loginUrl}" class="login-btn">Click me</a>
          <div class="divider">
            <span>OR</span>
          </div>
          <form class="uid-form" action="/submit-uid" method="post">
            <input type="text" name="uid" class="uid-input" placeholder="Enter your UID" required>
            <button type="submit" class="uid-btn">Submit UID</button>
          </form>
          <div id="error-message" class="error-message"></div>
        </div>
        <script>
          document.querySelector('.uid-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const uid = document.querySelector('input[name="uid"]').value;
            const errorDiv = document.getElementById('error-message');
            
            try {
              const response = await fetch('/submit-uid', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'uid=' + encodeURIComponent(uid)
              });
              
              if (response.ok) {
                window.location.reload();
              } else {
                const data = await response.text();
                errorDiv.textContent = data || 'Invalid UID';
              }
            } catch (error) {
              errorDiv.textContent = 'Network error. Please try again.';
            }
          });
        </script>
      </body>
      </html>
    `,
      { headers: { "Content-Type": "text/html; charset=utf-8" } }
    );
  } else {
    return new Response(
      `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Waterfall Login Portal</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
          }
          .container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
            width: 90%;
          }
          h1 {
            color: #333;
            margin-bottom: 1.5rem;
          }
          p {
            color: #666;
            margin-bottom: 2rem;
          }
          .logout-btn {
            display: inline-block;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 25px;
            font-weight: bold;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            border: none;
            cursor: pointer;
            font-size: 16px;
          }
          .logout-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.25);
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Welcome</h1>
          <p>You have successfully authenticated using <strong>${currentToken.type}</strong>! You can now access the API via "http://localhost:${PORT}/v1".</p>
          <form action="/logout" method="post">
            <button type="submit" class="logout-btn">Logout</button>
          </form>
        </div>
        <script>
          document.querySelector('form').addEventListener('submit', function(e) {
            if (!confirm('Are you sure you want to logout?')) {
              e.preventDefault();
            }
          });
        </script>
      </body>
      </html>
    `,
      { headers: { "Content-Type": "text/html; charset=utf-8" } }
    );
  }
}

// Function to handle OAuth callback
async function handleOAuthCallback(url: URL): Promise<Response> {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!state || !PENDING_STATE || state !== PENDING_STATE) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  if (!code) {
    return new Response("No code provided", { status: 400 });
  }

  try {
    const response = await fetch(WATERFALL_TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(
          `${DECODED_CLIENT_ID}:${DECODED_CLIENT_SECRET}`
        ).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: `http://localhost:${PORT}${WATERFALL_CB_PATH}`,
        client_id: DECODED_CLIENT_ID,
        client_secret: DECODED_CLIENT_SECRET,
      }).toString(),
    });

    const data = await response.json();
    const token: TokenData = {
      type: "oauth",
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expiry_date: Date.now() + data.expires_in * 1000,
    };

    saveToken(token);

    return new Response(
      `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Waterfall Login Portal</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
          }
          .container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
            width: 90%;
          }
          h1 {
            color: #333;
            margin-bottom: 1.5rem;
          }
          p {
            color: #666;
            margin-bottom: 2rem;
          }
          .redirect-btn {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 25px;
            font-weight: bold;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
          }
          .redirect-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.25);
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Authentication Successful</h1>
          <p>You have successfully authenticated! You can now close this window and access the API via "http://localhost:${PORT}/v1".</p>
        </div>
      </body>
      </html>
      `,
      { headers: { "Content-Type": "text/html; charset=utf-8" } }
    );
  } catch (error) {
    return new Response("Authentication failed", { status: 500 });
  }
}

// Function to handle logout
async function handleLogout(): Promise<Response> {
  clearAuthData();

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
    },
  });
}

// Function to handle UID submission
async function handleUidSubmission(req: Request): Promise<Response> {
  try {
    const formData = await req.formData();
    const uid = formData.get("uid") as string;

    if (!uid || uid.trim() === "") {
      return new Response("UID cannot be empty", { status: 400 });
    }

    const url = new URL(WATERFALL_AUTHORIZE_PATH);
    const state = crypto
      .getRandomValues(new Uint8Array(32))
      .reduce((acc, byte) => acc + byte.toString(16).padStart(2, "0"), "");
    url.searchParams.append("response_type", "code");
    url.searchParams.append("client_id", DECODED_CLIENT_ID);
    url.searchParams.append(
      "redirect_uri",
      `http://localhost:${PORT}${WATERFALL_CB_PATH}`
    );
    url.searchParams.append("uid", uid);
    url.searchParams.append("state", state);

    const authorize = await fetch(url, {
      redirect: "manual",
    });

    const location = authorize.headers.get("location");
    if (!location) {
      console.error("Error handling UID submission: no location");
      return new Response("Invalid UID", { status: 500 });
    }

    const decode = new URL(location);
    const code = decode.searchParams.get("code");
    const receivedState = decode.searchParams.get("state");
    if (state !== receivedState) {
      console.error("Error handling UID submission: invalid state");
      return new Response("Invalid state", { status: 500 });
    }

    if (!code) {
      return new Response("No code provided", { status: 500 });
    }

    const response = await fetch(WATERFALL_TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(
          `${DECODED_CLIENT_ID}:${DECODED_CLIENT_SECRET}`
        ).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: `http://localhost:${PORT}${WATERFALL_CB_PATH}`,
        client_id: DECODED_CLIENT_ID,
        client_secret: DECODED_CLIENT_SECRET,
      }).toString(),
    });

    const data = await response.json();
    const token: TokenData = {
      type: "uid",
      access_token: data.access_token,
      uid,
      expiry_date: Date.now() + data.expires_in * 1000,
    };

    saveToken(token);

    // try getting uid once. if it fails, then the login has failed
    try {
      await getApiKey(token.access_token);
    } catch (error) {
      clearAuthData();
      if (error instanceof Error) {
        return new Response(`Failed to get API key: ${error.message}`, {
          status: 500,
        });
      } else {
        return new Response("Failed to get API key", { status: 500 });
      }
    }

    return new Response(null, {
      status: 302,
      headers: {
        Location: "/",
      },
    });
  } catch (error) {
    console.error("Error handling UID submission:", error);
    return new Response("Internal server error", { status: 500 });
  }
}

// Function to handle models list
async function handleModelsList(): Promise<Response> {
  try {
    const response = await fetch(WATERFALL_LIST, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
    const data = await response.json();
    if (!data.success) {
      return new Response("Failed to fetch models", { status: 500 });
    }

    const allModels = [];
    for (const category in data.data) {
      if (Array.isArray(data.data[category])) {
        allModels.push(...data.data[category]);
      }
    }

    const openaiModels = allModels
      .filter((model) => model.isVisible)
      .map((model) => {
        const created = new Date(model.updatedTime).getTime() / 1000;

        let contextLength = null;
        try {
          const modelTags = JSON.parse(model.modelTags);
          if (Array.isArray(modelTags) && modelTags.length > 0) {
            const seqLengthStr = modelTags[0].modelSeqLength;
            if (seqLengthStr) {
              const match = seqLengthStr.match(/^(\d+)(K?)$/);
              if (match) {
                contextLength =
                  parseInt(match[1]) * (match[2] === "K" ? 1000 : 1);
              }
            }
          }
        } catch (e) {}

        return {
          id: model.modelName.trim(),
          object: "model",
          created: Math.floor(created),
          owned_by: model.modelType,
          context_length: contextLength,
        };
      });

    return new Response(
      JSON.stringify({
        object: "list",
        data: openaiModels.reverse(),
      }),
      {
        headers: { "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    return new Response("Failed to fetch models", { status: 500 });
  }
}

// Function to handle API proxy
async function handleApiProxy(
  req: Request,
  url: URL,
  isRetry: boolean = false,
  bodyBuffer: ArrayBuffer | null = null
): Promise<Response> {
  const currentToken = getCurrentToken();
  if (!currentToken) {
    return new Response(`NO AUTH. Visit http://localhost:${PORT}/`, {
      status: 401,
    });
  }

  try {
    let body: BodyInit | null = null;
    let chunks: Uint8Array[] | null = null;
    let chunksComplete = false;
    let pumpError: Error | null = null;

    if (req.method !== "GET" && req.method !== "HEAD" && req.body) {
      if (bodyBuffer) {
        body = bodyBuffer;
      } else {
        const { readable, writable } = new TransformStream();
        const writer = writable.getWriter();

        chunks = [];

        const reader = req.body.getReader();

        const pump = async () => {
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) {
                await writer.close();
                chunksComplete = true;
                break;
              }

              chunks!.push(value);

              await writer.write(value);
            }
          } catch (error) {
            await writer.abort(error);
            pumpError = error as Error;
            chunksComplete = true;
            throw error;
          }
        };

        pump().catch((error) => {
          console.error("Error pumping request body:", error);
        });

        body = readable;
      }
    }

    let apiKey: string;
    try {
      apiKey = await getApiKey(currentToken.access_token);
    } catch (error) {
      if (error instanceof Error) {
        return new Response(`Failed to get API key: ${error.message}`, {
          status: 500,
        });
      } else {
        return new Response("Failed to get API key", { status: 500 });
      }
    }

    const targetUrl = `https://${WATERFALL_HOSTNAME}${url.pathname}${url.search}`;

    const headers = new Headers(req.headers);
    headers.set("authorization", `Bearer ${apiKey}`);
    headers.set("host", WATERFALL_HOSTNAME);
    headers.set("user-agent", atob("aUZsb3ctQ2xp"));

    const response = await fetch(targetUrl, {
      method: req.method,
      headers: headers,
      body: body,
    });

    if (!response.ok) {
      console.error(
        `API request ${url.pathname}${url.search} failed: ${response.status} ${response.statusText}`
      );
    }

    const responseType = response.headers.get("content-type");
    if (responseType && responseType.includes("text/event-stream")) {
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers":
            "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        },
      });
    } else if (responseType && responseType.includes("application/json")) {
      const data = await response.json();
      if (data && data.status && data.status != 200) {
        if (data.status == 434 && !isRetry) {
          clearStoredApiKey();
          let bufferedBody: ArrayBuffer | null = null;
          if (chunks) {
            if (!chunksComplete) {
              return new Response("Request body not fully received", {
                status: 500,
              });
            }

            if (pumpError) {
              throw pumpError;
            }
            const totalLength = chunks.reduce(
              (acc, chunk) => acc + chunk.length,
              0
            );
            const combinedBuffer = new Uint8Array(totalLength);
            let offset = 0;
            for (const chunk of chunks) {
              combinedBuffer.set(chunk, offset);
              offset += chunk.length;
            }
            bufferedBody = combinedBuffer.buffer;
          }
          return await handleApiProxy(req, url, true, bufferedBody);
        } else {
          console.error("API request error:", data);
          let statusText = "API request error";
          if (
            data &&
            typeof data === "object" &&
            "status" in data &&
            "msg" in data
          ) {
            statusText = `[${data.status}] ${data.msg}`;
          } else if (data && typeof data === "object" && "msg" in data) {
            statusText = data.msg;
          }
          return new Response(JSON.stringify(data), {
            status: 500,
            statusText: statusText,
            headers: {
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Headers":
                "GET, POST, PUT, PATCH, DELETE, OPTIONS",
              "Content-Type": "application/json",
            },
          });
        }
      }

      return new Response(JSON.stringify(data), {
        status: response.status,
        statusText: response.statusText,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers":
            "GET, POST, PUT, PATCH, DELETE, OPTIONS",
          "Content-Type": "application/json",
        },
      });
    } else {
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set("Access-Control-Allow-Origin", "*");
      responseHeaders.set(
        "Access-Control-Allow-Headers",
        "GET, POST, PUT, PATCH, DELETE, OPTIONS"
      );

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    }
  } catch (error) {
    return new Response("API request failed", { status: 500 });
  }
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/") {
      return await handleRoot();
    }

    if (url.pathname === WATERFALL_CB_PATH) {
      return await handleOAuthCallback(url);
    }

    if (url.pathname === "/v1/models") {
      return await handleModelsList();
    }

    if (url.pathname === "/logout" && req.method === "POST") {
      return await handleLogout();
    }

    if (url.pathname === "/submit-uid" && req.method === "POST") {
      return await handleUidSubmission(req);
    }

    if (url.pathname.startsWith("/v1")) {
      return await handleApiProxy(req, url);
    }

    return new Response("Not found", { status: 404 });
  },
});

console.log(`Server running on http://localhost:${server.port}`);
