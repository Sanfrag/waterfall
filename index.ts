import { Database } from "bun:sqlite";
import { CLIENT_ID, CLIENT_SECRET } from "./config";

// Helper functions to decode base64 values
const decodeBase64 = (value: string): string => {
  return Buffer.from(value, "base64").toString("utf-8");
};

// Decode CLIENT_ID and CLIENT_SECRET for use in the application
const DECODED_CLIENT_ID = decodeBase64(CLIENT_ID);
const DECODED_CLIENT_SECRET = decodeBase64(CLIENT_SECRET);
import { mkdirSync, accessSync, constants, existsSync, unlinkSync } from "fs";
import { dirname } from "path";

// Function to ensure database path exists and is read/writable
function ensureDatabasePath(dbPath: string): void {
  try {
    // Get the directory part of the path
    const dir = dbPath.includes("/") ? dirname(dbPath) : ".";

    // If directory is not current directory, ensure it exists
    if (dir !== ".") {
      mkdirSync(dir, { recursive: true });
    }

    // If database file already exists, check read/write permissions
    if (existsSync(dbPath)) {
      try {
        accessSync(dbPath, constants.R_OK | constants.W_OK);
      } catch (error) {
        throw new Error(
          `Database file ${dbPath} is not readable/writable: ${error}`
        );
      }
    }
    // If database file doesn't exist, check if we can write to the directory
    else {
      try {
        // Try to create and delete a temporary file to test write permissions
        const testPath = dir !== "." ? `${dir}/.dbtest.tmp` : ".dbtest.tmp";
        Bun.write(testPath, "");
        // Delete the test file using fs.unlinkSync
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

// Define obfuscated hostnames
const WATERFALL_HOSTNAME = Buffer.from("aWZsb3cuY24=", "base64").toString(
  "utf-8"
);
const WATERFALL_API_HOSTNAME = Buffer.from(
  "YXBpcy5pZmxvdy5jbg==",
  "base64"
).toString("utf-8");

// Create table for key-value storage
db.run(`
  CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT
  )
`);

// Prepare statements for performance
const getTokenStmt = db.prepare("SELECT value FROM kv WHERE key = 'token'");
const saveTokenStmt = db.prepare(
  "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)"
);
const getApiKeyStmt = db.prepare("SELECT value FROM kv WHERE key = 'apiKey'");

interface TokenData {
  access_token: string;
  refresh_token: string;
  expiry_date: number;
  token_type: string;
  scope: string;
}

let isAuthenticated = false;

// Function to get current token
function getCurrentToken(): TokenData | null {
  try {
    const result = getTokenStmt.get();
    if (result && typeof result === "object" && "value" in result) {
      const tokenData = JSON.parse(result.value as string);
      // Validate token structure
      if (
        tokenData &&
        typeof tokenData === "object" &&
        tokenData.access_token &&
        tokenData.refresh_token &&
        typeof tokenData.expiry_date === "number"
      ) {
        return tokenData;
      }
    }
  } catch (error) {
    console.error("Error getting token from database:", error);
  }
  isAuthenticated = false;
  return null;
}

// Function to save token
function saveToken(token: TokenData) {
  const tokenJson = JSON.stringify(token);
  saveTokenStmt.run("token", tokenJson);
}

// Function to get API key
async function getApiKey(accessToken: string): Promise<string | null> {
  // Check if we have a cached API key
  const storedApiKey = getStoredApiKey();
  if (storedApiKey) {
    return storedApiKey;
  }

  const response = await fetch(
    `https://${WATERFALL_HOSTNAME}/api/oauth/getUserInfo?accessToken=${accessToken}`
  );
  const data = await response.json();
  const apiKey = data.data.apiKey as string;
  if (!apiKey) {
    return null;
  }

  // Cache the API key
  saveApiKey(apiKey);
  return apiKey;
}

// Function to get stored API key
function getStoredApiKey(): string | null {
  try {
    const result = getApiKeyStmt.get();
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

// Function to save API key
function saveApiKey(apiKey: string) {
  saveTokenStmt.run("apiKey", apiKey);
}

// Function to refresh token
async function refreshToken() {
  const currentToken = getCurrentToken();
  if (!currentToken) return;

  const response = await fetch(`https://${WATERFALL_HOSTNAME}/oauth/token`, {
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

  const data = await response.json();
  const newToken: TokenData = {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expiry_date: Date.now() + data.expires_in * 1000,
    token_type: data.token_type,
    scope: data.scope,
  };

  saveToken(newToken);
}

// Function to check and validate existing token on startup
async function checkExistingToken() {
  const currentToken = getCurrentToken();
  if (currentToken) {
    try {
      // Try to refresh the token to validate it
      await refreshToken();
      // If refresh succeeds, the token is valid
      isAuthenticated = true;
      console.log("Existing token validated, user is authenticated");
    } catch (error) {
      console.log("Existing token is invalid, user needs to re-authenticate");
      // Token is invalid, keep isAuthenticated as false
    }
  }
}

// Check existing token on startup
await checkExistingToken();

// Set up token refresh interval
setInterval(async () => {
  const currentToken = getCurrentToken();
  if (
    currentToken &&
    Date.now() > currentToken.expiry_date - 5 * 60 * 60 * 1000
  ) {
    // Refresh 5 hours before expiry
    await refreshToken();
  }
}, 60 * 60 * 1000); // Check every hour

let PORT = parseInt(process.env.PORT || "34007");
if (isNaN(PORT)) {
  PORT = 34007;
}

let PENDING_STATE: string | null = null;

// Function to handle root route
async function handleRoot(): Promise<Response> {
  if (!isAuthenticated) {
    PENDING_STATE = crypto
      .getRandomValues(new Uint8Array(32))
      .reduce((acc, byte) => acc + byte.toString(16).padStart(2, "0"), "");
    const loginUrl = `https://${WATERFALL_HOSTNAME}/oauth?loginMethod=phone&type=phone&redirect=${encodeURIComponent(
      `http://localhost:${PORT}/oauth2callback`
    )}&state=${PENDING_STATE}&client_id=${DECODED_CLIENT_ID}`;
    return new Response(
      `
      <!DOCTYPE html>
      <html>
      <head>
        <title>登录</title>
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
          .login-btn {
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
          .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.25);
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>请登录</h1>
          <a href="${loginUrl}" class="login-btn">使用 OAuth 登录</a>
        </div>
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
        <title>主页</title>
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
          <h1>欢迎</h1>
          <p>您已成功认证！现在可以使用 API。</p>
          <form action="/logout" method="post">
            <button type="submit" class="logout-btn">退出登录</button>
          </form>
        </div>
        <script>
          // Handle logout form submission
          document.querySelector('form').addEventListener('submit', function(e) {
            if (!confirm('您确定要退出登录吗？')) {
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

  // Validate state parameter to prevent CSRF attacks
  if (!state || !PENDING_STATE || state !== PENDING_STATE) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  if (!code) {
    return new Response("No code provided", { status: 400 });
  }

  try {
    const response = await fetch(`https://${WATERFALL_HOSTNAME}/oauth/token`, {
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
        redirect_uri: `http://localhost:${PORT}/oauth2callback`,
        client_id: DECODED_CLIENT_ID,
        client_secret: DECODED_CLIENT_SECRET,
      }).toString(),
    });

    const data = await response.json();
    const token: TokenData = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expiry_date: Date.now() + data.expires_in * 1000,
      token_type: data.token_type,
      scope: data.scope,
    };

    saveToken(token);
    isAuthenticated = true;

    return new Response(
      `
      <!DOCTYPE html>
      <html>
      <head>
        <title>认证成功</title>
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
          <h1>认证成功</h1>
          <p>您已成功认证！现在可以关闭此窗口并使用 API。</p>
          <a href="/" class="redirect-btn">返回主页</a>
        </div>
        <script>
          // Auto redirect after 3 seconds
          setTimeout(function() {
            window.location.href = "/";
          }, 3000);
        </script>
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
  try {
    // Clear token from database
    db.run(`DELETE FROM kv WHERE key = 'token'`);
    db.run(`DELETE FROM kv WHERE key = 'apiKey'`);

    // Update authentication status
    isAuthenticated = false;

    // Redirect to homepage
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/",
      },
    });
  } catch (error) {
    return new Response("退出登录失败", { status: 500 });
  }
}

// Function to handle models list
async function handleModelsList(): Promise<Response> {
  try {
    const response = await fetch(
      `https://${WATERFALL_HOSTNAME}/api/platform/models/list`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      }
    );
    const data = await response.json();
    if (!data.success) {
      return new Response("Failed to fetch models", { status: 500 });
    }

    // Flatten all models from different categories
    const allModels = [];
    for (const category in data.data) {
      if (Array.isArray(data.data[category])) {
        allModels.push(...data.data[category]);
      }
    }

    // Convert to OpenAI compatible format
    const openaiModels = allModels
      .filter((model) => model.isVisible)
      .map((model) => {
        const created = new Date(model.updatedTime).getTime() / 1000;

        // Extract contextLength from modelTags
        let contextLength = null;
        try {
          const modelTags = JSON.parse(model.modelTags);
          if (Array.isArray(modelTags) && modelTags.length > 0) {
            const seqLengthStr = modelTags[0].modelSeqLength;
            if (seqLengthStr) {
              // Convert strings like "128K" to numbers
              const match = seqLengthStr.match(/^(\d+)(K?)$/);
              if (match) {
                contextLength =
                  parseInt(match[1]) * (match[2] === "K" ? 1000 : 1);
              }
            }
          }
        } catch (e) {
          // Ignore parsing errors
        }

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
  if (!isAuthenticated) {
    return new Response(`没有登录，请访问 http://localhost:${PORT}/ 进行登录`, {
      status: 401,
    });
  }

  const currentToken = getCurrentToken();
  if (!currentToken) {
    return new Response(`没有登录，请访问 http://localhost:${PORT}/ 进行登录`, {
      status: 401,
    });
  }

  try {
    // Handle request body for potential retries
    let body: BodyInit | null = null;
    let chunks: Uint8Array[] | null = null; // Hold chunks only when needed
    let chunksComplete = false; // Track if all chunks have been recorded
    let pumpError: Error | null = null; // Track if pump encountered an error

    if (req.method !== "GET" && req.method !== "HEAD" && req.body) {
      if (bodyBuffer) {
        // Use buffered body for retries
        body = bodyBuffer;
      } else {
        // Create a TransformStream to both forward the stream and optionally buffer it
        const { readable, writable } = new TransformStream();
        const writer = writable.getWriter();

        // Only store chunks if we might need to retry (non-GET/HEAD requests)
        chunks = [];

        // Tee the request body to both forward to the target and optionally buffer for potential retry
        const reader = req.body.getReader();

        // Read the stream and write to both the outgoing request and optionally buffer it
        const pump = async () => {
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) {
                await writer.close();
                chunksComplete = true; // Mark chunks as complete
                break;
              }

              // Store chunk for potential retry
              chunks!.push(value);

              // Write to the outgoing stream
              await writer.write(value);
            }
          } catch (error) {
            await writer.abort(error);
            pumpError = error as Error; // Store the error
            chunksComplete = true; // Mark as complete even on error
            throw error;
          }
        };

        // Start pumping the stream asynchronously - don't wait for it
        pump().catch((error) => {
          console.error("Error pumping request body:", error);
        });

        // Set the readable stream as the body for the fetch request
        body = readable;
      }
    }

    const apiKey = await getApiKey(currentToken.access_token);

    if (!apiKey) {
      return new Response("Failed to get API key", { status: 500 });
    }

    const targetUrl = `https://${WATERFALL_API_HOSTNAME}${url.pathname}${url.search}`;

    // Clone headers and modify them
    const headers = new Headers(req.headers);
    headers.set("authorization", `Bearer ${apiKey}`);
    headers.set("host", WATERFALL_API_HOSTNAME);

    // Create request with all configuration upfront
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: headers,
      body: body,
    });

    if (!response.ok) {
      console.error(
        `API request ${url.pathname}${url.search} failed: ${response.status} ${response.statusText}`
      );
      return new Response("API request failed", { status: 500 });
    }

    const responseType = response.headers.get("content-type");
    if (responseType && responseType.includes("text/event-stream")) {
      // Stream the response body instead of buffering
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
      // Parse the response body as JSON
      const data = await response.json();
      if (data && data.status != 200) {
        if (data.status == 434 && !isRetry) {
          // Token expired, refresh and retry once
          clearStoredApiKey();
          // Assemble buffer only when we need to retry
          let bufferedBody: ArrayBuffer | null = null;
          if (chunks) {
            // If chunks aren't complete, it means there was an error during streaming
            if (!chunksComplete) {
              return new Response("Request body not fully received", {
                status: 500,
              });
            }

            // Check if pump encountered an error
            if (pumpError) {
              throw pumpError;
            }
            // Convert chunks to a single ArrayBuffer
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
          // Retry by calling the handler again with isRetry=true and the buffered body
          return await handleApiProxy(req, url, true, bufferedBody);
        } else {
          // Other error or already retried, return as-is
          console.error("API request error:", data);
          return new Response(JSON.stringify(data), {
            status: 500,
            statusText: "API request error: " + data.msg || "Unknown",
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
      // For non-stream responses, we need to handle them properly to avoid memory issues
      // Use stream piping to avoid buffering large responses in memory
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

    if (url.pathname === "/oauth2callback") {
      return await handleOAuthCallback(url);
    }

    if (url.pathname === "/v1/models") {
      return await handleModelsList();
    }

    if (url.pathname === "/logout" && req.method === "POST") {
      return await handleLogout();
    }

    if (url.pathname.startsWith("/v")) {
      return await handleApiProxy(req, url);
    }

    return new Response("Not found", { status: 404 });
  },
});

console.log(`Server running on http://localhost:${server.port}`);
