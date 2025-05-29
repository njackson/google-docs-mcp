// src/auth.ts
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import * as readline from 'readline/promises';
import { fileURLToPath } from 'url';

// --- Configure file paths with environment variable support ---
function getConfigPath(envVar: string, defaultFileName: string): string {
  // Check if environment variable is set
  const envPath = process.env[envVar];
  if (envPath) {
    return path.resolve(envPath);
  }

  // Default to user's config directory
  const userConfigDir = path.join(os.homedir(), '.config', 'google-docs-mcp');
  const defaultPath = path.join(userConfigDir, defaultFileName);

  return defaultPath;
}

// Ensure config directory exists
async function ensureConfigDirectoryExists() {
  const userConfigDir = path.join(os.homedir(), '.config', 'google-docs-mcp');
  try {
    await fs.mkdir(userConfigDir, { recursive: true });
  } catch (error) {
    // Directory creation failed, will fallback to current working directory in individual functions
    console.error(`Warning: Could not create config directory ${userConfigDir}, will use current working directory as fallback`);
  }
}

const TOKEN_PATH = getConfigPath('GOOGLE_TOKEN_PATH', 'token.json');
const CREDENTIALS_PATH = getConfigPath('GOOGLE_CREDENTIALS_PATH', 'credentials.json');

// Log the paths being used for debugging
console.error(`Using credentials file: ${CREDENTIALS_PATH}`);
console.error(`Using token file: ${TOKEN_PATH}`);
// --- End of path configuration ---

const SCOPES = [
  'https://www.googleapis.com/auth/documents',
  'https://www.googleapis.com/auth/drive' // Full Drive access for listing, searching, and document discovery
];

async function loadSavedCredentialsIfExist(): Promise<OAuth2Client | null> {
  try {
    await ensureConfigDirectoryExists();
    const content = await fs.readFile(TOKEN_PATH);
    const credentials = JSON.parse(content.toString());
    const { client_secret, client_id, redirect_uris } = await loadClientSecrets();
    const client = new google.auth.OAuth2(client_id, client_secret, redirect_uris?.[0]);
    client.setCredentials(credentials);
    return client;
  } catch (err) {
    return null;
  }
}

async function loadClientSecrets() {
  try {
    const content = await fs.readFile(CREDENTIALS_PATH);
    const keys = JSON.parse(content.toString());
    const key = keys.installed || keys.web;
    if (!key) throw new Error("Could not find client secrets in credentials.json.");
    return {
        client_id: key.client_id,
        client_secret: key.client_secret,
        redirect_uris: key.redirect_uris
    };
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      throw new Error(`Credentials file not found at: ${CREDENTIALS_PATH}

Please ensure you have:
1. Downloaded your Google API credentials JSON file
2. Set GOOGLE_CREDENTIALS_PATH environment variable, or
3. Placed the file at: ${CREDENTIALS_PATH}

See INSTALLATION.md for detailed setup instructions.`);
    }
    throw error;
  }
}

async function saveCredentials(client: OAuth2Client): Promise<void> {
  await ensureConfigDirectoryExists();
  const { client_secret, client_id } = await loadClientSecrets();
  const payload = JSON.stringify({
    type: 'authorized_user',
    client_id: client_id,
    client_secret: client_secret,
    refresh_token: client.credentials.refresh_token,
  });
  await fs.writeFile(TOKEN_PATH, payload);
  console.error('Token stored to', TOKEN_PATH);
}

async function authenticate(): Promise<OAuth2Client> {
  const { client_secret, client_id, redirect_uris } = await loadClientSecrets();
  const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris?.[0]);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const authorizeUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES.join(' '),
  });

  console.error('Authorize this app by visiting this url:', authorizeUrl);
  const code = await rl.question('Enter the code from that page here: ');
  rl.close();

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    if (tokens.refresh_token) { // Save only if we got a refresh token
         await saveCredentials(oAuth2Client);
    } else {
         console.error("Did not receive refresh token. Token might expire.");
    }
    console.error('Authentication successful!');
    return oAuth2Client;
  } catch (err) {
    console.error('Error retrieving access token', err);
    throw new Error('Authentication failed');
  }
}

export async function authorize(): Promise<OAuth2Client> {
  let client = await loadSavedCredentialsIfExist();
  if (client) {
    // Optional: Add token refresh logic here if needed, though library often handles it.
    console.error('Using saved credentials.');
    return client;
  }
  console.error('Starting authentication flow...');
  client = await authenticate();
  return client;
}
