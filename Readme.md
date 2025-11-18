# RM330 Repository

## Google Drive Integration

This repository includes a GitHub Actions workflow to import files from Google Drive.

### Prerequisites

- A Google Account with access to Google Drive
- Administrative access to this GitHub repository
- Basic familiarity with command line tools (for token generation)

---

## Complete Setup Guide - Step by Step

### Step 1: Create a Google Cloud Project and Enable Google Drive API

1. Open your web browser and go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Sign in with your Google Account
3. Click on the project dropdown at the top of the page
4. Click **"New Project"**
5. Enter a project name (e.g., "GitHub Actions Drive Import")
6. Click **"Create"** and wait for the project to be created
7. Make sure your new project is selected in the project dropdown
8. In the left sidebar, click **"APIs & Services"** > **"Library"**
9. Search for "Google Drive API"
10. Click on "Google Drive API" in the results
11. Click the **"Enable"** button
12. Wait for the API to be enabled (this may take a few seconds)

### Step 2: Create OAuth 2.0 Credentials

1. In the Google Cloud Console, go to **"APIs & Services"** > **"Credentials"**
2. Click **"Create Credentials"** at the top of the page
3. Select **"OAuth client ID"** from the dropdown
4. If prompted to configure the OAuth consent screen:
   - Click **"Configure Consent Screen"**
   - Select **"External"** user type
   - Click **"Create"**
   - Fill in the required fields:
     - App name: "GitHub Actions Drive Import"
     - User support email: (your email)
     - Developer contact information: (your email)
   - Click **"Save and Continue"**
   - Skip the "Scopes" step by clicking **"Save and Continue"**
   - Skip the "Test users" step by clicking **"Save and Continue"**
   - Click **"Back to Dashboard"**
5. Go back to **"Credentials"** and click **"Create Credentials"** > **"OAuth client ID"** again
6. For "Application type", select **"Desktop app"**
7. Enter a name (e.g., "Skicka Desktop Client")
8. Click **"Create"**
9. A dialog will appear with your credentials - **IMPORTANT: Copy these values now:**
   - **Client ID** (looks like: `xxxxx.apps.googleusercontent.com`)
   - **Client Secret** (a random string)
10. Click **"OK"** (you can also download the JSON file for backup)

### Step 3: Generate Token Cache Using Skicka

This is the most technical step. You need to run `skicka` on your local computer to authenticate and generate a token.

#### 3.1. Install Skicka

**On macOS (using Homebrew):**
```bash
brew install skicka
```

**On Linux:**
```bash
# Download the latest release from GitHub
wget https://github.com/google/skicka/releases/download/v0.8.0/skicka-v0.8.0-linux-amd64
chmod +x skicka-v0.8.0-linux-amd64
sudo mv skicka-v0.8.0-linux-amd64 /usr/local/bin/skicka
```

**On Windows:**
- Download the Windows executable from [Skicka Releases](https://github.com/google/skicka/releases)
- Add it to your PATH or run from the download directory

#### 3.2. Configure Skicka

1. Open a terminal/command prompt
2. Create a skicka configuration file:
```bash
skicka init
```
3. This creates `~/.skicka.config` (or `%USERPROFILE%\.skicka.config` on Windows)
4. Edit the configuration file and add your credentials:
```json
{
  "clientid": "YOUR_CLIENT_ID_FROM_STEP_2",
  "clientsecret": "YOUR_CLIENT_SECRET_FROM_STEP_2"
}
```

#### 3.3. Authenticate and Generate Token

1. Run the following command to authenticate:
```bash
skicka ls /
```
2. Skicka will open a browser window asking you to authorize the application
3. Sign in with your Google Account
4. Click **"Allow"** to grant permissions
5. The browser will show a success message
6. Go back to your terminal - skicka should now list your Google Drive root folder
7. Skicka has created a token file at `~/.skicka.tokencache.json`

#### 3.4. Get the Token Content

You need the entire content of the token file as a JSON string:

**On macOS/Linux:**
```bash
cat ~/.skicka.tokencache.json
```

**On Windows:**
```cmd
type %USERPROFILE%\.skicka.tokencache.json
```

Copy the entire JSON content (it will look like `{"access_token":"...","token_type":"Bearer",...}`)

### Step 4: Configure GitHub Secrets

1. Open your GitHub repository in a web browser
2. Click on **"Settings"** (you need admin access)
3. In the left sidebar, click **"Secrets and variables"** > **"Actions"**
4. Click **"New repository secret"**
5. Add the first secret:
   - Name: `GOOGLE_CLIENT_ID`
   - Secret: Paste your Client ID from Step 2
   - Click **"Add secret"**
6. Click **"New repository secret"** again
7. Add the second secret:
   - Name: `GOOGLE_CLIENT_SECRET`
   - Secret: Paste your Client Secret from Step 2
   - Click **"Add secret"**
8. Click **"New repository secret"** one more time
9. Add the third secret:
   - Name: `GOOGLE_DRIVE_TOKEN`
   - Secret: Paste the entire JSON content from Step 3.4
   - Click **"Add secret"**

You should now see all three secrets listed on the Actions secrets page.

---

## How to Use the Workflow

Once you've completed the setup steps above, you can import files from Google Drive:

1. Go to the **Actions** tab in your GitHub repository
2. In the left sidebar, click on **"Import Files from Google Drive"**
3. Click the **"Run workflow"** button (on the right side)
4. Fill in the required inputs:
   - **Folder path**: The path to your folder in Google Drive (see below for details)
   - **Target path**: Where to save the files in the repository (default: `./`)
5. Click **"Run workflow"** to start the import

#### Understanding Google Drive Folder Paths

**Important:** Skicka (the tool used by this workflow) works with **folder paths**, not folder IDs from URLs.

**To find your folder path:**
1. Open Google Drive in your browser
2. Navigate to the folder you want to import
3. Note the folder structure from your Drive root

**Examples:**
- If your folder is in the root of "My Drive" and named "ProjectData": `/ProjectData`
- If your folder is nested: `/Work/Projects/Data`
- If you're sharing a folder that's not in your root: Create or move it to a known path

**You can also use folder IDs (from URLs), but this is less reliable:**
1. Look at the URL when viewing a folder: `https://drive.google.com/drive/folders/1AbCdEfGhIjKlMnOpQrStUvWxYz`
2. The folder ID is: `1AbCdEfGhIjKlMnOpQrStUvWxYz`
3. Enter it in the workflow (the workflow will automatically add a `/` prefix)

**Recommendation:** Use folder paths for more predictable results.

#### What the Workflow Does

The workflow will:
1. Check out your repository
2. Connect to Google Drive using your credentials
3. Download all files from the specified folder
4. Save them to the specified path in the repository
5. Automatically commit and push the changes

---

## Troubleshooting

### "Permission denied" or "Authentication failed"

- Verify that all three secrets are correctly set in GitHub
- Make sure the token hasn't expired (Google tokens can expire after a period of inactivity)
- To regenerate the token:
  1. Run `skicka ls /` on your local machine
  2. Re-authenticate if prompted
  3. Copy the new token from `~/.skicka.tokencache.json`
  4. Update the `GOOGLE_DRIVE_TOKEN` secret in GitHub

### "Folder not found" or "No such file or directory"

**This is the most common issue.** Skicka uses path-based navigation:
- **Correct format:** `/MyFolder/SubFolder` (path from your Drive root)
- **Incorrect format:** `1AbCdEfGhIjKlMnOpQrStUvWxYz` (folder ID without context)

**To fix:**
1. Run `skicka ls /` locally to see your Drive root folders
2. Navigate to find your folder: `skicka ls /MyFolder`
3. Use the full path in the workflow, e.g., `/MyFolder/DataToImport`

### "No changes to commit - no files were downloaded"

This means the download didn't retrieve any files:
- The folder path is incorrect (see above)
- The folder is empty in Google Drive
- Your Google account doesn't have access to the folder
- Check the workflow logs in GitHub Actions for specific error messages

### Workflow Fails to Run

- Check the Actions tab for detailed error messages
- Ensure you have write permissions for the repository
- Verify that GitHub Actions are enabled for the repository (Settings > Actions > General)

### Files are Downloaded but Not Committed

- Check if the files exceed GitHub's size limits (100 MB recommended, 2 GB maximum per file)
- Large repositories may hit GitHub's repository size limit
- Check the workflow logs for git errors

---

## Important Notes

- **Folder Paths vs IDs**: Skicka works best with paths (like `/MyFolder/SubFolder`) rather than folder IDs from URLs
- **Token Security**: Your token gives access to Google Drive. Always store it in GitHub Secrets, never commit it to the repository
- **Token Expiration**: Google OAuth tokens can expire. If the workflow stops working after a while, regenerate the token (see Step 3)
- **File Size Limits**: GitHub has limits on file sizes. Very large files may fail to upload
- **Bandwidth**: Downloading many large files may take time. Check the Actions logs for progress

---

## Tips for Success

1. **Test with a Small Folder First**: Before importing large amounts of data, test with a small folder to ensure everything works
2. **Organize Your Drive**: Keep files you want to import in clearly-named folders at predictable paths
3. **Check Logs**: Always review the workflow logs in the Actions tab to see what happened
4. **Use Specific Paths**: Instead of importing your entire Drive, target specific folders
5. **Clean Up**: After importing, you may want to disable or delete old workflow runs to save Actions minutes

---

## Alternative: Using Folder Paths

Since skicka works with paths, here's the recommended workflow:

1. **Organize your Google Drive:**
   - Create a dedicated folder for files to import (e.g., `/GitHub-Imports/RM330-Data`)

2. **Find the path:**
   - Run `skicka ls /` locally to list root folders
   - Navigate to confirm: `skicka ls /GitHub-Imports`

3. **Use in workflow:**
   - Enter the full path: `/GitHub-Imports/RM330-Data`
   - Or just the folder name if it's in root: `/RM330-Data`

---

## References

- [Skicka Documentation](https://github.com/google/skicka)
- [action-google-drive GitHub Action](https://github.com/satackey/action-google-drive)
- [Google Drive API Documentation](https://developers.google.com/drive)

---

## Original Notes

instalar desde marketplace herramienta https://github.com/prasmussen/gdrive


