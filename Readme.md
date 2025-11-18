# RM330 Repository

## Google Drive Integration

This repository includes a GitHub Actions workflow to import files from Google Drive automatically.

### Quick Start Guide

Follow these steps to set up Google Drive integration:

---

## Step 1: Create Google Cloud Project and Enable API

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Sign in with your Google Account
3. Click the project dropdown at the top → **"New Project"**
4. Enter project name (e.g., "GitHub-GDrive-Import") → **"Create"**
5. Select your new project from the dropdown
6. Navigate to **"APIs & Services"** → **"Library"**
7. Search for **"Google Drive API"** and click on it
8. Click **"Enable"**

## Step 2: Create OAuth 2.0 Credentials

1. Go to **"APIs & Services"** → **"Credentials"**
2. Click **"Create Credentials"** → **"OAuth client ID"**
3. If prompted, configure the consent screen:
   - Click **"Configure Consent Screen"**
   - Select **"External"** → **"Create"**
   - Fill in required fields:
     - App name: "GitHub GDrive Import"
     - User support email: your email
     - Developer contact: your email
   - Click **"Save and Continue"** through all steps
   - Return to **"Credentials"**
4. Click **"Create Credentials"** → **"OAuth client ID"** again
5. Application type: **"Desktop app"**
6. Name: "Skicka Client"
7. Click **"Create"**
8. **IMPORTANT:** Copy and save:
   - **Client ID** (format: `xxxxx.apps.googleusercontent.com`)
   - **Client Secret** (random string)

## Step 3: Generate Token with Skicka

You need to install Skicka on your computer and authenticate with Google.

### Install Skicka

**macOS (Homebrew):**
```bash
brew install skicka
```

**Linux:**
```bash
wget https://github.com/google/skicka/releases/download/v0.8.0/skicka-v0.8.0-linux-amd64
chmod +x skicka-v0.8.0-linux-amd64
sudo mv skicka-v0.8.0-linux-amd64 /usr/local/bin/skicka
```

**Windows:**
Download from [Skicka Releases](https://github.com/google/skicka/releases) and add to PATH.

### Configure and Authenticate

1. Initialize skicka:
```bash
skicka init
```

2. Edit the config file (`~/.skicka.config` on macOS/Linux, `%USERPROFILE%\.skicka.config` on Windows):
```json
{
  "clientid": "YOUR_CLIENT_ID_FROM_STEP_2",
  "clientsecret": "YOUR_CLIENT_SECRET_FROM_STEP_2"
}
```

3. Authenticate (this will open your browser):
```bash
skicka ls /
```

4. Sign in, grant permissions, and return to terminal

5. Copy the token file content:

**macOS/Linux:**
```bash
cat ~/.skicka.tokencache.json
```

**Windows:**
```cmd
type %USERPROFILE%\.skicka.tokencache.json
```

Copy the entire JSON output (starts with `{"access_token":...`)

## Step 4: Configure GitHub Secrets

1. Go to your GitHub repository → **"Settings"** → **"Secrets and variables"** → **"Actions"**
2. Click **"New repository secret"** and add these three secrets:

| Secret Name | Value |
|------------|-------|
| `GOOGLE_CLIENT_ID` | Your Client ID from Step 2 |
| `GOOGLE_CLIENT_SECRET` | Your Client Secret from Step 2 |
| `GOOGLE_DRIVE_TOKEN` | Complete JSON from Step 3 |

---

## How to Use

### Running the Workflow

1. Go to **Actions** tab in GitHub
2. Select **"Import Files from Google Drive"** workflow
3. Click **"Run workflow"**
4. Fill in the inputs:
   - **Folder path**: Google Drive folder path (see below)
   - **Target path**: Where to save in repo (default: `./`)
5. Click **"Run workflow"**

### Understanding Folder Paths

The workflow uses **folder paths**, not URLs or folder IDs.

**Examples:**
- Root folder named "ProjectData": `/ProjectData`
- Nested folder: `/Work/Projects/Data2024`
- Subfolder: `/MyDocs/Reports/Q4`

**Important Notes:**
- Paths must start with `/`
- Use the folder structure as it appears in "My Drive"
- Paths are case-sensitive

**Finding Your Folder Path:**

You can verify the path locally:
```bash
skicka ls /                    # List root folders
skicka ls /MyFolder            # List contents of a folder
skicka ls /MyFolder/SubFolder  # Navigate deeper
```

### What the Workflow Does

1. ✓ Checks out your repository
2. ✓ Connects to Google Drive with your credentials
3. ✓ Downloads all files from the specified folder
4. ✓ Saves them to the target path in your repository
5. ✓ Automatically commits and pushes the changes

The `remove-outdated: true` setting ensures that if files are deleted from Google Drive, they'll also be removed from your repository on the next sync.

---

## Troubleshooting

### "Neither input download-from nor upload-to has been specified"

This error means the workflow configuration is incorrect. Make sure you're using the updated workflow file from this repository.

### "Permission denied" or "Authentication failed"

**Cause:** Invalid or expired credentials.

**Solution:**
1. Verify all three secrets are set correctly in GitHub
2. Check the token hasn't expired
3. Regenerate token:
   ```bash
   skicka ls /
   ```
4. Update `GOOGLE_DRIVE_TOKEN` secret with new token

### "Folder not found"

**Cause:** Incorrect folder path.

**Solution:**
1. Verify the path locally:
   ```bash
   skicka ls /
   skicka ls /YourFolder
   ```
2. Use the exact path (case-sensitive)
3. Ensure path starts with `/`
4. Check you have access to the folder in Google Drive

### "No changes to commit"

**Cause:** The folder exists but no files were downloaded.

**Possible reasons:**
- Folder is empty in Google Drive
- Path is incorrect
- No access to the folder
- Files already exist and haven't changed

**Solution:**
- Check workflow logs in Actions tab for specific errors
- Verify folder contains files in Google Drive
- Confirm your Google account has access

### Token Expiration

Google OAuth tokens can expire after prolonged inactivity.

**Symptoms:** Workflow worked before but now fails with authentication errors.

**Solution:** Regenerate the token (Step 3) and update the `GOOGLE_DRIVE_TOKEN` secret.

---

## Best Practices

### 1. Test with Small Folders First
Before importing large amounts of data, test with a small folder to ensure everything works.

### 2. Organize Your Drive
Keep files in clearly named folders with predictable paths:
- ✓ Good: `/GitHub-Imports/RM330-Data`
- ✗ Avoid: `/My Documents/Various/Stuff/Random/Data`

### 3. Be Mindful of File Sizes
- GitHub has file size limits (100 MB recommended maximum)
- Large files may fail to commit
- Repository size limit is typically 1-5 GB

### 4. Use Specific Paths
Import specific folders rather than your entire Drive:
- ✓ Good: `/Projects/RM330/DataFiles`
- ✗ Avoid: `/` (entire Drive)

### 5. Monitor Workflow Runs
Check the Actions tab after each run to ensure success and review what was imported.

---

## Security Notes

⚠️ **IMPORTANT:**
- Never commit the token file or credentials to the repository
- Always store credentials in GitHub Secrets
- Treat your token like a password - it grants access to your Google Drive
- Consider creating a dedicated Google account for automation
- Regularly review and rotate credentials

---

## Advanced Usage

### Scheduling Automatic Imports

You can modify the workflow to run on a schedule. Add this to the `on:` section:

```yaml
on:
  workflow_dispatch:    # Keep manual trigger
    # ... existing inputs ...
  schedule:
    - cron: '0 2 * * *'  # Runs daily at 2 AM UTC
```

### Importing to Different Branches

By default, files are imported to the current branch. You can modify the checkout step to target a specific branch:

```yaml
- name: Checkout repository
  uses: actions/checkout@v4
  with:
    ref: data-imports  # Specify target branch
```

---

## References

- [Skicka Documentation](https://github.com/google/skicka)
- [action-google-drive](https://github.com/satackey/action-google-drive)
- [Google Drive API](https://developers.google.com/drive)
- [GitHub Actions Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)

---

## Summary Setup Checklist

Use this checklist to ensure you've completed all setup steps:

- [ ] Created Google Cloud project
- [ ] Enabled Google Drive API
- [ ] Created OAuth 2.0 credentials
- [ ] Installed Skicka on local machine
- [ ] Configured Skicka with credentials
- [ ] Authenticated with Google and generated token
- [ ] Added `GOOGLE_CLIENT_ID` secret in GitHub
- [ ] Added `GOOGLE_CLIENT_SECRET` secret in GitHub
- [ ] Added `GOOGLE_DRIVE_TOKEN` secret in GitHub
- [ ] Verified folder path with `skicka ls`
- [ ] Tested workflow with a small folder first

Once all items are checked, you're ready to import files from Google Drive!

---
