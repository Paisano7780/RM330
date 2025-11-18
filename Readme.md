# RM330 Repository

## Google Drive Integration

This repository includes a GitHub Actions workflow to import files from Google Drive.

### Setup Instructions

Before you can use the Google Drive import workflow, you need to configure Google Drive API credentials:

#### 1. Create a Google Cloud Project and Enable Google Drive API

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google Drive API for your project
4. Go to "APIs & Services" > "Credentials"

#### 2. Create OAuth 2.0 Credentials

1. Click "Create Credentials" > "OAuth client ID"
2. Choose "Desktop app" as the application type
3. Note down the **Client ID** and **Client Secret**

#### 3. Generate Token

1. Follow the instructions from [satackey/action-google-drive](https://github.com/satackey/action-google-drive) to generate a token cache
2. You'll need to run `skicka` locally once to authenticate and generate the token

#### 4. Configure GitHub Secrets

Add the following secrets to your GitHub repository (Settings > Secrets and variables > Actions):

- `GOOGLE_CLIENT_ID`: Your Google OAuth Client ID
- `GOOGLE_CLIENT_SECRET`: Your Google OAuth Client Secret
- `GOOGLE_DRIVE_TOKEN`: Your Google Drive token cache JSON

### How to Use the Workflow

1. Go to the **Actions** tab in your GitHub repository
2. Select the "Import Files from Google Drive" workflow
3. Click "Run workflow"
4. Fill in the required inputs:
   - **Folder ID**: The ID of the Google Drive folder you want to import (you can find this in the folder URL: `https://drive.google.com/drive/folders/YOUR_FOLDER_ID`)
   - **Target path**: Where to save the files in the repository (default is `./` for the root directory)
5. Click "Run workflow" to start the import

The workflow will:
- Download all files from the specified Google Drive folder
- Save them to the specified path in the repository
- Commit and push the changes automatically

### Example

If your Google Drive folder URL is:
```
https://drive.google.com/drive/folders/1AbCdEfGhIjKlMnOpQrStUvWxYz
```

The Folder ID is: `1AbCdEfGhIjKlMnOpQrStUvWxYz`

---

## Original Notes

instalar desde marketplace herramienta https://github.com/prasmussen/gdrive

