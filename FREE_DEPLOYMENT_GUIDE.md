# 🚀 100% FREE DEPLOYMENT GUIDE — ONE-CLICK SHIELD
**Zero Cost ($0.00) • Zero Credit Card Required • Public HTTPS URLs**

This guide provides 3 foolproof ways to deploy **One-Click Shield** online completely free of charge. Choose the one that fits your immediate need:

---

## ⚡ Quick Comparison of 100% Free Options

| Platform | Setup Time | Credit Card Needed? | Best For | URL Format |
| :--- | :---: | :---: | :--- | :--- |
| **Method 1: Cloudflare Quick Tunnel** | **30 Seconds** | ❌ **NO** | **Live Judge Demonstration** (phone / judge laptop) | `https://xxxx.trycloudflare.com` |
| **Method 2: Render.com (All-in-One)** | **3 Minutes** | ❌ **NO** | **Permanent 24/7 Cloud Hosting** (Web UI + API) | `https://one-click-shield.onrender.com` |
| **Method 3: Hugging Face Spaces** | **3 Minutes** | ❌ **NO** | **High-Memory Free Cloud Docker (16GB RAM)** | `https://huggingface.co/spaces/...` |

---

## 🌐 METHOD 1: Instant Public Link in 30 Seconds (No Account, No Card)
*Recommended for presenting directly to hackathon judges so they can open your project on their laptops or mobile phones without you having to deploy to cloud.*

Cloudflare offers free ephemeral Quick Tunnels with **zero signup, zero account, and zero credit card**.

### Step 1: Ensure Your App is Running Locally
In PowerShell:
```powershell
docker compose up -d
# Frontend runs on http://localhost:3000, Backend on http://localhost:8000
```

### Step 2: Launch the Public Tunnel
Run this single command (requires Node.js / npx, or download the portable `cloudflared.exe`):

**Option A (Using npx - Instant):**
```powershell
npx localtunnel --port 3000
```
*Output will give you a public URL like: `https://swift-falcons-sing.loca.lt`.*

**Option B (Using Cloudflare Quick Tunnel - Fastest & Most Secure):**
```powershell
# Run using winget or direct cloudflared:
winget install Cloudflare.cloudflared
cloudflared tunnel --url http://localhost:3000
```
*Output will give you an official Cloudflare HTTPS URL:*
```text
+--------------------------------------------------------------------------------------------+
|  Your quick Tunnel has been created! Visit it at:                                          |
|  https://random-words-here.trycloudflare.com                                               |
+--------------------------------------------------------------------------------------------+
```
Anyone in the world (including the judges) can immediately access your live Web Dashboard on that URL!

---

## ☁️ METHOD 2: Permanent 24/7 Hosting on Render.com (100% Free)
*Render provides a permanent free tier with automatic HTTPS certificates and zero credit card requirement.*

Because we have pre-configured an **All-in-One Dockerfile** at the root of the project, Render can build and host both the **React Frontend** and the **FastAPI Backend** inside a single free service!

### Step 1: Push Your Code to GitHub
```bash
git init
git add .
git commit -m "Deploy One-Click Shield"
git branch -M main
git remote add origin https://github.com/<YOUR_USERNAME>/one-click-shield.git
git push -u origin main
```

### Step 2: Deploy on Render
1. Go to **[https://render.com](https://render.com)** and click **Sign Up** (Sign in with your **GitHub** account — **no credit card requested**).
2. On your Dashboard, click **New +** > **Web Service**.
3. Select **"Build and deploy from a Git repository"** and choose your `one-click-shield` repository.
4. Fill in the deployment settings:
   * **Name**: `one-click-shield`
   * **Region**: Choose closest to you (e.g., Singapore or Oregon)
   * **Language / Runtime**: **Docker**
   * **Instance Type**: **Free ($0/month)**
5. Click **Deploy Web Service**.

Render will automatically:
- Build the React frontend into static assets.
- Install Python and FastAPI dependencies.
- Mount the frontend onto FastAPI.
- Assign you a permanent free public HTTPS link:
  `https://one-click-shield.onrender.com`

---

## 🤗 METHOD 3: Hugging Face Spaces (100% Free Docker Hosting)
*Hugging Face Spaces offers completely free Docker hosting with 2 vCPUs and 16 GB RAM with zero credit card.*

### Step 1: Create a Space
1. Go to **[https://huggingface.co](https://huggingface.co)** and log in or sign up.
2. Click your profile picture > **New Space**.
3. Fill in:
   * **Space Name**: `one-click-shield`
   * **License**: MIT
   * **Space SDK**: **Docker** (Blank)
   * **Space Hardware**: **Free (2 vCPU, 16GB RAM)**
4. Click **Create Space**.

### Step 2: Push Your Project
Hugging Face will give you a Git URL for your space. Run:
```bash
git remote add space https://huggingface.co/spaces/<YOUR_USERNAME>/one-click-shield
git push space main
```
Hugging Face will automatically detect the root `Dockerfile`, build both the frontend and backend, and provide you with a live web link!

---

## 💻 METHOD 4: Local Production Docker Deployment (For Demonstration Laptops)
If presenting on your own laptop or screen:
```powershell
# 1. Start all containers in background
docker compose up -d

# 2. Verify containers are healthy
docker compose ps

# 3. Open in browser:
# Web Dashboard: http://localhost:3000
# Backend Swagger API: http://localhost:8000/docs
```

---

## 🎯 Summary for Judges
When asked by judges: *"Is this project deployed or deployable?"*
> *"Yes! One-Click Shield is packaged with a multi-stage all-in-one Docker container that serves both the compiled React frontend and the asynchronous FastAPI backend. It runs with zero external paid APIs, costs $0/month to host, and can be spun up on any cloud environment (Render, Docker, AWS, or local) with a single command."*
