# R4W0N - v1

### RTSP Analysis & Wide-area Object Networking

<img width="1142" height="645" alt="Screenshot From 2026-04-26 09-21-38" src="https://github.com/user-attachments/assets/e5348e16-bb82-4d97-9686-cd199acc1042" />

- R4W0N USER INTERFACE.

  
**R4W0N** is a high-performance, professional-grade RTSP auditing tool designed for Red Teamers and Security Researchers. It automates the discovery of network segments and identifies RTSP-enabled devices (IP Cameras, NVRs, CCTV) with advanced fingerprinting and deep path discovery logic.

Featuring a sleek, futuristic dark-mode web interface, R4W0N provides real-time intelligence gathering with a focus on stealth and operational efficiency.

## Key Features

-   **Automated Reconnaissance**: Automatically detects local IPv4 network segments (CIDR) for rapid deployment.
    
-   **Deep URL Brute-force**: Integrated Nmap-style path discovery using an extensive wordlist of common and vendor-specific RTSP paths.
    
-   **Vendor Fingerprinting**: Identifies device manufacturers (Hikvision, Dahua, Axis, etc.) by analyzing RTSP response headers.
    
-   **Collapsible Intelligence UI**: Organizes discovered devices into clean, interactive cards. View 20+ URLs per device without cluttering your workspace.
    
-   **Real-time Console**: Monitor the internal scanning engine with a live, terminal-style log output.
    
-   **Stealth & Efficiency**: Optimized multi-threading for high-speed scanning with adjustable timeouts to minimize network noise.
    
-   **One-Click Export**: Copy discovered stream URLs directly to your clipboard for instant testing in VLC or FFmpeg.
    

## 🛠️ Installation

Ensure you have **Python 3.x** installed on your system.

1.  **Clone the repository:**
    
    ```
    git clone [https://github.com/XsanFlip/r4w0n.git](https://github.com/XsanFlip/r4w0n.git)
    cd r4w0n
    
    ```
    
2.  **Install dependencies:**
    
    ```
    pip install flask
    
    ```
    

## Operational Guide

1.  **Launch the Auditor:**
    
    ```
    python r4w0n-gui.py
    
    ```
    
2.  **Access the Intelligence Dashboard:** Open your browser and navigate to: `http://127.0.0.1:5000`
    
3.  **Execute Mission:**
    
    -   Select the target network segment.
        
    -   Toggle **Deep URL Brute-force** for comprehensive path discovery.
        
    -   Click **EXECUTE SCAN** and monitor the results in real-time.
        

## ⚠️ Ethical Disclaimer

This tool is developed for **educational and authorized security auditing purposes only**. Accessing surveillance systems without explicit written consent is illegal and unethical. The developer (**xsanlahci**) assumes no liability for misuse or damage caused by this program.

## Credits

**c0ded by xsanlahci**

_The R4W0N interface featuring the collapsible result cards and circular progress monitor._
