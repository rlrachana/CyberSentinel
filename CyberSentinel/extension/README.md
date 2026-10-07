# CyberSentinel Chrome Extension (Proof-of-Concept)

This browser extension provides real-time client-side heuristic inspection of active browser tabs, bringing CyberSentinel's threat intelligence directly into Google Chrome or Chromium-based browsers (Brave, Edge, etc.).

---

## 🛠️ How to Load and Test in Chrome

1. Open Google Chrome.
2. Navigate to `chrome://extensions/` in your address bar.
3. Toggle on **Developer mode** in the top-right corner.
4. Click the **Load unpacked** button in the top-left corner.
5. Select the `extension/` folder located inside the `CyberSentinel/` directory:
   ```
   CyberSentinel/extension/
   ```
6. The **CyberSentinel - Phishing URL Shield** extension will appear in your toolbar!
7. Click on the shield icon while visiting any webpage to see real-time structural inspection, risk score, and detected indicators.
8. Click **Open Full CyberSentinel Dashboard** to jump into the complete Streamlit machine learning analysis app.
