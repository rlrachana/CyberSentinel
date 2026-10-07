// CyberSentinel Client-Side Heuristic & Threat Evaluator
document.addEventListener("DOMContentLoaded", () => {
  const urlDisplay = document.getElementById("urlDisplay");
  const verdictBox = document.getElementById("verdictBox");
  const verdictText = document.getElementById("verdictText");
  const riskScoreText = document.getElementById("riskScoreText");
  const flagsList = document.getElementById("flagsList");

  // Query active browser tab
  if (chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        analyzeUrl(tabs[0].url);
      } else {
        urlDisplay.textContent = "Could not read active URL";
      }
    });
  } else {
    // Fallback for direct browser testing
    analyzeUrl("https://en.wikipedia.org/wiki/Phishing");
  }

  function analyzeUrl(url) {
    urlDisplay.textContent = url;
    const flags = [];
    let score = 0;

    const lower = url.toLowerCase();
    let hostname = "";
    try {
      hostname = new URL(url).hostname;
    } catch (e) {
      hostname = url;
    }

    // 1. IP Address check
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipv4Regex.test(hostname)) {
      flags.push("Raw IP address used instead of hostname (+35 risk)");
      score += 35;
    }

    // 2. Length check
    if (url.length > 75) {
      flags.push(`Excessive URL length: ${url.length} chars (+20 risk)`);
      score += 20;
    }

    // 3. Credential masking '@'
    if (url.includes("@")) {
      flags.push("Contains '@' credential masking (+30 risk)");
      score += 30;
    }

    // 4. Double slash in path
    if (url.indexOf("//", 8) > 0) {
      flags.push("Double slash '//' redirect in path (+20 risk)");
      score += 20;
    }

    // 5. Hyphen in domain
    if (hostname.includes("-")) {
      flags.push("Hyphen in domain label (+10 risk)");
      score += 10;
    }

    // 6. Subdomain stacking
    const dots = (hostname.match(/\./g) || []).length;
    if (dots > 2) {
      flags.push(`Excessive subdomains (${dots} dots) (+15 risk)`);
      score += 15;
    }

    // 7. Insecure HTTP
    if (url.startsWith("http://")) {
      flags.push("Insecure unencrypted HTTP connection (+10 risk)");
      score += 10;
    }

    // 8. Suspicious keywords
    const keywords = ["login", "verify", "update", "account", "banking", "secure", "signin", "wallet", "password"];
    const matched = keywords.filter(kw => lower.includes(kw));
    if (matched.length > 0) {
      flags.push(`Suspicious keywords found: ${matched.join(", ")} (+15 risk)`);
      score += 15;
    }

    score = Math.min(score, 100);

    // Update UI
    flagsList.innerHTML = "";
    if (flags.length === 0) {
      const li = document.createElement("li");
      li.textContent = "✔ Clean URL structure. No red flags found.";
      flagsList.appendChild(li);
    } else {
      flags.forEach(f => {
        const li = document.createElement("li");
        li.textContent = f;
        flagsList.appendChild(li);
      });
    }

    verdictBox.className = "verdict-box";
    if (score < 35) {
      verdictBox.classList.add("safe");
      verdictText.textContent = "✅ Legitimate / Safe";
      riskScoreText.textContent = `Risk Level: ${score}% (Low)`;
    } else if (score < 65) {
      verdictBox.classList.add("suspicious");
      verdictText.textContent = "⚠️ Suspicious URL";
      riskScoreText.textContent = `Risk Level: ${score}% (Moderate)`;
    } else {
      verdictBox.classList.add("phishing");
      verdictText.textContent = "🚨 High Phishing Risk";
      riskScoreText.textContent = `Risk Level: ${score}% (High)`;
    }
  }
});
