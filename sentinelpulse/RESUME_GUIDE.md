# Resume & Interview Guide for SentinelPulse

Is file me aapke liye **ready-to-copy Resume Bullet Points**, **Skills Tags**, aur **Interview Questions & Answers** hain taaki aap confidently is project ko recruiters ko explain kar sako.

---

## 1. Resume Par Kaise Likhein?

**Project Title:**
`SentinelPulse — Multi-Source SOC Detection & Incident Triage Engine | Python, MITRE ATT&CK, SIEM Logic`

**3 Strong Resume Bullet Points (Copy-Paste Ready):**
* Built a zero-dependency Python SOC detection engine ingesting Linux SSH (`auth.log`) and Nginx/Apache web access logs into normalized security events mapped to **10 MITRE ATT&CK techniques** (`T1110`, `T1078`, `T1190`, `T1595`).
* Implemented sliding time-window brute-force detection and **cross-log kill-chain correlation**, automatically escalating post-brute-force SSH logins (`SP-CORR-001`) and multi-vector attacks into risk-scored (`0–100`) incidents.
* Engineered threat intelligence enrichment, RFC1918 internal-host classification, automated containment playbooks (`ufw`/`iptables`/`fail2ban`), and an interactive **HTML/JSON/Markdown SOC dashboard**, validated via automated unit tests.

**Skills Section Me Add Karein:**
`Log Analysis`, `SIEM & Detection Engineering`, `MITRE ATT&CK`, `Incident Triage`, `Python`, `SSH / Web Security`, `Threat Intelligence`, `OWASP Top 10`

---

## 2. Interview Me Kaise Explain Karein? (Simple 30-Second Pitch)

> *"Maine **SentinelPulse** naam ka ek mini-SIEM aur SOC triage tool Python me banaya hai. Real SOC me analysts ko alag-alag logs dekhne padte hain, toh mera tool Linux `auth.log` aur web server `access.log` dono ko parse karta hai. Isme JSON-based detection rules hain jo **MITRE ATT&CK** se mapped hain — jaise SSH brute-force, SQL injection, XSS, path traversal, aur directory enumeration.*
>
> *Iska sabse unique feature **Correlation** hai: agar koi IP pehle 5 failed SSH logins kare aur phir login succeed kar le, toh tool use `CRITICAL` compromise alert mark karta hai aur `0–100` risk score deta hai. Saath hi yeh threat intel check karke SOC analyst ke liye exact containment commands (`ufw`, `fail2ban`) aur ek interactive HTML dashboard generate karta hai."*

---

## 3. Common Interview Questions & Easy Answers

**Q1: Aapne `auth.log` aur `access.log` dono kyun liye?**
> Kyunki real attacks aksar sirf ek jagah nahi rukte. Agar ek hi attacker IP website par `/admin` scan kar raha hai aur saath me SSH par password guess kar raha hai, toh dono ko ek saath correlate karne se poora attack pattern (Kill Chain) dikh jata hai.

**Q2: Sliding window detection kya hota hai?**
> Agar kisi ne 1 mahine me 5 galat password daale toh wo brute-force nahi hai. Lekin agar 5 minutes (300 seconds) ke andar 5+ failed attempts aaye, tab woh brute-force hai. Mere code me `collections.deque` use karke sliding time window check kiya gaya hai.

**Q3: Alert fatigue kaise kam kiya?**
> Har ek malicious HTTP request par alag alert banane ke bajay, maine same IP + same rule ke hits ko ek single aggregated alert me group kiya hai aur top 5 evidence log lines attach ki hain.

**Q4: Agar internal IP (jaise `10.0.x.x`) se alert aaye toh kya hoga?**
> Mera `ThreatIntelEngine` RFC1918 private IPs ko detect karta hai. Internal IP hone par playbook blindly firewall drop command nahi deta, balki endpoint isolation aur lateral movement check karne ko kehta hai.

**Q5: Future me isme aur kya add kar sakte hain?**
> Real-time tailing (`watchdog`), AbuseIPDB/VirusTotal live API integration, Slack/Discord webhook alerts, aur Sigma rule YAML parser.
