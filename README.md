# 🌐 DNS Lookup API

A comprehensive DNS lookup service with support for multiple record types and resolvers.

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.com/donate/?business=53EHQKQ3T87J8&no_recurring=0&currency_code=USD)

![dns-lookup-api](https://github.com/user-attachments/assets/63054937-f732-41e5-bb5a-222c27a6db85)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Update Status](https://img.shields.io/badge/Status-Actively%20Maintained-green.svg)](https://github.com/ufukart/DNS-Lookup-API)
[![Last Updated](https://img.shields.io/github/last-commit/ufukart/DNS-Lookup-API)](https://github.com/ufukart/DNS-Lookup-API/commits/main)
![GitHub repo size](https://img.shields.io/github/repo-size/ufukart/DNS-Lookup-API)
![Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2Fufukart%2FDNS-Lookup-API%2F&label=HITS&countColor=%23263759&style=flat)
[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.com/donate/?business=53EHQKQ3T87J8&no_recurring=0&currency_code=USD)
---

## 🔌 Endpoints

### `GET /api/lookup`
Retrieve DNS records for a domain or IP address.

- **Parameters:**
  - `domain` (required): Domain name or IP address (e.g. `example.com` or `8.8.8.8`)
  - `resolver` (optional): Choose from `google`, `cloudflare`, `opendns`, `quad9`, `adguard`, `dnswatch`, `comodo`, `cleanbrowsing`, `ultradns`

### `GET /health`
Health check endpoint to verify service availability.

---

## 🧪 Example Usage

### Domain Lookup
/api/lookup?domain=example.com&resolver=cloudflare

### PTR (Reverse DNS) Lookup
/api/lookup?domain=8.8.8.8&resolver=google

### Demo Page
[DNS Lookup API Web Page](https://dns.zumbo.net)  
[DNS Lookup API JSON Result](https://dns.zumbo.net/api/lookup?domain=example.com&resolver=cloudflare)  
[PTR (Reverse DNS) Lookup API JSON Result](https://dns.zumbo.net/api/lookup?domain=8.8.8.8&resolver=cloudflare)  
---

## 📄 Supported Record Types

- `A`
- `AAAA`
- `NS`
- `MX`
- `TXT`
- `CNAME`
- `SOA`
- `SRV`
- `CAA`
- `PTR` (reverse DNS)

---

## 🚦 Rate Limiting

Rate limiting is applied per IP address to ensure fair usage and prevent abuse.

---

## 🛠️ Coming Soon

- Caching for frequent lookups
- Authentication support (API keys)
- JSON schema validation

---

## 🤝 Contributing

Feel free to open issues or pull requests to suggest improvements or report bugs.

---

## 📬 Contact

For any questions or feedback, please reach out via [GitHub Issues](../../issues) or submit a PR.
