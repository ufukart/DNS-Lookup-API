# 🌐 DNS Lookup API

A comprehensive DNS lookup service with support for multiple record types and resolvers.

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.com/donate/?business=53EHQKQ3T87J8&no_recurring=0&currency_code=USD)

![dns-lookup-api](https://github.com/user-attachments/assets/63054937-f732-41e5-bb5a-222c27a6db85)

---

## 🔌 Endpoints

### `GET /api/lookup`
Retrieve DNS records for a domain or IP address.

- **Parameters:**
  - `domain` (required): Domain name or IP address (e.g. `example.com` or `8.8.8.8`)
  - `resolver` (optional): Choose from `google`, `cloudflare`, `opendns`, or `quad9`

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
