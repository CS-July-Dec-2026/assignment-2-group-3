# CS_LAB_2

## CORS Misconfiguration Lab

**BankDash** is an intentionally vulnerable demo banking application designed to demonstrate a **CORS misconfiguration involving reflected origins and credentials**.

The lab includes an attacker portal, a vulnerable CORS configuration, a remediated allowlist-based configuration, and an automated verification suite.

### Video Demo

[Watch the Video Demo](https://drive.google.com/file/d/1BhYwIZDM3SvPiMQrZpxmYbx0bUgjvHb7/view?usp=drive_link)

---

## Vulnerability

The vulnerable server blindly reflects the `Origin` request header while allowing credentials:

```javascript
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  }

  next();
});
```

This allows an untrusted website to make credentialed cross-origin requests and read sensitive responses when the victim is authenticated.

---

## Remediation

The fixed configuration uses an explicit origin allowlist:

```javascript
const ALLOWED_ORIGINS = ['http://localhost:4000'];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');
  }

  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.sendStatus(204);

  next();
});
```

Unauthorized origins receive no `Access-Control-Allow-Origin` header, causing the browser to block JavaScript from reading the response.

---

## Lab Structure

```text
CS_LAB_2/
├── victim-app/       # BankDash application and API
├── attacker-site/    # Simulated malicious website
└── README.md
```

---

## Running the Lab

### 1. Start BankDash

```bash
cd victim-app
npm install
npm start
```

BankDash will run at:

`http://localhost:4000`

### 2. Start the Attacker Portal

In a separate terminal:

```bash
cd attacker-site
python3 -m http.server 5000
```

The attacker portal will run at:

`http://localhost:5000`

### 3. Demonstrate the Vulnerability

1. Open `http://localhost:4000`.
2. Log in using:

   * **Email:** `alice@example.com`
   * **Password:** `hunter2`
3. Confirm that the application is in **Vulnerable** mode.
4. Open `http://localhost:5000/evil.html`.
5. Execute the attack and observe the authenticated data being exposed.
6. Return to BankDash and toggle the CORS configuration to **Secure** mode.
7. Run the attack again.
8. The browser should block the attack because the attacker origin is not trusted.

---

## Verification

The project includes an automated CORS test suite covering both vulnerable and remediated configurations.

Run:

```bash
cd victim-app
node test-cors.js
```

Expected result:

```text
========================================
Summary: 6 Passed, 0 Failed
========================================
```

The tests verify:

* Reflected origin in vulnerable mode
* Credential support in vulnerable mode
* Blocking of unauthorized origins
* Allowing trusted origins
* Credential support for trusted origins
* Presence of `Vary: Origin`

---

## Security Takeaways

* Never blindly reflect the `Origin` header.
* Do not combine unrestricted origins with `Access-Control-Allow-Credentials: true`.
* Use an explicit server-side allowlist for trusted origins.
* Include `Vary: Origin` when dynamically setting `Access-Control-Allow-Origin`.
* Use CSRF protection for state-changing requests as an additional defense.

---

## Disclaimer

This project is an intentionally vulnerable security lab created for educational and demonstration purposes. Run it only in a controlled local environment.
