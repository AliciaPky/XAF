# Vulnerable LMS — XAF test target

A minimal, **intentionally SQLi-vulnerable** Learning Management System used as the
target application behind the XAF adaptive WAF. It replaces OWASP Juice Shop so the
test target is a genuine LMS with a vulnerable **login authentication** function
(FYP Objective 1).

## Vulnerabilities (by design)
| Location | Sink | Example payload |
|---|---|---|
| `/login` (POST `username`/`password`) | string-concatenated `SELECT` | `admin' -- ` / `' OR '1'='1` |
| `/courses` (GET `q`) | `LIKE '%...%'` concatenation | `' UNION SELECT code,title,instructor FROM courses-- -` |

## Seeded accounts
| Username | Password | Role |
|---|---|---|
| admin | S3cr3tAdmin! | admin |
| student1 | pass123 | student |
| lecturer | teach2026 | lecturer |

## Run (via the stack)
From the repo root:
```bash
docker compose up -d db lms nginx-modsec
```
- Direct (no WAF): http://localhost:5000
- Through the WAF: http://localhost:80

## ⚠️ Safety
Never expose this on a public network without the WAF in front and inbound
restricted to your own IP. No real data. Tear it down when not collecting results.
