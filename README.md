# Apni API-key wali website

User signup karta hai, API key banata hai, aur `/v1/chat` se aapki AI service use karta hai.
Andar se aapki apni Claude API key use hoti hai (jo user ko kabhi nahi dikhti).

## Computer par chalane ke steps

1. Python 3.10+ install karo (python.org).
2. Is folder mein terminal kholo aur chalao:
   ```
   pip install -r requirements.txt
   ```
3. `.env.example` ko copy karke `.env` naam do. Usme:
   - `ANTHROPIC_API_KEY` = Claude Platform se banayi hui aapki key
   - `SECRET_KEY` = ye command se banao: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
4. Server chalao:
   ```
   uvicorn main:app --reload
   ```
5. Browser mein kholo: http://127.0.0.1:8000

## Internet par live karna (Render.com)

1. Ye folder GitHub par daalo (`.env` mat daalna).
2. Render par "New Web Service" banao, repo connect karo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Environment variables mein `.env` wali saari values daalo, aur `HTTPS_ONLY=1`.
6. **Zaroori:** Render ki free service mein file-database (SQLite) restart par mit jata hai.
   Real users ke liye "Persistent Disk" lo aur `DB_PATH=/data/app.db` set karo,
   ya baad mein PostgreSQL par shift karo.

## API kaise call hoti hai

```
curl -X POST https://aapki-site.com/v1/chat \
  -H "Authorization: Bearer USER_KI_KEY" \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello!"}'
```

## Ismein kya hai / kya nahi

Hai: signup/login, hashed passwords, hashed API keys (key sirf ek baar dikhti hai),
revoke, free tokens, rate limit, usage tracking.

Abhi nahi hai (baad mein jodna padega): payment (Razorpay/Stripe) se credits kharidna,
email verification, password reset, admin panel.

## Kharche ki suraksha

- Claude Console mein apne account par **spending limit** lagao.
- `FREE_TOKENS` chhota rakho jab tak payment na jude.
- Pricing hamesha Claude ke asli cost se upar rakho.
- Commercial launch se pehle Anthropic ke terms padh lo (resell/API access ke rules).
