# BreachWatch

## Description

BreachWatch is a web app that makes the NIST National Vulnerability Database actually usable. The official NVD site works but it's not easy to read through. This app pulls from the same data and shows it in a cleaner way. You can search by product name or CVE ID, see severity scores, save CVEs you care about, and click any card to get the full technical details.

## Target Browsers

Works on Chrome, Firefox, Safari, and Edge. Built and tested on desktop. Mobile works but the layout is designed for wider screens.

## Link to Developer Manual

[Click here to go to the Developer Manual](#developer-manual)

---

# Developer Manual

This is for whoever picks this project up next. You need basic Node.js knowledge but you don't need to know anything about how this app works yet.

## 1. Install

You need Node.js (v18+) and a free Supabase account.

```
npm install
```

Create a `.env` file in the root folder with your Supabase credentials:

```
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your-anon-key-here
```

Then go to your Supabase project, open SQL Editor, and run this once:

```sql
CREATE TABLE saved_cves (
  id SERIAL PRIMARY KEY,
  cve_id TEXT UNIQUE NOT NULL,
  severity TEXT NOT NULL DEFAULT 'UNKNOWN',
  description TEXT,
  affected_software TEXT,
  saved_at TIMESTAMPTZ DEFAULT NOW()
);
```

Also go to Table Editor, find saved_cves, and make sure Row Level Security is disabled. If it's on, saves will fail silently.

## 2. Run

```
npm start
```

Opens on port 3000. Go to http://localhost:3000 in your browser. nodemon is set up so the server restarts automatically when you change files.

## 3. Tests

Start the server first, then in a second terminal:

```
npm test
```

Hits all 5 backend endpoints and checks they return the right status codes and data shapes.

## 4. API Endpoints

**GET /api/critical?days=30**
Pulls CVEs from the last 30, 60, or 90 days from NIST NVD. Returns up to 50. The `days` param is optional, defaults to 30.

**GET /api/search?q=openssl**
Keyword search across all NVD CVE descriptions. Returns up to 100 results.

**GET /api/search?cveId=CVE-2021-44228**
Direct lookup by CVE ID. Returns the single matching record with full CVSS data.

**GET /api/saved**
Returns everything in the Supabase watchlist, newest first.

**POST /api/saved**
Saves a CVE. Body needs: `cve_id`, `severity`, `description`, `affected_software`.

**DELETE /api/saved/:cveId**
Removes a CVE from the watchlist by its ID.

## 5. Known Issues and Future Work

**Bugs:**
- NVD rate limits unauthenticated requests to 5 per 30 seconds. Clicking the day buttons fast will cause errors. Just wait a second between clicks.
- Older CVEs sometimes have no CVSS v3 score so the score field shows blank.
- Affected software is empty on some CVEs because not all NVD records have CPE data.

**What to add next:**
- NVD API key support to raise the rate limit
- Severity filter on search results
- User accounts so the watchlist is per-user instead of shared
- CSV export on the Saved page
