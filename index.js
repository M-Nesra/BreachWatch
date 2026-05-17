require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const port = 3000;

const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_ANON_KEY || '';
let supabase = null;
if (supabaseUrl && supabaseKey) {
  supabase = createClient(supabaseUrl, supabaseKey);
  console.log('Supabase connected');
} else {
  console.log('Supabase not configured - check .env file');
}

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

app.use(express.json());
app.use(express.static(__dirname + '/public'));

app.get('/api/critical', (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const since = new Date();
  since.setDate(since.getDate() - days);
  const pubStartDate = since.toISOString().split('.')[0] + '.000';
  const pubEndDate = new Date().toISOString().split('.')[0] + '.000';

  const url = NVD_BASE + '?pubStartDate=' + pubStartDate + '&pubEndDate=' + pubEndDate + '&resultsPerPage=50';

  fetch(url)
    .then((result) => result.json())
    .then((resultJson) => {
      res.json(resultJson);
    })
    .catch((err) => {
      console.log('Error fetching critical CVEs:', err.message);
      res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
    });
});

app.get('/api/search', (req, res) => {
  const q = req.query.q;
  const cveId = req.query.cveId;

  if (!q && !cveId) {
    res.status(400).json({ error: 'Provide q or cveId query parameter' });
    return;
  }

  let url;
  if (cveId) {
    url = NVD_BASE + '?cveId=' + encodeURIComponent(cveId);
  } else {
    url = NVD_BASE + '?keywordSearch=' + encodeURIComponent(q) + '&resultsPerPage=100';
  }

  fetch(url)
    .then((result) => result.json())
    .then((resultJson) => {
      res.json(resultJson);
    })
    .catch((err) => {
      console.log('Error searching CVEs:', err.message);
      res.status(500).json({ error: 'Failed to search vulnerabilities' });
    });
});

app.get('/api/saved', (req, res) => {
  if (!supabase) {
    res.json({ data: [], message: 'Supabase not configured' });
    return;
  }

  supabase
    .from('saved_cves')
    .select('*')
    .order('saved_at', { ascending: false })
    .then((result) => {
      if (result.error) {
        console.log('Supabase error:', result.error.message);
        res.status(500).json({ error: 'Failed to retrieve saved CVEs' });
        return;
      }
      res.json({ data: result.data });
    });
});

app.post('/api/saved', (req, res) => {
  const cve_id = req.body.cve_id;
  const severity = req.body.severity;
  const description = req.body.description;
  const affected_software = req.body.affected_software;

  if (!cve_id) {
    res.status(400).json({ error: 'cve_id is required' });
    return;
  }

  if (!supabase) {
    res.status(503).json({ error: 'Supabase not configured' });
    return;
  }

  supabase
    .from('saved_cves')
    .insert([{
      cve_id: cve_id,
      severity: severity || 'UNKNOWN',
      description: description || '',
      affected_software: affected_software || '',
      saved_at: new Date().toISOString()
    }])
    .select()
    .then((result) => {
      if (result.error) {
        console.log('Supabase insert error:', result.error.message);
        if (result.error.code === '23505') {
          res.status(409).json({ error: 'CVE already saved' });
          return;
        }
        res.status(500).json({ error: 'Failed to save CVE' });
        return;
      }
      res.status(201).json({ data: result.data[0], message: 'CVE saved successfully' });
    });
});

app.delete('/api/saved/:cveId', (req, res) => {
  const cveId = req.params.cveId;

  if (!supabase) {
    res.status(503).json({ error: 'Supabase not configured' });
    return;
  }

  supabase
    .from('saved_cves')
    .delete()
    .eq('cve_id', cveId)
    .then((result) => {
      if (result.error) {
        console.log('Supabase delete error:', result.error.message);
        res.status(500).json({ error: 'Failed to remove CVE' });
        return;
      }
      res.json({ message: cveId + ' removed from watchlist' });
    });
});

app.get('/', (req, res) => {
  res.sendFile('public/index.html', { root: __dirname });
});

app.listen(port, () => {
  console.log('BreachWatch running on port: ' + port);
});
