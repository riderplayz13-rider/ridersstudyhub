export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  let { url } = req.query;
  if (!url) return res.status(400).send('Missing url');
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  try {
    const isPost = req.method === 'POST';
    const fetchOpts = {
      method: isPost ? 'POST' : 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
      },
      redirect: 'follow',
    };
    if (isPost && req.body) {
      const body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      fetchOpts.body = body;
      fetchOpts.headers['Content-Type'] = req.headers['content-type'] || 'application/x-www-form-urlencoded';
    }
    const response = await fetch(url, fetchOpts);

    const contentType = response.headers.get('content-type') || 'application/octet-stream';

    // Strip headers that block iframe embedding or expose proxy
    const blocked = new Set([
      'x-frame-options','content-security-policy','content-security-policy-report-only',
      'x-content-type-options','strict-transport-security','x-xss-protection',
      'transfer-encoding','content-encoding','set-cookie','permissions-policy',
      'content-disposition',
    ]);
    response.headers.forEach((v, k) => {
      if (!blocked.has(k.toLowerCase())) res.setHeader(k, v);
    });
    res.setHeader('Content-Type', contentType);
    res.setHeader('X-Frame-Options', 'ALLOWALL');
    res.setHeader('Cache-Control', 'no-store');

    const isHtml = contentType.includes('text/html');

    if (isHtml) {
      let html = await response.text();
      const pageOrigin = new URL(url).origin;
      const pageUrl = url;

      // 1. Set base href so relative paths resolve to the proxied origin
      const base = `<base href="${pageOrigin}/">`;
      if (/<\/head>/i.test(html)) {
        html = html.replace(/<\/head>/i, base + '</head>');
      } else if (/<head>/i.test(html)) {
        html = html.replace(/<head>/i, '<head>' + base);
      } else {
        html = base + html;
      }

      // 2. Rewrite absolute src/href resource URLs through proxy
      //    (belt-and-suspenders alongside the service worker)
      html = html.replace(
        /(\s(?:src|data-src|data-href|action)\s*=\s*["'])(https?:\/\/[^"'>]+)(["'])/gi,
        (m, pre, u, post) => pre + '/api/proxy?url=' + encodeURIComponent(u) + post
      );

      // 3. Rewrite <link rel="stylesheet"> hrefs through proxy
      html = html.replace(
        /(<link[^>]+rel=["']stylesheet["'][^>]+href=["'])(https?:\/\/[^"'>]+)(["'])/gi,
        (m, pre, u, post) => pre + '/api/proxy?url=' + encodeURIComponent(u) + post
      );
      html = html.replace(
        /(<link[^>]+href=["'])(https?:\/\/[^"'>]+)(["'][^>]+rel=["']stylesheet["'])/gi,
        (m, pre, u, post) => pre + '/api/proxy?url=' + encodeURIComponent(u) + post
      );

      // 4. Nav interceptor — catches link clicks & form submits.
      //    Posts to parent (our window manager) which reloads via proxy.
      //    Service worker handles everything else (XHR, fetch, dynamic imports).
      const navScript = `<script>(function(){
  var BASE=${JSON.stringify(pageUrl)};
  function nav(u){try{window.top.postMessage({r67:'nav',url:u},'*')}catch(e){}}
  function abs(h,base){try{return new URL(h,base).href}catch(x){return null}}
  document.addEventListener('click',function(e){
    var a=e.target.closest('a[href]');if(!a)return;
    var h=a.getAttribute('href');
    if(!h||h==='#'||h[0]==='#'||h.startsWith('javascript:'))return;
    var u=abs(h,BASE);if(!u||!u.startsWith('http'))return;
    e.preventDefault();e.stopPropagation();nav(u);
  },true);
  document.addEventListener('submit',function(e){
    var f=e.target,a=f.getAttribute('action')||BASE;
    var u=abs(a,BASE);if(!u||!u.startsWith('http'))return;
    e.preventDefault();
    var p=new URLSearchParams(new FormData(f)).toString();
    var m=(f.method||'get').toLowerCase();
    nav(m==='post'?u:(u+(p?(u.includes('?')?'&':'?')+p:'')));
  },true);
}());<\/script>`;

      if (/<\/body>/i.test(html)) {
        html = html.replace(/<\/body>/i, navScript + '</body>');
      } else {
        html += navScript;
      }

      res.send(html);
    } else {
      // Binary passthrough — images, fonts, scripts, wasm, etc.
      const buf = await response.arrayBuffer();
      res.send(Buffer.from(buf));
    }
  } catch (e) {
    res.status(500).json({ error: e.message, url });
  }
}
