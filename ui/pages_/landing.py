"""
XAF — OIDC Landing Page (Google Identity via Streamlit native auth).

Login is delegated to Google: the operator clicks "Sign in with Google",
gets redirected to accounts.google.com, and is redirected back already
authenticated. We never see the credentials.

The animated card is a self-contained components.html iframe (visual only) and
reserves an empty slot where the button goes. The actual login trigger is a
NATIVE st.button overlaid onto that slot — a button *inside* the iframe cannot
start the redirect: Streamlit's component iframe is sandboxed without
allow-top-navigation, so `window.parent.location = ...` is silently blocked.

Requires (see setup notes):
  - streamlit >= 1.42, Authlib >= 1.3.2
  - an [auth.google] section in .streamlit/secrets.toml
"""

import streamlit as st
import streamlit.components.v1 as components

PROVIDER = "google"   # must match the [auth.google] section in secrets.toml

CARD_HEIGHT = 460       # iframe height (px); button overlay is tuned against this

# ── the visual card (self-contained HTML/CSS/JS, empty slot where button lands)─
HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;}
  /* transparent: the gradient lives on the Streamlit page behind this iframe,
     so it runs the full viewport instead of stopping at CARD_HEIGHT */
  html,body{margin:0;height:100%;background:transparent;
    font-family:'Space Grotesk',system-ui,sans-serif;color:#e7eaf0;}
  @keyframes pulseRing{0%{transform:scale(1);opacity:.5;}70%{transform:scale(2.4);opacity:0;}100%{transform:scale(2.4);opacity:0;}}

  .wrap{position:relative;min-height:100vh;width:100%;overflow:hidden;display:flex;
    align-items:center;justify-content:center;padding:30px;background:transparent;}
  canvas{position:absolute;inset:0;width:100%;height:100%;display:block;}
  .card{position:relative;z-index:2;width:100%;max-width:440px;display:flex;
    flex-direction:column;align-items:center;gap:26px;}

  .logo{position:relative;width:60px;height:60px;display:flex;align-items:center;justify-content:center;
  font-family:'Space Grotesk',sans-serif;font-size:26px;font-weight:700;letter-spacing:.04em;
  transform:scale(1.6);transform-origin:center;} 
  .logo .ring{position:absolute;inset:0;border-radius:18px;border:1px solid #4f9dff;animation:pulseRing 2.6s ease-out infinite;}
  .logo .ring.b{animation-delay:1.3s;}
  .logo .xf{color:#9fc4ff;text-shadow:0 0 14px #4f9dff99;z-index:1;}
  .logo .box{width:60px;height:60px;flex:none;border-radius:18px;border:1px solid #2a3340;
    background:linear-gradient(135deg,#141b27,#0d1219);display:flex;align-items:center;
    justify-content:center;box-shadow:0 12px 40px rgba(0,0,0,.5);}
  .logo .a{color:#7db4ff;text-shadow:0 0 14px #4f9dffcc,0 0 26px #4f9dff88;}

  .head{text-align:center;display:flex;flex-direction:column;gap:9px;}
  .eyebrow{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.22em;color:#4f9dff;}
  h1{margin:0;font-size:27px;font-weight:600;letter-spacing:-.01em;}
  .sub{margin:0;font-size:14.5px;color:#8a93a3;line-height:1.55;max-width:330px;}

  /* empty placeholder — the native st.button is overlaid here from Python */
  .btnslot{width:100%;max-width:340px;height:52px;}

  .foot{display:flex;align-items:center;gap:8px;font-family:'JetBrains Mono',monospace;
    font-size:12px;color:#6b7488;}
  .foot .dot{width:6px;height:6px;border-radius:50%;background:#4f9dff;box-shadow:0 0 8px #4f9dff;}
</style>
</head>
<body>
<div class="wrap">
  <canvas id="net"></canvas>
  <div class="card">
    <div class="logo">
      <div class="ring"></div><div class="ring b"></div>
      <span class="xf" style="margin-right:-2px;">X</span>
      <span class="box"><span class="a">A</span></span>
      <span class="xf" style="margin-left:-2px;">F</span>
    </div>
    <div class="head">
      <div class="eyebrow">SECURE ACCESS</div>
      <h1>Operator sign-in</h1>
      <p class="sub">Authenticate with your Google account to continue to the operator console. Password &amp; verification are handled by Google.</p>
    </div>
    <div class="btnslot"></div>
    <div class="foot"><span class="dot"></span>Secured by Google Sign-In &middot; OAuth 2.0 / OIDC</div>
  </div>
</div>

<script>
  // ── canvas node network (visual only) ──
  const cv = document.getElementById('net'), ctx = cv.getContext('2d');
  let w, h, dpr, nodes = [];
  function resize(){
    dpr = Math.min(window.devicePixelRatio||1, 2);
    const r = cv.getBoundingClientRect(); w = r.width; h = r.height;
    cv.width = w*dpr; cv.height = h*dpr; ctx.setTransform(dpr,0,0,dpr,0,0);
  }
  resize(); window.addEventListener('resize', resize);
  for(let i=0;i<46;i++){
    nodes.push({x:Math.random()*w,y:Math.random()*h,
      vx:(Math.random()-.5)*0.35,vy:(Math.random()-.5)*0.35,r:Math.random()*1.6+0.6});
  }
  (function tick(){
    ctx.clearRect(0,0,w,h);
    for(const n of nodes){ n.x+=n.vx; n.y+=n.vy;
      if(n.x<0||n.x>w)n.vx*=-1; if(n.y<0||n.y>h)n.vy*=-1; }
    for(let i=0;i<nodes.length;i++) for(let j=i+1;j<nodes.length;j++){
      const a=nodes[i],b=nodes[j],dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy);
      if(d<130){ ctx.strokeStyle='rgba(79,157,255,'+(1-d/130)*0.45+')';
        ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); }
    }
    ctx.shadowColor='rgba(79,157,255,.9)'; ctx.shadowBlur=6;
    for(const n of nodes){ ctx.beginPath(); ctx.arc(n.x,n.y,n.r,0,7); ctx.fillStyle='rgba(170,206,255,.95)'; ctx.fill(); }
    ctx.shadowBlur=0;
    requestAnimationFrame(tick);
  })();
</script>
</body>
</html>
"""


def require_login() -> None:
    """Auth gate for the operator console.

    Call this at the top of app.py, right after st.set_page_config(). If the
    visitor is not signed in, it renders the Google sign-in screen and stops the
    script; it returns only once the user is authenticated, letting the caller
    go on to render the console.
    """
    if st.user.is_logged_in:
        # Authentication (Google) only proves *who* they are. Authorization: the
        # email must be on the operator allow-list in secrets.toml [access].
        # Fail closed — if the list is missing/empty, nobody gets in.
        allowed = [e.lower() for e in st.secrets.get("access", {}).get("operators", [])]
        if (st.user.email or "").lower() not in allowed:
            st.error(f"Access denied — {st.user.email} is not an authorized operator.")
            st.button("Sign out", on_click=st.logout)
            st.stop()
        return

    st.markdown(
        """
        <style>
          /* header must be removed from layout, not just made invisible --
             visibility:hidden leaves its ~3.5rem box behind as a gap */
          header[data-testid="stHeader"] {display:none !important;}
          #MainMenu, footer {display:none !important;}

          .block-container, [data-testid="stMainBlockContainer"] {
            padding:0 !important; max-width:100% !important;
          }
          section.main > div {padding:0 !important;}

          /* collapse the vertical block gap so the button overlay math is exact,
             and stretch children to full width so the button can center */
          [data-testid="stVerticalBlock"] {gap:0 !important; align-items:stretch !important;}
          [data-testid="stVerticalBlockBorderWrapper"] {gap:0 !important;}
          [data-testid="stElementContainer"] {width:100% !important;}

          /* this <style> block renders as an empty stMarkdown element */
          [data-testid="stMarkdown"]:empty,
          [data-testid="stMarkdownContainer"]:empty {display:none !important;}

          /* the gradient lives here, not in the iframe, so it spans the whole
             viewport -- the iframe is only CARD_HEIGHT tall and used to leave a
             flat #06080c band above and below it */
          [data-testid="stAppViewContainer"] {
            background:radial-gradient(1200px 700px at 50% -10%,#0d1523 0%,#06080c 62%)
                       no-repeat fixed !important;
          }
          [data-testid="stMain"], body {background:transparent !important;}
          html, body {background-color:#06080c !important;}

          /* vertically center the whole sign-in block in the viewport */
          [data-testid="stMain"] {
            display:flex !important; flex-direction:column; justify-content:center;
          }
          /* the component iframe paints its own white/opaque backdrop unless the
             page is allowed to show through */
          iframe[title="streamlit.components.v1.html"], iframe[title="st.iframe"] {
            display:block; background:transparent !important; color-scheme:normal;
          }

          /* pull the native button UP onto the card's empty slot, over the canvas */
          div[data-testid="stButton"] {
            display:flex; justify-content:center; width:100%;
            position:relative; z-index:5; margin-top:-152px;
          }
          div[data-testid="stButton"] > button {
            display:flex; align-items:center; justify-content:center; gap:12px;
            width:100%; max-width:340px; margin:0 auto;
            background:#4f9dff; color:#06101c; border:none; border-radius:14px;
            padding:15px 18px; font-weight:600; font-size:15px; letter-spacing:.01em;
            box-shadow:0 12px 34px rgba(79,157,255,.35);
            transition:filter .18s, box-shadow .18s, transform .1s;
          }
          /* the Google "G" -- a native button label can't hold an <svg>, so the
             mark rides in as a background-image on a pseudo-element */
          div[data-testid="stButton"] > button::before {
            content:""; flex:0 0 20px; width:20px; height:20px;
            background-repeat:no-repeat; background-size:contain; background-position:center;
            background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cpath fill='%23EA4335' d='M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z'/%3E%3Cpath fill='%234285F4' d='M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z'/%3E%3Cpath fill='%23FBBC05' d='M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z'/%3E%3Cpath fill='%2334A853' d='M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z'/%3E%3C/svg%3E");
          }
          div[data-testid="stButton"] > button:hover {
            filter:brightness(1.06); color:#06101c;
            box-shadow:0 14px 40px rgba(79,157,255,.45);
          }
          div[data-testid="stButton"] > button:active {transform:translateY(1px);}
          /* Streamlit wraps the label in its own <p>/<div>; strip its margins
             so the flex row centers the icon and text on the same baseline */
          div[data-testid="stButton"] > button p,
          div[data-testid="stButton"] > button div {margin:0; padding:0;}
        </style>
        """,
        unsafe_allow_html=True,
    )

    # visual card with an empty slot; the button below is overlaid onto that slot
    components.html(HTML, height=CARD_HEIGHT, scrolling=False)

    # the REAL login trigger — pulled up into the card by the CSS above
    st.button("Sign in with Google", type="primary",
              on_click=st.login, args=(PROVIDER,))

    st.stop()
