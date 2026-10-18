using System.Text.Encodings.Web;

namespace NetworkMonitor.Server.Auth;

/// <summary>
/// The sign-in page. It is rendered by the server (not the Blazor app) so nothing behind the
/// login, including the WebAssembly files, is served until the user has signed in.
/// </summary>
internal static class LoginPage
{
    public static string Render(string antiforgeryField, string antiforgeryToken, bool failed)
    {
        HtmlEncoder enc = HtmlEncoder.Default;
        string error = failed
            ? """<p class="error" role="alert">Incorrect username or password.</p>"""
            : "";

        return $$"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sign in · Network Monitor</title>
<style>{{Styles}}</style>
</head>
<body>
<main class="card">
  <h1><span class="logo">◉</span> Network Monitor</h1>
  <p class="sub">Sign in to view captured connections.</p>
  {{error}}
  <form method="post" action="/login">
    <input type="hidden" name="{{enc.Encode(antiforgeryField)}}" value="{{enc.Encode(antiforgeryToken)}}" />
    <label>Username<input name="username" autocomplete="username" required autofocus /></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
    <button type="submit">Sign in</button>
  </form>
</main>
</body>
</html>
""";
    }

    public const string Throttled = $$"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Too many attempts · Network Monitor</title>
<style>{{Styles}}</style>
</head>
<body>
<main class="card">
  <h1><span class="logo">◉</span> Network Monitor</h1>
  <p class="error" role="alert">Too many sign-in attempts. Wait a minute, then try again.</p>
  <p><a href="/login">Back to sign in</a></p>
</main>
</body>
</html>
""";

    private const string Styles = """
:root { --bg:#0d1117; --panel:#161b22; --border:#2b3340; --text:#e6edf3; --muted:#8b949e;
        --accent:#3fb950; --accent-dim:#238636; --error:#f85149; --blue:#58a6ff; }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:grid; place-items:center; padding:16px;
       background:var(--bg); color:var(--text);
       font:14px -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
.card { width:100%; max-width:360px; background:var(--panel); border:1px solid var(--border);
        border-radius:10px; padding:28px; }
h1 { margin:0 0 4px; font-size:20px; font-weight:600; }
.logo { color:var(--accent); margin-right:6px; }
.sub { margin:0 0 20px; color:var(--muted); }
label { display:block; margin-bottom:14px; color:var(--muted); font-size:13px; }
input { display:block; width:100%; margin-top:6px; padding:9px 10px; font-size:14px;
        background:var(--bg); color:var(--text); border:1px solid var(--border); border-radius:6px; }
input:focus { outline:none; border-color:var(--blue); }
button { width:100%; margin-top:6px; padding:10px; font-size:14px; color:#fff; cursor:pointer;
         background:var(--accent-dim); border:1px solid var(--accent-dim); border-radius:6px; }
button:hover { filter:brightness(1.1); }
.error { margin:0 0 16px; padding:9px 10px; border-radius:6px; color:#ffd7d5;
         background:rgba(248,81,73,.12); border:1px solid rgba(248,81,73,.4); }
a { color:var(--blue); }
""";
}
