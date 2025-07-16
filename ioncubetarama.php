<?php
// Hata raporlamayı etkinleştir
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Şifreli dosyaları saklamak için dizi
$encrypted_files = [];

// Dizinleri listeleyen fonksiyon
function getSubDirectories($base_dir) {
    $dirs = [];
    $items = scandir($base_dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $base_dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) {
            $dirs[] = $path;
        }
    }
    return $dirs;
}

// Şifreli dosyaları tarayan fonksiyon
function scanDirectory($dir) {
    global $encrypted_files;
    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $file;
        if (is_dir($path)) {
            scanDirectory($path); // Alt dizinleri tara
        } elseif (is_file($path) && pathinfo($path, PATHINFO_EXTENSION) === 'php') {
            $content = file_get_contents($path);
            if (isIonCubeEncrypted($content)) {
                $encrypted_files[] = $path;
            }
        }
    }
}

// ionCube şifrelemesini kontrol eden fonksiyon
function isIonCubeEncrypted($content) {
    // ionCube imzasını kontrol et
    if (preg_match('/ionCube/i', $content)) {
        return true;
    }
    // __halt_compiler ve ardından okunamaz veri bloğu kontrolü
    if (strpos($content, '__halt_compiler') !== false) {
        $binary_data = substr($content, strpos($content, '__halt_compiler') + strlen('__halt_compiler'));
        // Okunamaz veri bloğu içerip içermediğini kontrol et
        return preg_match('/[\x00-\x1F\x7F-\xFF]{100,}/', $binary_data);
    }
    // Dosyanın açık kaynak PHP olup olmadığını kontrol et
    if (preg_match('/<\?php\s*(return\s*array|class|function|if|foreach|while|\$[\w]+\s*=)/i', $content)) {
        // Açık kaynak PHP dosyası (örneğin, dil dosyaları veya config dosyaları)
        return false;
    }
    // Dosyanın büyük oranda okunamaz baytlar içerip içermediğini kontrol et
    $total_length = strlen($content);
    if ($total_length == 0) {
        return false;
    }
    // UTF-8 karakterlerini hariç tutarak yalnızca kontrol karakterlerini say
    $binary_length = strlen(preg_replace('/[\p{L}\p{N}\p{P}\p{S}\s]/u', '', $content));
    if ($binary_length / $total_length > 0.7) { // %70'ten fazla okunamazsa şifreli kabul et
        return true;
    }
    return false;
}

// URL oluşturma fonksiyonu
function getFileUrl($file_path, $base_dir) {
    $relative_path = str_replace($base_dir . DIRECTORY_SEPARATOR, '', $file_path);
    return 'http://' . $_SERVER['HTTP_HOST'] . '/' . str_replace(DIRECTORY_SEPARATOR, '/', $relative_path);
}

// Varsayılan olarak public_html dizini
$base_dir = $_SERVER['DOCUMENT_ROOT'] . DIRECTORY_SEPARATOR . 'public_html';
if (!is_dir($base_dir)) {
    $base_dir = $_SERVER['DOCUMENT_ROOT']; // Eğer public_html yoksa kök dizini kullan
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>ionCube Şifreli Dosya Tespit Aracı</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 800px; margin: auto; }
        .error { color: red; }
        .success { color: green; }
        .result { margin-top: 20px; }
        select, textarea { width: 100%; margin-top: 10px; }
        textarea { height: 200px; font-family: monospace; }
        ul { list-style-type: none; padding: 0; }
        li { padding: 5px 0; }
        a { text-decoration: none; color: blue; }
        a:hover { text-decoration: underline; }
        .file-actions { margin-top: 10px; }
        .file-actions button { padding: 8px 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .file-actions button:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h2>ionCube Şifreli Dosya Tespit Aracı</h2>
        <form method="post">
            <label for="directory">Taramak istediğiniz dizini seçin:</label><br>
            <select id="directory" name="directory" required>
                <option value="">Bir dizin seçin</option>
                <option value="<?php echo htmlspecialchars($base_dir); ?>">public_html</option>
                <?php
                // Seçilen dizinin alt dizinlerini listele
                $selected_dir = isset($_POST['directory']) ? $_POST['directory'] : $base_dir;
                if (is_dir($selected_dir)) {
                    $sub_dirs = getSubDirectories($selected_dir);
                    foreach ($sub_dirs as $dir) {
                        echo '<option value="' . htmlspecialchars($dir) . '">' . htmlspecialchars(str_replace($base_dir . DIRECTORY_SEPARATOR, '', $dir)) . '</option>';
                    }
                }
                ?>
            </select><br><br>
            <button type="submit" name="scan">Taramayı Başlat</button>
        </form>

        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['scan']) && !empty($_POST['directory'])) {
            $directory = rtrim($_POST['directory'], '/\\');
            
            // Dizin var mı ve erişilebilir mi kontrol et
            if (!is_dir($directory)) {
                echo '<p class="error">Hata: Geçersiz veya erişilemeyen dizin yolu!</p>';
            } else {
                // Taramayı başlat
                $encrypted_files = []; // Diziyi sıfırla
                scanDirectory($directory);
                
                // Sonuçları göster
                echo '<div class="result">';
                if (empty($encrypted_files)) {
                    echo '<p class="success">Şifreli dosya bulunamadı!</p>';
                } else {
                    echo '<h3>Bulunan Şifreli Dosyalar:</h3>';
                    echo '<ul>';
                    foreach ($encrypted_files as $file) {
                        echo '<li><a href="?file=' . urlencode($file) . '">' . htmlspecialchars(str_replace($base_dir . DIRECTORY_SEPARATOR, '', $file)) . '</a></li>';
                    }
                    echo '</ul>';
                }
                echo '</div>';
            }
        }

        // Dosya içeriğini göster ve "Dosyaya Git" butonu ekle
        if (isset($_GET['file']) && is_file($_GET['file'])) {
            $file_path = $_GET['file'];
            echo '<h3>Dosya İçeriği: ' . htmlspecialchars(str_replace($base_dir . DIRECTORY_SEPARATOR, '', $file_path)) . '</h3>';
            echo '<textarea readonly>' . htmlspecialchars(file_get_contents($file_path)) . '</textarea>';
            echo '<div class="file-actions">';
            echo '<a href="' . htmlspecialchars(getFileUrl($file_path, $base_dir)) . '" target="_blank"><button>Dosyaya Git</button></a>';
            echo '</div>';
        }
        ?>
    </div>
</body>
</html>