<?php
// Hata raporlamayı etkinleştir
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Şifreli dosyaları saklamak için dizi
$encrypted_files = [];

// Seçilen dizinin içeriğini listeleyen fonksiyon
function listDirectoryContents($dir) {
    $contents = [];
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        $contents[] = [
            'name' => $item,
            'path' => $path,
            'type' => is_dir($path) ? 'directory' : 'file'
        ];
    }
    return $contents;
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

// Breadcrumb oluşturma fonksiyonu
function generateBreadcrumb($path, $base_dir) {
    $parts = explode(DIRECTORY_SEPARATOR, $path);
    $breadcrumb = [];
    $current_path = '';
    foreach ($parts as $part) {
        if (empty($part)) continue;
        $current_path .= DIRECTORY_SEPARATOR . $part;
        $breadcrumb[] = [
            'name' => $part,
            'path' => $current_path
        ];
    }
    return $breadcrumb;
}

// Varsayılan olarak kök dizin
$base_dir = $_SERVER['DOCUMENT_ROOT'];
$current_file = __FILE__;
$current_dir = dirname($current_file);
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>ionCube Şifreli Dosya Tespit Aracı</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1000px; margin: auto; }
        .error { color: red; }
        .success { color: green; }
        .result { margin-top: 20px; }
        textarea { width: 100%; margin-top: 10px; height: 200px; font-family: monospace; font-size: 14px; }
        ul { list-style-type: none; padding: 0; }
        li { padding: 5px 0; }
        a { text-decoration: none; color: blue; }
        a:hover { text-decoration: underline; }
        .file-actions { margin-top: 10px; }
        .file-actions button, .scan-button { padding: 8px 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .file-actions button:hover, .scan-button:hover { background-color: #0056b3; }
        .breadcrumb { margin-bottom: 20px; font-size: 14px; }
        .breadcrumb a { margin-right: 5px; }
        .directory-list { margin-top: 20px; }
        .directory-list h3 { margin-bottom: 10px; }
        .directory-list ul { border: 1px solid #ddd; padding: 10px; border-radius: 4px; }
        .directory-list li.directory a { font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h2>ionCube Şifreli Dosya Tespit Aracı</h2>
        
        <!-- Breadcrumb -->
        <div class="breadcrumb">
            <strong>Geçerli Konum:</strong>
            <?php
            $breadcrumb = generateBreadcrumb($current_file, $base_dir);
            foreach ($breadcrumb as $index => $item) {
                if ($index > 0) echo ' / ';
                echo '<a href="?view_dir=' . urlencode($item['path']) . '">' . htmlspecialchars($item['name']) . '</a>';
            }
            ?>
        </div>

        <!-- Dizin İçeriği -->
        <?php
        $view_dir = isset($_GET['view_dir']) ? $_GET['view_dir'] : $current_dir;
        if (is_dir($view_dir)) {
            echo '<div class="directory-list">';
            echo '<h3>Seçilen Dizin: ' . htmlspecialchars(str_replace($base_dir . DIRECTORY_SEPARATOR, '', $view_dir)) . '</h3>';
            echo '<form method="post">';
            echo '<input type="hidden" name="directory" value="' . htmlspecialchars($view_dir) . '">';
            echo '<button type="submit" name="scan" class="scan-button">Taramayı Başlat</button>';
            echo '</form>';
            $contents = listDirectoryContents($view_dir);
            if (!empty($contents)) {
                echo '<ul>';
                foreach ($contents as $item) {
                    $icon = $item['type'] === 'directory' ? '📁 ' : '📄 ';
                    echo '<li class="' . $item['type'] . '"><a href="?view_dir=' . urlencode($item['type'] === 'directory' ? $item['path'] : $item['path'] . '&file=' . urlencode($item['path'])) . '">' . $icon . htmlspecialchars($item['name']) . '</a></li>';
                }
                echo '</ul>';
            } else {
                echo '<p>Bu dizinde içerik bulunamadı.</p>';
            }
            echo '</div>';
        }
        ?>

        <!-- Tarama Sonuçları -->
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