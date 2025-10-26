<?php
if (!isset($_GET['key']) || $_GET['key'] !== 'exlonea') {
    echo '<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"></head><body></body></html>';
    exit;
}

$baseDir = realpath(getcwd());
$selectedPath = $_GET['path'] ?? $baseDir;
$selectedItem = realpath($selectedPath);
$timeRange = $_GET['range'] ?? 'original';

/* === Zaman Aralıkları === */
$timeRanges = [
    'original' => 0,
    'today' => 1 * 24 * 60 * 60,
    '1day' => 1 * 24 * 60 * 60,
    '3days' => 3 * 24 * 60 * 60,
    '1week' => 7 * 24 * 60 * 60,
    '1month' => 30 * 24 * 60 * 60,
    '3months' => 90 * 24 * 60 * 60,
    '6months' => 180 * 24 * 60 * 60,
    '1year' => 365 * 24 * 60 * 60
];

$selectedTime = $timeRanges[$timeRange] ?? 0;

/* Bugün seçiliyse gün başından itibaren filtre uygula */
if ($timeRange === 'today') {
    $todayStart = strtotime('today');
    $timeAgo = $todayStart;
} elseif ($timeRange === 'original') {
    $timeAgo = 0;
} else {
    $timeAgo = time() - $selectedTime;
}

/* === Orijinal Listeleme (klasör + dosya) === */
function getFileListOriginal($dir) {
    $files = [];
    if (!is_dir($dir)) return $files;
    $items = @scandir($dir);
    if ($items === false) return $files;

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        $mtime = @filemtime($path) ?: 0;
        $files[] = [
            'name' => $item,
            'path' => $path,
            'type' => is_dir($path) ? 'dir' : 'file',
            'mtime' => $mtime,
            'icon' => is_dir($path) ? 'bi bi-folder-fill text-warning' : getFileIcon($item)
        ];
    }

    usort($files, function($a, $b) {
        if ($a['type'] === $b['type']) return strcmp($a['name'], $b['name']);
        return $a['type'] === 'dir' ? -1 : 1;
    });

    return $files;
}

/* === Recursive Dosya Listeleme (yalnızca dosyalar, tarih filtresiyle) === */
function getRecentFilesRecursive($dir, $timeAgo) {
    $results = [];
    $items = @scandir($dir);
    if ($items === false) return $results;

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        $mtime = @filemtime($path) ?: 0;

        if (is_dir($path)) {
            $results = array_merge($results, getRecentFilesRecursive($path, $timeAgo));
        } else {
            if ($mtime >= $timeAgo) {
                $results[] = [
                    'name' => $item,
                    'path' => $path,
                    'type' => 'file',
                    'mtime' => $mtime,
                    'icon' => getFileIcon($item)
                ];
            }
        }
    }
    return $results;
}

/* === Dosya ikonları === */
function getFileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = [
        'jpg'=>'bi bi-image', 'jpeg'=>'bi bi-image', 'png'=>'bi bi-image', 'gif'=>'bi bi-image',
        'php'=>'bi bi-file-code', 'html'=>'bi bi-file-code', 'css'=>'bi bi-file-code', 'js'=>'bi bi-file-code',
        'pdf'=>'bi bi-file-pdf', 'txt'=>'bi bi-file-text', 'zip'=>'bi bi-file-zip-fill'
    ];
    return $icons[$ext] ?? 'bi bi-file-earmark';
}

/* === Navigasyon sadece orijinal modda === */
$navigationItems = [];
if ($timeRange === 'original') {
    $navigationItems[] = ['name' => $baseDir, 'path' => $baseDir, 'is_dir' => true];
    if (is_dir($baseDir)) {
        $subItems = @scandir($baseDir);
        if ($subItems !== false) {
            foreach ($subItems as $item) {
                if ($item === '.' || $item === '..') continue;
                $path = $baseDir . DIRECTORY_SEPARATOR . $item;
                if (is_dir($path)) {
                    $navigationItems[] = ['name' => $path, 'path' => $path, 'is_dir' => true];
                }
            }
        }
    }
}

function getParentPath($path) {
    $parent = dirname($path);
    return $parent === '/' ? $parent : realpath($parent);
}

/* === Listeyi hazırla === */
if ($timeRange === 'original') {
    $files = getFileListOriginal($selectedItem);
} else {
    $files = getRecentFilesRecursive($selectedItem, $timeAgo);
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sunucu Değişiklik Takip</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; padding: 20px; }
        .table { font-size: 14px; }
        .nav-link { padding: 5px 10px; }
        .table-responsive { max-height: 400px; overflow-y: auto; display: block; }
        .file-icon { margin-right: 10px; }
        .back-link { cursor: pointer; padding: 5px 10px; display: inline-block; }
        @media (max-width: 576px) {
            .table { font-size: 12px; }
            .table td, .table th { padding: 5px; font-size: 10px; }
            .table th { font-size: 12px; }
        }
    </style>
</head>
<body>
<div class="container mt-4">
    <h2>Sunucu Değişiklik Takip</h2>

    <div class="mb-3">
        <?php if ($timeRange === 'original'): ?>
            <a class="back-link" href="?key=exlonea&path=<?php echo urlencode(getParentPath($selectedItem)); ?>">
                <i class="bi bi-three-dots"></i>
            </a>
            <div class="collapse navbar-collapse">
                <ul class="navbar-nav">
                    <?php foreach ($navigationItems as $item): ?>
                        <li class="nav-item">
                            <a class="nav-link <?php echo $selectedItem === realpath($item['path']) ? 'active' : ''; ?>"
                               href="?key=exlonea&path=<?php echo urlencode($item['path']); ?>">
                                <?php echo htmlspecialchars(basename($item['path'])); ?>
                                <?php if ($item['is_dir']): ?>
                                    <i class="bi bi-folder-fill text-warning"></i>
                                <?php endif; ?>
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
    </div>

    <div class="mb-3">
        <form method="get" class="row g-3">
            <input type="hidden" name="key" value="exlonea">
            <input type="hidden" name="path" value="<?php echo htmlspecialchars($selectedPath); ?>">
            <div class="col-auto">
                <select class="form-select" id="range" name="range" onchange="this.form.submit()">
                    <option value="original" <?php echo $timeRange === 'original' ? 'selected' : ''; ?>>Orijinal</option>
                    <option value="today" <?php echo $timeRange === 'today' ? 'selected' : ''; ?>>Bugün</option>
                    <option value="1day" <?php echo $timeRange === '1day' ? 'selected' : ''; ?>>Son 1 Gün</option>
                    <option value="3days" <?php echo $timeRange === '3days' ? 'selected' : ''; ?>>Son 3 Gün</option>
                    <option value="1week" <?php echo $timeRange === '1week' ? 'selected' : ''; ?>>Son 1 Hafta</option>
                    <option value="1month" <?php echo $timeRange === '1month' ? 'selected' : ''; ?>>Son 1 Ay</option>
                    <option value="3months" <?php echo $timeRange === '3months' ? 'selected' : ''; ?>>Son 3 Ay</option>
                    <option value="6months" <?php echo $timeRange === '6months' ? 'selected' : ''; ?>>Son 6 Ay</option>
                    <option value="1year" <?php echo $timeRange === '1year' ? 'selected' : ''; ?>>Son 1 Yıl</option>
                </select>
            </div>
        </form>
    </div>

    <p><strong>Seçilen Zaman Aralığı: 
        <?php echo $timeRange === 'original' ? 'Tüm Dosyalar' : date('d.m.Y H:i', $timeAgo) . ' sonrası'; ?>
    </strong> 
    <?php echo count($files); ?> öğe bulundu.</p>

    <div class="table-responsive">
        <table class="table table-bordered">
            <thead>
            <tr>
                <th></th>
                <th>Ad</th>
                <th>Dosya Yolu</th>
                <th>Son Değiştirme</th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($files as $file): ?>
                <tr>
                    <td></td>
                    <td>
                        <i class="<?php echo $file['icon']; ?> file-icon"></i>
                        <?php if ($file['type'] === 'dir' && $timeRange === 'original'): ?>
                            <a href="?key=exlonea&path=<?php echo urlencode($file['path']); ?>">
                                <?php echo htmlspecialchars($file['name']); ?>
                            </a>
                        <?php else: ?>
                            <?php echo htmlspecialchars($file['name']); ?>
                        <?php endif; ?>
                    </td>
                    <td>
                        <a href="<?php echo 'https://' . $_SERVER['HTTP_HOST'] . str_replace(realpath($_SERVER['DOCUMENT_ROOT']), '', $file['path']); ?>" target="_blank">
                            <?php echo htmlspecialchars($file['path']); ?>
                        </a>
                    </td>
                    <td><?php echo $file['mtime'] ? date('Y-m-d H:i:s', $file['mtime']) : '-'; ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>