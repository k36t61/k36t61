<?php
/**
 * index.php — Tek dosyalık web dosya yöneticisi
 * Kurulum: Bu dosyayı htdocs / public_html içine yükleyin, isterseniz aşağıdaki ayarları değiştirin,
 * siteadi.com adresinden şifreyle giriş yapın.
 */

/* ===================== AYARLAR ===================== */
$SIFRE     = '445566';                // Giriş şifresi (düz yazı VEYA password_hash() çıktısı)
$KOK       = '/';                     // '/' = sunucunun tüm klasörlerine çıkabilir (home, diğer domainler...)
                                      // Sadece bu sitenin klasörü olsun isterseniz: __DIR__
$SITE_ADI  = 'Site Yönetimi';
$DUZENLENEBILIR = ['php','html','htm','css','js','json','txt','md','xml','ini','log','csv','sql','svg','yml','yaml','htaccess','conf','env'];
/* ==================================================== */

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') == 443);
session_name('yonetim_oturum');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Strict']);
session_start();
if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(16)); }

$SELF = $_SERVER['SCRIPT_NAME'];
$kr = @realpath($KOK);
$KOK_REAL = str_replace('\\', '/', $kr !== false ? $kr : $KOK);
$KOK_BASE = rtrim($KOK_REAL, '/');   // kök '/' ise boş metin olur
$BU_DOSYA = str_replace('\\', '/', realpath(__FILE__));

/* ---------- Yardımcı fonksiyonlar ---------- */
function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function flash($t, $tip = 'ok') { $_SESSION['mesaj'] = [$tip, $t]; }
function git($url) { header('Location: ' . $url); exit; }

function cozum($rel, $varOlmali = true) {
    global $KOK_REAL, $KOK_BASE;
    $rel = trim(str_replace('\\', '/', (string)$rel), '/');
    if ($rel === '') return $KOK_REAL;
    foreach (explode('/', $rel) as $s) {
        if ($s === '' || $s === '.' || $s === '..' || strpos($s, "\0") !== false) return null;
    }
    $yol = $KOK_BASE . '/' . $rel;
    if ($varOlmali) {
        $r = realpath($yol);
        if ($r === false) return null;
        $r = str_replace('\\', '/', $r);
    } else {
        $ust = realpath(dirname($yol));
        if ($ust === false) return null;
        $r = str_replace('\\', '/', $ust) . '/' . basename($yol);
    }
    if ($r !== $KOK_REAL && strpos($r, $KOK_BASE . '/') !== 0) return null;
    return $r;
}
function gorece($tam) { global $KOK_BASE; return ltrim(substr($tam, strlen($KOK_BASE)), '/'); }
function adGecerli($ad) {
    return $ad !== '' && $ad !== '.' && $ad !== '..' && strlen($ad) <= 255
        && !preg_match('#[/\\\\\x00]#', $ad);
}
function birles($p, $ad) { return ($p === '' ? '' : $p . '/') . $ad; }
function boyutYaz($b) {
    if ($b < 1024) return $b . ' B';
    $u = ['KB', 'MB', 'GB', 'TB']; $i = -1;
    do { $b /= 1024; $i++; } while ($b >= 1024 && $i < 3);
    return number_format($b, $b < 10 ? 1 : 0, ',', '.') . ' ' . $u[$i];
}
function sil($yol) {
    if (is_link($yol) || is_file($yol)) return @unlink($yol);
    if (is_dir($yol)) {
        foreach (scandir($yol) as $x) {
            if ($x === '.' || $x === '..') continue;
            if (!sil($yol . '/' . $x)) return false;
        }
        return @rmdir($yol);
    }
    return false;
}
function sifreDogru($girilen) {
    global $SIFRE;
    if (strpos($SIFRE, '$2y$') === 0 || strpos($SIFRE, '$argon') === 0) return password_verify($girilen, $SIFRE);
    return hash_equals($SIFRE, $girilen);
}
/* Basit IP tabanlı deneme sınırı */
function ipDosya() { return sys_get_temp_dir() . '/yonetim_' . md5($_SERVER['REMOTE_ADDR'] ?? 'x') . '.json'; }
function ipOku() { $f = ipDosya(); $d = is_file($f) ? json_decode((string)@file_get_contents($f), true) : []; return is_array($d) ? $d : []; }
function kilitKalan() { $d = ipOku(); return max(0, (int)($d['kilit'] ?? 0) - time()); }
function hataKaydet() {
    $d = ipOku(); $d['n'] = (int)($d['n'] ?? 0) + 1;
    if ($d['n'] >= 5) { $d['kilit'] = time() + 600; $d['n'] = 0; }
    @file_put_contents(ipDosya(), json_encode($d), LOCK_EX);
}

/* ---------- Giriş ---------- */
$hata = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['islem'] ?? '') === 'giris') {
    if (kilitKalan() > 0) {
        $hata = 'Çok fazla hatalı deneme. ' . ceil(kilitKalan() / 60) . ' dakika sonra tekrar deneyin.';
    } else {
        if (sifreDogru((string)($_POST['sifre'] ?? ''))) {
            @unlink(ipDosya());
            session_regenerate_id(true);
            $_SESSION['giris'] = true;
            git($SELF);
        }
        hataKaydet();
        usleep(500000);
        $hata = 'Şifre hatalı.';
    }
}

function ortakStil() { ?>
<style>
:root{--bg:#f1f2ee;--panel:#fff;--line:#dcdfd8;--ink:#1c2226;--muted:#6a736d;--accent:#0f6b5c;--accent-ink:#fff;--danger:#b3261e;--folder:#c58a1b;--hover:#f5f7f3;--bar:#1c2226}
@media(prefers-color-scheme:dark){:root{--bg:#111514;--panel:#1a1f1e;--line:#2b3331;--ink:#e6eae7;--muted:#8d9893;--accent:#3fb59f;--accent-ink:#0b1a17;--danger:#f0776f;--folder:#e0a93b;--hover:#202726;--bar:#0c0f0e}}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
button,input,textarea{font:inherit;color:inherit}
a{color:var(--accent)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:var(--panel);padding:7px 13px;border-radius:7px;cursor:pointer;text-decoration:none;color:var(--ink);white-space:nowrap}
.btn:hover{background:var(--hover)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);font-weight:600}
.btn.primary:hover{filter:brightness(1.08)}
.btn.danger{color:var(--danger)}
input[type=text],input[type=password],input[type=search]{width:100%;border:1px solid var(--line);background:var(--panel);padding:9px 11px;border-radius:7px}
</style>
<?php }

if (empty($_SESSION['giris'])) {
    ?><!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>Giriş · <?= e($SITE_ADI) ?></title><?php ortakStil(); ?>
<style>
.giris{min-height:100vh;display:grid;place-items:center;padding:20px}
.kart{width:100%;max-width:360px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:28px}
.kart h1{margin:0 0 4px;font-size:21px}.kart p{margin:0 0 20px;color:var(--muted)}
label{display:block;font-size:13px;color:var(--muted);margin:14px 0 5px}
.kart .btn{width:100%;justify-content:center;margin-top:20px;padding:10px}
.hata{background:color-mix(in srgb,var(--danger) 12%,transparent);color:var(--danger);padding:9px 11px;border-radius:7px;margin-bottom:6px;font-size:14px}
</style></head><body>
<div class="giris"><form class="kart" method="post" autocomplete="on">
<h1><?= e($SITE_ADI) ?></h1><p>Devam etmek için giriş yapın.</p>
<?php if ($hata): ?><div class="hata" role="alert"><?= e($hata) ?></div><?php endif; ?>
<input type="hidden" name="islem" value="giris">
<label for="s">Şifre</label><input id="s" type="password" name="sifre" autocomplete="current-password" required autofocus>
<button class="btn primary">Giriş yap</button>
</form></div></body></html><?php
    exit;
}

/* ---------- Giriş yapıldı: istekler ---------- */
$csrf = $_SESSION['csrf'];

// Sunucu limitini aşan yükleme (PHP, POST verisini tamamen boşaltır)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST) && empty($_FILES) && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
    flash('Dosya, sunucunun izin verdiği boyut sınırını (' . ini_get('post_max_size') . ') aşıyor.', 'hata');
    header('Content-Type: application/json'); echo json_encode(['ok' => false]); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) { http_response_code(403); exit('Oturum doğrulaması başarısız. Sayfayı yenileyin.'); }
    $islem = $_POST['islem'] ?? '';
    $p = trim(str_replace('\\', '/', (string)($_POST['p'] ?? '')), '/');
    $dizin = cozum($p);
    $donus = $SELF . '?p=' . urlencode($p);

    if ($islem === 'cikis') {
        $_SESSION = []; session_destroy(); git($SELF);
    }
    if (!$dizin || !is_dir($dizin)) { flash('Klasör bulunamadı.', 'hata'); git($SELF); }

    switch ($islem) {
        case 'yukle':
            $ok = 0; $hatalar = [];
            $f = $_FILES['dosyalar'] ?? null;
            if ($f && is_array($f['name'])) {
                foreach ($f['name'] as $i => $ad) {
                    $ad = basename(str_replace('\\', '/', $ad));
                    if ($f['error'][$i] !== UPLOAD_ERR_OK) { $hatalar[] = $ad . ' (yüklenemedi)'; continue; }
                    if (!adGecerli($ad)) { $hatalar[] = $ad . ' (geçersiz ad)'; continue; }
                    if (move_uploaded_file($f['tmp_name'][$i], rtrim($dizin, '/') . '/' . $ad)) { $ok++; } else { $hatalar[] = $ad . ' (yazılamadı)'; }
                }
            }
            if ($hatalar) flash($ok . ' dosya yüklendi. Sorunlu: ' . implode(', ', $hatalar), 'hata');
            else flash($ok . ' dosya yüklendi.');
            header('Content-Type: application/json'); echo json_encode(['ok' => true]); exit;

        case 'klasor':
            $ad = trim((string)($_POST['ad'] ?? ''));
            if (!adGecerli($ad)) flash('Geçersiz klasör adı.', 'hata');
            elseif (file_exists(rtrim($dizin, '/') . '/' . $ad)) flash('Bu ada sahip bir öğe zaten var.', 'hata');
            elseif (@mkdir(rtrim($dizin, '/') . '/' . $ad, 0755)) flash('Klasör oluşturuldu.');
            else flash('Klasör oluşturulamadı.', 'hata');
            git($donus);

        case 'yenidosya':
            $ad = trim((string)($_POST['ad'] ?? ''));
            if (!adGecerli($ad)) flash('Geçersiz dosya adı.', 'hata');
            elseif (file_exists(rtrim($dizin, '/') . '/' . $ad)) flash('Bu ada sahip bir öğe zaten var.', 'hata');
            elseif (@file_put_contents(rtrim($dizin, '/') . '/' . $ad, '') !== false) flash('Dosya oluşturuldu.');
            else flash('Dosya oluşturulamadı.', 'hata');
            git($donus);

        case 'adlandir':
            $eski = (string)($_POST['eski'] ?? ''); $yeni = trim((string)($_POST['ad'] ?? ''));
            $src = adGecerli($eski) ? cozum(birles($p, $eski)) : null;
            if (!$src || !adGecerli($yeni)) flash('Geçersiz ad.', 'hata');
            elseif (file_exists(rtrim($dizin, '/') . '/' . $yeni)) flash('Bu ada sahip bir öğe zaten var.', 'hata');
            elseif (@rename($src, rtrim($dizin, '/') . '/' . $yeni)) flash('Ad değiştirildi.');
            else flash('Ad değiştirilemedi.', 'hata');
            git($donus);

        case 'sil':
            $n = 0; $kalan = [];
            foreach ((array)($_POST['sec'] ?? []) as $ad) {
                $ad = (string)$ad;
                $yol = adGecerli($ad) ? cozum(birles($p, $ad)) : null;
                if (!$yol || $yol === $KOK_REAL) { $kalan[] = $ad; continue; }
                if (sil($yol)) $n++; else $kalan[] = $ad;
            }
            if ($kalan) flash($n . ' öğe silindi. Silinemeyen: ' . implode(', ', $kalan), 'hata');
            else flash($n . ' öğe silindi.');
            git($donus);

        case 'zipac':
            $ad = (string)($_POST['ad'] ?? '');
            $zf = adGecerli($ad) ? cozum(birles($p, $ad)) : null;
            if (!class_exists('ZipArchive')) { flash('Sunucuda ZipArchive desteği yok.', 'hata'); git($donus); }
            if (!$zf || !is_file($zf)) { flash('Zip dosyası bulunamadı.', 'hata'); git($donus); }
            $z = new ZipArchive();
            if ($z->open($zf) !== true) { flash('Zip açılamadı.', 'hata'); git($donus); }
            for ($i = 0; $i < $z->numFiles; $i++) {
                $n = str_replace('\\', '/', (string)$z->getNameIndex($i));
                if ($n === '' || $n[0] === '/' || preg_match('#(^|/)\.\.(/|$)#', $n) || strpos($n, "\0") !== false || preg_match('#^[A-Za-z]:#', $n)) {
                    $z->close(); flash('Zip güvenli olmayan yollar içeriyor, açılmadı.', 'hata'); git($donus);
                }
            }
            $z->extractTo($dizin); $z->close();
            flash('Zip bulunduğu klasöre çıkarıldı.');
            git($donus);

        case 'kaydet':
            $rel = (string)($_POST['dosya'] ?? '');
            $f = cozum($rel);
            $uz = strtolower(pathinfo((string)$f, PATHINFO_EXTENSION));
            if (!$f || !is_file($f) || !in_array($uz, $DUZENLENEBILIR, true)) { flash('Dosya kaydedilemedi.', 'hata'); git($SELF); }
            if (@file_put_contents($f, (string)($_POST['icerik'] ?? ''), LOCK_EX) === false) flash('Yazma izni yok, kaydedilemedi.', 'hata');
            else flash('Kaydedildi.');
            git($SELF . '?duzenle=' . urlencode($rel));
    }
    git($SELF);
}

/* ---------- İndirme (dosya veya klasör -> zip) ---------- */
if (isset($_GET['indir'])) {
    $f = cozum($_GET['indir']);
    $irel = trim(str_replace('\\', '/', (string)$_GET['indir']), '/');
    $iust = dirname($irel); $iust = ($iust === '.' ? '' : $iust);
    if (!$f || (!is_file($f) && !is_dir($f))) { http_response_code(404); exit('Bulunamadı'); }
    if (is_dir($f)) {
        if ($irel === '') { flash('Kök klasör indirilemez.', 'hata'); git($SELF . '?p='); }
        if (!class_exists('ZipArchive')) { flash('Sunucuda ZipArchive desteği yok, klasör zip yapılamıyor.', 'hata'); git($SELF . '?p=' . urlencode($iust)); }
        @set_time_limit(0); @ignore_user_abort(true);
        $tmp = @tempnam(sys_get_temp_dir(), 'zip');
        if (!$tmp) $tmp = @tempnam(__DIR__, 'zip');
        if (!$tmp) { flash('Geçici zip dosyası oluşturulamadı.', 'hata'); git($SELF . '?p=' . urlencode($iust)); }
        register_shutdown_function(function () use ($tmp) { if (is_file($tmp)) @unlink($tmp); });
        $z = new ZipArchive();
        if ($z->open($tmp, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) { flash('Zip oluşturulamadı.', 'hata'); git($SELF . '?p=' . urlencode($iust)); }
        $baz = rtrim($f, '/');
        $kokAd = basename($f);
        $z->addEmptyDir($kokAd);
        try {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($f, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
            foreach ($it as $x) {
                if ($x->isLink()) continue;
                $yol = str_replace('\\', '/', $x->getPathname());
                $gor = $kokAd . '/' . ltrim(substr($yol, strlen($baz)), '/');
                if ($x->isDir()) $z->addEmptyDir($gor);
                elseif ($x->isReadable()) $z->addFile($yol, $gor);
            }
        } catch (Exception $ex) { /* okunamayan alt klasörler atlanır */ }
        if (!$z->close() || !is_file($tmp)) { flash('Zip yazılamadı (disk dolu veya izin yok).', 'hata'); git($SELF . '?p=' . urlencode($iust)); }
        while (ob_get_level()) ob_end_clean();
        $ad = $kokAd . '.zip';
        header('Content-Type: application/zip');
        header('Content-Length: ' . filesize($tmp));
        header('Content-Disposition: attachment; filename="' . addcslashes($ad, '"\\') . '"; filename*=UTF-8\'\'' . rawurlencode($ad));
        readfile($tmp);
        exit;
    }
    while (ob_get_level()) ob_end_clean();
    $ad = basename($f);
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . filesize($f));
    header('Content-Disposition: attachment; filename="' . addcslashes($ad, '"\\') . '"; filename*=UTF-8\'\'' . rawurlencode($ad));
    readfile($f);
    exit;
}

$mesaj = $_SESSION['mesaj'] ?? null; unset($_SESSION['mesaj']);

/* ---------- Düzenleyici sayfası ---------- */
if (isset($_GET['duzenle'])) {
    $rel = trim((string)$_GET['duzenle'], '/');
    $f = cozum($rel);
    $uz = strtolower(pathinfo((string)$f, PATHINFO_EXTENSION));
    if (!$f || !is_file($f) || !in_array($uz, $DUZENLENEBILIR, true) || filesize($f) > 2 * 1024 * 1024) {
        flash('Bu dosya düzenlenemez (tür desteklenmiyor veya 2 MB üzerinde).', 'hata'); git($SELF);
    }
    $ust = dirname($rel); $ust = ($ust === '.' ? '' : $ust);
    $geri = $SELF . '?p=' . urlencode($ust);
    ?><!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title><?= e(basename($f)) ?> · Düzenle</title><?php ortakStil(); ?>
<style>
body{display:flex;flex-direction:column;height:100vh}
.ust{background:var(--bar);color:#e6eae7;padding:10px 18px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.ust strong{font-weight:600;word-break:break-all}.ust .yol{color:#9aa6a0;font-size:13px}
.ust .btn{background:transparent;color:#e6eae7;border-color:#3a4642}.ust .btn.primary{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}
.bosluk{flex:1}
textarea{flex:1;width:100%;border:0;resize:none;padding:16px 18px;background:var(--panel);color:var(--ink);font:13.5px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;tab-size:4;white-space:pre;overflow:auto}
textarea:focus{outline:none}
.msj{padding:9px 18px;font-size:14px}.msj.ok{background:color-mix(in srgb,var(--accent) 16%,var(--panel))}.msj.hata{background:color-mix(in srgb,var(--danger) 14%,var(--panel));color:var(--danger)}
form{display:contents}
</style></head><body>
<form method="post" id="f">
<input type="hidden" name="csrf" value="<?= e($csrf) ?>"><input type="hidden" name="islem" value="kaydet"><input type="hidden" name="dosya" value="<?= e($rel) ?>">
<div class="ust">
  <a class="btn" href="<?= e($geri) ?>">Geri dön</a>
  <div><strong><?= e(basename($f)) ?></strong><div class="yol"><?= e($f) ?></div></div>
  <span class="bosluk"></span>
  <span class="yol">Ctrl+S ile kaydet</span>
  <button class="btn primary">Kaydet</button>
</div>
<?php if ($mesaj): ?><div class="msj <?= e($mesaj[0]) ?>" role="status"><?= e($mesaj[1]) ?></div><?php endif; ?>
<textarea name="icerik" id="ta" spellcheck="false" autocapitalize="off" autocomplete="off"><?= e(file_get_contents($f)) ?></textarea>
</form>
<script>
const ta=document.getElementById('ta');
ta.addEventListener('keydown',e=>{
  if(e.key==='Tab'){e.preventDefault();const s=ta.selectionStart;ta.setRangeText('\t',s,ta.selectionEnd,'end');}
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();document.getElementById('f').submit();}
});
</script></body></html><?php
    exit;
}

/* ---------- Dosya listesi ---------- */
$BASLA = (strpos(dirname($BU_DOSYA) . '/', $KOK_BASE . '/') === 0) ? ltrim(substr(dirname($BU_DOSYA), strlen($KOK_BASE)), '/') : '';
$p = isset($_GET['p']) ? trim(str_replace('\\', '/', (string)$_GET['p']), '/') : $BASLA;
$dizin = cozum($p);
if (!$dizin || !is_dir($dizin)) {
    $mesaj = ['hata', 'Bu klasöre erişilemiyor (yok veya sunucu erişimi kısıtlıyor). Site klasörüne dönüldü.'];
    $p = $BASLA; $dizin = cozum($p) ?: $KOK_REAL;
}
$liste = @scandir($dizin);
if ($liste === false) { $mesaj = ['hata', 'Bu klasörün içeriği okunamadı (izin yok).']; $liste = []; }

$ogeler = [];
foreach ($liste as $ad) {
    if ($ad === '.' || $ad === '..') continue;
    $tam = rtrim($dizin, '/') . '/' . $ad;
    $dir = is_dir($tam);
    $ogeler[] = [
        'ad' => $ad, 'dir' => $dir,
        'boyut' => (!$dir && is_file($tam)) ? (int)filesize($tam) : 0,
        'tarih' => (int)@filemtime($tam),
        'izin' => substr(sprintf('%o', @fileperms($tam)), -4),
        'uz' => strtolower(pathinfo($ad, PATHINFO_EXTENSION)),
    ];
}
usort($ogeler, function ($a, $b) {
    if ($a['dir'] !== $b['dir']) return $a['dir'] ? -1 : 1;
    return strnatcasecmp($a['ad'], $b['ad']);
});
$klasorSay = count(array_filter($ogeler, function ($o) { return $o['dir']; }));
$parcalar = $p === '' ? [] : explode('/', $p);
$ustDizin = count($parcalar) > 1 ? implode('/', array_slice($parcalar, 0, -1)) : '';
$bosDisk = @disk_free_space($dizin);
$kokEtiket = $KOK_BASE === '' ? '/' : $KOK_REAL;
?><!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title><?= e($SITE_ADI) ?></title><?php ortakStil(); ?>
<style>
.ust{background:var(--bar);color:#e6eae7;padding:11px 20px;display:flex;align-items:center;gap:14px}
.ust strong{font-size:16px;font-weight:650}.ust .bosluk{flex:1}
.ust .btn{background:transparent;color:#e6eae7;border-color:#3a4642;padding:5px 11px}
.ust small{color:#9aa6a0}
.ana{max-width:1180px;margin:0 auto;padding:18px 16px 30px}
.yolbar{display:flex;flex-wrap:wrap;align-items:center;gap:2px;margin-bottom:12px;font-size:14.5px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:7px 10px}
.yolbar .site{margin-left:auto;padding:4px 10px;font-size:13px}
.yolbar a:not(.btn){text-decoration:none;padding:3px 7px;border-radius:5px;color:var(--accent)}.yolbar a:not(.btn):hover{background:var(--hover);text-decoration:underline}
.yolbar .son{font-weight:650;padding:3px 7px}.yolbar .ay{color:var(--muted)}
.arac{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;align-items:center}
.arac .ara{flex:1;min-width:150px;max-width:280px;margin-left:auto}
.kutu{background:var(--panel);border:1px solid var(--line);border-radius:10px;position:relative;overflow:hidden}
.liste{max-height:calc(100vh - 325px);min-height:240px;overflow:auto}
.liste,textarea{scrollbar-width:thin;scrollbar-color:color-mix(in srgb,var(--accent) 60%,var(--panel)) var(--hover)}
.liste::-webkit-scrollbar,textarea::-webkit-scrollbar{width:12px;height:12px}
.liste::-webkit-scrollbar-track,textarea::-webkit-scrollbar-track{background:var(--hover);border-left:1px solid var(--line)}
.liste::-webkit-scrollbar-thumb,textarea::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--accent) 55%,var(--panel));border-radius:8px;border:3px solid var(--hover)}
.liste::-webkit-scrollbar-thumb:hover,textarea::-webkit-scrollbar-thumb:hover{background:var(--accent)}
.liste::-webkit-scrollbar-corner,textarea::-webkit-scrollbar-corner{background:var(--hover)}
.yukari{display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--accent) 7%,var(--panel));color:var(--accent);text-decoration:none;font-size:14.5px}
.yukari:hover{background:color-mix(in srgb,var(--accent) 14%,var(--panel))}
.yukari b{font-weight:650}.yukari span{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse}
th{position:sticky;top:0;background:var(--panel);text-align:left;font-weight:600;font-size:13px;color:var(--muted);padding:10px 12px;border-bottom:1px solid var(--line);z-index:1;white-space:nowrap}
td{padding:7px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
tbody tr:hover{background:var(--hover)}tbody tr:last-child td{border-bottom:0}
.c0{width:36px}.sag{text-align:right;white-space:nowrap}.sol{white-space:nowrap;color:var(--muted);font-size:13.5px}
.ad{display:flex;align-items:center;gap:9px;min-width:0}
.ad a,.ad span.t{overflow-wrap:anywhere;color:var(--ink);text-decoration:none}.ad a:hover{text-decoration:underline}
.ik{width:20px;height:20px;flex:none;fill:currentColor}.ik.k{color:var(--folder)}.ik.d{color:var(--muted)}
.is{display:flex;gap:2px;justify-content:flex-end;flex-wrap:wrap}
.is button,.is a{border:0;background:none;color:var(--accent);padding:4px 7px;border-radius:5px;cursor:pointer;font-size:13.5px;text-decoration:none}
.is button:hover,.is a:hover{background:color-mix(in srgb,var(--accent) 12%,transparent)}
.is .sl{color:var(--danger)}.is .sl:hover{background:color-mix(in srgb,var(--danger) 12%,transparent)}
.bos{padding:50px 20px;text-align:center;color:var(--muted)}
.alt{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:9px 14px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}
.msj{padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:14.5px}
.msj.ok{background:color-mix(in srgb,var(--accent) 14%,var(--panel));border:1px solid color-mix(in srgb,var(--accent) 35%,var(--line))}
.msj.hata{background:color-mix(in srgb,var(--danger) 12%,var(--panel));border:1px solid color-mix(in srgb,var(--danger) 35%,var(--line));color:var(--danger)}
.birak{position:absolute;inset:0;background:color-mix(in srgb,var(--accent) 14%,var(--panel));border:2px dashed var(--accent);border-radius:10px;display:none;place-items:center;font-weight:650;color:var(--accent);z-index:3;pointer-events:none}
.kutu.surukle .birak{display:grid}
.ilerleme{display:none;height:4px;background:var(--line)}.ilerleme i{display:block;height:100%;width:0;background:var(--accent);transition:width .15s}
dialog{border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--ink);padding:22px;width:min(380px,92vw)}
dialog::backdrop{background:rgba(0,0,0,.45)}
dialog h3{margin:0 0 14px;font-size:17px}.dbtn{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
@media(max-width:720px){.gizle{display:none}.liste{max-height:none}.ust small{display:none}}
</style></head><body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="i-k" viewBox="0 0 24 24"><path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></symbol>
<symbol id="i-d" viewBox="0 0 24 24"><path d="M6 2h8l5 5v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm7 1.5V8h4.5z"/></symbol>
</defs></svg>

<div class="ust">
  <strong><?= e($SITE_ADI) ?></strong><small><?= e($_SERVER['HTTP_HOST'] ?? '') ?></small>
  <span class="bosluk"></span>
  <form method="post"><input type="hidden" name="csrf" value="<?= e($csrf) ?>"><input type="hidden" name="islem" value="cikis"><button class="btn">Çıkış yap</button></form>
</div>

<div class="ana">
<?php if ($mesaj): ?><div class="msj <?= e($mesaj[0]) ?>" role="status"><?= e($mesaj[1]) ?></div><?php endif; ?>

<nav class="yolbar" aria-label="Konum">
  <?php if ($p === ''): ?><span class="son"><?= e($kokEtiket) ?></span>
  <?php else: ?><a href="<?= e($SELF . '?p=') ?>"><?= e($kokEtiket) ?></a>
    <?php $acc = ''; foreach ($parcalar as $i => $s): $acc = birles($acc, $s); ?>
      <?php if ($i > 0 || $KOK_BASE !== ''): ?><span class="ay">/</span><?php endif; ?>
      <?php if ($i === count($parcalar) - 1): ?><span class="son"><?= e($s) ?></span>
      <?php else: ?><a href="<?= e($SELF . '?p=' . urlencode($acc)) ?>"><?= e($s) ?></a><?php endif; ?>
    <?php endforeach; ?>
  <?php endif; ?>
  <?php if ($p !== $BASLA): ?><a class="btn site" href="<?= e($SELF . '?p=' . urlencode($BASLA)) ?>">Site klasörüne git</a><?php endif; ?>
</nav>

<div class="arac">
  <button class="btn primary" type="button" onclick="document.getElementById('dosyaSec').click()">Dosya yükle</button>
  <input type="file" id="dosyaSec" multiple hidden>
  <button class="btn" type="button" onclick="ac('Yeni klasör','klasor')">Yeni klasör</button>
  <button class="btn" type="button" onclick="ac('Yeni dosya','yenidosya')">Yeni dosya</button>
  <button class="btn danger" type="button" id="topluSil" onclick="topluSil()" disabled>Seçilenleri sil</button>
  <input class="ara" type="search" id="ara" placeholder="Bu klasörde ara" aria-label="Bu klasörde ara">
</div>

<div class="kutu" id="kutu">
  <div class="birak">Yüklemek için dosyaları buraya bırakın</div>
  <div class="ilerleme" id="ilerleme"><i></i></div>
  <?php if ($p !== ''): ?>
  <a class="yukari" href="<?= e($SELF . '?p=' . urlencode($ustDizin)) ?>">
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 19V5M5 12l7-7 7 7"/></svg>
    <b>Üst klasör</b><span><?= e($ustDizin === '' ? $kokEtiket : '/' . $ustDizin) ?></span>
  </a>
  <?php endif; ?>
  <form method="post" id="listeForm">
    <input type="hidden" name="csrf" value="<?= e($csrf) ?>"><input type="hidden" name="islem" value="sil"><input type="hidden" name="p" value="<?= e($p) ?>">
    <div class="liste">
    <table>
      <thead><tr>
        <th class="c0"><input type="checkbox" id="hepsi" aria-label="Tümünü seç"></th>
        <th>Ad</th><th class="sag gizle">Boyut</th><th class="gizle">Değiştirilme</th><th class="gizle">İzin</th><th class="sag">İşlem</th>
      </tr></thead>
      <tbody id="govde">
      <?php foreach ($ogeler as $o):
        $rel = birles($p, $o['ad']);
        $duz = !$o['dir'] && in_array($o['uz'], $DUZENLENEBILIR, true);
        $zip = !$o['dir'] && $o['uz'] === 'zip';
        $tamYol = rtrim($dizin, '/') . '/' . $o['ad'];
        $tehlike = ($tamYol === $BU_DOSYA) ? 'dosya' : (($o['dir'] && strpos($BU_DOSYA, $tamYol . '/') === 0) ? 'klasor' : '');
      ?>
      <tr data-ad="<?= e(mb_strtolower($o['ad'])) ?>">
        <td class="c0"><input type="checkbox" name="sec[]" value="<?= e($o['ad']) ?>" data-t="<?= e($tehlike) ?>" aria-label="<?= e($o['ad']) ?> seç"></td>
        <td><div class="ad">
          <?php if ($o['dir']): ?>
            <svg class="ik k"><use href="#i-k"/></svg><a href="<?= e($SELF . '?p=' . urlencode($rel)) ?>"><?= e($o['ad']) ?></a>
          <?php else: ?>
            <svg class="ik d"><use href="#i-d"/></svg>
            <?php if ($duz): ?><a href="<?= e($SELF . '?duzenle=' . urlencode($rel)) ?>"><?= e($o['ad']) ?></a>
            <?php else: ?><span class="t"><?= e($o['ad']) ?></span><?php endif; ?>
          <?php endif; ?>
        </div></td>
        <td class="sag sol gizle"><?= $o['dir'] ? '—' : e(boyutYaz($o['boyut'])) ?></td>
        <td class="sol gizle"><?= $o['tarih'] ? date('d.m.Y H:i', $o['tarih']) : '—' ?></td>
        <td class="sol gizle"><?= e($o['izin']) ?></td>
        <td><div class="is">
          <a href="<?= e($SELF . '?indir=' . urlencode($rel)) ?>"><?= $o['dir'] ? 'Zip indir' : 'İndir' ?></a>
          <?php if ($duz): ?><a href="<?= e($SELF . '?duzenle=' . urlencode($rel)) ?>">Düzenle</a><?php endif; ?>
          <?php if ($zip): ?><button type="button" onclick='gonder({islem:"zipac",ad:<?= json_encode($o['ad'], JSON_HEX_APOS | JSON_HEX_QUOT) ?>})'>Zip'i aç</button><?php endif; ?>
          <button type="button" onclick='ac("Yeniden adlandır","adlandir",<?= json_encode($o['ad'], JSON_HEX_APOS | JSON_HEX_QUOT) ?>)'>Ad değiştir</button>
          <button type="button" class="sl" onclick='tekSil(<?= json_encode($o['ad'], JSON_HEX_APOS | JSON_HEX_QUOT) ?>,<?= json_encode($tehlike) ?>)'>Sil</button>
        </div></td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    <?php if (!$ogeler): ?><div class="bos">Bu klasör boş. Dosyaları buraya sürükleyip bırakabilirsiniz.</div><?php endif; ?>
    </div>
  </form>
  <div class="alt">
    <span><?= $klasorSay ?> klasör, <?= count($ogeler) - $klasorSay ?> dosya</span>
    <span>Tek dosya sınırı: <?= e(ini_get('upload_max_filesize')) ?><?= $bosDisk ? ' · Boş alan: ' . e(boyutYaz((int)$bosDisk)) : '' ?></span>
  </div>
</div>
</div>

<dialog id="dlg"><form method="post" id="dlgForm">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>"><input type="hidden" name="p" value="<?= e($p) ?>">
  <input type="hidden" name="islem" id="dlgIslem"><input type="hidden" name="eski" id="dlgEski">
  <h3 id="dlgBaslik"></h3>
  <input type="text" name="ad" id="dlgAd" required autocomplete="off" aria-label="Ad">
  <div class="dbtn"><button type="button" class="btn" onclick="dlg.close()">Vazgeç</button><button class="btn primary">Tamam</button></div>
</form></dialog>

<script>
const CSRF=<?= json_encode($csrf) ?>, P=<?= json_encode($p) ?>, SELF=<?= json_encode($SELF) ?>;
const dlg=document.getElementById('dlg'), kutu=document.getElementById('kutu');

function ac(baslik,islem,deger){
  document.getElementById('dlgBaslik').textContent=baslik;
  document.getElementById('dlgIslem').value=islem;
  document.getElementById('dlgEski').value=islem==='adlandir'?deger:'';
  const i=document.getElementById('dlgAd'); i.value=deger||''; dlg.showModal(); i.focus();
  if(deger){const n=deger.lastIndexOf('.'); i.setSelectionRange(0,n>0?n:deger.length);}
}
function gonder(d){
  const f=document.createElement('form'); f.method='post'; f.action=SELF; d.csrf=CSRF; d.p=P;
  for(const k in d){const i=document.createElement('input'); i.type='hidden'; i.name=k; i.value=d[k]; f.appendChild(i);}
  document.body.appendChild(f); f.submit();
}
const TEHLIKE={
  dosya:'DİKKAT: Bu, şu an kullandığınız yönetim panelinin kendisi! Silerseniz panele erişiminiz kalmaz; tekrar kullanmak için hosting dosya yöneticisinden yeniden yüklemeniz gerekir.',
  klasor:'DİKKAT: Bu klasör, şu an kullandığınız yönetim panelini içeriyor! Silerseniz panel de silinir; tekrar kullanmak için hosting dosya yöneticisinden yeniden yüklemeniz gerekir.'
};
function tekSil(ad,t){
  let m='"'+ad+'" kalıcı olarak silinsin mi?';
  if(t) m=TEHLIKE[t]+'\n\n'+m;
  if(confirm(m)) gonder({islem:'sil','sec[]':ad});
}
const kutular=()=>[...document.querySelectorAll('input[name="sec[]"]')];
function guncelle(){
  const n=kutular().filter(c=>c.checked).length, b=document.getElementById('topluSil');
  b.disabled=n===0; b.textContent=n?('Seçilenleri sil ('+n+')'):'Seçilenleri sil';
}
function topluSil(){
  const sec=kutular().filter(c=>c.checked), n=sec.length;
  if(!n) return;
  const t=(sec.find(c=>c.dataset.t)||{dataset:{}}).dataset.t;
  let m=n+' öğe kalıcı olarak silinsin mi?';
  if(t) m=TEHLIKE[t]+'\n\n'+m;
  if(confirm(m)) document.getElementById('listeForm').submit();
}
document.getElementById('hepsi').addEventListener('change',e=>{
  kutular().forEach(c=>{if(!c.dataset.t&&c.closest('tr').style.display!=='none')c.checked=e.target.checked}); guncelle();
});
document.getElementById('govde').addEventListener('change',guncelle);
document.getElementById('ara').addEventListener('input',e=>{
  const q=e.target.value.trim().toLowerCase();
  document.querySelectorAll('#govde tr[data-ad]').forEach(r=>{r.style.display=r.dataset.ad.includes(q)?'':'none'});
});

/* Yükleme (ilerleme çubuğu ile) */
function yukle(dosyalar){
  if(!dosyalar.length) return;
  const fd=new FormData(); fd.append('csrf',CSRF); fd.append('islem','yukle'); fd.append('p',P);
  for(const f of dosyalar) fd.append('dosyalar[]',f);
  const bar=document.getElementById('ilerleme'), dolu=bar.firstElementChild; bar.style.display='block';
  const x=new XMLHttpRequest(); x.open('POST',SELF);
  x.upload.onprogress=e=>{if(e.lengthComputable) dolu.style.width=(e.loaded/e.total*100)+'%'};
  x.onload=()=>location.reload();
  x.onerror=()=>{bar.style.display='none'; alert('Yükleme sırasında bağlantı hatası oluştu.');};
  x.send(fd);
}
document.getElementById('dosyaSec').addEventListener('change',e=>yukle(e.target.files));
let sayac=0;
kutu.addEventListener('dragenter',e=>{e.preventDefault(); sayac++; kutu.classList.add('surukle');});
kutu.addEventListener('dragleave',()=>{sayac--; if(sayac<=0){sayac=0; kutu.classList.remove('surukle');}});
kutu.addEventListener('dragover',e=>e.preventDefault());
kutu.addEventListener('drop',e=>{e.preventDefault(); sayac=0; kutu.classList.remove('surukle'); yukle(e.dataTransfer.files);});
</script>
</body></html>
