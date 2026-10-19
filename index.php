<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');

session_start();
ob_start();

define('DATA_FILE', __DIR__ . '/xfile_data.json');
define('FILES_DIR', __DIR__ . '/dosyalar');
define('THUMBS_DIR', FILES_DIR . '/thumb');
define('SCREENSHOTS_DIR', FILES_DIR . '/ekran');
define('VIDEOS_DIR', FILES_DIR . '/video');
define('BFILES_DIR', FILES_DIR . '/bilgi');
define('HTACCESS_FILE', FILES_DIR . '/.htaccess');
define('APP_NAME', 'Exlonea');

function x_init() {
    if (!is_dir(FILES_DIR)) mkdir(FILES_DIR, 0755, true);
    if (!is_dir(SCREENSHOTS_DIR)) mkdir(SCREENSHOTS_DIR, 0755, true);
    if (!is_dir(THUMBS_DIR)) mkdir(THUMBS_DIR, 0755, true);
    if (!is_dir(VIDEOS_DIR)) mkdir(VIDEOS_DIR, 0755, true);
    if (!is_dir(BFILES_DIR)) mkdir(BFILES_DIR, 0755, true);
    if (!file_exists(HTACCESS_FILE)) {
        $h = "AddType text/plain .php .php2 .php3 .php4 .php5 .php6 .php7 .php8 .phtml .pht .phar .shtml .cgi .pl .py .asp .aspx .jsp\n";
        $h .= "<FilesMatch \"\.(?i:php|php[0-9]?|phtml|pht|phar|shtml)\$\">\n    SetHandler default-handler\n</FilesMatch>\n";
        file_put_contents(HTACCESS_FILE, $h);
    }
    if (!file_exists(DATA_FILE)) {
        $default = [
            'categories' => [],
            'dosya' => [],
'notes' => [],
            'github' => [],

        ];
        file_put_contents(DATA_FILE, json_encode($default, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
}

function x_sort_cmp($a,$b) {
    $ap=!empty($a['pinned']); $bp=!empty($b['pinned']);
    if ($ap !== $bp) return $ap ? -1 : 1;
    $ao=isset($a['sort_order']); $bo=isset($b['sort_order']);
    if ($ao && $bo) { if ($a['sort_order'] != $b['sort_order']) return $a['sort_order'] <=> $b['sort_order']; }
    elseif ($ao !== $bo) return $ao ? 1 : -1;
    if ($ap && $bp) {
        $aT=strtotime($a['pinned_at']??$a['pin_date']??$a['updated_at']??$a['date_added']??'0');
        $bT=strtotime($b['pinned_at']??$b['pin_date']??$b['updated_at']??$b['date_added']??'0');
        if ($aT !== $bT) return $bT <=> $aT;
    }
    return strtotime($b['date_added']??'0')<=>strtotime($a['date_added']??'0');
}
function x_data() { return json_decode(file_get_contents(DATA_FILE), true); }
function x_save($d) { file_put_contents(DATA_FILE, json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); }
function x_admin() { return isset($_SESSION['role']) && $_SESSION['role']==='admin'; }
function x_logged() { return isset($_SESSION['role']); }
function x_tab_defaults() { return array('dosya'=>array('label'=>'Dosya Arşivi','enabled'=>true),'github'=>array('label'=>'GitHub','enabled'=>true),'notes'=>array('label'=>'Bilgiler','enabled'=>true)); }
function x_tabs_build($data) {
    $t = x_tab_defaults();
    $st = (isset($data['settings']['tabs']) && is_array($data['settings']['tabs'])) ? $data['settings']['tabs'] : array();
    foreach ($t as $k=>$d) {
        if (isset($st[$k]['label']) && is_string($st[$k]['label']) && trim($st[$k]['label'])!=='') $t[$k]['label'] = mb_substr(trim($st[$k]['label']),0,30);
        if (isset($st[$k]['enabled'])) $t[$k]['enabled'] = (bool)$st[$k]['enabled'];
    }
    $any = false; foreach ($t as $x) if ($x['enabled']) $any = true;
    if (!$any) $t['notes']['enabled'] = true;
    return $t;
}
function x_tab_on($k) { return !empty($GLOBALS['x_tabs'][$k]['enabled']); }
function x_tab_label($k) { return isset($GLOBALS['x_tabs'][$k]['label']) ? $GLOBALS['x_tabs'][$k]['label'] : $k; }
function x_tab_first() { foreach ($GLOBALS['x_tabs'] as $k=>$t) if ($t['enabled']) return $k; return 'notes'; }
function x_fmt_size($b) { $b=(float)$b; if ($b>=1073741824) return round($b/1073741824,2).' GB'; if ($b>=1048576) return round($b/1048576,1).' MB'; return max(1,round($b/1024)).' KB'; }
function x_item_files($item) {
    $l = array();
    if (!empty($item['files']) && is_array($item['files'])) foreach ($item['files'] as $f) if (is_array($f) && isset($f['name'],$f['stored_name'])) $l[] = $f;
    return $l;
}
function x_save_note_files($key='nfile') {
    $out = array();
    if (!isset($_FILES[$key]) || !is_array($_FILES[$key]['name'])) return $out;
    $f = $_FILES[$key];
    $bad = array('php','php2','php3','php4','php5','php6','php7','php8','phtml','pht','phar','shtml','cgi','pl','py','asp','aspx','jsp','htaccess');
    foreach ($f['name'] as $i=>$nm) {
        if ($f['error'][$i]!==UPLOAD_ERR_OK || !is_uploaded_file($f['tmp_name'][$i])) continue;
        $orig = preg_replace('/[\x00-\x1F\x7F\\\\\/]+/u','',basename((string)$nm));
        if (!is_string($orig) || trim($orig)==='') $orig = 'dosya';
        $ext = strtolower(pathinfo($orig,PATHINFO_EXTENSION));
        $safeExt = (preg_match('/^[a-z0-9]{1,10}$/',$ext) && !in_array($ext,$bad,true)) ? $ext : 'bin';
        $stored = 'nf_'.bin2hex(random_bytes(10)).'.'.$safeExt;
        if (move_uploaded_file($f['tmp_name'][$i],BFILES_DIR.'/'.$stored)) {
            $out[] = array('name'=>$orig,'stored_name'=>$stored,'size'=>filesize(BFILES_DIR.'/'.$stored));
        }
    }
    return $out;
}
function x_delete_note_files($item) {
    foreach (x_item_files($item) as $f) { $p = BFILES_DIR.'/'.basename($f['stored_name']); if (is_file($p)) @unlink($p); }
}
function x_remove_note_files(&$item,$ns) {
    $keep = array();
    foreach (x_item_files($item) as $i=>$f) {
        if (in_array($i,$ns,true)) { $p = BFILES_DIR.'/'.basename($f['stored_name']); if (is_file($p)) @unlink($p); }
        else $keep[] = $f;
    }
    $item['files'] = $keep;
}
function x_ip() { return $_SERVER['REMOTE_ADDR'] ?? 'unknown'; }
function x_track(&$data, $type, $id, $action, $label='') {
    if (!isset($data['analytics']) || !is_array($data['analytics'])) $data['analytics'] = [];
    $data['analytics'][] = ['type'=>$type,'id'=>(string)$id,'action'=>$action,'label'=>$label,'ip'=>x_ip(),'role'=>$_SESSION['role']??'guest','time'=>date('Y-m-d H:i:s')];
    if (count($data['analytics']) > 10000) $data['analytics'] = array_slice($data['analytics'], -10000);
}
function x_h($s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function x_php_post() { return (isset($_POST['php_version_enabled']) && trim($_POST['php_version']??'')!=='') ? trim($_POST['php_version']) : null; }
function x_php_badge($v) {
    $v = trim((string)($v ?? ''));
    if ($v === '') return '<span style="color:var(--text3)">—</span>';
    return '<span class="badge badge-a" style="white-space:nowrap">PHP '.x_h($v).'</span>';
}
function x_php_field($name, $value, $labelStyle='') {
    $enabled = trim((string)$value) !== '';
    $sv = x_h($value ?? '');
    $label = $labelStyle!=='' ? '<span style="'.$labelStyle.'">PHP Versiyonu</span>' : '<span class="swl">PHP Versiyonu</span>';
    return '<div class="toggle-row php-ver-row"><label class="sw"><input type="checkbox" name="'.$name.'_enabled" value="1" onchange="togglePhpVer(this)" '.($enabled?'checked':'').'><span class="sl"></span></label>'.$label.'<input type="text" name="'.$name.'" class="php-ver-input" placeholder="örn: 7.3" value="'.$sv.'" '.($enabled?'':'disabled style="display:none"').'></div>';
}

function x_rich($s) {
    $s = (string)$s;
    $s = strip_tags($s, '<b><strong><i><em><u><ul><ol><li><h3><br><span><font>');
    $s = preg_replace_callback('/<(span|font)\b([^>]*)>/i', function($m) {
        $attrs = '';
        if (preg_match('/(?:style\s*=\s*["\'])([^"\']*)["\']/i', $m[2], $style)) {
            $safe = [];
            foreach (explode(';', $style[1]) as $rule) {
                if (strpos($rule, ':') === false) continue;
                [$property, $value] = array_map('trim', explode(':', $rule, 2));
                if (in_array(strtolower($property), ['color', 'font-size', 'font-weight', 'font-style', 'text-decoration'], true) && preg_match('/^[#a-z0-9 ,.()%\-]+$/i', $value)) {
                    $safe[] = strtolower($property).':'.$value;
                }
            }
            if ($safe) $attrs = ' style="'.x_h(implode(';', $safe)).'"';
        }
        if (preg_match('/(?:color\s*=\s*["\'])(#[a-f0-9]{3,8}|[a-z]+)["\']/i', $m[2], $color)) $attrs = ' style="color:'.x_h($color[1]).'"';
        return '<'.$m[1].$attrs.'>';
    }, $s);
    return $s;
}
function x_rich_editor($id, $name, $value='', $placeholder='Açıklamayı buraya yazın...') {
    $sid=x_h($id); $sname=x_h($name); $svalue=x_h($value); $shtml=x_rich($value); $splaceholder=x_h($placeholder);
    return '<div class="rich-editor"><div class="rich-toolbar" role="toolbar" aria-label="İçerik biçimlendirme"><button type="button" onclick="richCmd(\'bold\',\''.$sid.'\')" title="Kalın"><strong>B</strong></button><button type="button" onclick="richCmd(\'italic\',\''.$sid.'\')" title="İtalik"><em>I</em></button><button type="button" onclick="richCmd(\'underline\',\''.$sid.'\')" title="Altı çizili"><u>U</u></button><button type="button" onclick="richCmd(\'insertUnorderedList\',\''.$sid.'\')" title="Liste">•</button><button type="button" onclick="richCmd(\'formatBlock\',\''.$sid.'\',\'h3\')" title="Başlık">H</button><select class="rich-size-select" onchange="richCmd(\'fontSize\',\''.$sid.'\',this.value)" title="Yazı boyutu"><option value="" selected disabled hidden>Boyut</option><option value="2">Küçük</option><option value="3">Normal</option><option value="5">Büyük</option><option value="7">Çok büyük</option></select><input type="color" onchange="richCmd(\'foreColor\',\''.$sid.'\',this.value)" title="Yazı rengi"></div><div id="'.$sid.'" class="rich-content" contenteditable="true" data-target="'.$sname.'" data-placeholder="'.$splaceholder.'">'.$shtml.'</div><textarea name="'.$sname.'" id="'.$sid.'Value" class="rich-value" aria-hidden="true">'.$svalue.'</textarea></div>';
}

function x_thumb($src, $dest, $size=80) {
    if (!file_exists($src)) return false;
    $info = @getimagesize($src);
    if (!$info) return false;
    list($w,$h) = $info;
    $ratio = $w/$h;
    if ($ratio>1) { $nw=$size; $nh=intval($size/$ratio); } else { $nh=$size; $nw=intval($size*$ratio); }
    $img = null;
    switch($info[2]) {
        case IMAGETYPE_JPEG: $img=imagecreatefromjpeg($src); break;
        case IMAGETYPE_PNG: $img=imagecreatefrompng($src); break;
        case IMAGETYPE_GIF: $img=imagecreatefromgif($src); break;
        case IMAGETYPE_WEBP: $img=imagecreatefromwebp($src); break;
        default: return false;
    }
    if (!$img) return false;
    $t = imagecreatetruecolor($nw, $nh);
    if ($info[2]==IMAGETYPE_PNG||$info[2]==IMAGETYPE_WEBP) {
        imagealphablending($t, false); imagesavealpha($t, true);
        imagealphablending($img, true);
    }
    imagecopyresampled($t,$img,0,0,0,0,$nw,$nh,$w,$h);
    $ok = false;
    switch($info[2]) {
        case IMAGETYPE_JPEG: $ok=imagejpeg($t,$dest,75); break;
        case IMAGETYPE_PNG: $ok=imagepng($t,$dest,6); break;
        case IMAGETYPE_GIF: $ok=imagegif($t,$dest); break;
        case IMAGETYPE_WEBP: $ok=imagewebp($t,$dest,75); break;
    }
    imagedestroy($img); imagedestroy($t);
    return $ok;
}
function x_cat_tree($cats, $parent=null) {
    $r = [];
    foreach ($cats as $c) { if ($c['parent']===$parent) $r[]=$c; }
    usort($r, function($a, $b) {
        $aOrder = isset($a['order']) ? $a['order'] : 99;
        $bOrder = isset($b['order']) ? $b['order'] : 99;
        if ($aOrder == $bOrder) return 0;
        return ($aOrder < $bOrder) ? -1 : 1;
    });
    return $r;
}
function x_cat_name($cats, $id) {
    foreach ($cats as $c) if ((string)($c['id'] ?? '') === (string)$id) return $c['name'];
    return '—';
}
function x_cat_matches($item, $categoryId) {
    return (string)($item['category_id'] ?? '') === (string)$categoryId;
}
function x_img_exts() { return array('jpg','jpeg','png','gif','webp','bmp'); }
function x_url_is_public_ip($ip) {
    if (stripos($ip,'::ffff:')===0) $ip = substr($ip,7);
    return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}
function x_url_resolve($host) {
    $host = trim($host,'[]');
    if (filter_var($host, FILTER_VALIDATE_IP)) return array($host);
    $ips = array();
    $v4 = @gethostbynamel($host);
    if ($v4) $ips = $v4;
    if (function_exists('dns_get_record')) {
        $aaaa = @dns_get_record($host, DNS_AAAA);
        if ($aaaa) foreach ($aaaa as $r) if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
    }
    return $ips;
}
function x_download_image($url, $destTmp, $maxBytes = 10485760) {
    for ($hop=0; $hop<=3; $hop++) {
        $p = parse_url($url);
        if (!$p || empty($p['host']) || empty($p['scheme'])) return false;
        $scheme = strtolower($p['scheme']);
        if ($scheme!=='http' && $scheme!=='https') return false;
        if (isset($p['user']) || isset($p['pass'])) return false;
        $port = isset($p['port']) ? (int)$p['port'] : ($scheme==='https' ? 443 : 80);
        if ($port!==80 && $port!==443) return false;
        $ips = x_url_resolve($p['host']);
        if (!$ips) return false;
        foreach ($ips as $ip) if (!x_url_is_public_ip($ip)) return false;
        $code = 0; $location = ''; $written = 0;
        $out = @fopen($destTmp,'wb');
        if (!$out) return false;
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            $opts = array(
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => 8,
                CURLOPT_TIMEOUT => 20,
                CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; ImageFetcher/1.0)',
                CURLOPT_HTTPHEADER => array('Accept: image/*,*/*;q=0.8'),
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_WRITEFUNCTION => function($c,$d) use ($out,&$written,$maxBytes) {
                    $written += strlen($d);
                    if ($written > $maxBytes) return 0;
                    return fwrite($out,$d);
                },
                CURLOPT_HEADERFUNCTION => function($c,$h) use (&$location) {
                    if (stripos($h,'location:')===0) $location = trim(substr($h,9));
                    return strlen($h);
                }
            );
            if (!filter_var(trim($p['host'],'[]'), FILTER_VALIDATE_IP)) $opts[CURLOPT_RESOLVE] = array($p['host'].':'.$port.':'.$ips[0]);
            curl_setopt_array($ch,$opts);
            curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
        } else {
            $ctx = stream_context_create(array('http'=>array('method'=>'GET','timeout'=>20,'follow_location'=>0,'ignore_errors'=>true,'header'=>"Accept: image/*\r\nUser-Agent: Mozilla/5.0 (compatible; ImageFetcher/1.0)\r\n"),'ssl'=>array('verify_peer'=>true)));
            $in = @fopen($url,'rb',false,$ctx);
            if (!$in) { fclose($out); return false; }
            if (!empty($http_response_header)) foreach ($http_response_header as $h) {
                if (preg_match('#^HTTP/\S+\s+(\d+)#',$h,$m)) $code = (int)$m[1];
                elseif (stripos($h,'location:')===0) $location = trim(substr($h,9));
            }
            while (!feof($in)) {
                $d = fread($in,8192);
                if ($d===false) break;
                $written += strlen($d);
                if ($written > $maxBytes) break;
                fwrite($out,$d);
            }
            fclose($in);
        }
        fclose($out);
        if ($written > $maxBytes) return false;
        if ($code>=300 && $code<400 && $location!=='') {
            if (strpos($location,'//')===0) $location = $scheme.':'.$location;
            elseif ($location[0]==='/') $location = $scheme.'://'.$p['host'].(isset($p['port'])?':'.$p['port']:'').$location;
            elseif (!preg_match('#^https?://#i',$location)) return false;
            $url = $location;
            continue;
        }
        return ($code===200 && $written>0);
    }
    return false;
}
function x_image_ext_from_file($path) {
    $info = @getimagesize($path);
    if (!$info) return false;
    switch ($info[2]) {
        case IMAGETYPE_JPEG: return 'jpg';
        case IMAGETYPE_PNG: return 'png';
        case IMAGETYPE_GIF: return 'gif';
        case IMAGETYPE_WEBP: return 'webp';
        case IMAGETYPE_BMP: return 'bmp';
    }
    return false;
}
function x_save_images($fileKey, $urlKey, $dir, $base, $max=20) {
    $saved = array(); $k = 0;
    if (isset($_FILES[$fileKey]) && is_array($_FILES[$fileKey]['name'])) {
        foreach ($_FILES[$fileKey]['name'] as $i=>$nm) {
            if (count($saved) >= $max) break;
            if ((isset($_FILES[$fileKey]['error'][$i]) ? $_FILES[$fileKey]['error'][$i] : UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) continue;
            $ext = strtolower(pathinfo(basename($nm),PATHINFO_EXTENSION));
            if (!in_array($ext,x_img_exts(),true)) continue;
            $name = $base.'_'.(++$k).'.'.$ext;
            if (move_uploaded_file($_FILES[$fileKey]['tmp_name'][$i],$dir.'/'.$name)) $saved[] = $name;
        }
    }
    $raw = isset($_POST[$urlKey]) && is_string($_POST[$urlKey]) ? $_POST[$urlKey] : '';
    foreach (preg_split('/[\r\n]+/',$raw) as $url) {
        $url = trim($url);
        if ($url==='') continue;
        if (count($saved) >= $max) break;
        $tmp = tempnam(sys_get_temp_dir(),'imgurl_');
        if ($tmp===false) continue;
        $ext = x_download_image($url,$tmp) ? x_image_ext_from_file($tmp) : false;
        if (!$ext) { @unlink($tmp); $GLOBALS['x_img_url_failed']=true; continue; }
        $name = $base.'_'.(++$k).'.'.$ext;
        if (!@rename($tmp,$dir.'/'.$name)) {
            if (!@copy($tmp,$dir.'/'.$name)) { @unlink($tmp); $GLOBALS['x_img_url_failed']=true; continue; }
            @unlink($tmp);
        }
        @chmod($dir.'/'.$name,0644);
        $saved[] = $name;
    }
    return $saved;
}
function x_item_images($item,$mk) {
    $l = array();
    if (!empty($item[$mk])) $l[] = $item[$mk];
    if (!empty($item['gallery']) && is_array($item['gallery'])) foreach ($item['gallery'] as $f) if ($f) $l[] = $f;
    return $l;
}
function x_gal_meta($item,$mk) {
    $l = x_item_images($item,$mk);
    return array('_n'=>count($l), '_gv'=>$l ? abs(crc32(implode('|',$l))) : 0);
}
function x_delete_image_files($name) {
    foreach (array(SCREENSHOTS_DIR,THUMBS_DIR) as $d) { $p = $d.'/'.basename($name); if (is_file($p)) @unlink($p); }
}
function x_delete_all_images($item,$mk) {
    foreach (x_item_images($item,$mk) as $f) x_delete_image_files($f);
}
function x_remove_image_at(&$item,$mk,$n) {
    $l = x_item_images($item,$mk);
    if (!isset($l[$n])) return;
    x_delete_image_files($l[$n]);
    array_splice($l,$n,1);
    $item[$mk] = $l ? array_shift($l) : null;
    $item['gallery'] = $l;
}
function x_add_images(&$item,$mk,$new,$thumbs=false) {
    foreach ($new as $f) {
        if ($thumbs) x_thumb(SCREENSHOTS_DIR.'/'.$f, THUMBS_DIR.'/'.$f, 80);
        if (empty($item[$mk])) $item[$mk] = $f;
        else { if (empty($item['gallery']) || !is_array($item['gallery'])) $item['gallery'] = array(); $item['gallery'][] = $f; }
    }
}
function x_remove_images(&$item,$mk,$ns) {
    $l = x_item_images($item,$mk); $keep = array();
    foreach ($l as $i=>$f) { if (in_array($i,$ns,true)) x_delete_image_files($f); else $keep[] = $f; }
    $item[$mk] = $keep ? array_shift($keep) : null;
    $item['gallery'] = $keep;
}
function x_set_main_image(&$item,$mk,$n) {
    $l = x_item_images($item,$mk);
    if ($n<=0 || !isset($l[$n])) return;
    $m = $l[$n]; array_splice($l,$n,1); array_unshift($l,$m);
    $item[$mk] = array_shift($l);
    $item['gallery'] = $l;
}
function x_gal_js() {
    static $d = false;
    if ($d) return '';
    $d = true;
    return '<style>.gal-wrap input[type=checkbox]{-webkit-appearance:none;appearance:none;width:14px!important;height:14px!important;min-width:14px;padding:0!important;margin:0;background:#171a23;border:1px solid #2a2e40;border-radius:3px;cursor:pointer;display:inline-grid;place-content:center;flex:none;box-shadow:none}.gal-wrap input[type=checkbox]::before{content:"";width:8px;height:8px;transform:scale(0);transition:transform .1s ease;background:#fff;clip-path:polygon(14% 44%,0 59%,39% 100%,100% 18%,84% 4%,38% 71%)}.gal-wrap input[type=checkbox]:checked{background:#b71c1c;border-color:#b71c1c}.gal-wrap input[type=checkbox]:checked::before{transform:scale(1)}.gal-wrap input[type=checkbox]:focus-visible{outline:2px solid #b71c1c;outline-offset:2px}.gal-e{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:6px}.gal-i{position:relative;width:76px}.gal-i img{width:76px;height:76px;object-fit:cover;border-radius:6px;border:1px solid var(--border);display:block}.gal-i.main img{border-color:#b71c1c;box-shadow:0 0 0 1px #b71c1c}.gal-i .gk{position:absolute;top:4px;left:4px;margin:0;z-index:2}.gal-i .gm{display:block;width:100%;margin-top:4px;padding:3px 0;font-size:10px;font-family:inherit;background:transparent;color:var(--text2);border:1px solid var(--border);border-radius:4px;cursor:pointer}.gal-i .gm:hover{border-color:#b71c1c;color:#ff5c65}.gal-i .gl{display:block;margin-top:4px;text-align:center;font-size:10px;font-weight:700;color:#ff5c65}.gal-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px;font-size:12px;color:var(--text2)}.gal-bar button{padding:5px 10px;font-size:12px;font-family:inherit;border-radius:6px;border:1px solid #b71c1c;background:transparent;color:#ff5c65;cursor:pointer}.gal-bar button:disabled{opacity:.4;cursor:default}</style><script>function galAct(b,u,m){if(m&&!confirm(m))return;var f=b.closest("form");if(!f)return;f.setAttribute("action",u);f.setAttribute("method","post");f.submit()}function galSel(b){var w=b.closest(".gal-wrap"),k=w.querySelectorAll(".gk"),c=0,i;for(i=0;i<k.length;i++)if(k[i].checked)c++;var d=w.querySelector(".gal-del");d.disabled=!c;d.textContent=c?"Seçilenleri sil ("+c+")":"Seçilenleri sil";var a=w.querySelector(".gal-all");if(a&&b===a){for(i=0;i<k.length;i++)k[i].checked=a.checked;galSel(k[0])}}</script>';
}
function x_edit_gallery($type,$item,$mk) {
    $l = x_item_images($item,$mk);
    if (!$l) return '';
    $v = abs(crc32(implode('|',$l)));
    $id = rawurlencode($item['id']);
    $h = x_gal_js().'<div class="gal-wrap"><div class="gal-bar"><label style="display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" class="gal-all" onchange="galSel(this)"> Tümünü seç</label><button type="button" class="gal-del" disabled onclick="galAct(this,\'?action=img_bulk_remove&type='.$type.'&id='.$id.'\',\'Seçili resimler silinsin mi?\')">Seçilenleri sil</button></div><div class="gal-e">';
    foreach ($l as $i=>$f) {
        $src = '?action=gimg&type='.$type.'&id='.$id.'&n='.$i.'&t=1&v='.$v;
        $h .= '<div class="gal-i'.($i===0?' main':'').'"><input type="checkbox" class="gk" name="ns[]" value="'.$i.'" onchange="galSel(this)"><img src="'.x_h($src).'" alt="">';
        if ($i===0) $h .= '<span class="gl">Ana resim</span>';
        else $h .= '<button type="button" class="gm" onclick="galAct(this,\'?action=img_main&type='.$type.'&id='.$id.'&n='.$i.'\')">Ana yap</button>';
        $h .= '</div>';
    }
    return $h.'</div></div>';
}
function x_url_input($name) {
    static $script = false;
    $h = '<textarea name="'.$name.'" class="img-url" rows="2" placeholder="veya resim URL\'leri (her satıra bir adres)" autocomplete="off" spellcheck="false" style="margin-top:6px;width:100%;box-sizing:border-box;min-height:44px;font-family:inherit;font-size:12px;background:#0c0e14;color:var(--text2);border:1px solid var(--border);border-radius:6px;padding:11px;outline:none;transition:border-color .15s,box-shadow .15s" onfocus="this.style.borderColor=\'#b71c1c\';this.style.boxShadow=\'0 0 0 2px rgba(183,28,28,.35)\'" onblur="this.style.borderColor=\'\';this.style.boxShadow=\'none\'"></textarea>';
    if (!$script) {
        $script = true;
        $h .= '<script>if(typeof fu==="undefined"){window.fu=function(i,id){var a=document.getElementById(id),n=a.querySelector(".fzn"),t=a.querySelector(".fzt");if(i.files.length){a.classList.add("has");if(n){n.textContent=i.files.length>1?i.files.length+" resim seçildi":i.files[0].name;n.style.display=""}if(t)t.style.display="none"}else{a.classList.remove("has");if(n)n.style.display="none";if(t)t.style.display=""}}}</script>';
    }
    return $h;
}
function x_video_exts() { return array('mp4','webm','ogv','ogg','mov','m4v'); }
function x_video_mime($ext) { $m=array('mp4'=>'video/mp4','m4v'=>'video/mp4','webm'=>'video/webm','ogv'=>'video/ogg','ogg'=>'video/ogg','mov'=>'video/quicktime'); return isset($m[$ext])?$m[$ext]:'application/octet-stream'; }
function x_video_embed($url) {
    if (preg_match('~^https?://(?:www\.|m\.)?(?:youtube\.com/(?:watch\?(?:[^#]*&)?v=|embed/|shorts/)|youtu\.be/)([A-Za-z0-9_-]{11})~i',$url,$m)) return 'https://www.youtube-nocookie.com/embed/'.$m[1];
    if (preg_match('~^https?://(?:www\.)?vimeo\.com/(?:video/)?(\d+)~i',$url,$m)) return 'https://player.vimeo.com/video/'.$m[1];
    return null;
}
function x_save_videos($base,$max=10) {
    $saved = array(); $k = 0;
    if (isset($_FILES['video']) && is_array($_FILES['video']['name'])) {
        foreach ($_FILES['video']['name'] as $i=>$nm) {
            $err = isset($_FILES['video']['error'][$i]) ? $_FILES['video']['error'][$i] : UPLOAD_ERR_NO_FILE;
            if ($err === UPLOAD_ERR_NO_FILE) continue;
            if ($err !== UPLOAD_ERR_OK) { $GLOBALS['x_vid_failed']=true; continue; }
            if (count($saved) >= $max) break;
            $ext = strtolower(pathinfo(basename($nm),PATHINFO_EXTENSION));
            if (!in_array($ext,x_video_exts(),true)) { $GLOBALS['x_vid_failed']=true; continue; }
            $name = $base.'_v'.(++$k).'.'.$ext;
            if (move_uploaded_file($_FILES['video']['tmp_name'][$i],VIDEOS_DIR.'/'.$name)) { @chmod(VIDEOS_DIR.'/'.$name,0644); $saved[] = array('t'=>'f','v'=>$name,'n'=>basename($nm)); }
            else $GLOBALS['x_vid_failed']=true;
        }
    }
    $raw = isset($_POST['video_url']) && is_string($_POST['video_url']) ? $_POST['video_url'] : '';
    foreach (preg_split('/[\r\n]+/',$raw) as $url) {
        $url = trim($url);
        if ($url==='') continue;
        if (count($saved) >= $max) break;
        if (!preg_match('~^https?://[^\s<>"\']+$~i',$url)) { $GLOBALS['x_vid_failed']=true; continue; }
        $em = x_video_embed($url);
        $saved[] = $em ? array('t'=>'e','v'=>$em) : array('t'=>'u','v'=>$url);
    }
    return $saved;
}
function x_item_videos($item) {
    $l = array();
    if (!empty($item['videos']) && is_array($item['videos'])) foreach ($item['videos'] as $v) if (is_array($v) && isset($v['t'],$v['v'])) $l[] = $v;
    return $l;
}
function x_delete_all_videos($item) {
    foreach (x_item_videos($item) as $v) if ($v['t']==='f') { $p=VIDEOS_DIR.'/'.basename($v['v']); if (is_file($p)) @unlink($p); }
}
function x_remove_videos(&$item,$ns) {
    $keep = array(); $mv = isset($item['main_video']) && $item['main_video']!==null ? (int)$item['main_video'] : null; $newMv = null;
    foreach (x_item_videos($item) as $i=>$v) {
        if (in_array($i,$ns,true)) { if ($v['t']==='f') { $p=VIDEOS_DIR.'/'.basename($v['v']); if (is_file($p)) @unlink($p); } }
        else { if ($mv===$i) $newMv = count($keep); $keep[] = $v; }
    }
    $item['videos'] = $keep;
    $item['main_video'] = $newMv;
}
function x_note_main_video($note) {
    $v = x_item_videos($note);
    if (!$v) return null;
    if (isset($note['main_video']) && $note['main_video']!==null && isset($v[(int)$note['main_video']])) return (int)$note['main_video'];
    return empty($note['image']) ? 0 : null;
}
function x_note_thumb($note) {
    $id = x_h($note['id']); $vids = x_item_videos($note); $mv = x_note_main_video($note);
    $nj = htmlspecialchars(json_encode($note+array('_v'=>x_img_v(isset($note['image'])?$note['image']:''))+x_gal_meta($note,'image'),JSON_UNESCAPED_UNICODE));
    if ($mv!==null) {
        $vd = $vids[$mv]; $inner = '';
        if ($vd['t']==='e') {
            if (preg_match('~/embed/([A-Za-z0-9_-]{11})~',$vd['v'],$m)) $inner = '<img src="https://i.ytimg.com/vi/'.$m[1].'/mqdefault.jpg" alt="" loading="lazy">';
        } else {
            $src = $vd['t']==='f' ? '?action=vid&id='.$id.'&n='.$mv.'&f='.rawurlencode(basename($vd['v'])) : x_h($vd['v']);
            $inner = '<video src="'.$src.'#t=0.1" preload="metadata" muted playsinline tabindex="-1"></video>';
        }
        return '<span class="thumb-vid" role="button" title="Videoyu aç" onclick="viewNote('.$nj.')">'.$inner.'<span class="play-badge">&#9654;</span></span>';
    }
    if (!empty($note['image'])) {
        $u = '?action=note_image&id='.$id.'&v='.x_img_v($note['image']);
        $h = '<span class="thumb-wrap"><img class="thumb-img" src="'.$u.'" alt="'.x_h($note['title']).'" loading="lazy" onclick="showModal(\''.$u.'\')">'.($vids?'<span class="play-badge sm">&#9654;</span>':'').'</span>';
        if (x_admin()) $h .= '<a class="img-remove" href="?action=note_remove_image&id='.$note['id'].'&tab=notes" onclick="return confirm(\'Bu resmi silmek istiyor musunuz?\')">Resmi sil</a>';
        return $h;
    }
    return '<span class="thumb-placeholder">'.svg('image',14).'</span>';
}

function x_vid_redirect_flag() { return !empty($GLOBALS['x_vid_failed']) ? '&viderr=1' : ''; }
function x_video_send($path,$ext) {
    session_write_close();
    while (ob_get_level()) ob_end_clean();
    $size = filesize($path); $start = 0; $end = $size-1;
    $mt = (int)filemtime($path); $etag = '"'.md5($path.'|'.$mt.'|'.$size).'"';
    header_remove('Pragma');
    header('Cache-Control: private, max-age=31536000, immutable');
    header('Expires: '.gmdate('D, d M Y H:i:s', time()+31536000).' GMT');
    header('Last-Modified: '.gmdate('D, d M Y H:i:s', $mt).' GMT');
    header('ETag: '.$etag);
    $inm = isset($_SERVER['HTTP_IF_NONE_MATCH']) ? trim($_SERVER['HTTP_IF_NONE_MATCH']) : '';
    $ims = isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) ? strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) : false;
    if ($inm===$etag || ($inm==='' && $ims!==false && $ims>=$mt)) { http_response_code(304); exit; }
    header('Content-Type: '.x_video_mime($ext));
    header('Accept-Ranges: bytes');
    if (isset($_SERVER['HTTP_IF_RANGE']) && trim($_SERVER['HTTP_IF_RANGE'])!==$etag && strtotime($_SERVER['HTTP_IF_RANGE'])!==$mt) { unset($_SERVER['HTTP_RANGE']); }
    if (isset($_SERVER['HTTP_RANGE']) && preg_match('/bytes=(\d*)-(\d*)/',$_SERVER['HTTP_RANGE'],$m)) {
        if ($m[1]==='' && $m[2]!=='') { $start = max(0,$size-(int)$m[2]); }
        else { if ($m[1]!=='') $start=(int)$m[1]; if ($m[2]!=='') $end=min($end,(int)$m[2]); }
        if ($start>$end || $start>=$size) { http_response_code(416); header('Content-Range: bytes */'.$size); exit; }
        http_response_code(206);
        header('Content-Range: bytes '.$start.'-'.$end.'/'.$size);
    }
    header('Content-Length: '.($end-$start+1));
    $fp = fopen($path,'rb'); fseek($fp,$start); $left = $end-$start+1;
    while ($left>0 && !feof($fp)) { $chunk = fread($fp,min(8192*8,$left)); if ($chunk===false) break; echo $chunk; $left -= strlen($chunk); flush(); if (connection_aborted()) break; }
    fclose($fp); exit;
}
function x_video_form($id) {
    $ta = 'width:100%;box-sizing:border-box;min-height:44px;font-family:inherit;font-size:12px;background:#0c0e14;color:var(--text2);border:1px solid var(--border);border-radius:6px;padding:11px;outline:none';
    return x_vid_assets().'<div class="vid-box"><button type="button" class="vid-add" onclick="vidTog(this)">'.svg('plus',12).' Video ekle</button><div class="vid-panel" style="display:none"><div class="vid-tabs"><button type="button" class="on" onclick="vidTab(this,0)">Dosya olarak yükle</button><button type="button" onclick="vidTab(this,1)">URL olarak ekle</button></div><div class="vid-pane"><div class="file-zone" id="'.$id.'"><span class="fzt">Video seçmek için tıklayın (mp4, webm, ogg, mov)</span><span class="fzn" style="display:none"></span><input type="file" name="video[]" multiple accept="video/*" onchange="fu(this,\''.$id.'\')"></div></div><div class="vid-pane" style="display:none"><textarea name="video_url" rows="2" placeholder="Video adresleri (her satıra bir adres) — mp4/webm linki, YouTube veya Vimeo" autocomplete="off" spellcheck="false" style="'.$ta.';transition:border-color .15s,box-shadow .15s" onfocus="this.style.borderColor=\'#b71c1c\';this.style.boxShadow=\'0 0 0 2px rgba(183,28,28,.35)\'" onblur="this.style.borderColor=\'\';this.style.boxShadow=\'none\'"></textarea></div></div></div>';
}
function x_upload_assets() {
    static $d = false;
    if ($d) return '';
    $d = true;
    return <<<'EOT'
<style>
#upOv{position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:1000;display:none;align-items:center;justify-content:center;padding:16px}
#upOv.on{display:flex}
.up-box{width:380px;max-width:100%;background:#111318;border:1px solid #1e2130;border-radius:10px;padding:20px;box-shadow:0 10px 40px rgba(0,0,0,.5);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.up-t{color:#d1d5e0;font-size:13px;font-weight:700;margin-bottom:12px}
.up-bar{height:10px;background:#1a1d28;border-radius:6px;overflow:hidden}
.up-fill{height:100%;width:0;background:#b71c1c;border-radius:6px;transition:width .15s linear}
.up-row{display:flex;justify-content:space-between;gap:10px;margin-top:10px;font-size:12px;color:#8b8fa3}
.up-pct{color:#fff;font-weight:800;font-size:15px}
.up-err{color:#ff5c65;margin-top:12px;font-size:12px;display:none}
.up-x{margin-top:14px;padding:7px 14px;border-radius:6px;border:1px solid #1e2130;background:transparent;color:#d1d5e0;font-size:12px;cursor:pointer;font-family:inherit}
.up-x:hover{border-color:#b71c1c;color:#ff5c65}
</style>
<div id="upOv"><div class="up-box"><div class="up-t" id="upT">Yükleniyor...</div><div class="up-bar"><div class="up-fill" id="upF"></div></div><div class="up-row"><span class="up-pct" id="upP">%0</span><span id="upI"></span></div><div class="up-err" id="upE"></div><button type="button" class="up-x" id="upX">İptal</button></div></div>
<script>
(function(){
var ov=document.getElementById('upOv'),F=document.getElementById('upF'),P=document.getElementById('upP'),I=document.getElementById('upI'),T=document.getElementById('upT'),E=document.getElementById('upE'),X=document.getElementById('upX'),xhr=null,busy=false;
function fmtS(n){n=Math.max(0,Math.round(n));if(n<60)return n+' sn';var m=Math.floor(n/60);return m+' dk '+(n%60)+' sn'}
function fmtB(b){return b>=1048576?(b/1048576).toFixed(1)+' MB':Math.max(1,Math.round(b/1024))+' KB'}
function hasFiles(f){var i=f.querySelectorAll('input[type=file]');for(var k=0;k<i.length;k++)if(i[k].files&&i[k].files.length)return true;return false}
function setP(p){p=Math.max(0,Math.min(100,p));F.style.width=p+'%';P.textContent='%'+Math.floor(p)}
function fail(msg){busy=false;E.textContent=msg;E.style.display='block';X.textContent='Kapat';T.textContent='Yükleme başarısız';I.textContent=''}
X.onclick=function(){if(xhr&&busy){xhr.abort()}busy=false;ov.classList.remove('on')};
window.addEventListener('beforeunload',function(e){if(busy){e.preventDefault();e.returnValue=''}});
document.addEventListener('submit',function(e){
    var f=e.target;
    if(e.defaultPrevented||!f||f.tagName!=='FORM'||(f.enctype||'').indexOf('multipart')<0||!hasFiles(f))return;
    e.preventDefault();
    var fd=new FormData(f),t0=Date.now();
    xhr=new XMLHttpRequest();busy=true;
    xhr.open('POST',f.getAttribute('action')||location.href);
    T.textContent='Yükleniyor...';E.style.display='none';X.textContent='İptal';setP(0);I.textContent='Başlıyor...';ov.classList.add('on');
    xhr.upload.onprogress=function(ev){
        if(!ev.lengthComputable)return;
        var p=ev.loaded/ev.total*100,el=(Date.now()-t0)/1000,sp=el>0?ev.loaded/el:0;
        setP(p);
        I.textContent=fmtB(ev.loaded)+' / '+fmtB(ev.total)+(sp>0&&ev.loaded<ev.total&&el>0.7?' · '+fmtS((ev.total-ev.loaded)/sp)+' kaldı':'');
    };
    xhr.upload.onload=function(){setP(100);T.textContent='Kaydediliyor...';I.textContent='Sunucu işliyor'};
    xhr.onload=function(){
        if(xhr.status>=200&&xhr.status<400){busy=false;setP(100);T.textContent='Tamamlandı';I.textContent='';var u=xhr.responseURL||location.href;location.href=u}
        else fail('Sunucu hata verdi ('+xhr.status+'). Dosya boyutu sınırını kontrol edin.');
    };
    xhr.onerror=function(){fail('Bağlantı hatası. Lütfen tekrar deneyin.')};
    xhr.onabort=function(){busy=false};
    xhr.send(fd);
},false);
})();
</script>
EOT;
}
function x_vid_assets() {
    static $d = false;
    if ($d) return '';
    $d = true;
    return <<<'EOT'
<style>
.vid-add{padding:8px 12px;font-size:12px;font-family:inherit;border-radius:6px;border:1px solid #b71c1c;background:transparent;color:#ff5c65;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.vid-add:hover{background:rgba(183,28,28,.12)}
.vid-panel{margin-top:8px}.vid-tabs{display:flex;gap:6px;margin-bottom:8px}
.vid-tabs button{padding:6px 10px;font-size:12px;font-family:inherit;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--text2);cursor:pointer}
.vid-tabs button.on{border-color:#b71c1c;color:#ff5c65}
.vid-row{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);margin:4px 0;word-break:break-all}
.vp{position:relative;background:#000;border-radius:8px;overflow:hidden;margin:10px 0;outline:none;user-select:none;-webkit-user-select:none;touch-action:manipulation}
.vp video{width:100%;max-height:70vh;display:block;background:#000}
.vp:fullscreen,.vp:-webkit-full-screen{border-radius:0;margin:0;width:100%;height:100%}
.vp:fullscreen video,.vp:-webkit-full-screen video{max-height:none;height:100%}
.vp-tap{position:absolute;left:0;right:0;top:0;bottom:46px;cursor:pointer}
.vp-fb{position:absolute;top:50%;transform:translateY(-50%);padding:10px 16px;border-radius:30px;background:rgba(0,0,0,.6);color:#fff;font-size:15px;font-weight:700;opacity:0;pointer-events:none;transition:opacity .15s}
.vp-fb.show{opacity:1}.vp-fb.l{left:12%}.vp-fb.r{right:12%}
.vp-big{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:54px;height:54px;border-radius:50%;background:rgba(0,0,0,.55);color:#fff;display:flex;align-items:center;justify-content:center;font-size:22px;pointer-events:none;opacity:0;transition:opacity .15s}
.vp.paused .vp-big{opacity:1}
.vp-bar{position:absolute;left:0;right:0;bottom:0;height:46px;display:flex;align-items:center;gap:8px;padding:0 10px;background:linear-gradient(transparent,rgba(0,0,0,.85));color:#fff;font-size:12px;transition:opacity .2s}
.vp.idle:not(.paused) .vp-bar{opacity:0}.vp.idle:not(.paused){cursor:none}
.vp-bar button{background:none;border:0;color:#fff;cursor:pointer;font-size:12px;font-family:inherit;padding:6px 7px;border-radius:5px;white-space:nowrap}
.vp-bar button:hover{background:rgba(255,255,255,.15)}
.vp-seek{flex:1;min-width:40px;height:4px;-webkit-appearance:none;appearance:none;background:rgba(255,255,255,.3);border-radius:3px;outline:none;cursor:pointer;padding:0;border:0}
.vp-seek::-webkit-slider-thumb{-webkit-appearance:none;width:12px;height:12px;border-radius:50%;background:#b71c1c;border:0}
.vp-seek::-moz-range-thumb{width:12px;height:12px;border-radius:50%;background:#b71c1c;border:0}
.vp-time{white-space:nowrap;font-variant-numeric:tabular-nums}
.vp-volw{display:inline-flex;align-items:center;gap:2px}
.vp-vol{width:70px;height:4px;-webkit-appearance:none;appearance:none;background:linear-gradient(to right,#b71c1c var(--p,100%),rgba(255,255,255,.3) var(--p,100%));border-radius:3px;outline:none;cursor:pointer;padding:0;border:0}
.vp-vol::-webkit-slider-thumb{-webkit-appearance:none;width:11px;height:11px;border-radius:50%;background:#fff;border:0}
.vp-vol::-moz-range-thumb{width:11px;height:11px;border-radius:50%;background:#fff;border:0}
.vp video{transform-origin:center center;will-change:transform}
.vp-tap{touch-action:pan-x pan-y}.vp-tap.zoomed{touch-action:none;cursor:grab}
.vp-gal .vp-stage{min-height:40px}
.vp-strip{display:flex;gap:6px;overflow-x:auto;padding:4px 2px 10px;margin-bottom:6px;scrollbar-width:thin;scrollbar-color:var(--border) transparent;-webkit-overflow-scrolling:touch}
.vp-th{position:relative;width:72px;height:56px;flex:0 0 auto;border-radius:6px;border:2px solid var(--border);background:#000;overflow:hidden;cursor:pointer;opacity:.65;transition:.15s;padding:0}
.vp-th:hover{opacity:1}.vp-th.on{border-color:var(--green);opacity:1}
.vp-th video,.vp-th img{width:100%;height:100%;object-fit:cover;display:block;pointer-events:none}
.vp-th .vp-ph{width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:18px}
.vp-th .play-badge{width:16px;height:16px;line-height:16px;font-size:7px}
.vp-th .vp-no{position:absolute;left:3px;top:2px;font-size:9px;font-weight:700;color:#fff;background:rgba(0,0,0,.6);border-radius:3px;padding:0 4px;line-height:14px}
.vid-row .vid-main{color:#ff5c65;font-weight:700;font-size:11px}
.vid-row .vid-mk{padding:3px 8px;font-size:11px;font-family:inherit;background:transparent;color:var(--text2);border:1px solid var(--border);border-radius:4px;cursor:pointer}
.vid-row .vid-mk:hover{border-color:#b71c1c;color:#ff5c65}
.thumb-wrap,.thumb-vid{position:relative;display:inline-block;width:36px;height:36px;vertical-align:top}
.thumb-vid{border-radius:4px;overflow:hidden;border:1px solid var(--border);background:#000;cursor:pointer}
.thumb-vid video,.thumb-vid img{width:100%;height:100%;object-fit:cover;display:block;pointer-events:none}
.play-badge{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:18px;height:18px;border-radius:50%;background:rgba(0,0,0,.65);color:#fff;font-size:8px;line-height:18px;text-align:center;pointer-events:none;padding-left:1px;box-sizing:border-box}
.play-badge.sm{left:auto;top:auto;right:-3px;bottom:-3px;transform:none;width:15px;height:15px;line-height:15px;font-size:7px;background:#b71c1c;border:1px solid #fff}
.vp-embed{width:100%;aspect-ratio:16/9;border:0;border-radius:8px;margin:10px 0;display:block;background:#000}
@media(max-width:560px){.vp-vol{width:44px}.vp-bar{gap:2px;padding:0 4px}.vp-time{font-size:10px}.vp-bar button{padding:6px 4px}}
</style>
<script>
function vidStopAll(){var v=document.querySelectorAll('.vp video');for(var i=0;i<v.length;i++)v[i].pause()}
function vidTog(b){var p=b.parentNode.querySelector('.vid-panel');p.style.display=p.style.display==='none'?'':'none'}
function vidTab(b,i){var bx=b.closest('.vid-box'),t=bx.querySelectorAll('.vid-tabs button'),p=bx.querySelectorAll('.vid-pane');for(var j=0;j<t.length;j++){t[j].classList.toggle('on',j===i);p[j].style.display=j===i?'':'none'}}
function vidFmt(t){if(!isFinite(t))t=0;t=Math.floor(t);var h=Math.floor(t/3600),m=Math.floor(t%3600/60),s=t%60;return (h?h+':'+(m<10?'0':''):'')+m+':'+(s<10?'0':'')+s}
function vpCell(note,vd,i){
    if(vd.t==='e')return '<iframe class="vp-embed" src="'+String(vd.v).replace(/"/g,'&quot;')+'" allow="accelerometer;autoplay;encrypted-media;picture-in-picture;fullscreen" allowfullscreen loading="lazy"></iframe>';
    var src=vd.t==='f'?'?action=vid&id='+encodeURIComponent(note.id)+'&n='+i+'&f='+encodeURIComponent(vd.v):String(vd.v).replace(/"/g,'&quot;');
    return '<div class="vp paused" tabindex="0"><video preload="metadata" playsinline src="'+src+'"></video><div class="vp-tap"></div><div class="vp-fb l"></div><div class="vp-fb r"></div><div class="vp-big">&#9654;</div><div class="vp-bar"><button type="button" data-a="play" title="Oynat / Duraklat">&#9654;</button><button type="button" data-a="back" title="Geri sar">&#9194; 10</button><button type="button" data-a="fwd" title="İleri sar">10 &#9193;</button><input class="vp-seek" type="range" min="0" max="1000" value="0" step="1"><span class="vp-time">0:00 / 0:00</span><button type="button" data-a="zoom" title="Yakınlaştır (iki parmakla da yapabilirsiniz)">&#128269; 1×</button><span class="vp-volw"><button type="button" data-a="mute" title="Sesi aç / kapat">&#128266;</button><input class="vp-vol" type="range" min="0" max="100" value="100" step="1" title="Ses seviyesi" aria-label="Ses seviyesi"></span><button type="button" data-a="fs" title="Tam ekran">&#9974;</button></div></div>';
}
function vpThumb(note,vd,i){
    var inner='';
    if(vd.t==='e'){
        var m=String(vd.v).match(/\/embed\/([A-Za-z0-9_-]{11})/);
        inner=m?'<img src="https://i.ytimg.com/vi/'+m[1]+'/mqdefault.jpg" alt="" loading="lazy">':'<span class="vp-ph">&#127916;</span>';
    }else{
        var src=vd.t==='f'?'?action=vid&id='+encodeURIComponent(note.id)+'&n='+i+'&f='+encodeURIComponent(vd.v):String(vd.v).replace(/"/g,'&quot;');
        inner='<video src="'+src+'#t=0.1" preload="metadata" muted playsinline tabindex="-1"></video>';
    }
    return inner+'<span class="play-badge">&#9654;</span><span class="vp-no">'+(i+1)+'</span>';
}
function vpHtml(note){
    var v=note.videos||[];if(!v.length)return '';
    var order=[],mv=(note.main_video!=null&&v[note.main_video])?+note.main_video:-1,i,k,th='';
    if(mv>=0)order.push(mv);
    for(i=0;i<v.length;i++)if(i!==mv)order.push(i);
    if(order.length<2)return vpCell(note,v[order[0]],order[0]);
    window._vpNote=note;
    for(k=0;k<order.length;k++)th+='<button type="button" class="vp-th'+(k?'':' on')+'" title="Video '+(order[k]+1)+'" onclick="vpPick(this,'+order[k]+')">'+vpThumb(note,v[order[k]],order[k])+'</button>';
    return '<div class="vp-gal"><div class="vp-stage">'+vpCell(note,v[order[0]],order[0])+'</div><div class="vp-strip">'+th+'</div></div>';
}
function vpPick(btn,i){
    var note=window._vpNote;if(!note)return;
    var g=btn.closest('.vp-gal'),st=g.querySelector('.vp-stage'),b=g.querySelectorAll('.vp-th');
    vidStopAll();
    for(var j=0;j<b.length;j++)b[j].classList.toggle('on',b[j]===btn);
    st.innerHTML=vpCell(note,note.videos[i],i);
    vpInit(st);
    var v=st.querySelector('video');
    if(v){var pr=v.play();if(pr&&pr.catch)pr.catch(function(){})}
}
function vpInit(root){
    var ps=root.querySelectorAll('.vp');
    for(var k=0;k<ps.length;k++)(function(p){
        if(p._vp)return;p._vp=1;
        var v=p.querySelector('video'),tap=p.querySelector('.vp-tap'),seek=p.querySelector('.vp-seek'),tm=p.querySelector('.vp-time'),
            fbL=p.querySelector('.vp-fb.l'),fbR=p.querySelector('.vp-fb.r'),pb=p.querySelector('[data-a=play]'),mb=p.querySelector('[data-a=mute]'),vol=p.querySelector('.vp-vol'),volw=p.querySelector('.vp-volw'),zb=p.querySelector('[data-a=zoom]'),
            st={'-1':{n:0,tot:0,t:0,h:0},'1':{n:0,tot:0,t:0,h:0}},idleT=0,drag=false,z={s:1,x:0,y:0};
        function toggle(){if(v.paused)v.play();else v.pause()}
        function jump(sec){var d=v.duration||0;var t=v.currentTime+sec;v.currentTime=Math.max(0,d?Math.min(d,t):t)}
        function fb(side,tot){var e=side<0?fbL:fbR;e.textContent=(side<0?'⏪ -':'⏩ +')+tot+' sn';e.classList.add('show');clearTimeout(e._h);e._h=setTimeout(function(){e.classList.remove('show')},650)}
        function noTap(){p._nt=Date.now()}
        function zoneTap(side,fromBtn){
            var s=st[side],now=Date.now();
            if(now-s.t>700){s.n=0;s.tot=0}
            s.t=now;s.n++;
            clearTimeout(s.h);
            if(fromBtn){s.tot+=10;jump(side*10);fb(side,s.tot);return}
            if(s.n===1){s.h=setTimeout(function(){s.n=0;toggle()},320);return}
            s.tot+=10;jump(side*10);fb(side,s.tot);
        }
        tap.addEventListener('click',function(e){
            if(Date.now()-(p._nt||0)<400)return;
            var r=tap.getBoundingClientRect(),x=(e.clientX-r.left)/r.width;
            if(x<.35)zoneTap(-1,false);else if(x>.65)zoneTap(1,false);else toggle();
            p.focus&&p.focus({preventScroll:true});
        });
        // zoom
        function apply(){
            var w=p.clientWidth,h=v.clientHeight,mx=(z.s-1)*w/2,my=(z.s-1)*h/2;
            z.x=Math.max(-mx,Math.min(mx,z.x));z.y=Math.max(-my,Math.min(my,z.y));
            v.style.transform=z.s===1?'':'translate('+z.x+'px,'+z.y+'px) scale('+z.s+')';
            tap.classList.toggle('zoomed',z.s>1);
            zb.innerHTML='&#128269; '+(Math.round(z.s*10)/10)+'×';
        }
        function setScale(s){z.s=Math.max(1,Math.min(5,s));if(z.s===1){z.x=0;z.y=0}apply()}
        zb.onclick=function(){setScale(z.s<1.5?2:(z.s<2.5?3:1))};
        function dist(e){var a=e.touches[0],b=e.touches[1];return Math.sqrt(Math.pow(a.clientX-b.clientX,2)+Math.pow(a.clientY-b.clientY,2))}
        var tp={m:0,d:1,s:1,x:0,y:0,ox:0,oy:0,mv:0};
        function one(e){tp.m=1;tp.x=e.touches[0].clientX;tp.y=e.touches[0].clientY;tp.ox=z.x;tp.oy=z.y;tp.mv=0}
        tap.addEventListener('touchstart',function(e){
            if(e.touches.length===2){tp.m=2;tp.d=dist(e)||1;tp.s=z.s;noTap();e.preventDefault()}
            else if(e.touches.length===1&&z.s>1)one(e);
        },{passive:false});
        tap.addEventListener('touchmove',function(e){
            if(tp.m===2&&e.touches.length===2){setScale(tp.s*dist(e)/tp.d);noTap();e.preventDefault()}
            else if(tp.m===1&&e.touches.length===1){
                var dx=e.touches[0].clientX-tp.x,dy=e.touches[0].clientY-tp.y;
                if(Math.abs(dx)+Math.abs(dy)>6){tp.mv=1;noTap()}
                z.x=tp.ox+dx;z.y=tp.oy+dy;apply();e.preventDefault();
            }
        },{passive:false});
        tap.addEventListener('touchend',function(e){
            if(tp.m===2){noTap();if(e.touches.length===1&&z.s>1)one(e);else tp.m=0}
            else if(!e.touches.length){if(tp.mv)noTap();tp.m=0}
        });
        tap.addEventListener('mousedown',function(e){
            if(z.s<=1||e.button!==0)return;
            var sx=e.clientX,sy=e.clientY,ox=z.x,oy=z.y,moved=false;
            function mm(ev){var dx=ev.clientX-sx,dy=ev.clientY-sy;if(Math.abs(dx)+Math.abs(dy)>4){moved=true;noTap()}z.x=ox+dx;z.y=oy+dy;apply()}
            function mu(){document.removeEventListener('mousemove',mm);document.removeEventListener('mouseup',mu);if(moved)noTap()}
            document.addEventListener('mousemove',mm);document.addEventListener('mouseup',mu);e.preventDefault();
        });
        p.addEventListener('wheel',function(e){if(!(e.ctrlKey||e.metaKey))return;e.preventDefault();setScale(z.s*(e.deltaY<0?1.15:0.87))},{passive:false});
        p.querySelector('[data-a=back]').onclick=function(){zoneTap(-1,true)};
        p.querySelector('[data-a=fwd]').onclick=function(){zoneTap(1,true)};
        pb.onclick=toggle;
        var volOk=true;
        try{var tv=v.volume;v.volume=.5;volOk=Math.abs(v.volume-.5)<.01;v.volume=tv}catch(ex){volOk=false}
        if(!volOk&&vol)vol.style.display='none';
        function vSync(){
            var l=v.muted?0:v.volume,pc=Math.round(l*100);
            if(vol){vol.value=pc;vol.style.setProperty('--p',pc+'%')}
            mb.innerHTML=l===0?'&#128263;':(l<.4?'&#128264;':(l<.7?'&#128265;':'&#128266;'));
        }
        function saveVol(){try{localStorage.setItem('vpVol',String(v.muted?0:v.volume))}catch(ex){}}
        function setVol(x){x=Math.max(0,Math.min(1,x));v.volume=x;v.muted=(x===0);saveVol();vSync()}
        function stepVol(d){setVol((v.muted?0:v.volume)+d)}
        v.addEventListener('volumechange',vSync);
        if(vol){
            vol.addEventListener('input',function(){setVol(vol.value/100)});
            vol.addEventListener('click',function(e){e.stopPropagation()});
        }
        if(volw)volw.addEventListener('wheel',function(e){e.preventDefault();stepVol(e.deltaY<0?.05:-.05)},{passive:false});
        mb.onclick=function(){
            if(v.muted||v.volume===0){v.muted=false;if(v.volume===0)v.volume=.5}else{v.muted=true}
            saveVol();vSync();
        };
        try{var sv=parseFloat(localStorage.getItem('vpVol'));if(volOk&&!isNaN(sv)){v.volume=Math.max(0,Math.min(1,sv));v.muted=(sv===0)}}catch(ex){}
        vSync();
        function fsEl(){return document.fullscreenElement||document.webkitFullscreenElement}
        function fs(){
            if(fsEl()===p){(document.exitFullscreen||document.webkitExitFullscreen).call(document);return}
            var f=p.requestFullscreen||p.webkitRequestFullscreen;
            if(f){f.call(p)}else if(v.webkitEnterFullscreen){v.webkitEnterFullscreen()}
        }
        p.querySelector('[data-a=fs]').onclick=fs;
        v.addEventListener('play',function(){p.classList.remove('paused');pb.innerHTML='&#10074;&#10074;';var o=document.querySelectorAll('.vp video');for(var q=0;q<o.length;q++)if(o[q]!==v)o[q].pause()});
        v.addEventListener('pause',function(){p.classList.add('paused');pb.innerHTML='&#9654;'});
        v.addEventListener('timeupdate',function(){if(!drag&&v.duration)seek.value=Math.round(v.currentTime/v.duration*1000);tm.textContent=vidFmt(v.currentTime)+' / '+vidFmt(v.duration)});
        v.addEventListener('loadedmetadata',function(){tm.textContent=vidFmt(0)+' / '+vidFmt(v.duration)});
        seek.addEventListener('input',function(){drag=true;if(v.duration)v.currentTime=seek.value/1000*v.duration});
        seek.addEventListener('change',function(){drag=false});
        function wake(){p.classList.remove('idle');clearTimeout(idleT);idleT=setTimeout(function(){p.classList.add('idle')},2500)}
        p.addEventListener('mousemove',wake);p.addEventListener('touchstart',wake,{passive:true});p.addEventListener('click',wake);
        p.addEventListener('keydown',function(e){
            if(e.target===seek||e.target===vol)return;
            var kk=e.key;
            if(kk===' '||kk==='k'){e.preventDefault();toggle()}
            else if(kk==='ArrowLeft'){e.preventDefault();zoneTap(-1,true)}
            else if(kk==='ArrowRight'){e.preventDefault();zoneTap(1,true)}
            else if(kk==='f'||kk==='F'){e.preventDefault();fs()}
            else if(kk==='m'||kk==='M'){mb.onclick()}
            else if(kk==='ArrowUp'){e.preventDefault();stepVol(.1)}
            else if(kk==='ArrowDown'){e.preventDefault();stepVol(-.1)}
            else if(kk==='+'||kk==='='){setScale(z.s+.5)}
            else if(kk==='-'){setScale(z.s-.5)}
        });
    })(ps[k]);
}
function vidEditHtml(note){
    var v=note.videos||[];if(!v.length)return '';
    var mv=(note.main_video!=null&&v[note.main_video])?+note.main_video:(note._n?-1:0);
    var id=encodeURIComponent(note.id);
    var h='<div class="gal-wrap" style="margin-bottom:8px"><div class="gal-bar"><label style="display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" class="gal-all" onchange="galSel(this)"> Tüm videoları seç</label><button type="button" class="gal-del" disabled onclick="galAct(this,\'?action=vid_remove&id='+id+'\',\'Seçili videolar silinsin mi?\')">Seçilenleri sil</button></div>';
    for(var i=0;i<v.length;i++){
        var nm=v[i].t==='f'?(v[i].n||v[i].v):v[i].v;
        h+='<div class="vid-row"><input type="checkbox" class="gk" name="vns[]" value="'+i+'" onchange="galSel(this)"><span style="flex:1">&#9654; Video '+(i+1)+' — '+String(nm).replace(/</g,'&lt;')+'</span>'+(i===mv?'<span class="vid-main">Ana video</span>':'<button type="button" class="vid-mk" onclick="galAct(this,\'?action=vid_main&id='+id+'&n='+i+'\')">Ana yap</button>')+'</div>';
    }
    return h+'</div>';
}
</script>
EOT;
}
function x_img_redirect_flag() { return !empty($GLOBALS['x_img_url_failed']) ? '&imgerr=1' : ''; }
function x_img_v($file) {
    $file=(string)$file; if ($file==='') return 0;
    $p=SCREENSHOTS_DIR.'/'.$file;
    return is_file($p) ? (int)filemtime($p) : 0;
}
function x_img_send($ip) {
    if (!is_file($ip)) return false;
    session_write_close();
    $mt=(int)filemtime($ip); $etag='"'.md5($ip.'|'.$mt.'|'.filesize($ip)).'"';
    while (ob_get_level()) ob_end_clean();
    header_remove('Pragma');
    header('Cache-Control: private, max-age=31536000, immutable');
    header('Expires: '.gmdate('D, d M Y H:i:s', time()+31536000).' GMT');
    header('Last-Modified: '.gmdate('D, d M Y H:i:s', $mt).' GMT');
    header('ETag: '.$etag);
    $inm=isset($_SERVER['HTTP_IF_NONE_MATCH'])?trim($_SERVER['HTTP_IF_NONE_MATCH']):'';
    $ims=isset($_SERVER['HTTP_IF_MODIFIED_SINCE'])?strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']):false;
    if ($inm===$etag || ($inm==='' && $ims!==false && $ims>=$mt)) { http_response_code(304); exit; }
    header('Content-Type: '.(mime_content_type($ip)?:'image/jpeg'));
    header('Content-Length: '.filesize($ip));
    readfile($ip); exit;
}
function svg($n,$s=16) {
    $icons=[
        'shield'=>'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'eye'=>'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
        'download'=>'<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
        'trash'=>'<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>',
        'upload'=>'<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
        'lock'=>'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>',
        'unlock'=>'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 019.9-1"/>',
        'file'=>'<path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/>',
        'calendar'=>'<rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>',
        'logout'=>'<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
        'plus'=>'<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
        'chevron-down'=>'<polyline points="6 9 12 15 18 9"/>',
        'image'=>'<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>',
        'search'=>'<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
        'edit'=>'<path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>',
        'pin'=>'<line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 00-1.11-1.79l-1.78-.9A2 2 0 0115 10.76V6h1a2 2 0 000-4H8a2 2 0 000 4h1v4.76a2 2 0 01-1.11 1.79l-1.78.9A2 2 0 005 15.24V17z"/>',
        'folder'=>'<path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>',
        'code'=>'<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
        'menu'=>'<line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/>',
        'tag'=>'<path d="M20.59 13.41l-7.17 7.17a2 2 0 01-2.83 0L2 12V2h10l8.59 8.59a2 2 0 010 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/>',
        'x'=>'<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
        'check'=>'<polyline points="20 6 9 17 4 12"/>',
        'copy'=>'<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>',
        'info'=>'<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
        'book'=>'<path d="M4 19.5A2.5 2.5 0 016.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/>',
        'link'=>'<path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>',
        'cog'=>'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z"/>',
    ];
    $p=$icons[$n]??'';
    return "<svg width=\"$s\" height=\"$s\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">$p</svg>";
}

x_init();

$route = $_GET['action'] ?? 'list';
$tab = $_GET['tab'] ?? 'dosya';

if (isset($_GET['logout'])) { session_destroy(); header('Location: '.$_SERVER['SCRIPT_NAME']); exit; }

if (!x_logged() && $_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['password'])) {
    $p=trim($_POST['password']);
    if ($p==='ex445566') $_SESSION['role']='admin';
    elseif ($p==='445566') $_SESSION['role']='visitor';
    else $login_error=true;
    if (!isset($login_error)) {
        $loginData = x_data();
        x_track($loginData, 'auth', $_SESSION['role'], 'login', $_SESSION['role']);
        x_save($loginData);
        header('Location: '.$_SERVER['SCRIPT_NAME']); exit;
    }
}
if (!x_logged()) { x_login_page(isset($login_error)); exit; }

$data = x_data();
if (!isset($data['github']) || !is_array($data['github'])) { $data['github'] = []; }
if (!isset($data['notes']) || !is_array($data['notes'])) { $data['notes'] = []; }
if (!isset($data['analytics']) || !is_array($data['analytics'])) { $data['analytics'] = []; }
$GLOBALS['x_tabs'] = x_tabs_build($data);
if (!isset($_GET['tab'])) { $tab = x_tab_first(); }
if ($route==='list') {
    if ($tab==='analytics' || $tab==='settings') $tabOk = x_admin();
    elseif ($tab==='all') $tabOk = x_tab_on('dosya') || x_tab_on('github');
    else $tabOk = x_tab_on($tab);
    if (!$tabOk) { header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab='.x_tab_first()); exit; }
}
if (x_admin() && $route==='settings_save' && $_SERVER['REQUEST_METHOD']==='POST') {
    $new = array();
    foreach (x_tab_defaults() as $k=>$d) {
        $lbl = (isset($_POST['label']) && is_array($_POST['label']) && isset($_POST['label'][$k]) && is_string($_POST['label'][$k])) ? trim($_POST['label'][$k]) : '';
        $new[$k] = array('label'=>$lbl!=='' ? mb_substr($lbl,0,30) : $d['label'], 'enabled'=>(isset($_POST['enabled']) && is_array($_POST['enabled']) && isset($_POST['enabled'][$k])));
    }
    $any = false; foreach ($new as $x) if ($x['enabled']) $any = true;
    if (!$any) { header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=settings&msg=settings_none'); exit; }
    $data['settings']['tabs'] = $new;
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=settings&msg=settings_saved'); exit;
}
if (x_admin() && $route==='analytics_reset' && $_SERVER['REQUEST_METHOD']==='POST') {
    $data['analytics'] = [];
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=analytics&msg=analytics_reset'); exit;
}
if ($route==='analytics_event' && $_SERVER['REQUEST_METHOD']==='POST') {
    x_track($data, $_POST['type']??'other', $_POST['id']??'', $_POST['event']??'view', $_POST['label']??'');
    x_save($data); header('Content-Type: application/json'); echo json_encode(['ok'=>true]); exit;
}
if (x_admin() && $route==='reorder' && $_SERVER['REQUEST_METHOD']==='POST') {
    $type=$_POST['type']??'';
    $ids=array_values(array_filter((array)($_POST['ids']??[]),'is_string'));
    header('Content-Type: application/json');
    if (!in_array($type,['dosya','github','notes'],true) || !$ids) { echo json_encode(['ok'=>false]); exit; }
    $map=array_flip($ids);
    foreach ($data[$type] as &$it) { if (isset($map[$it['id']??''])) $it['sort_order']=$map[$it['id']]; }
    unset($it);
    x_save($data);
    echo json_encode(['ok'=>true]); exit;
}
$cats = &$data['categories'];
$role = $_SESSION['role'];


if (x_admin() && $route==='cat_add' && $_SERVER['REQUEST_METHOD']==='POST') {
    $cn=trim($_POST['cat_name']??''); $cp=trim($_POST['cat_parent']??'')?:null;
    if ($cn) { $cats[]=['id'=>'cat_'.uniqid(),'name'=>$cn,'parent'=>$cp,'order'=>count($cats)+1]; x_save($data); }
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=cat_added&tab='.$tab); exit;
}

if (x_admin() && $route==='cat_edit' && $_SERVER['REQUEST_METHOD']==='POST') {
    $cid=trim($_POST['cat_id']??''); $cn=trim($_POST['cat_name']??'');
    if ($cid && $cn) {
        foreach ($cats as &$category) if (($category['id']??'')===$cid) { $category['name']=$cn; break; }
        unset($category);
        x_save($data);
    }
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=cat_edited&tab='.$tab); exit;
}

if (x_admin() && $route==='cat_delete' && isset($_GET['id'])) {
    $cid=$_GET['id'];
    foreach ($data['dosya'] as &$s) { if (($s['category_id']??null)===$cid) $s['category_id']=null; }
    $cats=array_values(array_filter($cats, fn($c)=>$c['id']!==$cid&&$c['parent']!==$cid));
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=cat_deleted&tab='.$tab); exit;
}

if (x_admin() && $route==='bulk_delete' && $_SERVER['REQUEST_METHOD']==='POST') {
    $type=$_POST['type']??'';
    $ids=array_values(array_filter((array)($_POST['ids']??[]), 'is_string'));
    if ($ids && in_array($type,['dosya','github','notes'],true)) {
        if ($type==='dosya') {
            foreach ($data['dosya'] as $s) if (in_array($s['id']??'', $ids, true)) {
                $bf=FILES_DIR.'/'.$s['stored_name']; if (file_exists($bf)) unlink($bf); x_delete_all_images($s,'screenshot');
            }
        } elseif ($type==='github') {
            foreach ($data['github'] as $g) if (in_array($g['id']??'', $ids, true)) x_delete_all_images($g,'image');
        } else {
            foreach ($data['notes'] as $n) if (in_array($n['id']??'', $ids, true)) { x_delete_all_images($n,'image'); x_delete_all_videos($n); }
        }
        $data[$type]=array_values(array_filter($data[$type], fn($item)=>!in_array($item['id']??'', $ids, true)));
        x_save($data);
    }
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=bulk_deleted&tab='.($type==='dosya'?'dosya':($type==='github'?'github':'notes'))); exit;
}

if (x_admin() && $route==='delete' && isset($_GET['id'])) {
    foreach ($data['dosya'] as $i=>$s) {
        if ($s['id']===$_GET['id']) {
            $sf=FILES_DIR.'/'.$s['stored_name']; $ss=$s['screenshot']?SCREENSHOTS_DIR.'/'.$s['screenshot']:null;
            $th=$s['screenshot']?THUMBS_DIR.'/'.$s['screenshot']:null;
            if (file_exists($sf)) unlink($sf); x_delete_all_images($s,'screenshot');
            array_splice($data['dosya'],$i,1); x_save($data); break;
        }
    }
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=deleted&tab='.$tab); exit;
}

if (x_admin() && $route==='pin' && isset($_GET['id'])) {
    foreach ($data['dosya'] as &$s) { if ($s['id']===$_GET['id']) { $s['pinned']=!($s['pinned']??false); $s['pinned_at']=$s['pinned']?date('Y-m-d H:i:s'):null; break; } }
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab='.$tab); exit;
}

if (x_admin() && $route==='upload' && $_SERVER['REQUEST_METHOD']==='POST') {
    $name=trim($_POST['name']??'')?:'İsimsiz Dosya'; $desc=trim($_POST['description']??'');
    $hasPass=isset($_POST['has_password']); $catId=$_POST['category_id']??null; $phpVer=x_php_post();
    $sid=uniqid('sh_',true); $stored=null; $orig=null; $ssStored=null;
    if (isset($_FILES['dosya_arsiv'])&&$_FILES['dosya_arsiv']['error']===UPLOAD_ERR_OK) {
        $orig=basename($_FILES['dosya_arsiv']['name']);
        $ext=pathinfo($orig,PATHINFO_EXTENSION);
        $stored=$sid.'.'.($ext?:'txt');
        move_uploaded_file($_FILES['dosya_arsiv']['tmp_name'],FILES_DIR.'/'.$stored);
    }
    $newImgs=x_save_images('screenshot','screenshot_url',SCREENSHOTS_DIR,$sid);
    $ssStored=$newImgs?array_shift($newImgs):null; $gallery=$newImgs;
    foreach (array_merge($ssStored?array($ssStored):array(),$gallery) as $_f) x_thumb(SCREENSHOTS_DIR.'/'.$_f, THUMBS_DIR.'/'.$_f, 80);
    if ($stored) {
        $data['dosya'][]=['id'=>$sid,'name'=>$name,'description'=>$desc,'has_password'=>$hasPass,'show_code'=>isset($_POST['show_code']),'category_id'=>$catId,'php_version'=>$phpVer,'original_name'=>$orig,'stored_name'=>$stored,'screenshot'=>$ssStored,'gallery'=>$gallery,'date_added'=>date('Y-m-d H:i:s'),'pinned'=>false];
        x_save($data);
    }
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=uploaded&tab=dosya'.x_img_redirect_flag()); exit;
}

if (x_admin() && $route==='create' && $_SERVER['REQUEST_METHOD']==='POST') {
    $name=trim($_POST['name']??'')?:'Yeni Dosya'; $desc=trim($_POST['description']??'');
    $hasPass=isset($_POST['has_password']); $catId=$_POST['category_id']??null; $phpVer=x_php_post();
    $fname=trim($_POST['filename']??'')?:'dosya.php'; $content=$_POST['content']??'';
    $sid=uniqid('sh_',true); $ext=pathinfo($fname,PATHINFO_EXTENSION);
    $stored=$sid.'.'.($ext?:'txt');
    file_put_contents(FILES_DIR.'/'.$stored,$content);
    $ssStored=null;
    $newImgs=x_save_images('screenshot','screenshot_url',SCREENSHOTS_DIR,$sid);
    $ssStored=$newImgs?array_shift($newImgs):null; $gallery=$newImgs;
    foreach (array_merge($ssStored?array($ssStored):array(),$gallery) as $_f) x_thumb(SCREENSHOTS_DIR.'/'.$_f, THUMBS_DIR.'/'.$_f, 80);
    $data['dosya'][]=['id'=>$sid,'name'=>$name,'description'=>$desc,'has_password'=>$hasPass,'show_code'=>isset($_POST['show_code']),'category_id'=>$catId,'php_version'=>$phpVer,'original_name'=>$fname,'stored_name'=>$stored,'screenshot'=>$ssStored,'gallery'=>$gallery,'date_added'=>date('Y-m-d H:i:s'),'pinned'=>false];
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=created&tab=dosya'.x_img_redirect_flag()); exit;
}

if (x_admin() && $route==='edit' && isset($_GET['id'])) {
    $dosya=null;
    foreach ($data['dosya'] as $i=>$s) { if ($s['id']===$_GET['id']) { $dosya=&$data['dosya'][$i]; break; } }
    if (!$dosya) { header('Location: '.$_SERVER['SCRIPT_NAME']); exit; }
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        $dosya['name']=trim($_POST['name']??'')?:$dosya['name'];
        $dosya['description']=trim($_POST['description']??'');
$dosya['has_password']=isset($_POST['has_password']);
        $dosya['show_code']=isset($_POST['show_code']);
        $dosya['category_id']=$_POST['category_id']??$dosya['category_id'];
        $dosya['php_version']=x_php_post();
        if (isset($_FILES['dosya_arsiv'])&&$_FILES['dosya_arsiv']['error']===UPLOAD_ERR_OK) {
            $newOriginal=basename($_FILES['dosya_arsiv']['name']);
            $newExt=pathinfo($newOriginal,PATHINFO_EXTENSION);
            $newStored=$dosya['id'].'_'.time().($newExt?'.'.$newExt:'');
            if (move_uploaded_file($_FILES['dosya_arsiv']['tmp_name'],FILES_DIR.'/'.$newStored)) {
                $oldFile=FILES_DIR.'/'.$dosya['stored_name']; if (file_exists($oldFile)) unlink($oldFile);
                $dosya['stored_name']=$newStored; $dosya['original_name']=$newOriginal;
            }
        } elseif (isset($_POST['content'])) file_put_contents(FILES_DIR.'/'.$dosya['stored_name'],$_POST['content']);
        x_add_images($dosya,'screenshot',x_save_images('screenshot','screenshot_url',SCREENSHOTS_DIR,$dosya['id'].'_'.uniqid()),true);
        x_save($data);
        header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=edited&tab=dosya'.x_img_redirect_flag()); exit;
    }
    x_edit_page($dosya,$cats); exit;
}

if (x_admin() && $route==='github_add' && $_SERVER['REQUEST_METHOD']==='POST') {
    $url=trim($_POST['url']??'');
    $host = parse_url($url, PHP_URL_HOST);
    $isGithubRaw = $host && (strcasecmp($host, 'raw.githubusercontent.com') === 0 || preg_match('/(^|\.)github\.com$/i', $host));
    if (filter_var($url,FILTER_VALIDATE_URL) && $isGithubRaw) {
        $gid=uniqid('gh_');
        $newImgs=x_save_images('image','image_url',SCREENSHOTS_DIR,$gid);
        $image=$newImgs?array_shift($newImgs):null; $gallery=$newImgs;
        $data['github'][]=array('id'=>$gid,'name'=>trim($_POST['name']??'')?:'İsimsiz GitHub','description'=>trim($_POST['description']??''),'url'=>$url,'image'=>$image,'gallery'=>$gallery,'category_id'=>trim($_POST['category_id']??'')?:null,'php_version'=>x_php_post(),'encrypted'=>($_POST['encrypted']??'')==='1','show_code'=>isset($_POST['show_code']),'date_added'=>date('Y-m-d H:i:s'),'pinned'=>false);
        x_save($data);
    }
    $status = isset($gid) ? 'github_added' : 'github_invalid';
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg='.$status.'&tab=github'.x_img_redirect_flag()); exit;
}
if (x_admin() && $route==='github_delete' && isset($_GET['id'])) {
    foreach ($data['github'] as $i=>$g) if ($g['id']===$_GET['id']) { x_delete_all_images($g,'image'); array_splice($data['github'],$i,1); x_save($data); break; }
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=github_deleted&tab=github'); exit;
}
if (x_admin() && $route==='github_pin' && isset($_GET['id'])) {
    foreach ($data['github'] as &$g) if ($g['id']===$_GET['id']) { $g['pinned']=!($g['pinned']??false); $g['pinned_at']=$g['pinned']?date('Y-m-d H:i:s'):null; break; }
    x_save($data); header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=github'); exit;
}
if (x_admin() && $route==='github_edit' && isset($_GET['id'])) {
    foreach ($data['github'] as &$g) if ($g['id']===$_GET['id']) {
        if ($_SERVER['REQUEST_METHOD']==='POST') {
            $g['name']=trim($_POST['name']??'')?:$g['name'];
$g['description']=trim($_POST['description']??'');
  $g['category_id']=trim($_POST['category_id']??'')?:null;
  $g['php_version']=x_php_post();
$g['encrypted']=($_POST['encrypted']??'')==='1';
  $g['show_code']=isset($_POST['show_code']);
  $newUrl=trim($_POST['url']??$g['url']);
            $newHost=parse_url($newUrl, PHP_URL_HOST);
            if (filter_var($newUrl,FILTER_VALIDATE_URL) && $newHost && (strcasecmp($newHost,'raw.githubusercontent.com')===0 || preg_match('/(^|\.)github\.com$/i',$newHost))) $g['url']=$newUrl;
            x_add_images($g,'image',x_save_images('image','image_url',SCREENSHOTS_DIR,$g['id'].'_'.uniqid()),false);
            x_save($data); header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=github_edited&tab=github'.x_img_redirect_flag()); exit;
        }
        $github_edit=$g; break;
    }
    if (isset($github_edit)) { x_github_edit_page($github_edit,$cats); exit; }
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=github'); exit;
}

if (x_admin() && in_array($route,array('img_bulk_remove','img_main'),true) && isset($_GET['id'],$_GET['type']) && is_string($_GET['id']) && is_string($_GET['type'])) {
    $cfg=array('dosya'=>array('dosya','screenshot'),'github'=>array('github','image'),'note'=>array('notes','image'));
    $t=$_GET['type'];
    if (isset($cfg[$t])) {
        foreach ($data[$cfg[$t][0]] as &$it) if ($it['id']===$_GET['id']) {
            if ($route==='img_main') { if ($t==='note') $it['main_video']=null; x_set_main_image($it,$cfg[$t][1],(int)(isset($_GET['n'])?$_GET['n']:0)); }
            else x_remove_images($it,$cfg[$t][1],array_map('intval',(array)(isset($_POST['ns'])?$_POST['ns']:array())));
            break;
        }
        unset($it);
        x_save($data);
        if ($t==='dosya') $back='?action=edit&id='.rawurlencode($_GET['id']);
        elseif ($t==='github') $back='?action=github_edit&id='.rawurlencode($_GET['id']).'&tab=github';
        else $back='?tab=notes';
        header('Location: '.$_SERVER['SCRIPT_NAME'].$back); exit;
    }
}
if (x_admin() && $route==='img_remove' && isset($_GET['id'],$_GET['type'],$_GET['n']) && is_string($_GET['id']) && is_string($_GET['type'])) {
    $cfg=array('dosya'=>array('dosya','screenshot'),'github'=>array('github','image'),'note'=>array('notes','image'));
    $t=$_GET['type'];
    if (isset($cfg[$t])) {
        foreach ($data[$cfg[$t][0]] as &$it) if ($it['id']===$_GET['id']) { x_remove_image_at($it,$cfg[$t][1],(int)$_GET['n']); break; }
        unset($it);
        x_save($data);
        if ($t==='dosya') $back='?action=edit&id='.rawurlencode($_GET['id']);
        elseif ($t==='github') $back='?action=github_edit&id='.rawurlencode($_GET['id']).'&tab=github';
        else $back='?tab=notes';
        header('Location: '.$_SERVER['SCRIPT_NAME'].$back); exit;
    }
}
if (x_admin() && $route==='note_remove_image' && isset($_GET['id'])) {
    foreach ($data['notes'] as &$n) if ($n['id']===$_GET['id']) {
        x_remove_image_at($n,'image',0);
        break;
    }
    x_save($data); header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=notes'); exit;
}
if (x_admin() && $route==='remove_screenshot' && isset($_GET['id'])) {
    foreach ($data['dosya'] as &$s) if ($s['id']===$_GET['id']) {
        x_remove_image_at($s,'screenshot',0);
        break;
    }
    x_save($data); header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=dosya'); exit;
}
if (x_admin() && $route==='github_remove_image' && isset($_GET['id'])) {
    foreach ($data['github'] as &$g) if ($g['id']===$_GET['id']) {
        x_remove_image_at($g,'image',0);
        break;
    }
    x_save($data); header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=github'); exit;
}



if (x_admin() && $route==='note_add' && $_SERVER['REQUEST_METHOD']==='POST') {
    $title=trim($_POST['title']??'')?:'Not';
    $content=trim($_POST['content']??'');
    $nid=uniqid('note_');
    $newImgs=x_save_images('image','image_url',SCREENSHOTS_DIR,$nid);
    $noteImage=$newImgs?array_shift($newImgs):null; $noteGallery=$newImgs;
    $data['notes'][]=['id'=>$nid,'title'=>$title,'content'=>$content,'image'=>$noteImage,'gallery'=>$noteGallery,'videos'=>x_save_videos($nid),'files'=>x_save_note_files(),'date_added'=>date('Y-m-d H:i:s'),'pinned'=>false];
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=note_added&tab=notes'.x_img_redirect_flag().x_vid_redirect_flag()); exit;
}

if (x_admin() && $route==='note_edit' && isset($_GET['id'])) {
    foreach ($data['notes'] as &$n) {
        if ($n['id']===$_GET['id']) {
            $n['title']=trim($_POST['title']??'')?:$n['title'];
            $n['content']=trim($_POST['content']??'');
            x_add_images($n,'image',x_save_images('image','image_url',SCREENSHOTS_DIR,$n['id'].'_'.uniqid()),false);
            $nv=x_item_videos($n); foreach (x_save_videos($n['id'].'_'.uniqid()) as $vv) $nv[]=$vv; $n['videos']=$nv;
            $nfl=x_item_files($n); foreach (x_save_note_files() as $ff) $nfl[]=$ff; $n['files']=$nfl;
            break;
        }
    }
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=note_edited&tab=notes'.x_img_redirect_flag().x_vid_redirect_flag()); exit;
}

if (x_admin() && $route==='note_pin' && isset($_GET['id'])) {
    foreach ($data['notes'] as &$n) { if ($n['id']===$_GET['id']) { $n['pinned']=!($n['pinned']??false); $n['pinned_at']=$n['pinned']?date('Y-m-d H:i:s'):null; break; } }
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=notes'); exit;
}

if (x_admin() && $route==='note_delete' && isset($_GET['id'])) {
    foreach ($data['notes'] as $i=>$n) { if ($n['id']===$_GET['id']) { x_delete_all_images($n,'image'); x_delete_all_videos($n); x_delete_note_files($n); array_splice($data['notes'],$i,1); x_save($data); break; } }
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?msg=note_deleted&tab=notes'); exit;
}

if (x_admin() && $route==='nfile_remove' && isset($_GET['id']) && is_string($_GET['id'])) {
    foreach ($data['notes'] as &$it) if ($it['id']===$_GET['id']) {
        x_remove_note_files($it,array_map('intval',(array)(isset($_POST['fns'])?$_POST['fns']:array())));
        break;
    }
    unset($it);
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=notes'); exit;
}
if ($route==='nfile' && isset($_GET['id'],$_GET['n']) && is_string($_GET['id'])) {
    if (!x_admin() && !x_tab_on('notes')) { header('Location: '.$_SERVER['SCRIPT_NAME']); exit; }
    foreach ($data['notes'] as $it) if ($it['id']===$_GET['id']) {
        $fl = x_item_files($it); $fn = (int)$_GET['n'];
        if (isset($fl[$fn])) {
            $fp = BFILES_DIR.'/'.basename($fl[$fn]['stored_name']);
            if (is_file($fp)) {
                x_track($data,'nfile',$it['id'],'download',$fl[$fn]['name']); x_save($data);
                while (ob_get_level()) ob_end_clean();
                $fallback = preg_replace('/[^\x20-\x7E]/','_',str_replace(array('"','\\'),'_',$fl[$fn]['name']));
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="'.$fallback.'"; filename*=UTF-8\'\''.rawurlencode($fl[$fn]['name']));
                header('Content-Length: '.filesize($fp));
                header('X-Content-Type-Options: nosniff');
                readfile($fp); exit;
            }
        }
        break;
    }
    header('HTTP/1.0 404'); exit;
}
if (!x_admin() && in_array($route,array('download','preview','archive_content'),true) && !x_tab_on('dosya')) { header('Location: '.$_SERVER['SCRIPT_NAME']); exit; }

if ($route==='download' && isset($_GET['id'])) {
    foreach ($data['dosya'] as $s) {
        if ($s['id']===$_GET['id']) {
            $fp=FILES_DIR.'/'.$s['stored_name'];
            if (file_exists($fp)) {
                x_track($data, 'dosya', $s['id'], 'download', $s['name']??''); x_save($data);
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="'.basename($s['stored_name']).'"');
                header('Content-Length: '.filesize($fp));
                readfile($fp); exit;
            }
        }
    }
    header('Location: '.$_SERVER['SCRIPT_NAME']); exit;
}

if ($route==='archive_content' && isset($_GET['id'])) {
    foreach ($data['dosya'] as $s) {
        if ($s['id']===$_GET['id']) {
            $fp=FILES_DIR.'/'.$s['stored_name'];
            x_track($data, 'dosya', $s['id'], 'read', $s['name']??''); x_save($data);
            header('Content-Type: text/plain; charset=UTF-8');
            echo file_exists($fp)?file_get_contents($fp):'Dosya bulunamadı.';
            exit;
        }
    }
    header('HTTP/1.0 404'); exit;
}

if ($route==='preview' && isset($_GET['id'])) {
    foreach ($data['dosya'] as $s) { if ($s['id']===$_GET['id']) { $dosya=$s; break; } }
    if (isset($dosya)) {
        $fp=FILES_DIR.'/'.$dosya['stored_name'];
        $content=file_exists($fp)?file_get_contents($fp):'Dosya bulunamadı.';
        x_preview_page($dosya,$content,$cats); exit;
    }
    header('Location: '.$_SERVER['SCRIPT_NAME']); exit;
}

if ($route==='github_image' && isset($_GET['id'])) {
    foreach ($data['github'] as $g) {
        if ($g['id']===$_GET['id'] && !empty($g['image'])) {
            $ip=SCREENSHOTS_DIR.'/'.$g['image'];
            if (file_exists($ip)) { x_img_send($ip); }
        }
    }
    header('HTTP/1.0 404'); exit;
}

  if ($route==='note_image' && isset($_GET['id'])) {
  foreach ($data['notes'] as $n) if ($n['id']===$_GET['id'] && !empty($n['image'])) { $ip=SCREENSHOTS_DIR.'/'.$n['image']; if (file_exists($ip)) { x_img_send($ip); } }
  header('HTTP/1.0 404'); exit;
  }

  if ($route==='screenshot' && isset($_GET['id'])) {
    foreach ($data['dosya'] as $s) {
        if ($s['id']===$_GET['id']&&$s['screenshot']) { $sp=SCREENSHOTS_DIR.'/'.$s['screenshot']; if (file_exists($sp)) { x_img_send($sp); } }
    }
    header('HTTP/1.0 404'); exit;
}
if ($route==='vid' && isset($_GET['id'],$_GET['n']) && is_string($_GET['id'])) {
    foreach ($data['notes'] as $it) if ($it['id']===$_GET['id']) {
        $vl=x_item_videos($it); $vn=(int)$_GET['n'];
        if (isset($vl[$vn]) && $vl[$vn]['t']==='f') {
            $vp=VIDEOS_DIR.'/'.basename($vl[$vn]['v']);
            if (is_file($vp)) x_video_send($vp,strtolower(pathinfo($vp,PATHINFO_EXTENSION)));
        }
        break;
    }
    header('HTTP/1.0 404'); exit;
}
if (x_admin() && $route==='vid_main' && isset($_GET['id'],$_GET['n']) && is_string($_GET['id'])) {
    foreach ($data['notes'] as &$it) if ($it['id']===$_GET['id']) {
        $vn=(int)$_GET['n'];
        if (isset(x_item_videos($it)[$vn])) $it['main_video']=$vn;
        break;
    }
    unset($it);
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=notes'); exit;
}
if (x_admin() && $route==='vid_remove' && isset($_GET['id']) && is_string($_GET['id'])) {
    foreach ($data['notes'] as &$it) if ($it['id']===$_GET['id']) {
        x_remove_videos($it,array_map('intval',(array)(isset($_POST['vns'])?$_POST['vns']:array())));
        break;
    }
    unset($it);
    x_save($data);
    header('Location: '.$_SERVER['SCRIPT_NAME'].'?tab=notes'); exit;
}
if ($route==='gimg' && isset($_GET['id'],$_GET['type']) && is_string($_GET['id']) && is_string($_GET['type'])) {
    $cfg=array('dosya'=>array('dosya','screenshot'),'github'=>array('github','image'),'note'=>array('notes','image'));
    $t=$_GET['type'];
    if (isset($cfg[$t])) {
        foreach ($data[$cfg[$t][0]] as $it) if ($it['id']===$_GET['id']) {
            $l=x_item_images($it,$cfg[$t][1]); $n=(int)($_GET['n']??0);
            if (isset($l[$n])) {
                $sp=SCREENSHOTS_DIR.'/'.basename($l[$n]);
                if (!empty($_GET['t'])) {
                    $tp=THUMBS_DIR.'/'.basename($l[$n]);
                    if (is_file($tp)) x_img_send($tp);
                    if (is_file($sp) && x_thumb($sp,$tp,80)) x_img_send($tp);
                }
                if (is_file($sp)) x_img_send($sp);
            }
        }
    }
    header('HTTP/1.0 404'); exit;
}
if ($route==='thumb' && isset($_GET['id'])) {
    foreach ($data['dosya'] as $s) {
        if ($s['id']===$_GET['id']&&$s['screenshot']) {
            $tp=THUMBS_DIR.'/'.$s['screenshot'];
            if (file_exists($tp)) { x_img_send($tp); }
            $sp=SCREENSHOTS_DIR.'/'.$s['screenshot'];
            if (file_exists($sp)&&x_thumb($sp,$tp,80)) { x_img_send($tp); }
            x_img_send($sp); exit;
        }
    }
    header('HTTP/1.0 404'); exit;
}

$filterCat = ($tab==='dosya' || $tab==='github') ? '__all__' : ($_GET['cat'] ?? '__all__');
$msg = $_GET['msg'] ?? '';

$dosya = $data['dosya'];
usort($dosya, 'x_sort_cmp');
if ($filterCat!=='__all__') $dosya=array_values(array_filter($dosya,fn($s)=>x_cat_matches($s,$filterCat)));

$notes = $data['notes'];
usort($notes, 'x_sort_cmp');

$github = $data['github'];
usort($github, 'x_sort_cmp');
if ($filterCat!=='__all__') $github=array_values(array_filter($github,fn($g)=>x_cat_matches($g,$filterCat)));
$canSort = x_admin() && in_array($tab,['dosya','github','notes'],true);

  $catTree = x_cat_tree($cats);
  $activeCat = $filterCat;
$categoryHasdosya = $activeCat !== '__all__' && count(array_filter($data['dosya'], fn($s)=>x_cat_matches($s,$activeCat))) > 0;
  $categoryHasGithub = $activeCat !== '__all__' && count(array_filter($data['github'], fn($g)=>x_cat_matches($g,$activeCat))) > 0;
  $archiveTopActive = $tab === 'dosya' || $tab === 'all' && ($activeCat === '__all__' ? count($data['dosya']) > 0 : $categoryHasdosya);
  $githubTopActive = $tab === 'github' || $tab === 'all' && ($activeCat === '__all__' ? count($data['github']) > 0 : $categoryHasGithub);
  
  $toast='';
if (in_array($msg,['uploaded','created'])) $toast='Dosya eklendi';
elseif ($msg==='deleted') $toast='Dosya silindi';
elseif ($msg==='edited') $toast='Dosya güncellendi';
elseif ($msg==='cat_added') $toast='Kategori eklendi';
elseif ($msg==='cat_edited') $toast='Kategori adı güncellendi';
elseif ($msg==='cat_deleted') $toast='Kategori silindi';
elseif ($msg==='note_added') $toast='Not eklendi';
elseif ($msg==='note_edited') $toast='Not güncellendi';
elseif ($msg==='note_deleted') $toast='Not silindi';
elseif ($msg==='github_added') $toast='GitHub bağlantısı eklendi';
elseif ($msg==='settings_saved') $toast='Ayarlar kaydedildi';
elseif ($msg==='settings_none') $toast='En az bir sekme açık kalmalı';

 elseif ($msg==='github_invalid') $toast='Geçerli bir raw.githubusercontent.com bağlantısı girin';
 elseif ($msg==='github_edited') $toast='GitHub bağlantısı güncellendi';
elseif ($msg==='github_deleted') $toast='GitHub bağlantısı silindi';
	elseif ($msg==='bulk_deleted') $toast='Seçilen kayıtlar silindi';
if (!empty($_GET['viderr'])) $toast=($toast?$toast.' — ':'').'Video eklenemedi (desteklenmeyen biçim, geçersiz adres veya sunucu yükleme sınırı aşıldı)';
if (!empty($_GET['imgerr'])) $toast=($toast?$toast.' — ':'').'Resim URL\'sinden indirilemedi (geçersiz adres, geçersiz resim veya 10MB üzeri)';
	ob_clean();
	?>
	<!DOCTYPE html>
<html lang="tr"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title><?=APP_NAME?> — <?=$role==='admin'?'Yönetici':'Ziyaretçi'?></title>
<style>
:root {
    --bg:#0a0b0f; --surface:#111318; --surface2:#16181f; --border:#1e2130;
    --border2:#242836; --text:#8b8fa3; --text2:#d1d5e0; --text3:#555a6e;
    --green:#b71c1c; --green-bg:#b71c1c12; --green-glow:#b71c1c30;
    --red:#8f111c; --red-bg:#8f111c24; --blue:#448aff; --blue-bg:#448aff12;
    --amber:#ffab00; --amber-bg:#ffab0012;
    --r:8px; --r-sm:6px;
    --font:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    --mono:'JetBrains Mono','Fira Code','Consolas',monospace;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.5}
a{color:inherit;text-decoration:none}
.layout{display:flex;min-height:100vh}

.sb{width:220px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;height:100dvh;flex-shrink:0;z-index:20}
.sb-brand{padding:16px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
.sb-brand svg{color:var(--green);flex-shrink:0}
.sb-brand .t{font-size:16px;font-weight:800;color:var(--text2);letter-spacing:-.4px}
.sb-brand .t b{color:var(--green)}
.sb-nav{flex:1;min-height:0;overflow-y:auto;padding:8px 8px}
.sb-nav .sec{font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1.2px;padding:10px 10px 5px;font-weight:600}
.sb-nav .it{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:var(--r-sm);font-size:12px;font-weight:500;transition:all .1s;margin-bottom:1px;color:var(--text)}
.sb-nav .it:hover{background:var(--surface2);color:var(--text2)}
.sb-nav .it.act{background:var(--green-bg);color:var(--green)}
.sb-nav .it .n{margin-left:auto;font-size:9px;padding:1px 6px;border-radius:7px;background:var(--border);color:var(--text3);font-weight:600}
.sb-nav .sub{padding-left:16px}
.sb-nav .sub .it{font-size:11px}
.sb-footer{padding:10px;border-top:1px solid var(--border);flex-shrink:0}
.sb-user{display:flex;align-items:center;gap:7px;padding:7px 9px;border-radius:var(--r-sm);background:var(--surface2)}
.sb-user .av{width:26px;height:26px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:10px;flex-shrink:0}
.av-a{background:var(--red-bg);color:var(--red)}.av-z{background:var(--green-bg);color:var(--green)}
.sb-user .um{font-size:10px;line-height:1.3}
.sb-user .um .rn{color:var(--text2);font-weight:600}
.sb-user .um .rl{color:var(--text3);font-size:9px;text-transform:uppercase;letter-spacing:.5px}
.btn-logout{display:flex;align-items:center;gap:6px;width:100%;padding:7px 10px;margin-top:7px;background:transparent;border:1px solid var(--border);border-radius:var(--r-sm);color:var(--text);font-size:10px;cursor:pointer;font-family:var(--font);justify-content:center;transition:.1s}
.btn-logout:hover{border-color:var(--red);color:var(--red)}

.main{flex:1;display:flex;flex-direction:column;min-width:0;overflow:hidden}
.main-top{padding:12px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;justify-content:space-between;flex-wrap:wrap}
.main-top h1{font-size:15px;font-weight:700;color:var(--text2)}
.main-top .cr{font-size:10px;color:var(--text3)}
.top-r{display:flex;align-items:center;gap:8px}
.search-w{position:relative}
.search-w input{padding:7px 10px 7px 30px;background:#0c0e14;border:1px solid var(--border);border-radius:var(--r-sm);color:var(--text2);font-size:11px;outline:none;width:180px;font-family:var(--font);transition:.15s}
.search-w input:focus{border-color:var(--green);box-shadow:0 0 0 3px var(--green-glow);width:210px}
.search-w input::placeholder{color:var(--text3)}
.search-w .si{position:absolute;left:9px;top:50%;transform:translateY(-50%);color:var(--text3);pointer-events:none}
.btn-mob{display:none;align-items:center;gap:5px;padding:6px 10px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-sm);color:var(--text2);cursor:pointer;font-family:var(--font);font-size:11px}

.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);padding:0 18px}
.tabs a{padding:10px 16px;font-size:12px;font-weight:600;color:var(--text3);border-bottom:2px solid transparent;transition:.12s}
.tabs a:hover{color:var(--text2)}
.tabs a.act{color:var(--green);border-bottom-color:var(--green)}

.main-body{padding:14px 18px;flex:1;overflow-x:auto}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:7px 14px;border-radius:var(--r-sm);font-size:11.5px;font-weight:600;cursor:pointer;border:none;font-family:var(--font);transition:.12s;text-decoration:none;white-space:nowrap}
.btn-g{background:var(--green);color:#fff}.btn-g:hover{filter:brightness(1.1);box-shadow:0 3px 12px var(--green-glow)}
.btn-o{background:transparent;border:1px solid var(--border);color:var(--text2)}.btn-o:hover{border-color:var(--green);color:var(--green)}
.btn-ob{background:transparent;border:1px solid var(--border);color:var(--blue)}.btn-ob:hover{border-color:var(--blue);background:var(--blue-bg)}
  .btn-or{background:var(--red);border:1px solid var(--red);color:#fff}.btn-or:hover{border-color:var(--red);background:#a91422;filter:brightness(1.08)}
  input[type="checkbox"]{appearance:none;-webkit-appearance:none;width:14px;height:14px;margin:0;background:var(--surface2);border:1px solid var(--border);border-radius:3px;cursor:pointer;display:inline-grid;place-content:center;flex:none}input[type="checkbox"]::before{content:"";width:8px;height:8px;transform:scale(0);transition:transform .1s ease;background:#fff;clip-path:polygon(14% 44%,0 59%,39% 100%,100% 18%,84% 4%,38% 71%)}input[type="checkbox"]:checked{background:var(--red);border-color:var(--red)}input[type="checkbox"]:checked::before{transform:scale(1)}input[type="checkbox"]:focus-visible{outline:2px solid var(--red);outline-offset:2px}
  .btn-xs{font-size:10px;padding:3px 8px}
.btn-sm{font-size:10px;padding:5px 10px}

.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);margin-bottom:12px;overflow:hidden}
.panel-toggle{display:flex;align-items:center;gap:7px;width:100%;padding:11px 14px;background:transparent;border:none;color:#fff;font-size:12px;font-weight:600;cursor:pointer;font-family:var(--font)}
.panel-toggle:hover{background:var(--surface2)}
.panel-toggle .ar{color:var(--text3);margin-left:auto;transition:transform .2s}
.panel-toggle.open .ar{transform:rotate(180deg)}
.panel-body{display:none;padding:0 14px 14px}
.panel-body.open{display:block}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.form-grid .fw{grid-column:1/-1}
.fg{display:flex;flex-direction:column;gap:4px}
.fg label{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;font-weight:600}
.fg input[type=text],.fg input[type=url],.fg textarea,.fg select{padding:8px 10px;background:#0c0e14;border:1px solid var(--border);border-radius:var(--r-sm);color:var(--text2);font-size:12px;outline:none;font-family:var(--font);transition:.15s;resize:vertical}
.fg input:focus,.fg textarea:focus,.fg select:focus{border-color:var(--green);box-shadow:0 0 0 3px var(--green-glow)}
.fg textarea{min-height:90px;font-family:var(--mono);font-size:11px;tab-size:2}
.fg select{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%23555a6e' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 8px center;padding-right:26px}
.file-zone{position:relative;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:4px;padding:14px;border:2px dashed var(--border);border-radius:var(--r-sm);cursor:pointer;background:#0c0e14;text-align:center;transition:.15s}
.file-zone:hover{border-color:var(--green);background:var(--green-bg)}
.file-zone.has{border-color:var(--green);border-style:solid;background:var(--green-bg)}
.file-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}
.file-zone .fzt{font-size:10px;color:var(--text3)}
.file-zone .fzn{font-size:11px;color:var(--green);font-weight:600}
.gal-main{display:block;margin:0 auto 8px;cursor:pointer}.gal-strip{display:flex;gap:6px;overflow-x:auto;padding:4px 2px 10px;margin-bottom:6px;scrollbar-width:thin;scrollbar-color:var(--border) transparent}.gal-th{width:56px;height:56px;flex:0 0 auto;object-fit:cover;border-radius:6px;border:2px solid var(--border);cursor:pointer;opacity:.65;transition:.15s;background:var(--surface2)}.gal-th:hover{opacity:1}.gal-th.on{border-color:var(--green);opacity:1}
.toggle-row{display:flex;align-items:center;gap:10px;padding:4px 0}
.sw{position:relative;width:36px;height:20px;flex-shrink:0}
.sw input{opacity:0;width:0;height:0}
.sw .sl{position:absolute;inset:0;background:#1a1d28;border-radius:20px;cursor:pointer;transition:.15s}
.sw .sl::before{content:'';position:absolute;width:14px;height:14px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.15s}
.sw input:checked+.sl{background:var(--green)}
.sw input:checked+.sl::before{background:#fff;transform:translateX(16px)}
  .toggle-row .swl{font-size:11px;color:#fff}

.cat-chips{display:flex;flex-wrap:wrap;gap:5px}
.cat-chip{display:flex;align-items:center;gap:4px;padding:4px 8px;border-radius:var(--r-sm);font-size:10px;font-weight:500;background:var(--surface2);border:1px solid var(--border);color:var(--text)}
.cat-edit-form{display:flex;align-items:center;gap:3px}.cat-name-input{width:110px;padding:2px 4px;background:#0c0e14;border:1px solid var(--border);border-radius:3px;color:var(--text2);font:inherit}.cat-name-input:focus{outline:none;border-color:var(--green)}.cat-edit{display:inline-flex;padding:2px;background:transparent;border:0;color:var(--green);cursor:pointer}.cat-edit:hover{color:#fff}
.cat-chip .del{color:var(--red);cursor:pointer;font-weight:700;font-size:12px;line-height:1;opacity:.6;transition:.1s;padding:0 2px}
.cat-chip .del:hover{opacity:1}
.cat-sub{font-size:9px;color:var(--text3)}
.add-cat-form{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:5px}
.add-cat-form select,.add-cat-form input{padding:5px 8px;background:#0c0e14;border:1px solid var(--border);border-radius:var(--r-sm);color:var(--text2);font-size:11px;font-family:var(--font);outline:none}
.add-cat-form select:focus,.add-cat-form input:focus{border-color:var(--green)}

.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:var(--r)}
table{width:100%;border-collapse:collapse;min-width:900px}
.bulk-toolbar{display:flex;align-items:center;justify-content:flex-start;width:100%;margin:0 0 8px;padding:0;background:transparent;border:0}
.bulk-toolbar .bulk-delete{margin:0}
table th{padding:8px 10px;background:var(--surface);color:var(--text3);font-size:10px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;position:sticky;top:0;z-index:2}
table td{padding:8px 7px;border-bottom:1px solid var(--border2);font-size:12px;vertical-align:middle}
table tr:hover td{background:#ffffff02}
table tr.pinned td{background:var(--amber-bg)}
.select-cell{width:22px;padding-left:3px!important;padding-right:3px!important;text-align:center}
.col-pin{width:18px;padding-left:2px!important;padding-right:2px!important;text-align:center}
.col-thumb{width:44px;padding-left:2px!important;padding-right:2px!important;text-align:center}
.col-name{min-width:170px}
.col-desc{min-width:150px;max-width:210px}
.img-remove{display:block;white-space:nowrap;font-size:9px;margin-top:2px}
.col-cat{width:100px;text-align:center;white-space:nowrap}
.col-pass{width:80px;text-align:center}
.col-php{width:92px;text-align:center}
.col-file{width:130px}
.col-date{width:100px;white-space:nowrap}
.col-actions{width:150px;text-align:right}
.td-name{font-weight:600;color:var(--text2)}
.td-desc{color:var(--text);font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.td-file{font-family:var(--mono);font-size:10px;color:var(--text3)}
.td-date{font-size:10px;color:var(--text3);white-space:nowrap}
.thumb-img{width:36px;height:36px;border-radius:4px;object-fit:cover;border:1px solid var(--border);cursor:pointer;background:var(--surface2)}
.thumb-placeholder{width:36px;height:36px;border-radius:4px;border:1px solid var(--border);display:inline-flex;align-items:center;justify-content:center;color:var(--text3);background:var(--surface2)}
.badge{font-size:9px;padding:2px 6px;border-radius:4px;font-weight:700;text-transform:uppercase;letter-spacing:.3px;display:inline-flex;align-items:center;gap:3px;white-space:nowrap}
.badge-r{background:var(--red-bg);color:#ff5c65}.badge-g{background:var(--green-bg);color:#35d07f}.badge-b{background:var(--blue-bg);color:var(--blue)}.badge-a{background:var(--amber-bg);color:var(--amber)}

.note-table{min-width:600px}
.note-table .col-n-title{min-width:160px}
.note-table .col-n-content{min-width:300px}
.note-table .col-n-date{width:110px}
.note-table .col-n-actions{width:120px}

.note-content{font-size:11px;color:var(--text);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.note-title{font-weight:600;color:var(--text2)}
.note-title-button{border:0;background:none;padding:0;font:inherit;text-align:left;cursor:pointer}
.note-title-button:hover{color:var(--green)}

.empty{padding:40px 20px;text-align:center;color:var(--text3)}
.empty svg{opacity:.2;margin-bottom:10px}
.empty h3{font-size:13px;font-weight:500}
.empty p{font-size:11px;margin-top:2px}

.toast{position:fixed;bottom:18px;right:18px;padding:9px 16px;border-radius:var(--r-sm);font-size:11px;font-weight:600;z-index:99;animation:tu .2s ease,to 2.5s 1.8s ease forwards;pointer-events:none;background:#14532d;border:1px solid #166534;color:#dcfce7;box-shadow:0 6px 20px #00000040}
@keyframes tu{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes to{to{opacity:0;transform:translateY(-5px)}}

.modal-overlay{display:none;position:fixed;inset:0;background:#00000088;z-index:200;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:16px;max-width:90vw;max-height:85vh;overflow:auto}
.modal-box img{max-width:100%;max-height:70vh;display:block;border-radius:4px}
.modal-close{position:absolute;top:8px;right:12px;color:var(--text);cursor:pointer;font-size:18px;background:none;border:none;font-family:var(--font)}

@media(max-width:768px){
    .sb{display:none;position:fixed;inset:0;width:100%;height:100vh;height:100dvh;z-index:100;overflow:hidden}.sb.open{display:flex}
    .sb-footer{padding:10px 10px calc(10px + env(safe-area-inset-bottom))}
    .btn-mob{display:flex}
    .main-top{padding:10px 12px}.main-body{padding:10px 12px}
    .tabs{padding:0 12px}
    .form-grid{grid-template-columns:1fr}
    .search-w input{width:110px}.search-w input:focus{width:140px}
    table{min-width:700px}
}
.stats-head{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:14px}.stats-head h2{font-size:18px;color:var(--text2)}.stats-head p,.muted{color:var(--text3);font-size:11px}.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px}.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px}.stat-card b{display:block;font-size:24px;color:var(--green)}.stat-card span{font-size:10px;color:var(--text3)}.stats-columns{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.stats-title{padding:12px 14px;border-bottom:1px solid var(--border);font-weight:700;color:var(--text2)}.rank-list{padding:10px 14px;max-height:260px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border2) transparent}.rank-list::-webkit-scrollbar{width:6px}.rank-list::-webkit-scrollbar-thumb{background:var(--border2);border-radius:6px}.rank-row{position:relative;display:grid;grid-template-columns:minmax(0,1fr) auto auto auto auto;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);font-size:11px;overflow:hidden}.rank-row span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rank-row strong{color:var(--text2);white-space:nowrap}.rank-row em{font-style:normal;color:var(--green);font-size:10px}.rank-percent{display:none;color:var(--red);font-size:10px;font-weight:800;white-space:nowrap;min-width:38px;padding:4px 7px;text-align:center;background:var(--surface2);border:1px solid var(--border);border-radius:4px;line-height:1}.rank-row.show-percent .rank-percent{display:block}.rank-row i{position:absolute;left:0;bottom:0;height:2px;background:var(--green);opacity:.7;cursor:pointer}.rank-link-info{display:flex;align-items:center;gap:5px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rank-name-toggle{display:flex;align-items:center;gap:5px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;border:0;padding:0;background:none;color:inherit;font:inherit;text-align:left;cursor:pointer}.rank-name-toggle:hover{color:var(--text2)}.rank-link-action{display:inline-flex;align-items:center;justify-content:center;flex:none;color:var(--blue);cursor:pointer}.rank-link-action:hover{color:var(--red)}.rank-link-info>svg{color:var(--text3);flex-shrink:0}.rank-action-info{display:flex;align-items:center;gap:5px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rank-action-info svg{color:var(--text3);flex-shrink:0}.rank-action-icon{display:inline-flex;align-items:center;justify-content:center;flex:none;padding:2px;border:0;background:transparent;color:var(--blue);cursor:pointer}.rank-action-icon:hover{color:var(--green)}.rank-action-icon svg{display:block}.stats-columns+.panel{margin-top:12px}@media(max-width:900px){.stats-grid{grid-template-columns:repeat(2,1fr)}.stats-columns{grid-template-columns:1fr}}@media(max-width:500px){.stats-head{align-items:flex-start;flex-direction:column}.stats-grid{grid-template-columns:1fr 1fr}}
table tr.pinned td {
    background: rgba(127, 29, 29, .16);
}
table tr.pinned:hover td {
    background: rgba(127, 29, 29, .24);
}
table .col-pin{color:var(--red)}
  table tr.pinned .col-pin{color:var(--red)}
  td.col-actions{height:60px;white-space:nowrap}
.row-actions{display:flex;gap:3px;justify-content:flex-end;align-items:center}.archive-pin-action{color:var(--text3)!important}.archive-pin-action.is-pinned{color:var(--amber)!important}
table tr.pinned td{background:rgba(127,29,29,.16)}
table tr.pinned:hover td{background:rgba(127,29,29,.24)}
table tr.pinned .col-pin{color:var(--red)}
  #dosyaTable{min-width:900px}
    table .row-actions a.archive-pin-action:not(.is-pinned),
  table .row-actions a.archive-pin-action:not(.is-pinned) svg {
    color: var(--text3) !important;
    stroke: currentColor !important;
  }
  table .row-actions a.archive-pin-action.is-pinned,
  table .row-actions a.archive-pin-action.is-pinned svg {
    color: var(--amber) !important;
    stroke: currentColor !important;
  }
	.rich-editor{width:100%;min-width:0}
.rich-toolbar{display:flex;align-items:center;gap:5px;flex-wrap:wrap;width:100%;min-width:0;padding:6px;background:#0c0e14;border:1px solid var(--border);border-bottom:0;border-radius:var(--r-sm) var(--r-sm) 0 0}
.rich-toolbar button{display:inline-flex;align-items:center;justify-content:center;flex:0 0 28px;width:28px;height:28px;padding:0;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text2);font:600 12px var(--font);cursor:pointer}
.rich-toolbar button:hover{border-color:var(--green);color:var(--green);background:var(--green-bg)}
.rich-toolbar .rich-size-select{flex:0 0 116px;width:116px;min-width:116px;height:28px;padding:4px 28px 4px 8px;background-color:var(--surface2);background-position:right 7px center;border:1px solid var(--border);border-radius:4px;color:var(--text2);font:500 11px var(--font);line-height:18px;white-space:nowrap;overflow:visible}
.rich-toolbar input[type=color]{flex:0 0 28px;width:28px;height:28px;padding:2px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;cursor:pointer}
.rich-content{min-height:90px;padding:9px 10px;background:#0c0e14;border:1px solid var(--border);border-radius:0 0 var(--r-sm) var(--r-sm);color:var(--text2);font:12px var(--font);line-height:1.5;outline:none;overflow-wrap:anywhere}
.rich-content:focus{border-color:var(--green);box-shadow:0 0 0 3px var(--green-glow)}
.rich-content:empty::before{content:attr(data-placeholder);color:var(--text3);pointer-events:none}
.rich-value{display:none}
@media(max-width:420px){.rich-toolbar .rich-size-select{flex-basis:116px;width:116px;min-width:116px}.rich-toolbar{gap:4px}}
.col-drag{width:22px;min-width:22px;max-width:22px;padding:0!important;text-align:center}
.drag-h{display:inline-block;padding:8px 5px;color:var(--text3);cursor:grab;font-size:13px;line-height:1;letter-spacing:-3px;user-select:none;-webkit-user-select:none;touch-action:none}
.drag-h:hover{color:var(--green)}
tr.dragging td{background:var(--green-bg)!important;box-shadow:0 0 0 1px var(--green) inset}
tr.dragging .drag-h{cursor:grabbing}
body.drag-on{cursor:grabbing;user-select:none;-webkit-user-select:none}
</style>
</head>
<body>
<div class="layout">
<aside class="sb" id="sb">
    <div class="sb-brand"><?=svg('shield',18)?><div class="t"><b>Exlonea-</b>2026</div></div>
    <nav class="sb-nav">
        <div class="sec">Menü</div>
        <?php if (x_tab_on('dosya')): ?><a href="?tab=dosya<?=$activeCat!=='__all__'?'&cat='.$activeCat:''?>" class="it <?=$tab==='dosya'||($tab==='all'&&!empty($dosya))?'act':''?>"><?=svg('folder',13)?> <?=x_h(x_tab_label('dosya'))?><span class="n"><?=count($data['dosya'])?></span></a><?php endif; ?>
        <?php if (x_tab_on('github')): ?><a href="?tab=github<?=$activeCat!=='__all__'?'&cat='.$activeCat:''?>" class="it <?=$tab==='github'||($tab==='all'&&!empty($github))?'act':''?>"><?=svg('code',13)?> <?=x_h(x_tab_label('github'))?><span class="n"><?=count($data['github'])?></span></a><?php endif; ?>
        <?php if (x_tab_on('notes')): ?><a href="?tab=notes" class="it <?=$tab==='notes'?'act':''?>"><?=svg('book',13)?> <?=x_h(x_tab_label('notes'))?><span class="n"><?=count($data['notes'])?></span></a><?php endif; ?>
        <?php if (x_admin()): ?><a href="?tab=analytics" class="it <?=$tab==='analytics'?'act':''?>"><?=svg('eye',13)?> İstatistik <span class="n">ADMIN</span></a><a href="?tab=settings" class="it <?=$tab==='settings'?'act':''?>"><?=svg('cog',13)?> Ayarlar <span class="n">ADMIN</span></a><?php endif; ?>
        <?php if (x_tab_on('dosya')||x_tab_on('github')): ?>
        <div class="sec" style="margin-top:8px">Kategoriler</div>
        <a href="?tab=all" class="it <?=$tab==='all'&&$activeCat==='__all__'?'act':''?>"><?=svg('tag',13)?> Tümü<span class="n"><?=count($data['dosya']) + count($data['github'])?></span></a>
        <?php foreach ($catTree as $cat):
            $cnt=count(array_filter($data['dosya'],fn($s)=>($s['category_id']??null)===$cat['id'])) + count(array_filter($data['github'],fn($g)=>($g['category_id']??null)===$cat['id'])); ?>
        <a href="?tab=all&cat=<?=$cat['id']?>" class="it <?=$tab==='all'&&$activeCat===$cat['id']?'act':''?>"><?=svg('tag',12)?> <?=x_h($cat['name'])?><span class="n"><?=$cnt?></span></a>
        <?php foreach (x_cat_tree($cats,$cat['id']) as $sub):
            $scnt=count(array_filter($data['dosya'],fn($s)=>($s['category_id']??null)===$sub['id'])) + count(array_filter($data['github'],fn($g)=>($g['category_id']??null)===$sub['id'])); ?>
        <a href="?tab=all&cat=<?=$sub['id']?>" class="it sub <?=$tab==='all'&&$activeCat===$sub['id']?'act':''?>"><?=svg('tag',11)?> <?=x_h($sub['name'])?><span class="n"><?=$scnt?></span></a>
        <?php endforeach; endforeach; ?>
        <div class="sec" style="margin-top:8px">İstatistik</div>
        <div class="it" style="pointer-events:none"><?=svg('lock',12)?> Şifreli <span class="n"><?=count(array_filter($data['dosya'],fn($s)=>!empty($s['has_password']))) + count(array_filter($data['github'],fn($g)=>!empty($g['encrypted'])))?></span></div>
        <div class="it" style="pointer-events:none"><?=svg('unlock',12)?> Açık <span class="n"><?=count(array_filter($data['dosya'],fn($s)=>empty($s['has_password']))) + count(array_filter($data['github'],fn($g)=>empty($g['encrypted'])))?></span></div>
        <div class="it" style="pointer-events:none"><?=svg('pin',12)?> Sabitli <span class="n"><?=count(array_filter($data['dosya'],fn($s)=>$s['pinned']??false))?></span></div>
        <?php endif; ?>
    </nav>
    <div class="sb-footer">
        <div class="sb-user">
            <div class="av <?=$role==='admin'?'av-a':'av-z'?>"><?=$role==='admin'?'A':'Z'?></div>
            <div class="um"><div class="rn"><?=$role==='admin'?'Yönetici':'Ziyaretçi'?></div><div class="rl"><?=$role==='admin'?'Admin':'Kullanıcı'?></div></div>
        </div>
        <a class="btn-logout" href="?logout=1"><?=svg('logout',11)?> Çıkış</a>
    </div>
</aside>

<main class="main">
    <div class="main-top">
        <div>
            <h1><?=x_h($tab==='notes'?x_tab_label('notes'):($tab==='dosya'?x_tab_label('dosya'):($tab==='github'?x_tab_label('github'):($tab==='settings'?'Ayarlar':($tab==='analytics'?'İstatistik':($activeCat==='__all__'?'Tüm Dosyalar':x_cat_name($cats,$activeCat)))))))?></h1>
            <div class="cr"><?=APP_NAME?><?php if ($tab!=='settings'&&$tab!=='analytics'): ?> / <?=$tab==='notes'?count($notes):($tab==='all'?count($dosya)+count($github):count($dosya))?> öğe<?php endif; ?></div>
        </div>
        <div class="top-r">
            <button class="btn-mob" onclick="document.getElementById('sb').classList.toggle('open')"><?=svg('menu',14)?> Menü</button>
            <div class="search-w">
                <span class="si"><?=svg('search',12)?></span>
                <input type="text" id="search" placeholder="Ara...">
            </div>
        </div>
    </div>

  <div class="tabs">
  <?php if (x_tab_on('dosya')): ?><a href="?tab=dosya<?=$activeCat!=='__all__'?'&cat='.$activeCat:''?>" class="<?=$archiveTopActive?'act':''?>"><?=svg('folder',13)?> <?=x_h(x_tab_label('dosya'))?></a><?php endif; ?>
  <?php if (x_tab_on('github')): ?><a href="?tab=github<?=$activeCat!=='__all__'?'&cat='.$activeCat:''?>" class="<?=$githubTopActive?'act':''?>"><?=svg('link',13)?> <?=x_h(x_tab_label('github'))?></a><?php endif; ?>
  <?php if (x_tab_on('notes')): ?><a href="?tab=notes" class="<?=$tab==='notes'?'act':''?>"><?=svg('book',13)?> <?=x_h(x_tab_label('notes'))?></a><?php endif; ?>
  </div>

    <div class="main-body">

<?php if ($tab==='analytics' && x_admin()): ?>
<?php
  $events=$data['analytics']; $total=count($events); $countBy=function($type,$action)use($events){return count(array_filter($events,fn($e)=>($e['type']??'')===$type&&($e['action']??'')===$action));};
  $rank=function($type,$action)use($events){$r=[];foreach($events as $e)if(($e['type']??'')===$type&&($e['action']??'')===$action){$k=$e['id']?:($e['label']??'Bilinmiyor');if(!isset($r[$k]))$r[$k]=['id'=>$k,'label'=>$e['label']??$k,'count'=>0];$r[$k]['count']++;}usort($r,fn($a,$b)=>$b['count']<=>$a['count']);return $r;};
  $downloads=$rank('dosya','download'); $reads=$rank('note','read'); $copies=$rank('github','copy'); $logins=$rank('auth','login');
  foreach($copies as &$copy) { foreach($data['github'] as $githubItem) if(($githubItem['id']??'')===($copy['id']??'')) { $copy['label']=$githubItem['name']??$copy['label']; $copy['url']=$githubItem['url']??''; break; } } unset($copy);
  $percent=function($n,$sum){return $sum?round($n/$sum*100,1):0;};
?>
<div class="stats-head"><div><h2>Gelişmiş İstatistik Paneli</h2><p>Dosya arşivi, GitHub, bilgiler ve giriş hareketleri</p></div><form method="POST" action="?action=analytics_reset" onsubmit="return confirm('Tüm istatistik kayıtları sıfırlansın mı?')"><button class="btn btn-or btn-sm" type="submit"><?=svg('trash',12)?> İstatistikleri Sıfırla</button></form></div>
<div class="stats-grid"><div class="stat-card"><b><?=number_format($countBy('dosya','download'))?></b><span>Dosya indirme</span></div><div class="stat-card"><b><?=number_format($countBy('github','copy'))?></b><span>GitHub kopyalama</span></div><div class="stat-card"><b><?=number_format($countBy('dosya','read')+$countBy('note','read'))?></b><span>İçerik okuma</span></div><div class="stat-card"><b><?=number_format($countBy('auth','login'))?></b><span>Giriş</span></div></div>
  <div class="stats-columns"><div class="panel"><div class="stats-title">En çok indirilen dosyalar</div><div class="rank-list"><?php foreach($downloads as $r):?><div class="rank-row"><button class="rank-name-toggle" type="button" onclick="this.closest('.rank-row').classList.toggle('show-percent')" title="Yüzdeyi göster/gizle"><?=svg('download',11)?> <?=x_h($r['label'])?></button><strong><?=$r['count']?></strong><a class="rank-action-icon" href="?action=download&id=<?=x_h($r['id'])?>" title="Dosyayı indir" aria-label="Dosyayı indir"><?=svg('download',12)?></a><span class="rank-percent"><?=$percent($r['count'],$countBy('dosya','download'))?>%</span><i onclick="this.parentElement.classList.toggle('show-percent')" style="width:<?=$percent($r['count'],$countBy('dosya','download'))?>%"></i></div><?php endforeach;if(!$downloads):?><p class="muted">Henüz kayıt yok.</p><?php endif;?></div></div>
  <div class="panel"><div class="stats-title">En çok okunan bilgiler</div><div class="rank-list"><?php foreach($reads as $r):?><div class="rank-row"><button class="rank-name-toggle" type="button" onclick="this.closest('.rank-row').classList.toggle('show-percent')" title="Yüzdeyi göster/gizle"><?=svg('eye',11)?> <?=x_h($r['label'])?></button><strong><?=$r['count']?></strong><?php foreach($data['notes'] as $noteItem) if(($noteItem['id']??'')===($r['id']??'')):?><button class="rank-action-icon" type="button" onclick="viewNote(<?=htmlspecialchars(json_encode($noteItem+['_v'=>x_img_v($noteItem['image']??'')]+x_gal_meta($noteItem,'image'),JSON_UNESCAPED_UNICODE))?>)" title="Bilgiyi görüntüle" aria-label="Bilgiyi görüntüle"><?=svg('eye',12)?></button><?php endif;?><span class="rank-percent"><?=$percent($r['count'],$countBy('note','read'))?>%</span><i onclick="this.parentElement.classList.toggle('show-percent')" style="width:<?=$percent($r['count'],$countBy('note','read'))?>%"></i></div><?php endforeach;if(!$reads):?><p class="muted">Henüz kayıt yok.</p><?php endif;?></div></div>
  <div class="panel"><div class="stats-title">En çok kopyalanan GitHub linkleri</div><div class="rank-list"><?php foreach($copies as $r):?><div class="rank-row"><button class="rank-name-toggle rank-link-info" type="button" onclick="this.closest('.rank-row').classList.toggle('show-percent')" title="Yüzdeyi göster/gizle"><?=svg('link',11)?> <?=x_h($r['label'])?></button><strong><?=$r['count']?></strong><?php if (!empty($r['url'])):?><a class="rank-link-action" href="<?=x_h($r['url'])?>" target="_blank" rel="noopener noreferrer" title="GitHub linkini aç" aria-label="GitHub linkini aç"><?=svg('link',11)?></a><button class="rank-action-icon" type="button" onclick="copyGithub(this,<?=htmlspecialchars(json_encode($r['url']))?>)" title="GitHub linkini kopyala" aria-label="GitHub linkini kopyala"><?=svg('copy',12)?></button><?php endif;?><span class="rank-percent"><?=$percent($r['count'],$countBy('github','copy'))?>%</span><i onclick="this.parentElement.classList.toggle('show-percent')" style="width:<?=$percent($r['count'],$countBy('github','copy'))?>%"></i></div><?php endforeach;if(!$copies):?><p class="muted">Henüz kayıt yok.</p><?php endif;?></div></div></div>
<div class="panel"><div class="stats-title">Son girişler ve IP kayıtları</div><div class="table-wrap"><table><thead><tr><th>Rol</th><th>Zaman</th><th>IP</th></tr></thead><tbody><?php foreach(array_reverse($events) as $e)if(($e['type']??'')==='auth'):?><tr><td><?=x_h($e['label']??$e['id'])?></td><td><?=x_h(date('d.m.y - H:i',strtotime($e['time']??'now')))?></td><td><code><?=x_h($e['ip']??'unknown')?></code></td></tr><?php endif; ?></tbody></table></div></div>
<?php elseif ($tab==='settings' && x_admin()): ?>
<div class="stats-head"><div><h2>Ayarlar</h2><p>Sekmeleri aç/kapat ve menü adlarını değiştir</p></div></div>
<div class="panel"><div style="padding:14px">
<form method="POST" action="?action=settings_save&tab=settings">
<?php foreach (x_tab_defaults() as $k=>$d): $c = $GLOBALS['x_tabs'][$k]; ?>
<div class="set-row">
    <label class="sw" title="Göster / gizle"><input type="checkbox" name="enabled[<?=$k?>]" value="1" <?=$c['enabled']?'checked':''?>><span class="sl"></span></label>
    <div class="fg"><label>Menü adı <span class="muted">(varsayılan: <?=x_h($d['label'])?>)</span></label><input type="text" name="label[<?=$k?>]" value="<?=x_h($c['label'])?>" maxlength="30" placeholder="<?=x_h($d['label'])?>"></div>
</div>
<?php endforeach; ?>
<p class="muted" style="margin:6px 0 14px">Kapalı sekmeler hem yöneticiden hem ziyaretçiden gizlenir. En az bir sekme açık kalmalıdır. Adı boş bırakırsanız varsayılan ad kullanılır. Dosya yükleme paneli Bilgiler sekmesinin içindedir.</p>
<button class="btn btn-g" type="submit"><?=svg('check',13)?> Kaydet</button>
</form></div></div>
<style>.set-row{display:flex;align-items:center;gap:14px;margin-bottom:12px}.set-row .fg{flex:1;margin:0;display:flex;flex-direction:column;gap:6px}.set-row .fg label{font-size:11px;color:var(--text)}.set-row .fg input{padding:10px;background:#0c0e14;border:1px solid var(--border);border-radius:6px;color:var(--text2);font-size:13px;width:100%;max-width:340px;outline:none;font-family:var(--font)}.set-row .fg input:focus{border-color:var(--green)}</style>
<?php elseif ($tab==='dosya' || $tab==='all'): ?>
<?php if (x_admin()): ?>
<div class="panel">
    <button class="panel-toggle" onclick="tPanel(this)"><?=svg('upload',13)?> Dosya Yükle<span class="ar"><?=svg('chevron-down',11)?></span></button>
    <div class="panel-body">
        <form method="POST" action="?action=upload&tab=dosya" enctype="multipart/form-data">
            <div class="form-grid">
                <div class="fg"><label>Dosya Adı</label><input type="text" name="name" placeholder="örn: WSO v2.5" required></div>
                <div class="fg"><label>Kategori</label><select name="category_id"><option value="">Kategorisiz</option><?php foreach ($cats as $c): $pr=$c['parent']?x_cat_name($cats,$c['parent']).' → ':''; ?><option value="<?=$c['id']?>"><?=$pr.x_h($c['name'])?></option><?php endforeach; ?></select></div>
                <div class="fg fw"><label>Açıklama</label><?=x_rich_editor('dosyaUploadDescription','description','','Açıklamayı buraya yazın...')?></div>
                <div class="fg"><label>Dosya</label><div class="file-zone" id="ufz"><?=svg('upload',14)?> <span class="fzt">Dosya seçmek için tıklayın</span><span class="fzn" style="display:none"></span><input type="file" name="dosya_arsiv" required onchange="fu(this,'ufz')"></div></div>
                <div class="fg"><label>Ekran Görüntüsü</label><div class="file-zone" id="usz"><?=svg('image',14)?> <span class="fzt">Görsel(ler) — birden fazla seçilebilir</span><span class="fzn" style="display:none"></span><input type="file" name="screenshot[]" multiple accept="image/*" onchange="fu(this,'usz')"></div><?=x_url_input('screenshot_url')?></div>
<div class="fw"><div class="toggle-row"><label class="sw"><input type="checkbox" name="has_password" value="1"><span class="sl"></span></label><span class="swl">Şifre korumalı</span></div><div class="toggle-row"><label class="sw"><input type="checkbox" name="show_code" value="1"><span class="sl"></span></label><span class="swl">Kod içeriğini göster</span></div><?=x_php_field('php_version','')?></div>
                <div class="fw"><button class="btn btn-g" type="submit"><?=svg('upload',13)?> Yükle</button></div>
            </div>
        </form>
    </div>
</div>

<div class="panel">
    <button class="panel-toggle" onclick="tPanel(this)"><?=svg('code',13)?> Kod Editörü — Dosya Oluştur<span class="ar"><?=svg('chevron-down',11)?></span></button>
    <div class="panel-body">
        <form method="POST" action="?action=create&tab=dosya" enctype="multipart/form-data">
            <div class="form-grid">
                <div class="fg"><label>Dosya Adı</label><input type="text" name="name" placeholder="örn: dosya" required></div>
                <div class="fg"><label>İndirilecek Dosya Adı</label><input type="text" name="filename" placeholder="örn: dosya.php" required></div>
                <div class="fg"><label>Kategori</label><select name="category_id"><option value="">Kategorisiz</option><?php foreach ($cats as $c): $pr=$c['parent']?x_cat_name($cats,$c['parent']).' → ':''; ?><option value="<?=$c['id']?>"><?=$pr.x_h($c['name'])?></option><?php endforeach; ?></select></div>
                <div class="fg"><label>Açıklama</label><?=x_rich_editor('dosyaCreateDescription','description','','Açıklamayı buraya yazın...')?></div>
                <div class="fg fw"><label>Kod İçeriği</label><textarea name="content" rows="12" placeholder="&lt;?php&#10;// Kod buraya&#10;?&gt;" spellcheck="false"></textarea></div>
                <div class="fg"><label>Ekran Görüntüsü</label><div class="file-zone" id="csz"><?=svg('image',14)?> <span class="fzt">Görsel(ler) — birden fazla seçilebilir</span><span class="fzn" style="display:none"></span><input type="file" name="screenshot[]" multiple accept="image/*" onchange="fu(this,'csz')"></div><?=x_url_input('screenshot_url')?></div>
<div class="fg"><div class="toggle-row"><label class="sw"><input type="checkbox" name="has_password" value="1"><span class="sl"></span></label><span class="swl">Şifre korumalı</span></div><div class="toggle-row"><label class="sw"><input type="checkbox" name="show_code" value="1"><span class="sl"></span></label><span class="swl">Kod içeriğini göster</span></div><?=x_php_field('php_version','')?></div>
                <div class="fw"><button class="btn btn-g" type="submit"><?=svg('plus',13)?> Oluştur</button></div>
            </div>
        </form>
    </div>
</div>

<div class="panel">
    <button class="panel-toggle" onclick="tPanel(this)"><?=svg('tag',13)?> Kategori Yönetimi<span class="ar"><?=svg('chevron-down',11)?></span></button>
    <div class="panel-body">
        <div class="cat-chips">
            <?php foreach ($cats as $c): ?>
            <span class="cat-chip"><form method="POST" action="?action=cat_edit&tab=dosya" class="cat-edit-form"><input type="hidden" name="cat_id" value="<?=x_h($c['id'])?>"><input class="cat-name-input" type="text" name="cat_name" value="<?=x_h($c['name'])?>" aria-label="Kategori adı"><button class="cat-edit" type="submit" title="Kategori adını kaydet" aria-label="Kategori adını kaydet"><?=svg('check',11)?></button></form><?php if ($c['parent']):?><span class="cat-sub">(alt: <?=x_h(x_cat_name($cats,$c['parent']))?>)</span><?php endif;?><a class="del" href="?action=cat_delete&id=<?=$c['id']?>&tab=dosya" onclick="return confirm('Kategori silinsin mi?')">&times;</a></span>
            <?php endforeach; ?>
        </div>
        <form method="POST" action="?action=cat_add&tab=dosya" class="add-cat-form">
            <input type="text" name="cat_name" placeholder="Kategori adı" required>
            <select name="cat_parent"><option value="">Ana kategori</option><?php foreach (x_cat_tree($cats) as $c):?><option value="<?=$c['id']?>">Alt: <?=x_h($c['name'])?></option><?php endforeach;?></select>
            <button class="btn btn-o btn-xs" type="submit"><?=svg('plus',11)?> Ekle</button>
        </form>
    </div>
</div>
<?php endif; ?>

<?php if (($tab==='dosya' && empty($dosya)) || ($tab==='all' && empty($dosya) && empty($github))): ?>
<div class="empty"><?=svg('file',32)?><h3><?=$tab==='dosya'?'Henüz dosya eklenmedi':'Bu kategoride içerik yok'?></h3><?php if (x_admin()):?><p><?=$tab==='dosya'?'Yukarıdaki panelden dosya ekleyebilirsiniz.':'Yukarıdaki panelden dosya veya GitHub bağlantısı ekleyebilirsiniz.'?></p><?php endif;?></div>
<?php elseif (!empty($dosya)): ?>
<form method="POST" action="?action=bulk_delete&tab=dosya" class="bulk-form" onsubmit="return confirmBulk(this)"><input type="hidden" name="type" value="dosya"><?php if (x_admin()): ?><div class="bulk-toolbar"><button class="btn btn-or btn-xs bulk-delete" type="submit" disabled style="display:none"><?=svg('trash',11)?> Seçilenleri sil</button></div><?php endif; ?>

<div class="table-wrap">
<table id="dosyaTable" data-type="dosya">
<thead><tr>
    <?php if ($canSort): ?><th class="col-drag"></th><?php endif; ?><?php if (x_admin()): ?><th class="select-cell"><input type="checkbox" class="select-all" onchange="toggleBulk(this)" aria-label="Tüm dosyaları seç"></th><?php endif; ?><th class="col-pin"></th>
    <th class="col-thumb"></th>
    <th class="col-name">Ad</th>
    <th class="col-desc">Açıklama</th>
    <th class="col-cat">Kategori</th>
    <th class="col-pass">Durum</th>
    <th class="col-php">PHP</th>
    <th class="col-file">Dosya</th>
    <th class="col-date">Tarih</th>
    <th class="col-actions">İşlem</th>
</tr></thead>
<tbody>
<?php foreach ($dosya as $sh):
    $ext=pathinfo($sh['original_name']??'',PATHINFO_EXTENSION);
    $pinned=$sh['pinned']??false;
    $searchData=x_h(strtolower($sh['name'].' '.($sh['description']??'').' '.($sh['original_name']??'').' '.x_cat_name($cats,$sh['category_id']??null)));
?>
<tr class="<?=$pinned?'pinned':''?>" data-id="<?=x_h($sh['id'])?>" data-search="<?=$searchData?>">
    <?php if ($canSort): ?><td class="col-drag"><span class="drag-h" title="Sürükleyerek sırala">&#8942;&#8942;</span></td><?php endif; ?><?php if (x_admin()): ?><td class="select-cell"><input type="checkbox" name="ids[]" value="<?=x_h($sh['id'])?>" onchange="syncBulk(this)" aria-label="<?=x_h($sh['name'])?> seç"></td><?php endif; ?><td class="col-pin"><?php if ($pinned):?><?=svg('pin',13)?><?php endif;?></td>
    <td class="col-thumb">
        <?php if ($sh['screenshot']): ?>
        <img class="thumb-img" src="?action=thumb&id=<?=$sh['id']?>&v=<?=x_img_v($sh['screenshot']??'')?>" alt="" loading="lazy" onclick="showModal('?action=screenshot&id=<?=$sh['id']?>&v=<?=x_img_v($sh['screenshot']??'')?>')">
        <?php if (x_admin()):?><a class="img-remove" href="?action=remove_screenshot&id=<?=$sh['id']?>&tab=dosya" onclick="return confirm('Bu resmi silmek istiyor musunuz?')">Resmi sil</a><?php endif;?>
        <?php else: ?>
        <span class="thumb-placeholder"><?=svg('file',14)?></span>
        <?php endif; ?>
    </td>
<td class="col-name"><button class="td-name archive-open-button" type="button" onclick="viewdosya(<?=htmlspecialchars(json_encode($sh+['_v'=>x_img_v($sh['screenshot']??'')]+x_gal_meta($sh,'screenshot'),JSON_UNESCAPED_UNICODE))?>)"><?=x_h($sh['name'])?></button></td>
    <td class="col-desc"><button class="td-desc td-desc-button" type="button" title="Açıklamayı görmek için tıklayın" onclick="viewdosya(<?=htmlspecialchars(json_encode($sh+['_v'=>x_img_v($sh['screenshot']??'')]+x_gal_meta($sh,'screenshot'),JSON_UNESCAPED_UNICODE))?>)"><?=x_rich($sh['description']??'')?:'—'?></button></td>
    <td class="col-cat"><?php if ($sh['category_id']??null):?><span class="badge badge-b"><?=x_h(x_cat_name($cats,$sh['category_id']))?></span><?php else:?><span style="color:var(--text3)">—</span><?php endif;?></td>
    <td class="col-pass"><?php if ($sh['has_password']):?><span class="badge badge-r"><?=svg('lock',9)?> Şifreli</span><?php else:?><span class="badge badge-g"><?=svg('unlock',9)?> Açık</span><?php endif;?></td><td class="col-php"><?=x_php_badge($sh['php_version']??'')?></td>
    <td><span class="td-file"><?=x_h($sh['original_name']??'—')?></span></td>
    <td class="td-date"><?=x_h(date('d.m.y - H:i',strtotime($sh['date_added']??'now')))?></td>
    <td class="col-actions"><div class="row-actions">
        <button class="btn btn-o btn-xs" type="button" onclick="viewdosya(<?=htmlspecialchars(json_encode($sh+['_v'=>x_img_v($sh['screenshot']??'')]+x_gal_meta($sh,'screenshot'),JSON_UNESCAPED_UNICODE))?>)" title="Görüntüle"><?=svg('eye',11)?></button>
        <a class="btn btn-ob btn-xs" href="?action=download&id=<?=$sh['id']?>" title="İndir"><?=svg('download',11)?></a>
        <?php if (x_admin()):?>
        <a class="btn btn-o btn-xs" href="?action=edit&id=<?=$sh['id']?>" title="Düzenle" style="color:var(--amber)"><?=svg('edit',11)?></a>
        <a class="btn btn-o btn-xs archive-pin-action <?=$pinned?'is-pinned':''?>" href="?action=pin&id=<?=$sh['id']?>&tab=dosya" title="<?=$pinned?'Kaldır':'Sabitle'?>"><?=svg('pin',11)?></a>
        <a class="btn btn-or btn-xs" href="?action=delete&id=<?=$sh['id']?>&tab=dosya" onclick="return confirm('Silinsin mi?')" title="Sil"><?=svg('trash',11)?></a>
        <?php endif;?>
        </div></td>
</tr>
<?php endforeach; ?>
</tbody></table></div>
</form>
<?php endif; ?>
<?php if (!empty($github) && ($tab==='github' || $tab==='all')): ?>
<?php if ($tab==='all'): ?><form method="POST" action="?action=bulk_delete&tab=github" class="bulk-form" onsubmit="return confirmBulk(this)"><input type="hidden" name="type" value="github"><div class="bulk-toolbar"><button class="btn btn-or btn-xs bulk-delete" type="submit" disabled style="display:none"><?=svg('trash',11)?> Seçilenleri sil</button></div><?php endif; ?>
<div class="table-wrap" style="margin-top:16px">
<table id="githubCategoryTable"><thead><tr><?php if ($tab==='all' && x_admin()): ?><th class="select-cell"><input type="checkbox" class="select-all" onchange="toggleBulk(this)" aria-label="Tüm GitHub bağlantılarını seç"></th><?php endif; ?><th class="col-pin"></th><th class="col-thumb"></th><th class="col-name">Ad</th><th class="col-desc">Açıklama</th><th class="col-cat">Kategori</th><th>Durum</th><th class="col-php">PHP</th><th>GitHub Linki</th><th>Tarih</th><th>İşlem</th></tr></thead><tbody>
<?php foreach ($github as $gh): $gp=$gh['pinned']??false; $gs=x_h(strtolower($gh['name'].' '.($gh['description']??'').' '.$gh['url'])); $shortUrl=mb_strlen($gh['url'])>42?mb_substr($gh['url'],0,39).'…':$gh['url']; ?>
<tr class="<?=$gp?'pinned':''?>" data-search="<?=$gs?>"><?php if ($tab==='all' && x_admin()): ?><td class="select-cell"><input type="checkbox" name="ids[]" value="<?=x_h($gh['id'])?>" onchange="syncBulk(this)" aria-label="<?=x_h($gh['name'])?> seç"></td><?php endif; ?><td class="col-pin"><?php if ($gp):?><?=svg('pin',13)?><?php endif;?></td><td class="col-thumb"><?php if (!empty($gh['image'])):?><img class="thumb-img" src="?action=github_image&id=<?=x_h($gh['id'])?>&v=<?=x_img_v($gh['image']??'')?>" alt="<?=x_h($gh['name'])?>" loading="lazy" onclick="showModal('?action=github_image&id=<?=x_h($gh['id'])?>&v=<?=x_img_v($gh['image']??'')?>')"><?php else:?><span class="thumb-placeholder"><?=svg('link',14)?></span><?php endif;?></td><td><button class="td-name github-title-button" type="button" onclick="viewGithub(<?=htmlspecialchars(json_encode($gh+['_v'=>x_img_v($gh['image']??'')]+x_gal_meta($gh,'image'),JSON_UNESCAPED_UNICODE))?>)"><?=x_h($gh['name'])?></button></td><td class="col-desc"><button class="td-desc td-desc-button" type="button" onclick="viewGithub(<?=htmlspecialchars(json_encode($gh+['_v'=>x_img_v($gh['image']??'')]+x_gal_meta($gh,'image'),JSON_UNESCAPED_UNICODE))?>)"><?=x_rich($gh['description']??'')?:'—'?></button></td><td><span class="badge badge-b"><?=x_h(x_cat_name($cats,$gh['category_id']??null))?></span></td><td class="col-pass"><?php if (!empty($gh['encrypted'])):?><span class="badge badge-r"><?=svg('lock',9)?> Şifreli</span><?php else:?><span class="badge badge-g"><?=svg('unlock',9)?> Açık</span><?php endif;?></td><td class="col-php"><?=x_php_badge($gh['php_version']??'')?></td><td class="github-url-cell"><a href="<?=x_h($gh['url'])?>" target="_blank" rel="noopener noreferrer" class="td-file" title="<?=x_h($gh['url'])?>"><?=x_h($shortUrl)?></a></td><td class="td-date"><?=x_h(date('d.m.y - H:i',strtotime($gh['date_added']??'now')))?></td><td class="col-actions"><div class="row-actions"><button class="btn btn-ob btn-xs" type="button" data-github-id="<?=x_h($gh['id'])?>" onclick="copyGithub(this,<?=htmlspecialchars(json_encode($gh['url']))?>)" title="GitHub linkini kopyala"><?=svg('copy',11)?> Kopyala</button></div></td></tr>
<?php endforeach; ?></tbody></table></div><?php if ($tab==='all'): ?></form><?php endif; ?>
<?php endif; ?>

<?php elseif ($tab==='github'): ?>
<?php if (x_admin()): ?>
<div class="panel">
    <button class="panel-toggle" onclick="tPanel(this)"><?=svg('plus',13)?> Yeni GitHub Bağlantısı<span class="ar"><?=svg('chevron-down',11)?></span></button>
    <div class="panel-body">
        <form method="POST" action="?action=github_add&tab=github" enctype="multipart/form-data">
            <div class="form-grid">
                <div class="fg"><label>İsim</label><input type="text" name="name" placeholder="Proje adı" required></div>
                <div class="fg"><label>Raw GitHub Linki</label><input type="url" name="url" placeholder="https://raw.githubusercontent.com/kullanici/proje/main/dosya.php" required></div>
                <div class="fg fw"><label>Açıklama</label><?=x_rich_editor('githubAddDescription','description','','Açıklamayı buraya yazın...')?></div>
                <div class="fg"><label>Kategori</label><select name="category_id"><option value="">Kategorisiz</option><?php foreach ($cats as $cat): ?><option value="<?=x_h($cat['id'])?>"><?=x_h($cat['name'])?></option><?php endforeach; ?></select></div>
                <div class="fg"><div class="toggle-row"><label class="sw"><input type="checkbox" name="encrypted" value="1"><span class="sl"></span></label><span class="swl">Şifre korumalı</span></div><div class="toggle-row"><label class="sw"><input type="checkbox" name="show_code" value="1" checked><span class="sl"></span></label><span class="swl">Kod bilgilerini göster</span></div><?=x_php_field('php_version','')?></div>
                <div class="fg fw"><label>Resim (opsiyonel)</label><div class="file-zone" id="ghfz"><?=svg('upload',14)?> <span class="fzt">Görselleri seçmek için tıklayın (birden fazla)</span><span class="fzn" style="display:none"></span><input type="file" name="image[]" multiple accept="image/*" onchange="fu(this,'ghfz')"></div><?=x_url_input('image_url')?></div>
                <div class="fw"><button class="btn btn-g" type="submit"><?=svg('plus',13)?> Ekle</button></div>
            </div>
        </form>
    </div>
</div>
<?php endif; ?>
<?php if (empty($data['github'])): ?>
<div class="empty"><?=svg('link',32)?><h3>Henüz GitHub bağlantısı eklenmedi</h3><?php if (x_admin()):?><p>Yukarıdaki panelden bağlantı ekleyebilirsiniz.</p><?php endif;?></div>
<?php else: ?>
<form method="POST" action="?action=bulk_delete&tab=github" class="bulk-form" onsubmit="return confirmBulk(this)"><input type="hidden" name="type" value="github"><?php if (x_admin()): ?><div class="bulk-toolbar"><button class="btn btn-or btn-xs bulk-delete" type="submit" disabled style="display:none"><?=svg('trash',11)?> Seçilenleri sil</button></div><?php endif; ?>

<div class="table-wrap"><table id="githubTable" data-type="github"><thead><tr><?php if ($canSort): ?><th class="col-drag"></th><?php endif; ?><?php if (x_admin()): ?><th class="select-cell"><input type="checkbox" class="select-all" onchange="toggleBulk(this)" aria-label="Tüm GitHub bağlantılarını seç"></th><?php endif; ?><th class="col-pin"></th><th class="col-thumb"></th><th class="col-name">Ad</th><th class="col-desc">Açıklama</th><th class="col-cat">Kategori</th><th>Durum</th><th class="col-php">PHP</th><th>GitHub Linki</th><th>Tarih</th><th>İşlem</th></tr></thead><tbody>
<?php foreach ($github as $gh): $gp=$gh['pinned']??false; $gs=x_h(strtolower($gh['name'].' '.($gh['description']??'').' '.$gh['url'])); $shortUrl=mb_strlen($gh['url'])>42?mb_substr($gh['url'],0,39).'…':$gh['url']; ?>
<tr class="<?=$gp?'pinned':''?>" data-id="<?=x_h($gh['id'])?>" data-search="<?=$gs?>"><?php if ($canSort): ?><td class="col-drag"><span class="drag-h" title="Sürükleyerek sırala">&#8942;&#8942;</span></td><?php endif; ?><?php if (x_admin()): ?><td class="select-cell"><input type="checkbox" name="ids[]" value="<?=x_h($gh['id'])?>" onchange="syncBulk(this)" aria-label="<?=x_h($gh['name'])?> seç"></td><?php endif; ?><td class="col-pin"><?php if ($gp):?><?=svg('pin',13)?><?php endif;?></td><td class="col-thumb"><?php if (!empty($gh['image'])):?><img class="thumb-img" src="?action=github_image&id=<?=x_h($gh['id'])?>&v=<?=x_img_v($gh['image']??'')?>" alt="<?=x_h($gh['name'])?>" loading="lazy" onclick="showModal('?action=github_image&id=<?=x_h($gh['id'])?>&v=<?=x_img_v($gh['image']??'')?>')"><?php if (x_admin()):?><a class="img-remove" href="?action=github_remove_image&id=<?=x_h($gh['id'])?>&tab=github" onclick="return confirm('Bu resmi silmek istiyor musunuz?')">Resmi sil</a><?php endif;?><?php else:?><span class="thumb-placeholder"><?=svg('link',14)?></span><?php endif;?></td><td><button class="td-name github-title-button" type="button" onclick="viewGithub(<?=htmlspecialchars(json_encode($gh+['_v'=>x_img_v($gh['image']??'')]+x_gal_meta($gh,'image'),JSON_UNESCAPED_UNICODE))?>)"><?=x_h($gh['name'])?></button></td><td class="col-desc"><button class="td-desc td-desc-button" type="button" title="Açıklamayı görmek için tıklayın" onclick="viewGithub(<?=htmlspecialchars(json_encode($gh+['_v'=>x_img_v($gh['image']??'')]+x_gal_meta($gh,'image'),JSON_UNESCAPED_UNICODE))?>)"><?=x_rich($gh['description']??'')?:'—'?></button></td><td class="col-cat"><?php if ($gh['category_id']??null): ?><span class="badge badge-b"><?=x_h(x_cat_name($cats,$gh['category_id']))?></span><?php else: ?><span style="color:var(--text3)">—</span><?php endif; ?></td><td class="col-pass"><?php if (!empty($gh['encrypted'])):?><span class="badge badge-r"><?=svg('lock',9)?> Şifreli</span><?php else:?><span class="badge badge-g"><?=svg('unlock',9)?> Açık</span><?php endif;?></td><td class="col-php"><?=x_php_badge($gh['php_version']??'')?></td><td class="github-url-cell"><a href="<?=x_h($gh['url'])?>" target="_blank" rel="noopener noreferrer" class="td-file" title="<?=x_h($gh['url'])?>"><?=x_h($shortUrl)?></a></td><td class="td-date"><?=x_h(date('d.m.y - H:i',strtotime($gh['date_added']??'now')))?></td><td><div style="display:flex;gap:3px"><button class="btn btn-ob btn-xs" type="button" data-github-id="<?=x_h($gh['id'])?>" onclick="copyGithub(this,<?=htmlspecialchars(json_encode($gh['url']))?>)"><?=svg('copy',11)?> Kopyala</button><?php if (x_admin()):?><a class="btn btn-o btn-xs" href="?action=github_edit&id=<?=$gh['id']?>" title="Düzenle" style="color:var(--amber)"><?=svg('edit',11)?></a><a class="btn btn-o btn-xs" href="?action=github_pin&id=<?=$gh['id']?>&tab=github" title="Sabitle" style="color:<?=$gp?'var(--amber)':'var(--text3)'?>"><?=svg('pin',11)?></a><a class="btn btn-or btn-xs" href="?action=github_delete&id=<?=$gh['id']?>&tab=github" onclick="return confirm('Silinsin mi?')" title="Sil"><?=svg('trash',11)?></a><?php endif;?></div></td></tr>
<?php endforeach; ?></tbody></table></div></form>
<?php endif; ?>

<?php else: ?>
<?php if (x_admin()): ?>
<div class="panel">
<button class="panel-toggle" onclick="tPanel(this)"><?=svg('plus',13)?> Yeni Bilgi Ekle<span class="ar"><?=svg('chevron-down',11)?></span></button>
    <div class="panel-body">
        <form method="POST" action="?action=note_add&tab=notes" enctype="multipart/form-data" onsubmit="return prepareRichForm(this,'noteAddEditor')">
            <div class="form-grid">
                <div class="fg"><label>Başlık</label><input type="text" name="title" placeholder="Bilgi başlığı..." required></div>
<div class="fg fw"><label>İçerik</label><div class="rich-editor"><div class="rich-toolbar" role="toolbar" aria-label="İçerik biçimlendirme"><button type="button" onclick="richCmd('bold','noteAddEditor')" title="Kalın"><strong>B</strong></button><button type="button" onclick="richCmd('italic','noteAddEditor')" title="İtalik"><em>I</em></button><button type="button" onclick="richCmd('underline','noteAddEditor')" title="Altı çizili"><u>U</u></button><button type="button" onclick="richCmd('insertUnorderedList','noteAddEditor')" title="Liste">•</button><button type="button" onclick="richCmd('formatBlock','noteAddEditor','h3')" title="Başlık">H</button><select class="rich-size-select" onchange="richCmd('fontSize','noteAddEditor',this.value)" title="Yazı boyutu"><option value="" selected disabled hidden>Boyut</option><option value="2">Küçük</option><option value="3">Normal</option><option value="5">Büyük</option><option value="7">Çok büyük</option></select><input type="color" onchange="richCmd('foreColor','noteAddEditor',this.value)" title="Yazı rengi"></div><div id="noteAddEditor" class="rich-content" contenteditable="true" data-placeholder="Bilgi içeriğini buraya yazın..."></div><textarea name="content" id="noteAddContent" class="rich-value" aria-hidden="true"></textarea></div></div>
                <div class="fg fw"><label>Resim (opsiyonel)</label><div class="file-zone" id="notefz"><?=svg('upload',14)?> <span class="fzt">Görselleri seçmek için tıklayın (birden fazla)</span><span class="fzn" style="display:none"></span><input type="file" name="image[]" multiple accept="image/*" onchange="fu(this,'notefz')"></div><?=x_url_input('image_url')?></div>
                <div class="fg fw"><label>Video (opsiyonel)</label><?=x_video_form('noteAddVfz')?></div>
                <div class="fg fw"><label>Dosya (opsiyonel)</label><div class="file-zone" id="noteAddNf"><?=svg('upload',14)?> <span class="fzt">Dosya seçmek için tıklayın (birden fazla seçilebilir)</span><span class="fzn" style="display:none"></span><input type="file" name="nfile[]" multiple onchange="nfu(this,'noteAddNf')"></div></div>
                <div class="fw"><button class="btn btn-g" type="submit"><?=svg('plus',13)?> Ekle</button></div>
            </div>
        </form>
    </div>
</div>
<?php endif; ?>

<?php if (empty($notes)): ?>
<div class="empty"><?=svg('book',32)?><h3>Henüz bilgi eklenmedi</h3><?php if (x_admin()):?><p>Yukarıdaki formdan bilgi ekleyebilirsiniz.</p><?php endif;?></div>
<?php else: ?>
<form method="POST" action="?action=bulk_delete&tab=notes" class="bulk-form" onsubmit="return confirmBulk(this)"><input type="hidden" name="type" value="notes"><?php if (x_admin()): ?><div class="bulk-toolbar"><button class="btn btn-or btn-xs bulk-delete" type="submit" disabled style="display:none"><?=svg('trash',11)?> Seçilenleri sil</button></div><?php endif; ?>

<div class="table-wrap">
<table class="note-table" id="noteTable" data-type="notes">
<thead><tr>
    <?php if ($canSort): ?><th class="col-drag"></th><?php endif; ?><?php if (x_admin()): ?><th class="select-cell"><input type="checkbox" class="select-all" onchange="toggleBulk(this)" aria-label="Tüm bilgileri seç"></th><?php endif; ?><th class="col-pin"></th>
    <th class="col-thumb"></th>
    <th class="col-n-title">Başlık</th>
    <th class="col-n-content">İçerik</th>
    <th class="col-n-date">Tarih</th>
    <th class="col-n-actions">İşlem</th>
</tr></thead>
<tbody>
<?php foreach ($notes as $note):
    $np=$note['pinned']??false;
    $searchData=x_h(strtolower($note['title'].' '.$note['content'].' '.implode(' ',array_column(x_item_files($note),'name'))));
?>
<tr class="<?=$np?'pinned':''?>" data-id="<?=x_h($note['id'])?>" data-search="<?=$searchData?>">
    <?php if ($canSort): ?><td class="col-drag"><span class="drag-h" title="Sürükleyerek sırala">&#8942;&#8942;</span></td><?php endif; ?><?php if (x_admin()): ?><td class="select-cell"><input type="checkbox" name="ids[]" value="<?=x_h($note['id'])?>" onchange="syncBulk(this)" aria-label="<?=x_h($note['title'])?> seç"></td><?php endif; ?><td class="col-pin"><?php if ($np):?><?=svg('pin',13)?><?php endif;?></td>
    <td class="col-thumb"><?=x_note_thumb($note)?></td>
    <td><button class="note-title note-title-button" type="button" onclick="viewNote(<?=htmlspecialchars(json_encode($note+['_v'=>x_img_v($note['image']??'')]+x_gal_meta($note,'image'),JSON_UNESCAPED_UNICODE))?>)"><?=x_h($note['title'])?></button><?php if (x_item_files($note)): ?><span class="nf-badge" title="Ekli dosya">&#128206; <?=count(x_item_files($note))?></span><?php endif; ?></td>
    <td><button class="note-content td-desc-button" type="button" title="İçeriğin tamamını görmek için tıklayın" onclick="viewNote(<?=htmlspecialchars(json_encode($note+['_v'=>x_img_v($note['image']??'')]+x_gal_meta($note,'image'),JSON_UNESCAPED_UNICODE))?>)"><?=x_rich($note['content'])?:'—'?></button></td>
    <td class="td-date"><?=x_h(date('d.m.y - H:i',strtotime($note['date_added']??'now')))?></td>
    <td>
        <div style="display:flex;gap:3px">
            <button class="btn btn-o btn-xs" onclick="viewNote(<?=htmlspecialchars(json_encode($note+['_v'=>x_img_v($note['image']??'')]+x_gal_meta($note,'image'),JSON_UNESCAPED_UNICODE))?>)" title="Görüntüle"><?=svg('eye',11)?></button>
            <?php if (x_admin()):?>
            <button class="btn btn-o btn-xs" onclick="editNote(<?=htmlspecialchars(json_encode($note+['_v'=>x_img_v($note['image']??'')]+x_gal_meta($note,'image'),JSON_UNESCAPED_UNICODE))?>)" title="D������zenle" style="color:var(--amber)"><?=svg('edit',11)?></button>
            <a class="btn btn-o btn-xs" href="?action=note_pin&id=<?=$note['id']?>&tab=notes" title="<?=$np?'Kaldır':'Sabitle'?>" style="color:<?=$np?'var(--amber)':'var(--text3)'?>"><?=svg('pin',11)?></a>
            <a class="btn btn-or btn-xs" href="?action=note_delete&id=<?=$note['id']?>&tab=notes" onclick="return confirm('Not silinsin mi?')" title="Sil"><?=svg('trash',11)?></a>
            <?php endif;?>
        </div>
    </td>
</tr>
<?php endforeach; ?>
</tbody></table></div></form>
<?php endif; ?>
<?php endif; ?>

    </div>
</main>
</div>

<div class="modal-overlay" id="imgModal" onclick="closeModal()">
    <div class="modal-box" onclick="event.stopPropagation()">
        <img id="modalImg" src="" alt="">
        <button class="modal-close" onclick="closeModal()">&times;</button>
    </div>
</div>

<?php if ($toast): ?><div class="toast <?=($msg==='github_invalid'||$msg==='settings_none'||!empty($_GET['imgerr'])||!empty($_GET['viderr']))?'error':''?>"><?=$toast?></div><?php endif; ?>

<style>
  .toast{background:#14532d!important;border:1px solid #22c55e!important;color:#dcfce7!important}
  .toast.error{background:#7f1d1d!important;border-color:#ef4444!important;color:#fee2e2!important}
  *{scrollbar-color:var(--border) var(--surface2);scrollbar-width:thin}*::-webkit-scrollbar{width:8px;height:8px}*::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}*::-webkit-scrollbar-thumb:hover{background:var(--green)}*::-webkit-scrollbar-track{background:var(--surface2)}.rich-editor{border:1px solid var(--border);border-radius:6px;overflow:hidden;background:var(--surface2)}.rich-toolbar{display:flex;align-items:center;gap:4px;padding:6px;border-bottom:1px solid var(--border);background:var(--surface)}.rich-toolbar button,.rich-toolbar select,.rich-toolbar input{height:28px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text2);font:12px var(--mono);cursor:pointer}.rich-toolbar button{min-width:28px}.rich-toolbar button:hover,.rich-toolbar select:hover,.rich-toolbar select:focus{border-color:var(--green);color:var(--green)}.rich-toolbar .rich-size-select{min-width:76px;width:76px;padding:0 22px 0 7px;overflow:visible;text-overflow:clip;white-space:nowrap}.rich-toolbar input{width:32px;padding:2px}.rich-content{min-height:90px;max-height:320px;padding:10px;color:var(--text);font-size:13px;line-height:1.6;outline:none;overflow:auto;scrollbar-color:var(--border) var(--surface2);scrollbar-width:thin}.rich-content::-webkit-scrollbar{width:8px}.rich-content::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}.rich-content::-webkit-scrollbar-track{background:var(--surface2)}.rich-content:empty:before{content:attr(data-placeholder);color:var(--text3);pointer-events:none}.rich-editor:focus-within{border-color:var(--red);box-shadow:0 0 0 2px rgba(239,68,68,.18),inset 0 0 0 1px rgba(239,68,68,.28)}.rich-content:focus{box-shadow:none}.rich-content h3{margin:8px 0;color:var(--green)}.rich-content ul{padding-left:22px}.rich-value{display:none}.github-modal-box{width:min(900px,94vw);max-height:90vh;overflow:auto;padding:22px;background:var(--surface);border:1px solid var(--border)}
  .archive-open-button{background:none;border:0;padding:0;cursor:pointer;font:inherit;text-align:left}.archive-open-button:hover,.github-title-button:hover{color:#b91c1c}.github-title-button{background:none;border:0;padding:0;cursor:pointer;font:inherit;text-align:left}.github-url-cell{max-width:170px}.github-url-cell .td-file{display:block;max-width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .archive-detail-image{display:block;width:100%;max-height:300px;object-fit:contain;border-radius:8px;margin:0 auto 14px;background:var(--surface2);cursor:pointer}
  .archive-detail-description,.archive-code-panel pre{scrollbar-color:var(--border) var(--surface2);scrollbar-width:thin}.archive-code-panel pre{max-height:360px;overflow:auto;white-space:pre-wrap;word-break:break-word;line-height:1.5;margin:0;background:#0c0e14;border:1px solid var(--border);border-radius:6px;padding:12px;color:var(--text2);font:11px var(--mono)}
  .github-modal-box::-webkit-scrollbar,.github-modal-box pre::-webkit-scrollbar,.github-detail-description::-webkit-scrollbar,.archive-detail-description::-webkit-scrollbar{width:8px;height:8px}.github-detail-description,.archive-detail-description,.github-modal-box pre{scrollbar-color:var(--border) var(--surface2);scrollbar-width:thin}.archive-detail-description{max-height:260px;overflow:auto;white-space:pre-wrap;word-break:break-word;padding:14px;background:#0c0e14;border:1px solid var(--border);border-radius:8px;color:var(--text2);line-height:1.7}.note-detail-image{display:block;max-width:100%;max-height:280px;object-fit:contain;border-radius:8px;margin:0 auto 14px;cursor:pointer}.github-modal-box::-webkit-scrollbar,.github-modal-box pre::-webkit-scrollbar.github-modal-box::-webkit-scrollbar-thumb,.github-modal-box pre::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}.github-modal-box::-webkit-scrollbar-track,.github-modal-box pre::-webkit-scrollbar-track{background:var(--surface2)}.td-desc-button{display:block;width:100%;border:0;background:none;color:inherit;font:inherit;text-align:left;padding:0;cursor:pointer}.img-remove{display:inline-block;white-space:nowrap;color:var(--red);font-size:9px;margin-top:3px}.img-remove:hover{text-decoration:underline}.td-desc-button:hover{color:var(--green)}.td-desc-button>*:first-child{margin-top:0}.td-desc-button{display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;overflow:hidden;max-height:3.2em}
#githubModalContent{min-width:0}.github-detail-description{max-height:220px;overflow:auto;white-space:pre-wrap;word-break:break-word;padding:12px;background:#0c0e14;border:1px solid var(--border);border-radius:6px;margin-bottom:12px}.github-code-panel{position:relative}.github-code-panel pre{max-height:330px;overflow:auto;white-space:pre-wrap;word-break:break-word;line-height:1.5;margin:0}.github-code-label{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.08em}.github-code-heading{display:flex;align-items:center;justify-content:space-between;margin-bottom:5px}.icon-copy{display:flex;align-items:center;justify-content:center;width:28px;height:26px;border:1px solid var(--border);border-radius:5px;background:var(--surface2);color:var(--text2);cursor:pointer}.icon-copy:hover{border-color:var(--red);color:var(--red)}.icon-copy svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:1.8}
  .table-wrap{width:100%;max-width:100%;max-height:max(260px,calc(100vh - 330px));overflow:auto;scrollbar-color:var(--border) var(--surface2);scrollbar-width:thin;border-radius:var(--r)}.table-wrap::-webkit-scrollbar{width:8px;height:8px}.table-wrap::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}.table-wrap::-webkit-scrollbar-thumb:hover{background:var(--amber)}.table-wrap::-webkit-scrollbar-track{background:var(--surface2)}.table-wrap table{width:100%;border-collapse:separate;border-spacing:0}.table-wrap thead th{position:sticky;top:0;z-index:2;background:var(--surface);box-shadow:0 1px 0 var(--border)}.table-wrap .col-actions{min-width:132px}.table-wrap .col-pin{width:28px;min-width:28px}.table-wrap td.col-actions>div,.table-wrap td.col-actions .row-actions{white-space:nowrap}#dosyaTable,#githubTable,.note-table{min-width:900px}.bulk-toolbar{display:flex;align-items:center;justify-content:flex-start;gap:10px;width:100%;margin:0 0 10px;padding:0;background:transparent;border:0;border-radius:0}.bulk-toolbar label{display:flex;align-items:center;gap:7px;color:var(--text2);font-size:12px;cursor:pointer}.bulk-toolbar .bulk-delete{margin:0}.select-cell{width:34px;min-width:34px;text-align:center;white-space:nowrap}.select-cell input{appearance:none;-webkit-appearance:none;width:14px;height:14px;margin:0;border:1px solid #4b5060;border-radius:3px;background:#282c36;box-shadow:inset 0 0 0 1px #171a22;cursor:pointer;vertical-align:middle}.select-cell input:hover{border-color:#73798a;background:#333846}.select-cell input:checked{background:#6b7280;border-color:#9ca3af;box-shadow:inset 0 0 0 3px #282c36}.select-cell input:focus-visible{outline:2px solid var(--green);outline-offset:2px}.select-cell .bulk-delete{margin-left:6px;vertical-align:middle;text-transform:none}.note-table{min-width:760px}td.col-actions a[href*="action=pin"],td.col-actions a[href*="action=note_pin"],td.col-actions a[href*="action=github_pin"]{color:var(--amber)!important}.table-wrap td.col-actions a[href*="action=pin"]:hover,.table-wrap td.col-actions a[href*="action=note_pin"]:hover,.table-wrap td.col-actions a[href*="action=github_pin"]:hover{border-color:var(--amber);color:var(--amber)!important}@media(max-width:768px){.table-wrap{max-height:max(220px,calc(100vh - 260px))}}@media(max-height:480px){.table-wrap{max-height:max(180px,calc(100vh - 150px))}.main-top{padding:8px 12px}.tabs{padding:0 12px}.tabs a{padding:8px 10px}.main-body{padding:8px 12px}}.toggle-row.php-ver-row input.php-ver-input[type=text]{width:68px;min-width:68px;max-width:68px;padding:5px 7px;background:#0c0e14;border:1px solid var(--border);border-radius:var(--r-sm);color:var(--text2);font-size:11px;font-family:var(--mono);box-sizing:border-box}.php-ver-row .php-ver-input:focus{outline:none;border-color:var(--green)}
.table-wrap th.select-cell,.table-wrap td.select-cell{width:24px;min-width:24px;max-width:24px;padding-left:2px!important;padding-right:2px!important}
.table-wrap th.col-pin,.table-wrap td.col-pin{width:18px;min-width:18px;max-width:18px;padding-left:0!important;padding-right:0!important}
.table-wrap th.col-thumb,.table-wrap td.col-thumb{width:40px;min-width:40px;padding-left:2px!important;padding-right:4px!important}
</style>
<div class="modal-overlay" id="githubModal" onclick="this.classList.remove('open')">
    <div class="modal-box github-modal-box" onclick="event.stopPropagation()">
        <div id="githubModalContent"></div>
        <button class="modal-close" onclick="document.getElementById('githubModal').classList.remove('open')">&times;</button>
    </div>
</div>

<style>.nf-list{margin-top:12px;border:1px solid var(--border);border-radius:8px;overflow:hidden}.nf-title{padding:8px 12px;font-size:11px;font-weight:700;color:var(--text2);background:var(--surface2)}.nf-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-top:1px solid var(--border);color:var(--text2);text-decoration:none;font-size:12px}.nf-item:hover{background:rgba(183,28,28,.08)}.nf-nm{flex:1;min-width:0;word-break:break-all}.nf-sz{color:var(--text3);font-size:11px;white-space:nowrap}.nf-dl{padding:3px 9px;border:1px solid #b71c1c;border-radius:5px;color:#ff5c65;font-size:11px;white-space:nowrap}.nf-badge{margin-left:6px;font-size:10px;color:var(--text3);white-space:nowrap}</style>
<?=x_vid_assets()?><div class="modal-overlay" id="noteModal" onclick="this.classList.remove('open');vidStopAll()">
    <div class="modal-box" onclick="event.stopPropagation()" style="min-width:400px;max-width:700px">
        <div id="noteModalContent"></div>
        <button class="modal-close" onclick="document.getElementById('noteModal').classList.remove('open');vidStopAll()">&times;</button>
    </div>
</div>

<div class="modal-overlay" id="noteEditModal" onclick="this.classList.remove('open')">
    <div class="modal-box" onclick="event.stopPropagation()" style="min-width:400px;max-width:700px">
        <form method="POST" action="?action=note_edit&tab=notes" id="noteEditForm" enctype="multipart/form-data" onsubmit="return prepareRichForm(this,'noteEditEditor')">
            <input type="hidden" name="id" id="noteEditId">
            <div class="form-grid" style="grid-template-columns:1fr">
                <div class="fg"><label>Başlık</label><input type="text" name="title" id="noteEditTitle" required></div>
                <div class="fg"><label>İçerik</label><div class="rich-editor"><div class="rich-toolbar" role="toolbar" aria-label="İçerik biçimlendirme"><button type="button" onclick="richCmd('bold','noteEditEditor')" title="Kalın"><strong>B</strong></button><button type="button" onclick="richCmd('italic','noteEditEditor')" title="İtalik"><em>I</em></button><button type="button" onclick="richCmd('underline','noteEditEditor')" title="Altı çizili"><u>U</u></button><button type="button" onclick="richCmd('insertUnorderedList','noteEditEditor')" title="Liste">•</button><button type="button" onclick="richCmd('formatBlock','noteEditEditor','h3')" title="Başlık">H</button><select class="rich-size-select" onchange="richCmd('fontSize','noteEditEditor',this.value)" title="Yazı boyutu"><option value="" selected disabled hidden>Boyut</option><option value="2">Küçük</option><option value="3">Normal</option><option value="5">Büyük</option><option value="7">Çok büyük</option></select><input type="color" onchange="richCmd('foreColor','noteEditEditor',this.value)" title="Yazı rengi"></div><div id="noteEditEditor" class="rich-content" contenteditable="true" data-placeholder="Bilgi içeriğini buraya yazın..."></div><textarea name="content" id="noteEditContent" class="rich-value" aria-hidden="true"></textarea></div></div>
                <div class="fg fw"><label>Resimler (opsiyonel)</label><?=x_gal_js()?><div id="noteEditGal"></div><div class="file-zone" id="noteEditFz"><?=svg('upload',14)?> <span class="fzt">Görselleri seçmek için tıklayın (birden fazla)</span><span class="fzn" style="display:none"></span><input type="file" name="image[]" multiple accept="image/*" onchange="fu(this,'noteEditFz')"></div><?=x_url_input('image_url')?></div>
                <div class="fg fw"><label>Video (opsiyonel)</label><div id="noteEditVid"></div><?=x_video_form('noteEditVfz')?></div>
                <div class="fg fw"><label>Dosyalar (opsiyonel)</label><div id="noteEditFiles"></div><div class="file-zone" id="noteEditNf"><?=svg('upload',14)?> <span class="fzt">Dosya seçmek için tıklayın (birden fazla seçilebilir)</span><span class="fzn" style="display:none"></span><input type="file" name="nfile[]" multiple onchange="nfu(this,'noteEditNf')"></div></div>
                <div class="fw"><button class="btn btn-g" type="submit"><?=svg('check',13)?> Kaydet</button></div>
            </div>
        </form>
        <button class="modal-close" onclick="document.getElementById('noteEditModal').classList.remove('open')">&times;</button>
    </div>
</div>

<script>

(function(){
var cur=null;
function rowsOf(tb,except){return Array.prototype.filter.call(tb.children,function(r){return r!==except&&r.tagName==='TR'&&r.style.display!=='none'})}
document.addEventListener('pointerdown',function(e){
    var h=e.target.closest&&e.target.closest('.drag-h');if(!h||(e.pointerType==='mouse'&&e.button!==0))return;
    var row=h.closest('tr'),tb=row.parentNode,wrap=row.closest('.table-wrap');
    e.preventDefault();
    cur={row:row,tb:tb,wrap:wrap,h:h,id:e.pointerId,y:e.clientY,moved:false,raf:0};
    try{h.setPointerCapture(e.pointerId)}catch(x){}
    row.classList.add('dragging');document.body.classList.add('drag-on');
    h.addEventListener('pointermove',mv);h.addEventListener('pointerup',up);h.addEventListener('pointercancel',up);
    tick();
});
function place(){
    var c=cur;if(!c)return;
    var list=rowsOf(c.tb,c.row),before=null;
    for(var i=0;i<list.length;i++){var r=list[i].getBoundingClientRect();if(c.y<r.top+r.height/2){before=list[i];break}}
    if(before){if(c.row.nextElementSibling!==before)c.tb.insertBefore(c.row,before)}
    else if(c.row!==c.tb.lastElementChild)c.tb.appendChild(c.row);
}
function mv(e){if(!cur)return;cur.y=e.clientY;cur.moved=true;place()}
function tick(){
    if(!cur)return;
    var w=cur.wrap;
    if(w){var r=w.getBoundingClientRect(),d=0;if(cur.y<r.top+50)d=-12;else if(cur.y>r.bottom-50)d=12;if(d){w.scrollTop+=d;place()}}
    cur.raf=requestAnimationFrame(tick);
}
function up(){
    var c=cur;if(!c)return;cur=null;cancelAnimationFrame(c.raf);
    c.h.removeEventListener('pointermove',mv);c.h.removeEventListener('pointerup',up);c.h.removeEventListener('pointercancel',up);
    c.row.classList.remove('dragging');document.body.classList.remove('drag-on');
    if(!c.moved)return;
    var table=c.tb.closest('table'),fd=new URLSearchParams();
    fd.append('type',table.dataset.type);
    Array.prototype.forEach.call(c.tb.children,function(r){if(r.dataset.id)fd.append('ids[]',r.dataset.id)});
    fetch('?action=reorder',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
    .then(function(r){return r.json()}).then(function(j){sortToast(j&&j.ok?'Sıralama kaydedildi':'Sıralama kaydedilemedi',!(j&&j.ok))})
    .catch(function(){sortToast('Sıralama kaydedilemedi',true)});
}
function sortToast(t,err){var d=document.createElement('div');d.className='toast'+(err?' error':'');d.textContent=t;document.body.appendChild(d);setTimeout(function(){d.remove()},2600)}
})();
function togglePhpVer(cb){var row=cb.closest('.php-ver-row');if(!row)return;var inp=row.querySelector('.php-ver-input');if(!inp)return;if(cb.checked){inp.disabled=false;inp.style.display='';inp.focus()}else{inp.disabled=true;inp.style.display='none';inp.value=''}}
function tPanel(btn){btn.classList.toggle('open');btn.nextElementSibling.classList.toggle('open')}
function bulkBoxes(form){return Array.from(form.querySelectorAll('input[name="ids[]"]'))}

function syncBulk(input){var form=input.closest('.bulk-form');if(!form)return;var boxes=bulkBoxes(form),count=boxes.filter(function(b){return b.checked}).length;form.querySelectorAll('.bulk-delete').forEach(function(b){b.disabled=count===0;b.style.display=count?'':'none'});form.querySelectorAll('.select-all').forEach(function(b){b.checked=boxes.length>0&&count===boxes.length})}
function toggleBulk(master){var form=master.closest('.bulk-form');if(!form)return;bulkBoxes(form).forEach(function(b){b.checked=master.checked});syncBulk(bulkBoxes(form)[0]||master)}
function confirmBulk(form){var count=bulkBoxes(form).filter(function(b){return b.checked}).length;return count>0&&confirm(count+' seçili kayıt silinsin mi?')}
function richCmd(command,id,value){var editor=document.getElementById(id);if(!editor)return;editor.focus();document.execCommand(command,false,value||null);syncRich(editor)}
function syncRich(editor){var target=editor.dataset.target?document.querySelector('[name="'+editor.dataset.target+'"]'):document.getElementById(editor.id==='noteEditEditor'?'noteEditContent':'noteAddContent');if(target)target.value=editor.innerHTML}
function prepareRichForm(form,editorId){var editor=document.getElementById(editorId);if(editor)syncRich(editor);return true}
document.addEventListener('input',function(e){if(e.target&&e.target.classList&&e.target.classList.contains('rich-content'))syncRich(e.target)});document.querySelectorAll('.rich-content').forEach(function(e){syncRich(e)});
function fu(i,id){var a=document.getElementById(id),n=a.querySelector('.fzn'),t=a.querySelector('.fzt');
if(i.files.length){a.classList.add('has');n.textContent=i.files.length>1?i.files.length+(/^video/.test(i.name)?' video':' resim')+' seçildi':i.files[0].name;n.style.display='';t.style.display='none'}
else{a.classList.remove('has');n.style.display='none';t.style.display=''}}

function fitTables(){
    var ws=document.querySelectorAll('.table-wrap');
    for(var i=0;i<ws.length;i++){
        var w=ws[i];if(w.offsetParent===null)continue;
        var top=w.getBoundingClientRect().top+(window.pageYOffset||0);
        w.style.maxHeight=Math.max(220,Math.floor(window.innerHeight-top-16))+'px';
    }
}
window.addEventListener('load',fitTables);window.addEventListener('resize',fitTables);window.addEventListener('orientationchange',fitTables);
document.addEventListener('click',function(){setTimeout(fitTables,60)});
fitTables();
document.getElementById('search').addEventListener('input',function(e){
var q=e.target.value.toLowerCase();
['dosyaTable','noteTable','githubTable'].forEach(function(id){var t=document.getElementById(id);
if(t) t.querySelectorAll('tbody tr').forEach(r=>{r.style.display=(r.dataset.search||'').includes(q)?'':'none'})})
})

function showModal(src){document.getElementById('githubModal').classList.remove('open');document.getElementById('noteModal').classList.remove('open');document.getElementById('noteEditModal').classList.remove('open');document.getElementById('modalImg').src=src;document.getElementById('imgModal').classList.add('open')}
function closeModal(){document.getElementById('imgModal').classList.remove('open')}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeModal()})

function galHtml(type,it,cls,style){
    var n=it._n||0;if(!n)return '';
    var base='?action=gimg&type='+type+'&id='+encodeURIComponent(it.id)+'&v='+(it._gv||0);
    var h='<div class="gal"><img class="gal-main '+(cls||'')+'" style="'+(style||'')+'" src="'+base+'&n=0" alt="" onclick="showModal(this.src)">';
    if(n>1){h+='<div class="gal-strip">';for(var i=0;i<n;i++)h+='<img class="gal-th'+(i?'':' on')+'" src="'+base+'&n='+i+'&t=1" alt="" loading="lazy" onclick="galPick(this)">';h+='</div>'}
    return h+'</div>';
}
function galPick(el){var g=el.closest('.gal'),m=g.querySelector('.gal-main');m.src=el.src.replace('&t=1','');var t=g.querySelectorAll('.gal-th');for(var j=0;j<t.length;j++)t[j].classList.toggle('on',t[j]===el)}
function galEditHtml(type,it){
    var n=it._n||0;if(!n)return '';
    var id=encodeURIComponent(it.id),base='?action=gimg&type='+type+'&id='+id+'&v='+(it._gv||0);
    var h='<div class="gal-wrap"><div class="gal-bar"><label style="display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" class="gal-all" onchange="galSel(this)"> Tümünü seç</label><button type="button" class="gal-del" disabled onclick="galAct(this,\'?action=img_bulk_remove&type='+type+'&id='+id+'\',\'Seçili resimler silinsin mi?\')">Seçilenleri sil</button></div><div class="gal-e">';
    for(var i=0;i<n;i++){
        h+='<div class="gal-i'+((i||it.main_video!=null)?'':' main')+'"><input type="checkbox" class="gk" name="ns[]" value="'+i+'" onchange="galSel(this)"><img src="'+base+'&n='+i+'&t=1" alt="">';
        h+=(i||it.main_video!=null)?'<button type="button" class="gm" onclick="galAct(this,\'?action=img_main&type='+type+'&id='+id+'&n='+i+'\')">Ana yap</button>':'<span class="gl">Ana resim</span>';
        h+='</div>';
    }
    return h+'</div></div>';
}
function viewDescription(description){
    var modal=document.getElementById('githubModal'), content=document.getElementById('githubModalContent');
    content.innerHTML='<div class="archive-detail-description">'+(description||'Açıklama yok')+'</div>';
    modal.classList.add('open');
  }
function viewdosya(dosya){
    var c=document.getElementById('githubModalContent');
    var name=String(dosya.name||'İsimsiz Dosya').replace(/[<>&]/g,function(x){return {'<':'&lt;','>':'&gt;','&':'&amp;'}[x]});
    var image=galHtml('dosya',dosya,'archive-detail-image');
    c.innerHTML='<h3 style="color:var(--green);margin-bottom:8px">'+name+'</h3>'+image+'<div class="archive-detail-description">'+(dosya.description||'Açıklama yok')+'</div>'+(dosya.show_code!==false?'<div class="archive-code-panel" style="margin-top:12px"><div class="github-code-heading"><div class="github-code-label">Kod içeriği</div><button class="icon-copy" type="button" title="Kodu kopyala" aria-label="Kodu kopyala" onclick="copyCode(this)"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"></rect><path d="M5 15V5a2 2 0 0 1 2-2h10"></path></svg></button></div><pre id="archiveCode">Kod yükleniyor...</pre></div>':'');
    document.getElementById('githubModal').classList.add('open');
    if(dosya.show_code!==false)fetch('?action=archive_content&id='+encodeURIComponent(dosya.id)).then(function(r){return r.text()}).then(function(t){var code=document.getElementById('archiveCode');if(code)code.textContent=t}).catch(function(){var code=document.getElementById('archiveCode');if(code)code.textContent='Kod yüklenemedi.'});
  }
function copyGithub(button,url){
    var githubRow=button.closest('tr'), githubName=githubRow?((githubRow.querySelector('.github-title-button')||{}).textContent||''):' '; 
    fetch('?action=analytics_event',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'type=github&event=copy&id='+encodeURIComponent(button.dataset.githubId||url)+'&label='+encodeURIComponent(githubName.trim()||url)}).catch(function(){});
    function done(){var old=button.innerHTML;button.textContent='Kopyalandı';button.classList.add('copied');setTimeout(function(){button.innerHTML=old;button.classList.remove('copied')},1500)}
    if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(url).then(done)}else{var a=document.createElement('textarea');a.value=url;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();done()}
}
function viewGithub(g){
  fetch('?action=analytics_event',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'type=github&event=read&id='+encodeURIComponent(g.id||'')+'&label='+encodeURIComponent(g.name||'')}).catch(function(){});
    var c=document.getElementById('githubModalContent'), safeName=String(g.name||'').replace(/[<>&]/g,function(x){return {'<':'&lt;','>':'&gt;','&':'&amp;'}[x]});
    var image=galHtml('github',g,'','max-width:100%;max-height:300px;object-fit:contain;border-radius:6px;cursor:pointer');
    c.innerHTML='<h3 style="color:var(--green);margin-bottom:8px">'+safeName+'</h3>'+image+'<div class="github-detail-description">'+(g.description||'Açıklama yok')+'</div>'+(g.show_code!==false?'<div class="github-code-panel"><div class="github-code-heading"><div class="github-code-label">Kod bilgileri</div><button class="icon-copy" type="button" title="Kodu kopyala" aria-label="Kodu kopyala" onclick="copyCode(this)"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"></rect><path d="M5 15V5a2 2 0 0 1 2-2h10"></path></svg></button></div><pre id="githubCode" style="white-space:pre-wrap;word-break:break-word;max-height:360px;overflow:auto;background:#0c0e14;border:1px solid var(--border);border-radius:6px;padding:12px;color:var(--text2);font:11px var(--mono)">Kod yükleniyor...</pre></div>':'');
    document.getElementById('githubModal').classList.add('open');
    if(g.show_code!==false)fetch(g.url).then(function(r){return r.text()}).then(function(t){var code=document.getElementById('githubCode');if(code)code.textContent=t}).catch(function(){var code=document.getElementById('githubCode');if(code)code.textContent='Kod yüklenemedi. Raw bağlantıyı kontrol edin.'});
}
function copyCode(button){copyText(button,document.getElementById('githubCode').textContent)}
function copyText(button,text){if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(function(){button.textContent='Kopyalandı'})}else{var a=document.createElement('textarea');a.value=text;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();button.textContent='Kopyalandı'}}
function nfEsc(t){return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function nfSize(b){b=+b||0;return b>=1073741824?(b/1073741824).toFixed(2)+' GB':(b>=1048576?(b/1048576).toFixed(1)+' MB':Math.max(1,Math.round(b/1024))+' KB')}
function nfu(i,id){var a=document.getElementById(id),n=a.querySelector('.fzn'),t=a.querySelector('.fzt');if(i.files.length){a.classList.add('has');n.textContent=i.files.length>1?i.files.length+' dosya seçildi':i.files[0].name;n.style.display='';t.style.display='none'}else{a.classList.remove('has');n.style.display='none';t.style.display=''}}
function nfHtml(note){
    var f=note.files||[];if(!f.length)return '';
    var id=encodeURIComponent(note.id),h='<div class="nf-list"><div class="nf-title">Dosyalar ('+f.length+')</div>';
    for(var i=0;i<f.length;i++)h+='<a class="nf-item" href="?action=nfile&id='+id+'&n='+i+'" title="İndir"><span class="nf-nm">&#128206; '+nfEsc(f[i].name)+'</span><span class="nf-sz">'+nfSize(f[i].size)+'</span><span class="nf-dl">İndir</span></a>';
    return h+'</div>';
}
function nfEditHtml(note){
    var f=note.files||[];if(!f.length)return '';
    var id=encodeURIComponent(note.id);
    var h='<div class="gal-wrap" style="margin-bottom:8px"><div class="gal-bar"><label style="display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" class="gal-all" onchange="galSel(this)"> Tüm dosyaları seç</label><button type="button" class="gal-del" disabled onclick="galAct(this,\'?action=nfile_remove&id='+id+'\',\'Seçili dosyalar silinsin mi?\')">Seçilenleri sil</button></div>';
    for(var i=0;i<f.length;i++)h+='<div class="vid-row"><input type="checkbox" class="gk" name="fns[]" value="'+i+'" onchange="galSel(this)"><span style="flex:1">&#128206; '+nfEsc(f[i].name)+' <span class="nf-sz">'+nfSize(f[i].size)+'</span></span><a class="vid-mk" href="?action=nfile&id='+id+'&n='+i+'">İndir</a></div>';
    return h+'</div>';
}
function viewNote(note){
    fetch('?action=analytics_event',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'type=note&event=read&id='+encodeURIComponent(note.id||'')+'&label='+encodeURIComponent(note.title||'')}).catch(function(){});
var noteImage=galHtml('note',note,'note-detail-image');
    document.getElementById('noteModalContent').innerHTML='<h3 style="color:var(--green);margin-bottom:8px">'+note.title.replace(/</g,'&lt;')+'</h3>'+(note.main_video!=null?vpHtml(note)+noteImage:noteImage+vpHtml(note))+'<div class="archive-detail-description">'+(note.content||'Açıklama yok')+'</div>'+nfHtml(note)+'<div style="margin-top:10px;font-size:10px;color:var(--text3)">'+ (note.date_added ? new Date(note.date_added.replace(' ','T')).toLocaleString('tr-TR',{day:'2-digit',month:'2-digit',year:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).replace(/,\s*|\s+(?=\d{2}:\d{2}$)/,' - ') : '')+'</div>';
    vpInit(document.getElementById('noteModalContent'));
    document.getElementById('noteModal').classList.add('open')
}
function editNote(note){
    document.getElementById('noteEditId').value=note.id;
    document.getElementById('noteEditTitle').value=note.title;
    document.getElementById('noteEditEditor').innerHTML=note.content||'';
    document.getElementById('noteEditContent').value=note.content||'';
    document.getElementById('noteEditForm').action='?action=note_edit&id='+note.id+'&tab=notes';
    var _u=document.querySelector('#noteEditForm textarea.img-url');if(_u)_u.value='';var _gf=document.querySelector('#noteEditForm input[type=file]');if(_gf){_gf.value='';fu(_gf,'noteEditFz')}var _gg=document.getElementById('noteEditGal');if(_gg)_gg.innerHTML=galEditHtml('note',note);var _vv=document.getElementById('noteEditVid');if(_vv)_vv.innerHTML=vidEditHtml(note);var _nfl=document.getElementById('noteEditFiles');if(_nfl)_nfl.innerHTML=nfEditHtml(note);var _nff=document.querySelector('#noteEditForm input[name="nfile[]"]');if(_nff){_nff.value='';nfu(_nff,'noteEditNf')}var _vf=document.querySelector('#noteEditForm input[name="video[]"]');if(_vf){_vf.value='';fu(_vf,'noteEditVfz')}var _vu=document.querySelector('#noteEditForm textarea[name=video_url]');if(_vu)_vu.value='';
    document.getElementById('noteEditModal').classList.add('open')
}
</script>
<?=x_upload_assets()?>
</body></html>
<?php
function x_login_page($err=false) {
    $shake=$err?'shake':'';
    ?><!DOCTYPE html><html lang="tr"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title><?=APP_NAME?></title>
    <style>
        :root{--bg:#0a0b0f;--surface:#111318;--border:#1e2130;--text:#8b8fa3;--text2:#d1d5e0;--green:#b71c1c;--glow:#b71c1c30}
        *{margin:0;padding:0;box-sizing:border-box}
        body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;overflow:hidden}
        .bg{position:fixed;inset:0;background:radial-gradient(ellipse at 25% 30%,#b71c1c04 0%,transparent 55%),radial-gradient(ellipse at 70% 70%,#448aff03 0%,transparent 55%)}
        .bg::after{content:'';position:absolute;inset:0;background-image:linear-gradient(#ffffff03 1px,transparent 1px),linear-gradient(90deg,#ffffff03 1px,transparent 1px);background-size:50px 50px}
        .wrap{position:relative;z-index:1;width:380px;max-width:95vw;padding:16px}
        .card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:36px 28px;box-shadow:0 0 0 1px #ffffff03,0 8px 32px #00000040}
        .icon{width:44px;height:44px;margin:0 auto 16px;display:flex;align-items:center;justify-content:center;background:var(--glow);border-radius:10px;color:var(--green)}
        .card h1{text-align:center;color:var(--text2);font-size:20px;font-weight:800;letter-spacing:-.5px;margin-bottom:2px}
        .card h1 b{color:var(--green)}
        .card .sub{text-align:center;color:var(--text);font-size:12px;margin-bottom:24px}
        .card input[type=password]{width:100%;padding:13px 15px;background:#0c0e14;border:1px solid var(--border);border-radius:8px;color:var(--text2);font-size:14px;outline:none;text-align:center;transition:.2s}
        .card input[type=password]:focus{border-color:var(--green);box-shadow:0 0 0 3px var(--glow)}
        .card input::placeholder{color:#3a3d4a}
        .card button{width:100%;margin-top:14px;padding:13px;background:var(--green);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;transition:.2s}
        .card button:hover{filter:brightness(1.1);box-shadow:0 3px 16px var(--glow)}
        .hint{text-align:center;margin-top:18px;font-size:11px;color:#3a3d4a}.hint span{color:var(--text)}
        .shake{animation:sh .4s ease}
        @keyframes sh{0%,100%{transform:translateX(0)}20%{transform:translateX(-5px)}40%{transform:translateX(5px)}60%{transform:translateX(-3px)}80%{transform:translateX(3px)}}table tr.pinned td {
    background: var(--amber-bg);
    height: 58px;
}td.col-actions {
    height: 60px;
}
    </style></head><body>
    <div class="bg"></div>
    <div class="wrap"><div class="card <?=$shake?>">
        <div class="icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
        <h1><b>Exlonea-</b>2026</h1><p class="sub">Yönetim</p>
        <form method="POST"><input type="password" name="password" placeholder="Erişim anahtarı" autofocus autocomplete="off"><button type="submit">Panele Bağlan</button></form>
    </div></div></body></html>
    <?php exit;
}

function x_preview_page($dosya,$content,$cats) {
    $ext=pathinfo($dosya['original_name']??'',PATHINFO_EXTENSION);
    $lines=count(preg_split('/\R/',$content));
    $bytes=strlen($content);
    ?><!DOCTYPE html><html lang="tr"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title><?=x_h($dosya['name'])?> — <?=APP_NAME?></title>
    <style>
        :root{--bg:#0a0b0f;--surface:#111318;--border:#1e2130;--text:#8b8fa3;--text2:#d1d5e0;--green:#b71c1c;--red:#ff5252;--mono:'JetBrains Mono','Fira Code','Consolas',monospace;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
        *{margin:0;padding:0;box-sizing:border-box}
        body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh}
        .bar{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10;gap:12px;flex-wrap:wrap}
        .bar-l{display:flex;align-items:center;gap:10px}.bar h2{color:var(--green);font-size:14px;font-weight:700;font-family:var(--font)}
        .pills{display:flex;gap:6px;flex-wrap:wrap}
        .pill{font-size:10px;padding:3px 8px;border-radius:4px;font-weight:700;font-family:var(--font);letter-spacing:.3px;display:inline-flex;align-items:center;gap:4px}
        .pill-r{background:#5b0b0b;color:#ff4d4d}.pill-g{background:#b71c1c15;color:var(--green)}.pill-b{background:#0c0e14;color:var(--text)}
        .bar-r{display:flex;gap:6px}
        .btn{display:inline-flex;align-items:center;gap:5px;padding:7px 13px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--border);text-decoration:none;font-family:var(--font);transition:.12s;color:var(--text2);background:transparent}
        .btn:hover{border-color:var(--green);color:var(--green)}
        .btn-g{background:var(--green);color:#fff;border-color:var(--green)}.btn-g:hover,.btn-g:focus-visible{filter:brightness(1.1);color:#fff;border-color:var(--green)}
        .desc-m{margin:0 16px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:8px;font-family:var(--font)}
        .desc-m .lbl{font-size:10px;color:#555;text-transform:uppercase;letter-spacing:1px;margin-bottom:3px}
        .desc-m .val{font-size:13px;color:var(--text2)}
        .wrap{max-width:1100px;margin:0 auto;padding:20px}
        .ss-wrap{margin:0 16px 16px;display:flex;justify-content:center;align-items:center}
        .ss-wrap img{display:block;width:auto;max-width:100%;max-height:360px;object-fit:contain;border-radius:8px;border:1px solid var(--border)}
        .code-h{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;background:#0d0f16;border:1px solid var(--border);border-radius:8px 8px 0 0;border-bottom:none;font-family:var(--font)}
  .code-actions{display:flex;align-items:center;gap:10px}.copy-btn{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--border);border-radius:5px;padding:5px 9px;background:transparent;color:var(--text2);font:600 11px var(--font);cursor:pointer;transition:.12s}.copy-btn:hover,.copy-btn:focus-visible{border-color:var(--green);color:#fff;outline:none}.copy-btn.copied{color:#fff;background:var(--green);border-color:var(--green)}
        .code-h .lang{font-size:11px;color:#555;text-transform:uppercase;letter-spacing:1px}
        .code-h .stats{font-size:11px;color:#555}
        .code-b{background:#0c0e14;border:1px solid var(--border);border-radius:0 0 8px 8px;padding:18px 20px;max-height:min(60vh,560px);overflow:auto;overscroll-behavior:contain}
        .code-b pre{color:var(--text2);font-size:12.5px;line-height:1.7;white-space:pre-wrap;word-break:break-all;margin:0;tab-size:2}
        @media(max-width:640px){.bar{flex-direction:column;align-items:stretch;padding:10px 12px}.bar-l{align-items:flex-start;flex-direction:column;gap:7px}.bar-r{width:100%}.bar-r .btn{flex:1;justify-content:center}.wrap{padding:12px}.ss-wrap{margin:0 12px 12px}.ss-wrap img{width:100%;max-width:100%;max-height:42vh}.code-b{padding:12px 14px;max-height:48vh}.code-b pre{font-size:11px;line-height:1.55}}table tr.pinned td {
    background: var(--amber-bg);
    height: 58px;
}td.col-actions {
    height: 60px;
}
    </style></head><body>
    <div class="bar">
        <div class="bar-l">
            <h2><?=x_h($dosya['name'])?></h2>
            <div class="pills">
                <span class="pill pill-b"><?=x_h($dosya['original_name']??'—')?></span>
                <?php if($dosya['has_password']):?><span class="pill pill-r"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Şifreli</span>
                <?php else:?><span class="pill pill-g"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 019.9-1"/></svg> Açık</span><?php endif;?>
                <?php if($dosya['category_id']??null):?><span class="pill pill-b"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20.59 13.41l-7.17 7.17a2 2 0 01-2.83 0L2 12V2h10l8.59 8.59a2 2 0 010 2.82z"/></svg> <?=x_h(x_cat_name($cats,$dosya['category_id']))?></span><?php endif;?>
            </div>
        </div>
        <div class="bar-r">
            <a class="btn" href="<?=$_SERVER['SCRIPT_NAME']?>">Panele Dön</a>
            <a class="btn btn-g" href="?action=download&id=<?=$dosya['id']?>"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> İndir</a>
        </div>
    </div>
    <?php if($dosya['description']??''):?>
    <div style="margin:12px 16px 0"><div class="desc-m"><div class="lbl">Açıklama</div><div class="val"><?=x_rich($dosya['description'])?></div></div></div>
    <?php endif;?>
    <?php if($dosya['screenshot']??''):?>
    <div class="ss-wrap"><img src="?action=screenshot&id=<?=$dosya['id']?>&v=<?=x_img_v($dosya['screenshot']??'')?>" alt="" loading="lazy"></div>
    <?php endif;?>
    <div class="wrap">
        <div class="code-h"><span class="lang"><?=x_h($ext?:'txt')?></span><div class="code-actions"><span class="stats"><?=$lines?> satır &middot; <?=$bytes?> byte</span><button class="copy-btn" type="button" onclick="copyCode(this)"><?=svg('copy',12)?> Tümünü Kopyala</button></div></div>
        <div class="code-b"><pre id="codeContent"><?=x_h($content)?></pre></div>
        <script>function copyCode(button){const code=document.getElementById('codeContent').textContent;navigator.clipboard.writeText(code).then(()=>{const old=button.innerHTML;button.classList.add('copied');button.textContent='Kopyalandı';setTimeout(()=>{button.innerHTML=old;button.classList.remove('copied')},1600)}).catch(()=>{const area=document.createElement('textarea');area.value=code;document.body.appendChild(area);area.select();document.execCommand('copy');area.remove();button.textContent='Kopyalandı';setTimeout(()=>button.innerHTML='<?=svg('copy',12)?> Tümünü Kopyala',1600)})}</script>
    </div></body></html>
    <?php exit;
}

function x_edit_page($dosya,$cats) {
    $content=file_exists(FILES_DIR.'/'.$dosya['stored_name'])?file_get_contents(FILES_DIR.'/'.$dosya['stored_name']):'';
    ?><!DOCTYPE html><html lang="tr"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>Düzenle: <?=x_h($dosya['name'])?> — <?=APP_NAME?></title>
    <style>
        :root{--bg:#0a0b0f;--surface:#111318;--border:#1e2130;--text:#8b8fa3;--text2:#d1d5e0;--text3:#555a6e;--green:#b71c1c;--glow:#b71c1c30;--mono:'JetBrains Mono','Fira Code','Consolas',monospace;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
        *{margin:0;padding:0;box-sizing:border-box}
        body{background:var(--bg);color:var(--text);font-family:var(--font)}
        .bar{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;background:var(--surface);border-bottom:1px solid var(--border);gap:12px}
        .bar h2{color:var(--text2);font-size:14px;font-weight:700}
        .btn{display:inline-flex;align-items:center;gap:5px;padding:7px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--border);text-decoration:none;font-family:var(--font);transition:.12s;color:var(--text2);background:transparent}
        .btn:hover{border-color:var(--green);color:var(--green)}
        .btn-g{background:var(--green);color:#fff;border-color:var(--green)}.btn-g:hover,.btn-g:focus-visible{filter:brightness(1.1);color:#fff;border-color:var(--green)}
        .wrap{max-width:1000px;margin:0 auto;padding:20px}
        .form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
        .form-grid .fw{grid-column:1/-1}
        .fg{display:flex;flex-direction:column;gap:5px}
        .fg label{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;font-weight:600}
        .fg input[type=text],.fg input[type=url],.fg textarea,.fg select{padding:10px 13px;background:#0c0e14;border:1px solid var(--border);border-radius:6px;color:var(--text2);font-size:13px;outline:none;font-family:var(--font);transition:.15s;resize:vertical}
        .fg textarea{font-family:var(--mono);font-size:12px;min-height:280px;tab-size:2}
        .fg input:focus,.fg textarea:focus,.fg select:focus{border-color:var(--green);box-shadow:0 0 0 3px var(--glow)}
        *{scrollbar-color:var(--border) var(--bg);scrollbar-width:thin}::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}::-webkit-scrollbar-thumb:hover{background:var(--green)}
        .fg select{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23555a6e' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:30px}
        .toggle-row{display:flex;align-items:center;gap:12px;padding:6px 0}
        .sw{position:relative;width:40px;height:22px}
        .toggle-row.php-ver-row input.php-ver-input[type=text]{width:68px;min-width:68px;max-width:68px;padding:5px 7px;background:#0c0e14;border:1px solid var(--border);border-radius:var(--r-sm);color:#fff;font-size:11px;font-family:var(--mono);box-sizing:border-box}.php-ver-row .php-ver-input:focus{outline:none;border-color:var(--green)}
        .sw input{opacity:0;width:0;height:0}
        .sw .sl{position:absolute;inset:0;background:#1a1d28;border-radius:22px;cursor:pointer;transition:.15s}
        .sw .sl::before{content:'';position:absolute;width:16px;height:16px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.15s}
        .sw input:checked+.sl{background:var(--green)}
        .sw input:checked+.sl::before{background:#fff;transform:translateX(18px)}
        .file-zone{position:relative;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:6px;padding:14px;border:2px dashed var(--border);border-radius:6px;cursor:pointer;background:#0c0e14;text-align:center;transition:.15s}
        .file-zone:hover{border-color:var(--green);background:#b71c1c08}
        .file-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}
        .file-zone .fzt{font-size:11px;color:var(--text3)}
        .rich-editor{border:1px solid var(--border);border-radius:6px;overflow:hidden;background:#0c0e14}.rich-toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:4px;padding:6px;border-bottom:1px solid var(--border);background:var(--surface)}.rich-toolbar button,.rich-toolbar select,.rich-toolbar input{height:28px;background:#0c0e14;border:1px solid var(--border);border-radius:4px;color:var(--text2);font:12px var(--font);cursor:pointer;box-sizing:border-box}.rich-toolbar button{min-width:28px}.rich-toolbar button:hover,.rich-toolbar select:hover,.rich-toolbar select:focus{border-color:var(--green);color:var(--green)}.rich-toolbar .rich-size-select{flex:0 0 100px;min-width:100px;width:100px;height:30px;padding:0 24px 0 8px;overflow:visible;text-overflow:clip;white-space:nowrap;line-height:28px}.rich-toolbar input{width:32px;padding:2px}.rich-content{min-height:90px;max-height:320px;padding:10px;color:var(--text2);font-size:13px;line-height:1.6;outline:none;overflow:auto;scrollbar-color:var(--border) var(--bg);scrollbar-width:thin}.rich-content::-webkit-scrollbar{width:8px}.rich-content::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}.rich-content::-webkit-scrollbar-track{background:var(--bg)}.rich-content:empty:before{content:attr(data-placeholder);color:var(--text3);pointer-events:none}.rich-content:focus{box-shadow:inset 0 0 0 1px var(--green)}.rich-content h3{margin:8px 0;color:var(--green)}.rich-content ul{padding-left:22px}.rich-value{display:none}@media(max-width:640px){.form-grid{grid-template-columns:1fr}.bar{flex-direction:column;align-items:flex-start}.wrap{padding:12px}}table tr.pinned td {
    background: var(--amber-bg);
    height: 58px;
}td.col-actions {
    height: 60px;
}
    </style></head><body>
    <div class="bar"><h2>Düzenle: <?=x_h($dosya['name'])?></h2><a class="btn" href="<?=$_SERVER['SCRIPT_NAME']?>">Vazgeç</a></div>
    <div class="wrap">
        <form method="POST" action="?action=edit&id=<?=$dosya['id']?>" enctype="multipart/form-data" onsubmit="return prepareRichForm(this,'dosyaEditDescription')">
            <div class="form-grid">
                <div class="fg"><label>Dosya Adı</label><input type="text" name="name" value="<?=x_h($dosya['name'])?>" required></div>
                <div class="fg"><label>Kategori</label><select name="category_id"><option value="">Kategorisiz</option><?php foreach ($cats as $c):$pr=$c['parent']?x_cat_name($cats,$c['parent']).' → ':'';?><option value="<?=$c['id']?>" <?=($dosya['category_id']??null)===$c['id']?'selected':''?>><?=$pr.x_h($c['name'])?></option><?php endforeach;?></select></div>
                <div class="fg fw"><label>Açıklama</label><?=x_rich_editor('dosyaEditDescription','description',$dosya['description']??'','Açıklamayı buraya yazın...')?></div>
                <div class="fg fw"><label>Kod İçeriği</label><textarea name="content" rows="18" spellcheck="false"><?=x_h($content)?></textarea></div>
                <div class="fg fw"><label>Yeni Dosya Yükle</label><div class="file-zone" id="efz"><?=svg('upload',14)?> <span class="fzt">Mevcut dosyayı değiştirmek için tıklayın</span><span class="fzn" style="display:none"></span><input type="file" name="dosya_arsiv" onchange="fu(this,'efz')"></div></div>
                <div class="fg"><label>Ekran Görüntüleri</label><?=x_edit_gallery('dosya',$dosya,'screenshot')?><div class="file-zone" id="ssfz"><span class="fzt">Görsel(ler) ekle — birden fazla seçilebilir</span><span class="fzn" style="display:none"></span><input type="file" name="screenshot[]" multiple accept="image/*" onchange="fu(this,'ssfz')"></div><?=x_url_input('screenshot_url')?></div>
                <div class="fg"><div class="toggle-row"><label class="sw"><input type="checkbox" name="has_password" value="1" <?=$dosya['has_password']?'checked':''?>><span class="sl"></span></label><span style="font-size:12px;color:#fff">Şifre korumalı</span></div><div class="toggle-row"><label class="sw"><input type="checkbox" name="show_code" value="1" <?=($dosya['show_code']??true)?'checked':''?>><span class="sl"></span></label><span style="font-size:12px;color:#fff">Kod içeriğini göster</span></div><?=x_php_field('php_version',$dosya['php_version']??'','font-size:12px;color:#fff')?></div>
                <div class="fw"><button class="btn btn-g" type="submit"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Kaydet</button></div>
                </div>
        </form>
    </div><script>function togglePhpVer(cb){var row=cb.closest('.php-ver-row');if(!row)return;var inp=row.querySelector('.php-ver-input');if(!inp)return;if(cb.checked){inp.disabled=false;inp.style.display='';inp.focus()}else{inp.disabled=true;inp.style.display='none';inp.value=''}}function richCmd(command,id,value){var editor=document.getElementById(id);if(!editor)return;editor.focus();document.execCommand(command,false,value||null);syncRich(editor)}function syncRich(editor){var target=editor.dataset.target?document.querySelector('[name="'+editor.dataset.target+'"]'):document.getElementById(editor.id+'Value');if(target)target.value=editor.innerHTML}function prepareRichForm(form,editorId){var editor=document.getElementById(editorId);if(editor)syncRich(editor);return true}document.addEventListener('input',function(e){if(e.target&&e.target.classList&&e.target.classList.contains('rich-content'))syncRich(e.target)});document.querySelectorAll('.rich-content').forEach(function(e){syncRich(e)});function fu(i,id){var a=document.getElementById(id),n=a.querySelector('.fzn'),t=a.querySelector('.fzt');if(i.files.length){a.classList.add('has');n.textContent=i.files.length>1?i.files.length+' resim seçildi':i.files[0].name;n.style.display='';t.style.display='none'}}</script><?=x_upload_assets()?></body></html>
    <?php exit;
  }

function x_github_edit_page($g,$cats=array()) {
    ?><!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>GitHub Düzenle — <?=APP_NAME?></title><style>
    :root{--bg:#0a0b0f;--surface:#111318;--border:#1e2130;--text:#8b8fa3;--text2:#d1d5e0;--green:#b71c1c;--glow:#b71c1c30;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:var(--font)}.bar{padding:14px 18px;background:var(--surface);border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}.bar h2{margin:0;color:var(--text2);font-size:15px}.btn{padding:8px 14px;border:1px solid var(--border);border-radius:6px;color:var(--text2);text-decoration:none;background:transparent;cursor:pointer;font-size:13px}.btn-g{background:var(--green);border-color:var(--green);color:#fff}.btn-cancel{border-color:var(--border);color:var(--red);background:transparent;transition:.12s}.btn-cancel:hover{border-color:var(--red);background:var(--red-bg);color:var(--red)}.wrap{max-width:700px;margin:auto;padding:24px}.fg{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}.fg label{font-size:11px;color:var(--text)}input,select{padding:11px;background:#0c0e14;border:1px solid var(--border);border-radius:6px;color:var(--text2);font-size:13px;width:100%;outline:none}input:focus,select:focus{border-color:var(--green);box-shadow:0 0 0 3px var(--glow)}select option{background:#0c0e14;color:var(--text2)}.file-zone{position:relative;min-height:44px;padding:12px 14px;background:#0c0e14;border:1px dashed var(--border);border-radius:6px;color:var(--text);font-size:12px;display:flex;align-items:center;gap:8px;cursor:pointer;transition:border-color .15s,box-shadow .15s}.file-zone:hover,.file-zone:focus-within{border-color:var(--green);box-shadow:0 0 0 3px var(--glow)}.file-zone input[type=file]{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer;padding:0}.file-zone .fzn{color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.form-actions{display:flex;justify-content:flex-start;align-items:center;gap:8px;margin-top:18px}.toggle-row{display:flex;align-items:center;gap:10px;padding:4px 0}.sw{position:relative;width:36px;height:20px;flex-shrink:0}.sw input{opacity:0;width:0;height:0}.sw .sl{position:absolute;inset:0;background:#1a1d28;border-radius:20px;cursor:pointer;transition:.15s}.sw .sl:before{content:'';position:absolute;width:14px;height:14px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.15s}.sw input:checked+.sl{background:var(--green)}.sw input:checked+.sl:before{transform:translateX(16px)}.swl{font-size:12px;color:var(--text2)}input:focus,select:focus{outline:none;border-color:var(--green);box-shadow:0 0 0 3px var(--glow)}
    .rich-editor{border:1px solid var(--border);border-radius:6px;overflow:hidden;background:#0c0e14}.rich-toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:4px;padding:6px;border-bottom:1px solid var(--border);background:var(--surface)}.rich-toolbar button,.rich-toolbar select,.rich-toolbar input{height:28px;background:#0c0e14;border:1px solid var(--border);border-radius:4px;color:var(--text2);font:12px var(--font);cursor:pointer;box-sizing:border-box}.rich-toolbar button{min-width:28px}.rich-toolbar button:hover,.rich-toolbar select:hover,.rich-toolbar select:focus{border-color:var(--green);color:var(--green)}.rich-toolbar .rich-size-select{flex:0 0 100px;min-width:100px;width:100px;height:30px;padding:0 24px 0 8px;overflow:visible;text-overflow:clip;white-space:nowrap;line-height:28px}.rich-toolbar input{width:32px;padding:2px}.rich-content{min-height:90px;max-height:320px;padding:10px;color:var(--text2);font-size:13px;line-height:1.6;outline:none;overflow:auto;scrollbar-color:var(--border) var(--bg);scrollbar-width:thin}.rich-content::-webkit-scrollbar{width:8px}.rich-content::-webkit-scrollbar-thumb{background:var(--border);border-radius:8px}.rich-content::-webkit-scrollbar-track{background:var(--bg)}.rich-content:empty:before{content:attr(data-placeholder);color:var(--text3);pointer-events:none}.rich-content:focus{box-shadow:inset 0 0 0 1px var(--green)}.rich-content h3{margin:8px 0;color:var(--green)}.rich-content ul{padding-left:22px}.rich-value{display:none}.toggle-row{display:flex;align-items:center;gap:12px}.toggle-row>span{font-size:12px;color:#fff}.sw{position:relative;width:40px;height:22px}.sw input{opacity:0;width:0;height:0}.sw .sl{position:absolute;inset:0;background:#1a1d28;border-radius:22px;cursor:pointer}.sw .sl:before{content:'';position:absolute;width:16px;height:16px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.15s}.sw input:checked+.sl{background:var(--green)}.sw input:checked+.sl:before{transform:translateX(18px)}.toggle-row.php-ver-row input.php-ver-input[type=text]{width:68px;min-width:68px;max-width:68px;padding:5px 7px;background:#0c0e14;border:1px solid var(--border);border-radius:var(--r-sm);color:#fff;font-size:11px;font-family:var(--mono);box-sizing:border-box}.php-ver-row .php-ver-input:focus{outline:none;border-color:var(--green)}</style></head><body><div class="bar"><h2>GitHub Bağlantısını Düzenle</h2><a class="btn btn-cancel" href="<?=$_SERVER['SCRIPT_NAME']?>?tab=github">Vazgeç</a></div><div class="wrap"><form method="POST" enctype="multipart/form-data" action="?action=github_edit&id=<?=x_h($g['id'])?>&tab=github" onsubmit="return prepareRichForm(this,'githubEditDescription')"><div class="fg"><label>İsim</label><input name="name" value="<?=x_h($g['name'])?>" required></div><div class="fg"><label>Raw GitHub Linki</label><input type="url" name="url" value="<?=x_h($g['url'])?>" required></div><div class="fg"><label>Açıklama</label><?=x_rich_editor('githubEditDescription','description',$g['description']??'','Açıklamayı buraya yazın...')?></div><div class="fg"><label>Kategori</label><select name="category_id"><option value="">Kategorisiz</option><?php foreach ($cats as $cat): ?><option value="<?=x_h($cat['id'])?>" <?=($g['category_id']??'')===$cat['id']?'selected':''?>><?=x_h($cat['name'])?></option><?php endforeach; ?></select></div><div class="fg"><div class="toggle-row"><label class="sw"><input type="checkbox" name="encrypted" value="1" <?=!empty($g['encrypted'])?'checked':''?>><span class="sl"></span></label><span class="swl">Şifre korumalı</span></div><div class="toggle-row"><label class="sw"><input type="checkbox" name="show_code" value="1" <?=($g['show_code']??true)?'checked':''?>><span class="sl"></span></label><span>Kod bilgilerini göster</span></div><?=x_php_field('php_version',$g['php_version']??'')?></div><div class="fg"><label>Resimler (opsiyonel)</label><?=x_edit_gallery('github',$g,'image')?><div class="file-zone" id="ghefz"><?=svg('upload',14)?> <span class="fzt">Görselleri seçmek için tıklayın (birden fazla)</span><span class="fzn" style="display:none"></span><input type="file" name="image[]" multiple accept="image/*" onchange="var n=this.files&&this.files.length>1?this.files.length+' resim seçildi':(this.files&&this.files[0]?this.files[0].name:'');this.parentNode.querySelector('.fzt').style.display=n?'none':'';var z=this.parentNode.querySelector('.fzn');z.textContent=n;z.style.display=n?'inline':'none'"></div><?=x_url_input('image_url')?></div><div class="form-actions"><button class="btn btn-g" type="submit"><?=svg('check',13)?> Kaydet</button></div></form></div><script>function togglePhpVer(cb){var row=cb.closest('.php-ver-row');if(!row)return;var inp=row.querySelector('.php-ver-input');if(!inp)return;if(cb.checked){inp.disabled=false;inp.style.display='';inp.focus()}else{inp.disabled=true;inp.style.display='none';inp.value=''}}function richCmd(command,id,value){var editor=document.getElementById(id);if(!editor)return;editor.focus();document.execCommand(command,false,value||null);syncRich(editor)}function syncRich(editor){var target=editor.dataset.target?document.querySelector('[name="'+editor.dataset.target+'"]'):document.getElementById(editor.id+'Value');if(target)target.value=editor.innerHTML}function prepareRichForm(form,editorId){var editor=document.getElementById(editorId);if(editor)syncRich(editor);return true}document.addEventListener('input',function(e){if(e.target&&e.target.classList&&e.target.classList.contains('rich-content'))syncRich(e.target)});document.querySelectorAll('.rich-content').forEach(function(e){syncRich(e)});</script><?=x_upload_assets()?></body></html><?php exit;
}