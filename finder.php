<style>
    #sbz {text-align: center;color: #000;font-size: 30px;font-weight: bold;line-height: 0.8em;letter-spacing: 0.2em;margin:0;text-shadow: 0 1px 20px #00FF00, 0 0 5px #00FF00, 0 0px 30px #00FF00, 1px 0 3px #00FF00;}
    span.tab{padding: 0 10px; }
    .box{
        -moz-box-shadow: 1px 1px 8px #666;
        -webkit-box-shadow: 1px 1px 8px #666;
        box-shadow: 1px 1px 8px #40D5D2;
        border: solid 1px black;
        -webkit-border-radius: 8px 8px 0px 0px;
        -moz-border-radius: 8px 8px 0px 0px;
        border-radius: 8px 8px 0px 0px;
        margin: 15px 0px;
         opacity: 0.8;
         width:100%;
    }
    #footer {
    position : absolute;
    bottom : 0;
    height : 50px;
    margin-top : 50px;
    }
	tr td {
		border: 1px solid #eee;
	}
    body{
        background-color: black;
       background: url('https://i.ytimg.com/vi/AQSAywNNM-s/maxresdefault.jpg') no-repeat center center fixed;
    }
</style>
<?php
@set_time_limit(0);error_reporting(0);
function recurseDir($dir,$list) {
    if(is_dir($dir)) {
        if($dh = opendir($dir)){
            while($file = readdir($dh)){
                if($file != '.' && $file != '..'){
                    if(is_dir($dir . '/' .  $file)){
                        $list = recurseDir($dir .'/' .  $file  . '/',$list);
                    }else{
                        $list[] = $dir . '/' . $file;
                     }
                }
             }
        }
         closedir($dh);         
   }
   return $list;
}
echo '<html><head><title>Shellfinder</title></head><body><center><pre id="sbz">Shellfinder</pre><div class="box" align="left">';

if(empty($_POST["go"])==0){
    $files = array();
    $files = recurseDir($_POST["directory"],$files);
    echo '<table cellpadding="2"><tr><td>Path</td><td>Functions</td><td> Shell ?</td><td>OPTION</td></tr>';
    $i =1;
    foreach($files as $file){
        if($file!=getcwd() . $_SERVER["PHP_SELF"]){
            $content=file_get_contents($file);
            if (preg_match('/(<\?php)/i',$content)){
                if (preg_match('/(base64_\(|eval\s*\(|system\s*\(|shell_|exec\s*\(|move_uploaded_file\s*\(|gzinflate\s*\()/i',$content)){   
                    $ve1=0;$ve2=0;$ve3=0;$ve4=0;$ve5=0;$ve6=0;
                    echo '<tr><td>'. $file . '</td><td>';
                    if (preg_match('/(base64_)/i',$content)){echo "base64 decoding/encoding,";$ve1=1;}
                    if (preg_match('/(eval)/i',$content)){echo "eval,";$ve2=1;}
                    if (preg_match('/(system)/i',$content)){echo "system,";$ve3=1;}
                    if (preg_match('/(shell_)/i',$content)){echo "Shell_,";$ve4=1;}
                    if (preg_match('/(move_uploaded_file)/i',$content)){echo "move_uploaded_file,";$ve5=1;}
                    if (preg_match('/(gzinflate)/i',$content)){echo "gzinflate,";$ve6=1;}
                    echo '</td><td>';
                    if(($ve1==1 && $ve2==1) || ($ve6==1 && $ve2==1)){
                        echo '<font color="red">possible shell 85%</font>';
                    }elseif($ve5==1){
                        echo '<font color="red">possible uploader 90%</font>';
                    }elseif($ve4==1){
                        echo '<font color="red">possible shell-Console 50%</font>';
                    }elseif($ve3==1){
                        echo '<font color="red">system-shell 50%</font>';
                    }else{
                        echo ' ';
                    }

                    $i++;
                }
            }
        }
    }
    echo '</tr></table>';
}else{
    if(!empty($_POST["de"])){
        echo '</center>';
    }else{
        echo '<center>To start the scanning press go.</br>Bu Biraz zamanınızı alabilir :)</br></br><form method="POST">scann : <input type="text" name="directory" value="' . $_SERVER["DOCUMENT_ROOT"] . '"/></br><input type="submit" name="go" value="Shell Bul"/></form></center>';
    }
}
echo '</div></center></body></html>';
?>