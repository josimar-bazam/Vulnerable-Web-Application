<!DOCTYPE html>
<html>
<head>
   <title>XSS 1</title>
   <link rel="shortcut icon" href="../Resources/hmbct.png" />
</head>
<body>
    <div style="background-color:#c9c9c9;padding:15px;">
      <button type="button" name="homeButton" onclick="location.href='../homepage.html';">Home Page</button>
      <button type="button" name="mainButton" onclick="location.href='xssmainpage.html';">Main Page</button>
    </div>
    <div align="center">
       <form method="POST" action="" name="form">
           <p>Your name:<input type="text" name="username"></p>
           <input type="submit" name="submit" value="Submit">
       </form>
    </div>
    <?php
    // Set security headers
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';");
    header("X-XSS-Protection: 1; mode=block");
    header("X-Frame-Options: SAMEORIGIN");

    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["username"])) {
        // Validate and sanitize input
        $username = filter_input(INPUT_POST, "username", FILTER_SANITIZE_STRING);
        
        // Output encoding
        $encoded_username = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
        
        echo "Your name is " . $encoded_username;
    }
    ?>
</body>
</html>
