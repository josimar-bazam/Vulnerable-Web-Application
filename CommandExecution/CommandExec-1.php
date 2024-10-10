<html>
  <head>
    <link rel="shortcut icon" href="../Resources/hmbct.png" />
    <title>CommandExec-1</title>
  </head>
  <body>
    <div style="background-color:#afafaf;padding:15px;border-radius:20px 20px 0px 0px">
      <button type="button" name="homeButton" onclick="location.href='../homepage.html';">Home Page</button>
      <button type="button" name="mainButton" onclick="location.href='commandexec.html';">Main Page</button>
    </div>
    <div style="background-color:#c9c9c9;padding:20px;">
      <h1 align="center">Login as Admin</h1>
    <form align="center" action="CommandExec-1.php" method="POST">
      <?php
      // Generate and store CSRF token
      session_start();
      if (empty($_SESSION['csrf_token'])) {
          $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
      }
      <?php
      // Generate CSRF token if not already set
      if (empty($_SESSION['csrf_token'])) {
          $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
      }
      ?>
      <form action="login.php" method="POST">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
          <div>
              <label for="username">Username:</label>
              <input type="text" id="username" name="username" required autocomplete="username">
          </div>
          <div>
              <label for="password">Password:</label>
              <input type="password" id="password" name="password" required autocomplete="current-password">
          </div>
          <div>
              <input type="submit" value="Submit">
          </div>
      </form>
      
  </div>
  <div style="background-color:#ecf2d0;padding:20px;border-radius:0px 0px 20px 20px" align="center">
    <?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
      // Verify CSRF token
      if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
          die('CSRF token validation failed');
      }

      // Sanitize and validate input
      $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
      $password = $_POST['password'];

      // In a real-world scenario, you would hash the password and compare it with a stored hash
      if ($username === 'Admin' && $password === 'ufoundmypassword') {
        echo "WELLDONE";
      } else {
        echo "Invalid credentials";
      }
    }
    ?>
  </div>
  </body>
</html>
