<?php
$server = "localhost";
$username = "root";
$password = "";
$dbname = "shoppe";
$con = mysqli_connect($server, $username, $password, $dbname);

if (!$con) {
    die("Connection failed: " . mysqli_connect_error());
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = $_POST['email'];
    $user_password = $_POST['password']; // Store the user input password in a different variable

    // Use prepared statement to prevent SQL injection
    $sql = "SELECT username, email, password FROM register WHERE email = ?";
    $stmt = mysqli_prepare($con, $sql);

    // Check if the statement was prepared successfully
    if ($stmt === false) {
        die("Error: " . mysqli_error($con));
    }

    // "s" corresponds to one placeholder for the email value to be bound
    mysqli_stmt_bind_param($stmt, "s", $email);

    // Execute the query
    mysqli_stmt_execute($stmt);

    // Bind the result to variables
    mysqli_stmt_bind_result($stmt, $username, $email, $hashed_password);

    // Fetch the result
    mysqli_stmt_fetch($stmt);

    // Verify the password
    if (password_verify($user_password, $hashed_password)) {
        // Password is correct, user is authorized
        // You can now set session variables to keep the user logged in
        // or perform any other required actions before redirecting to the home page.

        // Set session variables (example)
        session_start();
        $_SESSION['user_email'] = $email;
        $_SESSION['user_name'] = $username;

        // Redirect to the home page
        header("Location: index.html");
        exit();
    } else {
        // Password is incorrect
        echo "Login failed. Invalid email or password.";
    }

    mysqli_stmt_close($stmt);
}

mysqli_close($con);
?>
