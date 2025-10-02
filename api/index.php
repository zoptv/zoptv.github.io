<?php
// Set X-Frame-Options header to deny loading in iframes from other websites
header('X-Frame-Options: DENY');
// Rest of your PHP code goes here
?>

<!DOCTYPE html><html><head>
<title>index</title>
<meta name="referrer" content="origin">
<meta http-equiv="X-UA-Compatible" content="IE=edge"/>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
* {margin: 0; padding: 0;  box-sizing: border-box;}
html, body {height: 100%;  width: 100%; }
body {
background: #0d0d0d; /* color black */
display: flex;
justify-content: center;
align-items: center;
}

h2 {
font-family: digital, Arial, sans-serif;
font-size: 6vw; font-weight:900;
color: #27ff0a; /* color green */
text-shadow: 0 0 30px green, 0 0 40px green;
line-height: 20.4vh;
text-align: center;
position: relative;
}
</style>
</head><body><h2 id="host"></h2>
<script>document.getElementById("host").innerHTML = window.location.hostname;</script></body></html>
