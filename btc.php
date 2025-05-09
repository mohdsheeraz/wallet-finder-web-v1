<?php
// index.php

// WordPress gating if you are connecting the code to wordpress website for user to selling the service (remove if not using wordpress)
//require_once( $_SERVER['DOCUMENT_ROOT'] . '/wp-load.php' );
//if ( ! is_user_logged_in() ) {
//  wp_redirect('https://yourwebsite.com/shop');
//  exit;
//}
//check which user is subscribed to
//$current_user = wp_get_current_user();
//global $wpdb;
//$user_plan = $wpdb->get_var(
// $wpdb->prepare("SELECT subscription_plan FROM wp_users WHERE ID = %d", $current_user->ID)
//);
//if ( empty($user_plan) ) {
//  wp_redirect('https://wallet.sparkfusion.tech/shop');
//  exit;
//}

// DB connection to log the private key with balance
$conn = new mysqli("localhost", "Database User", "Database Password", "Database name");
if ($conn->connect_error) {
  die("DB Error: " . $conn->connect_error);
}

// AJAX handler Do Not Touch It
if (isset($_GET['action']) && $_GET['action'] === 'generate') {
  header('Content-Type: application/json; charset=UTF-8');

  // 1. Generate private key Do Not Touch It
  $privHex = bin2hex(random_bytes(32));

  // 2. ECC params Do Not Touch It
  $p  = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',16);
  $Gx = gmp_init('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',16);
  $Gy = gmp_init('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',16);

  // 3. EC functions Do Not Touch It
  function pointAdd($P,$Q,$p){ if($P===null)return $Q; if($Q===null)return $P;
    if(gmp_cmp($P['x'],$Q['x'])===0){
      if(gmp_cmp(gmp_mod(gmp_add($P['y'],$Q['y']),$p),0)===0) return null;
      return pointDouble($P,$p);
    }
    $s = gmp_mod(
      gmp_mul(gmp_sub($Q['y'],$P['y']), gmp_invert(gmp_sub($Q['x'],$P['x']), $p)),
      $p
    );
    $xR = gmp_mod(gmp_sub(gmp_sub(gmp_pow($s,2),$P['x']),$Q['x']),$p);
    $yR = gmp_mod(gmp_sub(gmp_mul($s,gmp_sub($P['x'],$xR)),$P['y']),$p);
    return ['x'=>$xR,'y'=>$yR];
  }
  function pointDouble($P,$p){ if($P===null) return null;
    $s = gmp_mod(
      gmp_mul(gmp_mul(3,gmp_pow($P['x'],2)), gmp_invert(gmp_mul(2,$P['y']),$p)),
      $p
    );
    $xR = gmp_mod(gmp_sub(gmp_pow($s,2),gmp_mul(2,$P['x'])),$p);
    $yR = gmp_mod(gmp_sub(gmp_mul($s,gmp_sub($P['x'],$xR)),$P['y']),$p);
    return ['x'=>$xR,'y'=>$yR];
  }
  function scalarMultiply($kHex,$P,$p){
    $k=gmp_init($kHex,16); $res=null; $add=$P;
    while(gmp_cmp($k,0)>0){
      if(gmp_testbit($k,0)) $res=pointAdd($res,$add,$p);
      $add=pointDouble($add,$p);
      $k=gmp_div_q($k,2);
    }
    return $res;
  }
  function base58Check($hex){
    $alpha='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    $bin=hex2bin($hex);
    $chk=substr(hash('sha256',hash('sha256',$bin,true),true),0,4);
    $full=$bin.$chk;
    $num=gmp_init(bin2hex($full),16); $str='';
    while(gmp_cmp($num,0)>0){
      list($num,$r)=gmp_div_qr($num,58);
      $str=$alpha[gmp_intval($r)].$str;
    }
    for($i=0;$i<strlen($full)&&$full[$i]==="\x00";$i++){
      $str='1'.$str;
    }
    return $str;
  }

  // 4. Derive address Do Not Touch It
  $P = scalarMultiply($privHex, ['x'=>$Gx,'y'=>$Gy], $p);
  if (!$P) { http_response_code(500); echo json_encode(['error'=>'EC error']); exit;}
  $xHex   = str_pad(gmp_strval($P['x'],16),64,'0',STR_PAD_LEFT);
  $prefix = (gmp_mod($P['y'],2)==0)?'02':'03';
  $pubHex = $prefix.$xHex;
  $rip    = hash('ripemd160', hash('sha256', hex2bin($pubHex), true), true);
  $payload= '00'.bin2hex($rip);
  $address= base58Check($payload);

  // 5. Fetch balance using blockchain.info can be change if you want another service
  $balJson = @file_get_contents("https://blockchain.info/balance?active={$address}");
  if ($balJson === FALSE) {
    http_response_code(429);
    echo json_encode(['error'=>'rate limit']);
    exit;
  }
  $jd  = json_decode($balJson,true);
  $bal = isset($jd[$address]['final_balance']) ? $jd[$address]['final_balance']/1e8 : 0;

  // 6. Log positive balance private key (please enter db details above to use this feature)
  if ($bal > 0) {
    $stmt = $conn->prepare("INSERT INTO wallet_scans(private_key,btc_address,balance)VALUES(?,?,?)");
    $stmt->bind_param("ssd",$privHex,$address,$bal); $stmt->execute(); $stmt->close();
    $stmt = $conn->prepare("INSERT INTO btc_wallets(private_key,btc_address,balance)VALUES(?,?,?)");
    $stmt->bind_param("ssd",$privHex,$address,$bal); $stmt->execute(); $stmt->close();
  }

  // 7. Return the values we fetch and created
  echo json_encode(['private_key'=>$privHex,'btc_address'=>$address,'balance'=>$bal]);
  exit;
}
  //ui ux starts
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Bitcoin Wallet Finder 🚀</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #111;
      color: #fff;
      text-align: center;
      margin: 20px;
    }
    .container {
      max-width: 600px;
      margin: auto;
      padding: 20px;
      border-radius: 10px;
      background: linear-gradient(135deg, #1e1e1e, #333);
      box-shadow: 0px 0px 20px rgba(0, 255, 170, 0.6);
    }
    .btc-box {
      background: rgba(255, 255, 255, 0.1);
      padding: 15px;
      border-radius: 5px;
      margin: 10px auto;
      font-weight: bold;
      width: 80%;
      word-wrap: break-word;
    }
    .glow {
      text-shadow: 0px 0px 10px #00ffae;
    }
    #loading {
      color: #ffae00;
      font-size: 16px;
      animation: blink 1s infinite;
    }
    @keyframes blink {50%{opacity:0.5;}}
    button {
      padding: 10px 20px;
      font-size: 16px;
      margin: 10px 5px;
      border: none;
      border-radius: 5px;
      background-color: #ff4444;
      color: #fff;
      cursor: pointer;
    }
    button:hover {
      background-color: #ff0000;
    }
    #walletCounter {
      margin-top: 10px;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>🔥 Bitcoin Wallet Finder</h2>
    <div class="btc-box"><strong>Bitcoin Address:</strong> <span id="btcAddress">–</span></div>
    <div class="btc-box"><strong>Private Key:</strong> <span id="privateKey">–</span></div>
    <div class="btc-box"><strong>Balance:</strong> <span id="balance">0 BTC</span></div>
    <p id="loading">Press “Start” to begin.</p>
    <button onclick="start()">Start</button>
    <button onclick="stop()">Stop</button>
    <p id="walletCounter">Wallets Scanned: 0</p>
  </div>

  <script>
    let gen=false, cnt=0, toID;
    function start() {
      if (gen) return;
      gen = true;
      document.getElementById('loading').innerText = '🔄 Searching…';
      run();
    }
    function stop() {
      gen = false;
      clearTimeout(toID);
      document.getElementById('loading').innerText = '⏸️ Paused';
    }
    function run() {
      if (!gen) return;
      cnt++;
      document.getElementById('walletCounter').innerText = 'Wallets Scanned: ' + cnt;
      fetch('?action=generate')
        .then(r => {
          if (r.status === 429) {
            stop();
            document.getElementById('loading').innerText = '❗ Rate limit reached.';
            throw 'limit';
          }
          return r.json();
        })
        .then(d => {
          document.getElementById('btcAddress').innerText = d.btc_address;
          document.getElementById('privateKey').innerText = d.private_key;
          document.getElementById('balance').innerText   = d.balance + ' BTC';
          toID = setTimeout(run, 250);
        })
        .catch(e => {
          if (e !== 'limit' && gen) {
            console.error(e);
            toID = setTimeout(run, 2000);
          }
        });
    }
  </script>
</body>
</html>
