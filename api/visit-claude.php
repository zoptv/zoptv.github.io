<?php
//Source:https://claude.ai/chat/ab4e6999-28e3-427b-a762-5e892444ca4c

// Advanced IP Detection with Proxy/VPN Detection
function getRealIPAddress() {
    $ip_keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 
                'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 
                'HTTP_FORWARDED', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    
    $detected_ips = [];
    $proxy_headers = [];
    
    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            $proxy_headers[] = $key;
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                    $detected_ips[] = [
                        'ip' => $ip,
                        'header' => $key,
                        'is_private' => !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
                    ];
                }
            }
        }
    }
    
    return [
        'primary_ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
        'all_ips' => $detected_ips,
        'proxy_headers' => $proxy_headers,
        'proxy_detected' => count($proxy_headers) > 1
    ];
}

// Advanced Proxy/VPN Detection
function detectProxyVPN($ip) {
    $proxy_indicators = [];
    
    // Check common proxy ports
    $proxy_ports = [80, 8080, 3128, 1080, 8000, 8888];
    
    // Check if IP is in known proxy ranges
    $proxy_ranges = [
        '10.0.0.0/8',
        '172.16.0.0/12', 
        '192.168.0.0/16',
        '169.254.0.0/16'
    ];
    
    foreach ($proxy_ranges as $range) {
        if (ipInRange($ip, $range)) {
            $proxy_indicators[] = "Private IP range: $range";
        }
    }
    
    // Check HTTP headers for proxy signatures
    $proxy_headers = [
        'HTTP_VIA' => 'Via header present',
        'HTTP_X_FORWARDED_FOR' => 'X-Forwarded-For present',
        'HTTP_X_FORWARDED_HOST' => 'X-Forwarded-Host present',
        'HTTP_X_FORWARDED_PROTO' => 'X-Forwarded-Proto present',
        'HTTP_X_REAL_IP' => 'X-Real-IP present',
        'HTTP_FORWARDED' => 'Forwarded header present',
        'HTTP_PROXY_CONNECTION' => 'Proxy-Connection present',
        'HTTP_X_FORWARDED_SERVER' => 'X-Forwarded-Server present'
    ];
    
    foreach ($proxy_headers as $header => $description) {
        if (isset($_SERVER[$header])) {
            $proxy_indicators[] = $description;
        }
    }
    
    // Additional proxy detection via API (limited calls)
    if (count($proxy_indicators) < 2) {
        $proxy_check = @file_get_contents("http://check.getipintel.net/check.php?ip={$ip}&contact=admin@example.com");
        if ($proxy_check && floatval($proxy_check) > 0.8) {
            $proxy_indicators[] = "High proxy probability: " . ($proxy_check * 100) . "%";
        }
    }
    
    return $proxy_indicators;
}

function ipInRange($ip, $range) {
    list($subnet, $bits) = explode('/', $range);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    return ($ip & $mask) == $subnet;
}

// Advanced User Agent Analysis
function analyzeUserAgent($userAgent) {
    $analysis = [];
    $suspicious_indicators = [];
    
    // Common fake user agent patterns
    $fake_patterns = [
        '/^Mozilla\/5\.0$/' => 'Incomplete Mozilla string',
        '/Mozilla\/4\.0 \(compatible; MSIE/' => 'Old IE signature (likely fake)',
        '/bot|crawler|spider/i' => 'Bot signature',
        '/^curl|wget|python|java/i' => 'Programming tool signature',
        '/Headless/' => 'Headless browser detected',
        '/PhantomJS|Selenium/' => 'Automation tool detected'
    ];
    
    foreach ($fake_patterns as $pattern => $description) {
        if (preg_match($pattern, $userAgent)) {
            $suspicious_indicators[] = $description;
        }
    }
    
    // Analyze consistency in user agent
    $browser_info = parseAdvancedUserAgent($userAgent);
    
    // Check for inconsistencies
    if (isset($browser_info['browser']) && isset($browser_info['os'])) {
        // Chrome on iOS should not exist (iOS uses Safari engine)
        if ($browser_info['browser'] === 'Chrome' && strpos($browser_info['os'], 'iOS') !== false) {
            $suspicious_indicators[] = 'Impossible Chrome on iOS combination';
        }
        
        // Check for outdated browser versions
        if (isset($browser_info['browser_version'])) {
            $version = floatval($browser_info['browser_version']);
            if ($browser_info['browser'] === 'Chrome' && $version < 70) {
                $suspicious_indicators[] = 'Suspiciously old Chrome version';
            }
            if ($browser_info['browser'] === 'Firefox' && $version < 60) {
                $suspicious_indicators[] = 'Suspiciously old Firefox version';
            }
        }
    }
    
    // Check user agent length (too short or too long can be suspicious)
    if (strlen($userAgent) < 50) {
        $suspicious_indicators[] = 'Unusually short user agent string';
    } elseif (strlen($userAgent) > 500) {
        $suspicious_indicators[] = 'Unusually long user agent string';
    }
    
    return [
        'browser_info' => $browser_info,
        'suspicious_indicators' => $suspicious_indicators,
        'trustworthiness' => count($suspicious_indicators) === 0 ? 'High' : (count($suspicious_indicators) < 3 ? 'Medium' : 'Low')
    ];
}

function parseAdvancedUserAgent($userAgent) {
    $info = [];
    
    // Enhanced browser detection with version validation
    $browsers = [
        'Chrome' => [
            'pattern' => '/Chrome\/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/',
            'engine' => 'Blink'
        ],
        'Firefox' => [
            'pattern' => '/Firefox\/([0-9]+\.[0-9]+)/',
            'engine' => 'Gecko'
        ],
        'Safari' => [
            'pattern' => '/Version\/([0-9]+\.[0-9]+(?:\.[0-9]+)?).*Safari\/([0-9]+\.[0-9]+)/',
            'engine' => 'WebKit'
        ],
        'Edge' => [
            'pattern' => '/Edg\/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/',
            'engine' => 'Blink'
        ],
        'Opera' => [
            'pattern' => '/OPR\/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/',
            'engine' => 'Blink'
        ]
    ];
    
    foreach ($browsers as $browser => $data) {
        if (preg_match($data['pattern'], $userAgent, $matches)) {
            $info['browser'] = $browser;
            $info['browser_version'] = $matches[1];
            $info['engine'] = $data['engine'];
            break;
        }
    }
    
    // Enhanced OS detection
    $os_patterns = [
        'Windows 11' => '/Windows NT 10\.0.*Windows.*11|Windows NT 10\.0.*Build 2[2-9][0-9][0-9][0-9]/',
        'Windows 10' => '/Windows NT 10\.0/',
        'Windows 8.1' => '/Windows NT 6\.3/',
        'Windows 7' => '/Windows NT 6\.1/',
        'macOS Monterey' => '/Intel Mac OS X 10[._]1[5-9]|Mac OS X 10[._]1[5-9]/',
        'macOS' => '/Mac OS X ([0-9]+[._][0-9]+(?:[._][0-9]+)?)/',
        'Ubuntu' => '/Ubuntu\/([0-9]+\.[0-9]+)/',
        'Linux' => '/Linux/',
        'Android' => '/Android ([0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?)/',
        'iOS' => '/OS ([0-9]+_[0-9]+(?:_[0-9]+)?) like Mac OS X/',
    ];
    
    foreach ($os_patterns as $os => $pattern) {
        if (preg_match($pattern, $userAgent, $matches)) {
            $info['os'] = $os;
            if (isset($matches[1])) {
                $info['os_version'] = str_replace('_', '.', $matches[1]);
            }
            break;
        }
    }
    
    // Device detection with brand extraction
    if (preg_match('/\(([^;]+);[^)]*Android/', $userAgent, $matches)) {
        $device_info = trim($matches[1]);
        $info['device'] = $device_info;
        $info['device_type'] = 'Mobile';
    } elseif (preg_match('/iPhone/', $userAgent)) {
        if (preg_match('/iPhone OS ([0-9_]+)/', $userAgent, $matches)) {
            $info['device'] = 'iPhone (iOS ' . str_replace('_', '.', $matches[1]) . ')';
        } else {
            $info['device'] = 'iPhone';
        }
        $info['device_type'] = 'Mobile';
    } elseif (preg_match('/iPad/', $userAgent)) {
        $info['device'] = 'iPad';
        $info['device_type'] = 'Tablet';
    } elseif (preg_match('/Windows NT/', $userAgent)) {
        $info['device'] = 'Windows PC';
        $info['device_type'] = 'Desktop';
    } elseif (preg_match('/Mac OS X/', $userAgent)) {
        $info['device'] = 'Mac';
        $info['device_type'] = 'Desktop';
    } else {
        $info['device'] = 'Unknown Device';
        $info['device_type'] = 'Unknown';
    }
    
    return $info;
}

// Get enhanced location with VPN/Proxy indicators
function getEnhancedLocationInfo($ip) {
    // Primary location service
    $location_data = @file_get_contents("http://ip-api.com/json/{$ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query");
    
    if ($location_data) {
        $location = json_decode($location_data, true);
        
        // Additional proxy/VPN checks
        if (isset($location['proxy']) || isset($location['hosting'])) {
            $location['vpn_proxy_detected'] = true;
        }
        
        return $location;
    }
    
    return null;
}

// Fingerprint validation
function validateFingerprint() {
    $fingerprint_data = [];
    
    // Collect server-side fingerprint data
    $fingerprint_data['accept'] = $_SERVER['HTTP_ACCEPT'] ?? '';
    $fingerprint_data['accept_language'] = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    $fingerprint_data['accept_encoding'] = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
    $fingerprint_data['connection'] = $_SERVER['HTTP_CONNECTION'] ?? '';
    $fingerprint_data['host'] = $_SERVER['HTTP_HOST'] ?? '';
    
    return $fingerprint_data;
}

// Main data collection
$ip_analysis = getRealIPAddress();
$primary_ip = $ip_analysis['primary_ip'];
$proxy_detection = detectProxyVPN($primary_ip);
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$ua_analysis = analyzeUserAgent($user_agent);
$location_info = getEnhancedLocationInfo($primary_ip);
$fingerprint = validateFingerprint();
$referrer = $_SERVER['HTTP_REFERER'] ?? 'Direct';
$timestamp = date('Y-m-d H:i:s');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Visitor Detection System</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            color: #333;
        }

        .container {
            max-width: 1200px;
            width: 100%;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            padding: 30px;
            animation: slideIn 0.8s ease-out;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
        }

        .header h1 {
            color: #2c3e50;
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header p {
            color: #7f8c8d;
            font-size: 1.1rem;
        }

        .security-status {
            background: linear-gradient(145deg, #e74c3c, #c0392b);
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
            font-weight: bold;
        }

        .security-status.safe {
            background: linear-gradient(145deg, #27ae60, #229954);
        }

        .security-status.warning {
            background: linear-gradient(145deg, #f39c12, #e67e22);
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }

        .info-card {
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .info-card.suspicious {
            border-left: 5px solid #e74c3c;
        }

        .info-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
        }

        .info-card h3 {
            color: #2c3e50;
            font-size: 1.3rem;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .icon {
            width: 24px;
            height: 24px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            border-radius: 6px;
            display: inline-block;
        }

        .info-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
        }

        .info-item:last-child {
            border-bottom: none;
        }

        .info-label {
            font-weight: 600;
            color: #495057;
            flex: 1;
        }

        .info-value {
            color: #2c3e50;
            font-weight: 500;
            flex: 2;
            text-align: right;
            word-break: break-all;
        }

        .highlight {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.9rem;
        }

        .warning {
            background: #e74c3c;
            color: white;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.85rem;
        }

        .safe {
            background: #27ae60;
            color: white;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.85rem;
        }

        .suspicious-list {
            background: rgba(231, 76, 60, 0.1);
            border: 1px solid #e74c3c;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }

        .suspicious-list h4 {
            color: #e74c3c;
            margin-bottom: 10px;
        }

        .suspicious-list ul {
            list-style: none;
            padding: 0;
        }

        .suspicious-list li {
            background: rgba(231, 76, 60, 0.2);
            padding: 8px;
            margin: 5px 0;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        .fingerprint-section {
            background: linear-gradient(145deg, #3498db, #2980b9);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }

        .real-time {
            background: linear-gradient(145deg, #28a745, #20c997);
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }

        .refresh-btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }

        .refresh-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
        }

        .timestamp {
            text-align: center;
            color: #6c757d;
            font-style: italic;
            margin-top: 20px;
        }

        @media (max-width: 768px) {
            .container {
                margin: 10px;
                padding: 20px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            
            .info-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 5px;
            }
            
            .info-value {
                text-align: left;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Advanced Visitor Detection System</h1>
            <p>Advanced proxy, VPN & spoofing detection with real-time analysis</p>
        </div>

        <?php 
        $total_suspicious = count($proxy_detection) + count($ua_analysis['suspicious_indicators']);
        $security_class = $total_suspicious === 0 ? 'safe' : ($total_suspicious < 3 ? 'warning' : '');
        $security_message = $total_suspicious === 0 ? '✅ Clean Connection Detected' : 
                           ($total_suspicious < 3 ? '⚠️ Some Suspicious Indicators Found' : '🚨 Multiple Security Concerns Detected');
        ?>
        
        <div class="security-status <?php echo $security_class; ?>">
            <?php echo $security_message; ?> - Trust Level: <?php echo $ua_analysis['trustworthiness']; ?>
        </div>

        <div class="real-time">
            <strong>📡 Advanced Detection Active</strong> - Real-time proxy/VPN/spoofing analysis
        </div>

        <div class="info-grid">
            <!-- IP Analysis -->
            <div class="info-card <?php echo count($proxy_detection) > 0 ? 'suspicious' : ''; ?>">
                <h3><span class="icon"></span> IP Address Analysis</h3>
                <div class="info-item">
                    <span class="info-label">Primary IP:</span>
                    <span class="info-value highlight"><?php echo htmlspecialchars($primary_ip); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Proxy Headers:</span>
                    <span class="info-value"><?php echo count($ip_analysis['proxy_headers']); ?> detected</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Multiple IPs:</span>
                    <span class="info-value"><?php echo count($ip_analysis['all_ips']); ?> found</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Proxy Status:</span>
                    <span class="info-value <?php echo count($proxy_detection) > 0 ? 'warning' : 'safe'; ?>">
                        <?php echo count($proxy_detection) > 0 ? 'Suspicious' : 'Clean'; ?>
                    </span>
                </div>
                
                <?php if (count($proxy_detection) > 0): ?>
                <div class="suspicious-list">
                    <h4>🚨 Proxy/VPN Indicators:</h4>
                    <ul>
                        <?php foreach ($proxy_detection as $indicator): ?>
                        <li><?php echo htmlspecialchars($indicator); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
                <?php endif; ?>
            </div>

            <!-- Browser Analysis -->
            <div class="info-card <?php echo count($ua_analysis['suspicious_indicators']) > 0 ? 'suspicious' : ''; ?>">
                <h3><span class="icon"></span> Browser Authenticity</h3>
                <div class="info-item">
                    <span class="info-label">Browser:</span>
                    <span class="info-value"><?php echo htmlspecialchars($ua_analysis['browser_info']['browser'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Version:</span>
                    <span class="info-value"><?php echo htmlspecialchars($ua_analysis['browser_info']['browser_version'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Engine:</span>
                    <span class="info-value"><?php echo htmlspecialchars($ua_analysis['browser_info']['engine'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Authenticity:</span>
                    <span class="info-value <?php echo $ua_analysis['trustworthiness'] === 'High' ? 'safe' : 'warning'; ?>">
                        <?php echo $ua_analysis['trustworthiness']; ?>
                    </span>
                </div>
                
                <?php if (count($ua_analysis['suspicious_indicators']) > 0): ?>
                <div class="suspicious-list">
                    <h4>🚨 Suspicious Browser Indicators:</h4>
                    <ul>
                        <?php foreach ($ua_analysis['suspicious_indicators'] as $indicator): ?>
                        <li><?php echo htmlspecialchars($indicator); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
                <?php endif; ?>
            </div>

            <!-- Operating System -->
            <div class="info-card">
                <h3><span class="icon"></span> Operating System</h3>
                <div class="info-item">
                    <span class="info-label">OS:</span>
                    <span class="info-value highlight"><?php echo htmlspecialchars($ua_analysis['browser_info']['os'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Version:</span>
                    <span class="info-value"><?php echo htmlspecialchars($ua_analysis['browser_info']['os_version'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Platform:</span>
                    <span class="info-value" id="platform">Detecting...</span>
                </div>
                <div class="info-item">
                    <span class="info-label">CPU Cores:</span>
                    <span class="info-value" id="cores">Detecting...</span>
                </div>
            </div>

            <!-- Device Information -->
            <div class="info-card">
                <h3><span class="icon"></span> Device Details</h3>
                <div class="info-item">
                    <span class="info-label">Device:</span>
                    <span class="info-value highlight"><?php echo htmlspecialchars($ua_analysis['browser_info']['device'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Type:</span>
                    <span class="info-value"><?php echo htmlspecialchars($ua_analysis['browser_info']['device_type'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Screen:</span>
                    <span class="info-value" id="resolution">Detecting...</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Touch Support:</span>
                    <span class="info-value" id="touch">Detecting...</span>
                </div>
            </div>

            <?php if ($location_info && $location_info['status'] === 'success'): ?>
            <!-- Location Information -->
            <div class="info-card">
                <h3><span class="icon"></span> Geographic Location</h3>
                <div class="info-item">
                    <span class="info-label">Country:</span>
                    <span class="info-value"><?php echo htmlspecialchars($location_info['country'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Region:</span>
                    <span class="info-value"><?php echo htmlspecialchars($location_info['regionName'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">City:</span>
                    <span class="info-value"><?php echo htmlspecialchars($location_info['city'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">ISP:</span>
                    <span class="info-value"><?php echo htmlspecialchars($location_info['isp'] ?? 'Unknown'); ?></span>
                </div>
                <?php if (isset($location_info['proxy']) || isset($location_info['hosting'])): ?>
                <div class="info-item">
                    <span class="info-label">VPN/Hosting:</span>
                    <span class="info-value warning">Detected</span>
                </div>
                <?php endif; ?>
            </div>

            <!-- Network Analysis -->
            <div class="info-card">
                <h3><span class="icon"></span> Network Analysis</h3>
                <div class="info-item">
                    <span class="info-label">ASN:</span>
                    <span class="info-value"><?php echo htmlspecialchars($location_info['as'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Organization:</span>
                    <span class="info-value"><?php echo htmlspecialchars($location_info['org'] ?? 'Unknown'); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Mobile Network:</span>
                    <span class="info-value"><?php echo isset($location_info['mobile']) && $location_info['mobile'] ? 'Yes' : 'No'; ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Timezone:</span>
                    <span class="info-value"><?php echo htmlspecialchars($location_info['timezone'] ?? 'Unknown'); ?></span>
                </div>
            </div>
            <?php endif; ?>

            <!-- Browser Fingerprint -->
            <div class="info-card">
                <h3><span class="icon"></span> Browser Fingerprint</h3>
                <div class="info-item">
                    <span class="info-label">Accept Headers:</span>
                    <span class="info-value" id="accept-headers">Analyzing...</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Languages:</span>
                    <span class="info-value"><?php echo htmlspecialchars(substr($fingerprint['accept_language'], 0, 30)); ?>...</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Encoding:</span>
                    <span class="info-value"><?php echo htmlspecialchars($fingerprint['accept_encoding']); ?></span>
                </div>
                <div class="info-item">
                    <span class="info-label">Connection:</span>
                    <span class="info-value"><?php echo htmlspecialchars($fingerprint['connection']); ?></span>
                </div>
            </div>

            <!-- Advanced Detection -->
            <div class="info-card">
                <h3><span class="icon"></span> Advanced Analysis</h3>
                <div class="info-item">
                    <span class="info-label">WebRTC IP:</span>
                    <span class="info-value" id="webrtc-ip">Detecting...</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Canvas Hash:</span>
                    <span class="info-value" id="canvas-hash">Generating...</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Audio Context:</span>
                    <span class="info-value" id="audio-context">Testing...</span>
                </div>
                <div class="info-item">
                    <span class="info-label">WebGL Vendor:</span>
                    <span class="info-value" id="webgl-vendor">Detecting...</span>
                </div>
            </div>
        </div>

        <!-- Detailed User Agent Analysis -->
        <div class="fingerprint-section">
            <h3>🔍 Complete User Agent Analysis</h3>
            <p><strong>Raw User Agent:</strong></p>
            <p style="word-break: break-all; margin: 10px 0; font-family: monospace; background: rgba(255,255,255,0.2); padding: 10px; border-radius: 5px;">
                <?php echo htmlspecialchars($user_agent); ?>
            </p>
            <div style="margin-top: 15px;">
                <strong>Analysis Result:</strong> 
                <span style="background: <?php echo $ua_analysis['trustworthiness'] === 'High' ? '#27ae60' : ($ua_analysis['trustworthiness'] === 'Medium' ? '#f39c12' : '#e74c3c'); ?>; padding: 4px 8px; border-radius: 4px;">
                    <?php echo $ua_analysis['trustworthiness']; ?> Trust Level
                </span>
            </div>
        </div>

        <div style="text-align: center; margin-top: 30px;">
            <button class="refresh-btn" onclick="performDeepScan()">
                🔄 Perform Deep Scan
            </button>
            <button class="refresh-btn" onclick="window.location.reload();" style="margin-left: 15px;">
                🔍 Refresh Analysis
            </button>
        </div>

        <div class="timestamp">
            Analysis completed: <?php echo $timestamp; ?>
        </div>
    </div>

    <script>
        // Advanced client-side detection
        document.addEventListener('DOMContentLoaded', function() {
            performAdvancedDetection();
        });

        function performAdvancedDetection() {
            // Basic system info
            document.getElementById('resolution').textContent = screen.width + ' x ' + screen.height;
            document.getElementById('platform').textContent = navigator.platform || 'Unknown';
            document.getElementById('cores').textContent = navigator.hardwareConcurrency || 'Unknown';
            document.getElementById('touch').textContent = 'ontouchstart' in window ? 'Yes' : 'No';

            // Accept headers analysis
            analyzeAcceptHeaders();

            // WebRTC IP detection
            detectWebRTCIP();

            // Canvas fingerprinting
            generateCanvasFingerprint();

            // Audio context fingerprinting
            generateAudioFingerprint();

            // WebGL detection
            detectWebGL();

            // Additional browser consistency checks
            performConsistencyChecks();
        }

        function analyzeAcceptHeaders() {
            // Check if fetch API is available and headers are consistent
            if (typeof fetch !== 'undefined') {
                const headers = new Headers();
                const acceptHeader = headers.get('accept') || 'Standard browser headers';
                document.getElementById('accept-headers').textContent = 'Standard';
            } else {
                document.getElementById('accept-headers').textContent = 'Limited API access';
            }
        }

        function detectWebRTCIP() {
            const rtcPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
            
            if (!rtcPeerConnection) {
                document.getElementById('webrtc-ip').textContent = 'WebRTC not supported';
                return;
            }

            const pc = new rtcPeerConnection({
                iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
            });

            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));

            pc.onicecandidate = function(event) {
                if (event.candidate) {
                    const candidate = event.candidate.candidate;
                    const ipMatch = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
                    if (ipMatch) {
                        const webrtcIP = ipMatch[1];
                        document.getElementById('webrtc-ip').textContent = webrtcIP;
                        
                        // Compare with server-detected IP
                        const serverIP = '<?php echo $primary_ip; ?>';
                        if (webrtcIP !== serverIP && !webrtcIP.startsWith('192.168.') && !webrtcIP.startsWith('10.') && !webrtcIP.startsWith('172.')) {
                            document.getElementById('webrtc-ip').innerHTML = webrtcIP + ' <span style="background: #e74c3c; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em;">IP Mismatch!</span>';
                        }
                    }
                }
            };

            setTimeout(() => {
                if (document.getElementById('webrtc-ip').textContent === 'Detecting...') {
                    document.getElementById('webrtc-ip').textContent = 'Detection failed';
                }
            }, 3000);
        }

        function generateCanvasFingerprint() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            // Draw a unique pattern
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('Browser fingerprint test 🔍', 2, 2);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Advanced detection system', 4, 17);
            
            const canvasData = canvas.toDataURL();
            const hash = simpleHash(canvasData);
            document.getElementById('canvas-hash').textContent = hash.substring(0, 16) + '...';
        }

        function generateAudioFingerprint() {
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const analyser = audioContext.createAnalyser();
                const gainNode = audioContext.createGain();
                
                oscillator.type = 'triangle';
                oscillator.frequency.value = 10000;
                gainNode.gain.value = 0;
                
                oscillator.connect(analyser);
                analyser.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.start();
                
                setTimeout(() => {
                    const bufferLength = analyser.frequencyBinCount;
                    const dataArray = new Uint8Array(bufferLength);
                    analyser.getByteFrequencyData(dataArray);
                    
                    const audioHash = simpleHash(dataArray.toString());
                    document.getElementById('audio-context').textContent = audioHash.substring(0, 16) + '...';
                    
                    oscillator.stop();
                    audioContext.close();
                }, 100);
                
            } catch (e) {
                document.getElementById('audio-context').textContent = 'Not available';
            }
        }

        function detectWebGL() {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                    const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                    document.getElementById('webgl-vendor').textContent = vendor + ' / ' + renderer;
                } else {
                    document.getElementById('webgl-vendor').textContent = 'WebGL available, vendor masked';
                }
            } else {
                document.getElementById('webgl-vendor').textContent = 'WebGL not supported';
            }
        }

        function performConsistencyChecks() {
            const inconsistencies = [];
            
            // Check if browser claims vs actual capabilities match
            const userAgent = navigator.userAgent;
            
            // Check for common spoofing indicators
            if (userAgent.includes('Chrome') && !window.chrome) {
                inconsistencies.push('Claims Chrome but chrome object missing');
            }
            
            if (userAgent.includes('Safari') && userAgent.includes('Chrome')) {
                // This is normal for Chrome, but check for other inconsistencies
            }
            
            // Check plugins consistency
            if (navigator.plugins.length === 0 && !userAgent.includes('Headless')) {
                inconsistencies.push('No plugins detected (suspicious)');
            }
            
            // Display inconsistencies
            if (inconsistencies.length > 0) {
                console.warn('Browser inconsistencies detected:', inconsistencies);
            }
        }

        function simpleHash(str) {
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                const char = str.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            return hash.toString(16);
        }

        function performDeepScan() {
            // Show loading state
            const btn = event.target;
            const originalText = btn.textContent;
            btn.textContent = '🔄 Deep Scanning...';
            btn.disabled = true;
            
            // Perform additional checks
            setTimeout(() => {
                // Re-run all detection methods
                performAdvancedDetection();
                
                // Check for automation tools
                checkAutomationTools();
                
                // Test for virtual machines
                checkVirtualMachine();
                
                btn.textContent = originalText;
                btn.disabled = false;
                
                alert('Deep scan completed! Check console for additional details.');
            }, 2000);
        }

        function checkAutomationTools() {
            const automationIndicators = [];
            
            // Check for common automation tools
            if (window.phantom) automationIndicators.push('PhantomJS detected');
            if (window._phantom) automationIndicators.push('PhantomJS (_phantom) detected');
            if (window.callPhantom) automationIndicators.push('PhantomJS (callPhantom) detected');
            if (window.selenium) automationIndicators.push('Selenium detected');
            if (window.webdriver) automationIndicators.push('WebDriver detected');
            if (navigator.webdriver) automationIndicators.push('WebDriver property detected');
            
            // Check for headless browser indicators
            if (!window.outerHeight || !window.outerWidth) {
                automationIndicators.push('Suspicious window dimensions');
            }
            
            if (automationIndicators.length > 0) {
                console.warn('Automation tools detected:', automationIndicators);
            }
        }

        function checkVirtualMachine() {
            const vmIndicators = [];
            
            // Check for common VM indicators
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            
            if (gl) {
                const vendor = gl.getParameter(gl.VENDOR);
                const renderer = gl.getParameter(gl.RENDERER);
                
                if (renderer.includes('VMware') || renderer.includes('VirtualBox') || 
                    renderer.includes('Virtual') || vendor.includes('VMware')) {
                    vmIndicators.push('Virtual machine graphics detected');
                }
            }
            
            // Check CPU core count (VMs often have fewer cores)
            if (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2) {
                vmIndicators.push('Low CPU core count (possible VM)');
            }
            
            if (vmIndicators.length > 0) {
                console.warn('Virtual machine indicators:', vmIndicators);
            }
        }

        // Real-time updates
        setInterval(() => {
            const now = new Date();
            const timestamp = document.querySelector('.timestamp');
            if (timestamp) {
                timestamp.innerHTML = 'Last updated: ' + now.toLocaleString();
            }
        }, 1000);
    </script>
</body>
</html>
