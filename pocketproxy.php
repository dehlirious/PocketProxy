<?php
$captchascript = "Captcha/AIO-Captcha.php";
if (file_exists($captchascript)) {
	include_once $captchascript;
}

$config = [
	//By default, password protection is disabled. If this setting is changed password protection will be enabled.
	//This password is used to restrict access to PocketProxy via password protection
	'lockedPassword' => 'vErYl0ngPasswordPh@se',
	
	//Specifies the duration of the session in hours before requiring the password again.
	'lockedSessionLength' => '3',
	
	// If you have a HTTPS:// website,  you need to set this to "https" otherwise there will be bugs and content(css/js) won't load properly!
	// If you are on HTTP, this needs to be set to "http"
	'httpvariable' => 'https',
	
	// Start/default URL that will be proxied when PocketProxy is first loaded in a browser/accessed directly with no URL to proxy
	// If empty, PocketProxy will show its own landing page
	'startURL' => "",
	
	// 1.44GB downloaded file size limitation (like mp4's and such)
	'maxdl' => 2444440000,
	
	// When no $startURL is configured above, PocketProxy will show its own landing page with a URL form field
	// and the configured example URL. The example URL appears in the instructional text on the PocketProxy landing page,
	// and is proxied when pressing the 'Proxy It!' button on the landing page if its URL form is left blank
	'landingExampleURL' => "https://example.net",
	
	// Path for the blacklist log file, leave it to this value to disable logging of this aspect 
	'blacklistlog' => "logxzx/captchablacklist.log",
	
	// Change this to false to disable captcha codes from being displayed in plaintext
	'cce' => true,
	
	//To make a user enter a captcha for specified website(s) "archive.org"
	'captchasites' => [
		"roblox.com", "xbox.com","youtube.com","icann.org", "duckdns.org", "steamcommunity.com",
		"steamgifts.com", "archive.ph", "archive.md", "archive.is", "archive.li", "archive.vn", "archive.org", "archive.com",
	],
	
	//To make a UserAgent forced to enter a captcha regardless of website.
	'captchaagents' => [
		// Pre-filled with many Bot captcha's.
		"Amazonbot/0.1", "Googlebot/2.1", "Bingbot/2.0", "Slackbot/1.0", "Facebookbot/2.1", "Twitterbot/2.0",
		"LinkedInBot/2.0", "Pinterest/0.1", "Tumblr/1.0", "Applebot/1.0", "WhatsApp/2.0", "Skypebot/1.0", "Snapchat/1.0", "Discordbot/2.0",
		"Redditbot/1.0", "Yandexbot/3.0", "Ahrefsbot/5.0", "Majestic-12/1.0", "CommonCrawl/2.0", "SemrushBot/3.0", "Baiduspider/2.0",
		"Exabot/1.0", "Sogou web spider/2.0", "DuckDuckGo/1.0", "Blekko/1.0", "BingPreview/1.0", "Ecosia/1.0", "Seznambot/3.0",
		"Xenu Link Sleuth/2.0", "Wayback Machine/3.0", "Wget/1.0", "Curl/7.0", "Python-urllib/3.0", "Ruby/2.0", "Java/1.0", "MJ12bot/1.0",
		"rogerbot/2.0", "Exabot/3.0", "Ezooms/1.0", "DotBot/1.0", "YandexImages/3.0", "Yahoo! Slurp/3.0", "Barkrowler/1.0", "CCBot/2.0", "
		SemrushBot/2.0", "ia_archiver/2.0", "TurnitinBot/2.0", "BLEXBot/1.0", "AdsBot-Google/2.0", "Gigabot/3.0", "Yeti/1.0", "ZoominfoBot/1.0",
		"Nutch/1.0", "GrapeshotCrawler/2.0", "oBot/2.0", "Mail.RU_Bot/2.0", "BingPreview/2.0", "Screaming Frog SEO Spider/1.0",
		"magpie-crawler/1.0", "Baidu Spider/3.0", "LinkedInBot/1.0", "Curl/8.0", "PHP/7.0", "Python/3.0", "Go-http-client/1.0",
		"Java/11.0", "Ruby/3.0", "RamblerMail/1.0", "SeznamBot/1.0", "DuckDuckBot/1.0", "rogerbot/3.0", "YandexBot/4.0", "PaperLiBot/2.0",
		"Barkrowler/2.0", "Sogou web spider/3.0", "Wget/2.0", "libwww-perl/6.0", "PHP/8.0", "AhrefsBot/6.0", "BUbiNG/7.0",
		"Dataprovider.com/8.0", "Cortex/9.0", "DomainStatsBot/10.0", "SiteBot/11.0", "Qwantify/12.0", "AiHitBot/13.0",
		"Seekport Crawler/14.0", "PiplBot/15.0", "Zenserp/16.0", "g00g1e.net/17.0", "PaperBot/18.0", "YippyBot/19.0", "DuckDuckGo/20.0",
		"SputnikBot/21.0", "LinksSpyder/22.0", "SerendeputyBot/23.0", "PingdomBot/24.0", "Hatena Crawler/25.0",
		"Screaming Frog SEO Spider/26.0", "NaverBot/27.0", "Bingbot/28.0", "DotBot/2.0", "SeznamBot/2.0", "MJ12bot/2.0", "BLEXBot/2.0",
		"Sogou web spider/4.0", "Gigabot/4.0", "YandexBot/5.0", "Yahoo! Slurp/4.0", "SemrushBot/3.0", "TurnitinBot/3.0", "AdsBot-Google/3.0",
		"Googlebot-Image/1.0", "BingPreview/3.0", "Qwantify/2.0", "Curl/9.0", "Python/4.0", "Java/12.0", "Ruby/4.0",
		"RamblerMail/2.0", "oBot/3.0", "Mail.RU_Bot/3.0", "Screaming Frog SEO Spider/2.0", "magpie-crawler/2.0", "Baidu Spider/4.0",
		"LinkedInBot/2.0", "PHP/9.0", "Go-http-client/2.0", "Googlebot-Mobile/1.0", "Bingbot-Mobile/1.0",
	],
	
	//Likely to not have to touch these
	'forceCORS' => true, // To enable CORS (cross-origin resource sharing) for proxied sites
	'disallowLocal' => true, // Set to false to allow sites on the local network to be proxied
	

];

class Proxy {
	public $a, $maxdl, $forceCORS, $blacklistlog, $cce, $blacklistPatterns, $CaptchaSites, $Lpassword, $LsessionL,
		$httpvariable, $whitelistPatterns, $disallowLocal, $startURL, $landingExampleURL, $requiredExtensions;
	
	public function __construct($config) {
	
		//Temporarily Not in $config because of usage of getHostnamePattern
		
		//To allow proxying any URL, set $whitelistPatterns to an empty array (the default).
		//To ONLY allow proxying of specific domains, fill this array.
		$this->whitelistPatterns = [
			// Usage example: To whitelist any URL at example.net, including sub-domains, uncomment the
			// line below (which is equivalent to [ @^https?://([a-z0-9-]+\.)*example\.net@i ]):
			// $this->getHostnamePattern("example.net")
		];
		$this->blacklistPatterns = [
			$this->getHostnamePattern($_SERVER['HTTP_HOST']),
			$this->getHostnamePattern($_SERVER['SERVER_NAME']),
			$this->getHostnamePattern("httpbin.org"),
		];
		//

		$this->Lpassword = $config['lockedPassword'];
		$this->LsessionL = $config['lockedSessionLength'];
		$this->CaptchaSites = $config['captchasites'];
		$this->CaptchaAgents = $config['captchaagents'];

		$this->httpvariable = isset($config['httpvariable']) ? $config['httpvariable'] : null;
		$this->cce = isset($config['cce']) ? $config['cce'] : null;
		$this->forceCORS = isset($config['forceCORS']) ? $config['forceCORS'] : null;
		$this->disallowLocal = isset($config['disallowLocal']) ? $config['disallowLocal'] : null;
		$this->startURL = isset($config['startURL']) ? $config['startURL'] : null;
		$this->maxdl = isset($config['maxdl']) ? $config['maxdl'] : null;
		$this->landingExampleURL = isset($config['landingExampleURL']) ? $config['landingExampleURL'] : null;
		$this->blacklistlog = isset($config['blacklistlog']) ? $config['blacklistlog'] : null;

		$this->requiredExtensions = ["curl", "mbstring", "xml"];

		define("PROXY_PREFIX", $this->httpvariable . "://" . 
			(strpos($_SERVER["HTTP_HOST"], ":") ? implode(":", explode(":", $_SERVER["HTTP_HOST"], -1)) : $_SERVER["HTTP_HOST"]) .
			($_SERVER['SERVER_PORT'] != 80 && $_SERVER['SERVER_PORT'] != 443 ? ':' . $_SERVER['SERVER_PORT'] : '') . 
			$_SERVER["SCRIPT_NAME"] . "?");


		if (version_compare(PHP_VERSION, "5.4.7", "<")) {
			die("PocketProxy requires PHP version 5.4.7 or later.");
		}

		foreach ($this->requiredExtensions as $requiredExtension) {
			if (!extension_loaded($requiredExtension)) {
				die("PocketProxy requires PHP's \"" . $requiredExtension . "\" extension. Please install/enable it on your server and try again.");
			}
		}
	}
	
	/**
	 * Extracts the domain from a given URL by removing the protocol and path.
	 *
	 * This function removes the 'http://' or 'https://' and any subsequent path or query string
	 * from the provided URL to extract the domain.
	 */
	public function getDomain($url) {
		if (preg_match('/[a-z0-9][a-z0-9\-]{0,63}\.[a-z]{2,6}(\.[a-z]{1,2})?$/i', parse_url((strpos($url, "://") === false ? "http://" : "") . trim($url) , PHP_URL_HOST), $match)) {
			return $match[0];
		}
	}

	/**
	 * Helper function to generate a regex pattern that matches HTTP[S] URLs for a given hostname.
	 *
	 * This function generates a regex pattern that matches all HTTP[S] URLs with the specified hostname,
	 * including subdomains. The generated pattern can be used in whitelist or blacklist patterns.
	 */
	public function getHostnamePattern($hostname) {
		return "@^https?://([a-z0-9-]+\.)*" . str_replace(".", "\.", $hostname) . "@i";
	}

	/**
	 * Helper function to determine whether to allow proxying of a given URL.
	 *
	 * This function checks if the provided URL passes whitelist, blacklist, and local restrictions
	 * to determine whether it is valid for proxying.
	 */
	public function isValidURL($url) {
		return $this->passesWhitelist($url) && $this->passesBlacklist($url) && ($this->disallowLocal ? !$this->isLocal($url) : true);
	}
	
	/**
	 * Retrieves the user's IP address from server headers.
	 *
	 * This function checks various server headers in the order of priority
	 * to determine the user's IP address. It first looks for Cloudflare headers
	 * if applicable, and falls back to the REMOTE_ADDR header 
	 * if no valid IP is found in the previous headers.
	 */
	public function getUserIp() {
		// Define the headers in the order of priority for determining the user IP
		$headersToCheck = [
			'HTTP_CF_CONNECTING_IP',	// Cloudflare header, useful if you're using Cloudflare services
			'CF-Connecting-IP',	// Cloudflare header, useful if you're using Cloudflare services
			//'HTTP_CLIENT_IP',		   // Direct client IP
			//'HTTP_X_FORWARDED_FOR',   // Can be uncommented if you decide to trust this header
		];

		foreach ($headersToCheck as $header) {
			if (isset($_SERVER[$header])) {
				$ip = $_SERVER[$header];
				if (filter_var($ip, FILTER_VALIDATE_IP)) {
					$this->ip = $ip; // Assign the first valid IP found to the class property
					return $ip; // Return the IP and stop further processing
				}
			}
		}

		// If no valid IP is found in the headers above, fallback to REMOTE_ADDR
		if (filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
			$this->ip = $_SERVER['REMOTE_ADDR'];
			return $this->ip;
		}

		// If no valid IP is found at all, you might want to handle it differently
		// For now, let's return null indicating no valid IP was found
		$this->ip = null;
		return null;
	}
	
	/**
	 * Helper function used to remove keys from an associative array using case insensitive matching.
	 * 
	 * This function iterates through the keys of the provided associative array and removes keys 
	 * that match the keys specified in the $keys2remove array, ignoring case. It returns an array 
	 * containing the keys that were removed.
	 */
	public function removeKeys(&$assoc, $keys2remove) {
		$keys = array_keys($assoc);
		$map = [];
		$removedKeys = [];
		foreach ($keys as $key) {
			$map[strtolower($key) ] = $key;
		}
		foreach ($keys2remove as $key) {
			$key = strtolower($key);
			if (isset($map[$key])) {
				unset($assoc[$map[$key]]);
				$removedKeys[] = $map[$key];
			}
		}
		return $removedKeys;
	}
	
	/**
	 * Retrieves all HTTP headers from the current request.
	 *
	 * This function returns an array containing all HTTP headers present in the current request.
	 * If the 'getallheaders' function is available, it is used to retrieve the headers.
	 * Otherwise, the function iterates over $_SERVER to collect header values.
	 */
	public function getAllHeaders() {
		if (!function_exists("getallheaders")) {
			// Adapted from http://www.php.net/manual/en/function.getallheaders.php#99814
			$result = [];
			foreach ($_SERVER as $key => $value) {
				if (substr($key, 0, 5) == "HTTP_") {
					$key = str_replace(" ", "-", ucwords(strtolower(str_replace("_", " ", substr($key, 5)))));
					$result[$key] = $value;
				}
			}
			return $result;
		} else {
			// If getallheaders() function already exists, use it
			return getallheaders();
		}
	}
	
	/**
	 * Converts a relative URL to an absolute URL based on a given base URL.
	 * Modified version of code found at https://web.archive.org/web/20121014113424/https://nashruddin.com/PHP_Script_for_Converting_Relative_to_Absolute_URL
	 *
	 * This function supports various relative URL formats, including those that start with
	 * "/", "?", "#", or are relative to the current directory or parent directories.
	 * It handles paths with "../" and "./", and automatically detects and preserves absolute URLs.
	 * Additionally, it supports URLs with or without authentication and custom ports.
	 * 
	 * Situations where it's failed:
	 * ["rel" => "../../../page2.html", "base" => "http://www.example.com/dir1/dir2/dir3/dir4/", "expected" => "http://www.example.com/page2.html"],
	 * FAIL: Expected http://www.example.com/page2.html, got http://www.example.com/dir1/dir2/page2.html
	 * 
	 * ["rel" => "../../../updir/page2.html", "base" => "http://www.example.com/dir/subdir/another/page1.html", "expected" => "http://www.example.com/updir/page2.html"],
	 * FAIL: Expected http://www.example.com/updir/page2.html, got http://www.example.com/dir/updir/page2.html
	 * 
	 * ["rel" => "file2.txt", "base" => "file:///C:/dir1/file1.txt", "expected" => "file:///C:/dir1/file2.txt"],
	 * FAIL: Expected file:///C:/dir1/file2.txt, got file://C:/dir1/file2.txt
	 * 
	 */
	public function rel2abs($rel, $base) {
		if (empty($rel)) {
			$rel = "";
		}
		if (parse_url($rel, PHP_URL_SCHEME) != "" || strpos($rel, "//") === 0) {
			return $rel; // Return if already an absolute URL
		}
		
		if (!empty($rel) && ($rel[0] == "#" || $rel[0] == "?")) {
			return $base . $rel; // Queries and anchors
		}


		// Validate the base URL
		$parsedBase = parse_url($base);
		if (!$parsedBase) {
			// Handle error: invalid base URL
			return false; // Or handle as appropriate for your use case
		}
		extract($parsedBase); // Parse base URL and convert to local variables: $scheme, $host, $path

		$path = isset($path) ? preg_replace("#/[^/]*$#", "", $path) : "/"; // Remove non-directory element from path
		if (!empty($rel) && $rel[0] == "/") {
			$path = ""; // Destroy path if relative url points to root
		}

		// Add condition for default HTTPS port (443)
		$port = isset($port) && $port != 80 && $port != 443 ? ":" . $port : "";

		$auth = isset($user) ? $user . (isset($pass) ? ":$pass" : "") . "@" : "";

		$abs = "$auth$host$port$path/$rel"; // Dirty absolute URL

		// Ensure the loop that resolves "../" is safe against malformed inputs
		$loopSafetyCounter = 0;
		while (strpos($abs, '../') !== false && $loopSafetyCounter++ < 20) { // Prevent infinite loops
			$abs = preg_replace('#/([^/]+/)?\.\./#', '/', $abs, -1, $count);
			if ($count == 0) {
				break; // Exit if no replacements were made
			}
		}

		$abs = preg_replace('#/\./#', '/', $abs); // Resolve "/./"
		$abs = preg_replace('#//+#', '/', $abs); // Remove duplicate slashes
		return $scheme . "://" . $abs; // Absolute URL is ready
	}
	
	
	/**
	 * This function generates a user agent string based on the specified operating system.
	 */
	function generateUA($userAgent) {
		$userAgent = strtolower($userAgent);
		$os = 'Unknown';
		$operatingSystems = ['linux', 'iphone', 'ipad', 'macintosh', 'mac os', 'windows', 'android'];

		foreach ($operatingSystems as $osName) {
			if (strpos($userAgent, $osName) !== false) {
				$os = ucfirst($osName);
				break;
			}
		}

		if (strpos($userAgent, 'android') !== false && strpos($userAgent, 'chrome') !== false) {
			$os = 'android';
		}
		switch (strtolower($os)) {
			case 'windows':
				return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
			case 'macintosh':
			case 'mac os':
				return 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/107.0.0.0';
			case 'edge':
				return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/121.0.2277.128';
			case 'android':
				return 'Mozilla/5.0 (Android 14; Mobile; rv:123.0) Gecko/123.0 Firefox/123.0';
			case 'iphone':
				return 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1';
			case 'ipad':
				return 'Mozilla/5.0 (iPad; CPU OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1';
			case 'linux':
				return 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
			default:
				return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
		}
	}

	/**
	 * Convert a memory limit value to bytes.
	 *
	 * This function takes a memory limit value in various formats (e.g., '256M', '2G', '1024K')
	 * and converts it to bytes for easier processing and comparison.
	 */
	public function memoryLimitToBytes($val) {
		$val = trim($val);

		// Check if the value is purely numeric, which means it's already in bytes
		if (is_numeric($val)) {
			return (int)$val;
		}

		// Regular expression to separate the number from the unit
		if (preg_match('/^(\d+)([gmk])$/i', $val, $matches)) { // Update here
			$value = (int)$matches[1];
			$unit = strtolower($matches[2]);

			switch ($unit) {
				case 'g':
					return $value * 1024 * 1024 * 1024;
				case 'm':
					return $value * 1024 * 1024;
				case 'k':
					return $value * 1024;
			}
		}

		// If the input doesn't match expected patterns, throw an exception
		throw new InvalidArgumentException("Invalid memory limit format: {$val}");
	}

	/**
	 * Determines if the given URL is a local address or not.
	 *
	 * This function checks whether the provided URL corresponds to a local address 
	 * by attempting to resolve the hostname to its corresponding IP addresses and 
	 * checking if any of them fall within the private or reserved IP range.
	 */
	public function isLocal($url) {
		//First, generate a list of IP addresses that correspond to the requested URL.
		$ips = [];
		$host = parse_url($url, PHP_URL_HOST);
		
		if (filter_var($host, FILTER_VALIDATE_IP)) {
			//The supplied host is already a valid IP address.
			$ips = [$host];
		}
		else {
			//The host is not a valid IP address; attempt to resolve it to one.
			$dnsResult = @dns_get_record($host, DNS_A + DNS_AAAA); // bug warning code https://bugs.php.net/bug.php?id=73149 , supressed with '@'
			
			if(!is_bool($dnsResult)){//Fixes my array_map error. Doesn't fix the blank page when the domain isn't resolvable.
				$ips = array_map(function ($dnsRecord) {
					return $dnsRecord["type"] == "A" ? $dnsRecord["ip"] : $dnsRecord["ipv6"];
				}
				, $dnsResult);
			}
		}
		foreach ($ips as $ip) {
			//Determine whether any of the IPs are in the private or reserved range.
			if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Validates a URL against the whitelist.
	 *
	 * This function checks if the provided URL matches any of the patterns in the whitelist.
	 * If the whitelist is empty, all URLs are considered valid.
	 */
	public function passesWhitelist($url) {
		if (count($this->whitelistPatterns) === 0) {
			return true;
		}
		foreach ($this->whitelistPatterns as $pattern) {
			if (preg_match($pattern, $url)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Validates a URL against the blacklist.
	 *
	 * This function checks if the provided URL matches any of the patterns in the blacklist.
	 * If the URL matches any pattern in the blacklist, it is considered invalid.
	 */
	public function passesBlacklist($url) {
		foreach ($this->blacklistPatterns as $pattern) {
			if (preg_match($pattern, $url)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Logs the provided URL along with the user's IP address to a blacklist log file.
	 *
	 * This function checks if the blacklist log file exists, is readable, and writable, 
	 * along with its directory. It also ensures that the provided URL is not already logged 
	 * to prevent duplicates. If all conditions are met, it appends the URL and user's IP 
	 * address to the blacklist log file.
	 */
	public function logcbl($url) {
		// Get the directory of the blacklist log file
		$logDirectory = dirname($this->blacklistlog);
		
		// Check if the blacklist log file and its directory exist, are readable, and writable
		if (file_exists($this->blacklistlog) && is_readable($this->blacklistlog) 
			&& is_writable($this->blacklistlog) && is_dir($logDirectory) && is_writable($logDirectory)
			&& $this->blacklistlog !== "logxzx/captchablacklist.log") {
			
			$file = file($this->blacklistlog);
			$line_count_pre = count($file);
			
			// Construct the content to be logged
			$content = $this->getUserIp() . "; #" . $url . PHP_EOL;
			
			// Check if the URL is not already logged to prevent duplicates
			if (!in_array($content, $file)) {
				file_put_contents($this->blacklistlog, $content, FILE_APPEND | LOCK_EX);
			}
			
			unset($file);
		}
	}


	/**
	 * Handles access control for the application.
	 *
	 * This function manages access control by enforcing password protection.
	 * If the password is correct, it sets session variables to indicate successful login.
	 * If no password is provided or if the password is incorrect, it displays a login form.
	 */
	public function handleAccess() {
		if ($this->Lpassword !== 'vErYl0ngPasswordPh@se') {
			session_name('MugglerLugglerDuggler');
			session_start(); // Start the session only when needed
		}
		
		if (isset($_POST['privsubmit_pwd'])) {
			$pass = isset($_POST['passwd']) ? $_POST['passwd'] : '';

			if ($pass != $this->Lpassword) {
				$this->showForm("Wrong password");
				exit();
			} else {
				$_SESSION['loggedin'] = true;
				$_SESSION['start_time'] = time();
				$_SESSION['expire_time'] = $_SESSION['start_time'] + ($this->LsessionL * 60 * 60);
			}
		} else {
			if ((!isset($_SESSION['loggedin']) || !$_SESSION['loggedin'] || time() >= $_SESSION['expire_time']) && $this->Lpassword !== 'vErYl0ngPasswordPh@se') {
				$this->showForm();
				exit();
			}
		}
	}
	
	/**
	 * Displays the login form.
	 */
	public function showForm($error="Login"){
		echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Login</title><meta name="viewport" content="width=device-width, initial-scale=1.0">
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"><style>body { background: #f8f9fa; }.error { font: 24px/1.5 sans-serif; color: #dc3545; }</style></head>
		<body><div class="container mt-5"><div class="row justify-content-center"><div class="col-md-6 text-center"><p class="error">' . $error . '</p><form action="' . addslashes($_SERVER['REQUEST_URI']) . '" method="post" name="pwd"><label for="passwd" class="visually-hidden">Password:</label><input class="form-control mb-3" name="passwd" type="password" id="passwd" required>
		<button class="btn btn-primary" type="submit" name="privsubmit_pwd">Login</button></form></div></div></div></body></html>'; 
	}

	//Makes an HTTP request via cURL, using request data that was passed directly to this script.
	public function makeRequest($url) {
		$user_agent = $this->generateUA($_SERVER["HTTP_USER_AGENT"]);
		
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);

		//Get ready to proxy the browser's request headers...
		$browserRequestHeaders = $this->getallheaders();

		//Let cURL set some headers on its own and strip away bad headers that reveal too much information!
		$removedHeaders = $this->removeKeys($browserRequestHeaders, [
			// "Accept-Encoding", // Removed because it gave me issues! I don't know why yet
			"Content-Length", "permissions-policy",
			"strict-transport-security", "report-to", "Host",
			"x-content-type-options", "cross-origin-opener-policy-report-only",
			"content-security-policy", "x-frame-options", "x-robots-tag",
			"x-xss-protection", "X-Frame-Options", "Origin", "ETag", "X-UIDH", 
			"User-Agent", "Pragma", "Upgrade-Insecure-Requests",
			"Client-IP", "X-Real-IP", "X-Forwarded-For",
			"HTTP_CF_CONNECTING_IP", "REMOTE_ADDR", "HTTP_X_FORWARDED_FOR", "HTTP_CLIENT_IP",
			"X-Forwarded-Host", "HTTP_X_REAL_IP", "HTTP_VIA", "Forwarded", "CF-Connecting-IP", "X-Cluster-Client-Ip",
			"X-Forwarded-Server", "X-ProxyUser-Ip", "X-Real-Host", "X-Original-URL", "X-Original-Forwarded-For",
			"X-Client-IP", "X-Originating-IP", "X-User-IP", "X-Remote-Addr",
			"Proxy-Authorization", "If-Modified-Since", "If-None-Match", "X-Requested-With", "X-Requested-For",
			"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", // Security fetch metadata headers
		]);

		$removedHeaders = array_map("strtolower", $removedHeaders);

		curl_setopt($ch, CURLOPT_ENCODING, "");
		//Transform the associative array from getallheaders() into an indexed array of header strings to be passed to cURL.
		$curlRequestHeaders = [];
		
		foreach ($browserRequestHeaders as $name => $value) {
			if (!in_array(strtolower($name), $removedHeaders)) {
				$curlRequestHeaders[] = $name . ": " . $value;
			}
		}
		
		//Any `origin` header sent by the browser will refer to the proxy itself.
		//If an `origin` header is present in the request, rewrite it to point to the correct origin.
		if (in_array("origin", $removedHeaders)) {
			$urlParts = parse_url($url);
			$port = @array_key_exists("port", $urlParts) == null ? "" : $urlParts["port"]; // Modified to remove a PHP Warning code
			$curlRequestHeaders[] = "Origin: " . $urlParts["scheme"] . "://" . $urlParts["host"] . (empty($port) ? "" : ":" . $port);
		}
		
		curl_setopt($ch, CURLOPT_HTTPHEADER, $curlRequestHeaders);

		//Proxy any received GET/POST/PUT data.
		switch ($_SERVER["REQUEST_METHOD"]) {
			case "POST":
				$postData = [];
				parse_str(file_get_contents("php://input") , $postData);
				//Captcha related issue fixed!
				if (isset($postData["phrase"])) {
					$_SERVER["REQUEST_METHOD"] = "GET";
				} else {
					curl_setopt($ch, CURLOPT_POST, true);
					//For some reason, $HTTP_RAW_POST_DATA isn't working as documented at
					//http://php.net/manual/en/reserved.variables.httprawpostdata.php
					//but the php://input method works. This is likely to be flaky
					//across different server environments.
					//More info here: http://stackoverflow.com/questions/8899239/http-raw-post-data-not-being-populated-after-upgrade-to-php-5-3
					//If the ProxyForm field appears in the POST data, remove it so the destination server doesn't receive it.
					if (isset($postData["ProxyForm"])) {
						unset($postData["ProxyForm"]);
					}
					curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
				}
			break;
			case "PUT":
				curl_setopt($ch, CURLOPT_PUT, true);
				curl_setopt($ch, CURLOPT_INFILE, fopen("php://input", "r"));
			break;
		}

		//Other cURL options.
		curl_setopt($ch, CURLOPT_HEADER, true);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		//Set the request URL.
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_MAXFILESIZE, $this->maxdl);

		//Make the request.
		$response = curl_exec($ch);
		$responseInfo = curl_getinfo($ch);
		$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
		curl_close($ch);

		//Setting CURLOPT_HEADER to true above forces the response headers and body
		//to be output together--separate them.
		$responseHeaders = substr($response, 0, $headerSize);
		$responseBody = substr($response, $headerSize);
		
		// Extract cookies from response headers
		preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $responseHeaders, $matches);
		$cookies = array();
		foreach ($matches[1] as $item) {
			// Parse the cookie string into name, value, and attributes
			parse_str($item, $cookie);

			// Prefix all cookie names with the domain name
			foreach ($cookie as $name => $value) {
				$new_name = $prefix = str_replace('.', '', $this->getDomain($url)) . '_' . $name;
				$cookie[$new_name] = $value;
				unset($cookie[$name]); // Remove the old cookie name
			}

			// Rebuild the cookie string
			$cookie_string = http_build_query($cookie, '', '; ');

			// Add the modified cookie to the array
			$cookies[] = $cookie_string;
		}

		// Set the extracted and modified cookies
		foreach ($cookies as $cookie_string) {
			list($name, $value) = explode('=', $cookie_string, 2);
			$value = trim($value);
			if (!empty($value) && $value !== "DELETE") {
				// Set the cookie
				header('Set-Cookie: ' . $cookie_string, false);
			}
		}
		

		return ["headers" => $responseHeaders, "body" => $responseBody, "responseInfo" => $responseInfo, ];
	}
	
	/**
	 * Proxify contents of url() references in blocks of CSS text.
	 *
	 * This function normalizes CSS content by replacing URLs with proxified URLs,
	 * ensuring that all URLs in the CSS content are properly proxied.
	 * It also handles memory exhaustion gracefully by returning the original CSS content
	 * if the memory limit is nearing exhaustion during processing.
	 */
	public function proxifyCSS($css, $baseURL) {
		/* Please note: This is unsecure. For now, it should be disabled. */
		//$memoryLimit = ini_get('memory_limit');
		
		// If memory limit is set to -1 (unlimited), manually set it to 1GB for our checks
		//$memoryLimitBytes = ($memoryLimit == -1) ? $this->memoryLimitToBytes('1G') : $this->memoryLimitToBytes($memoryLimit);
		//$safeMemoryLimit = $memoryLimitBytes * 0.95; // Stay 5% below the memory limit

		// Split the CSS content into lines
		$sourceLines = explode("\n", $css);
		$normalizedLines = [];

		// Loop through each line of the CSS content
		foreach ($sourceLines as $line) {
			//if (memory_get_usage() > $safeMemoryLimit) {
				// Memory limit nearing exhaustion, stop processing and return the original CSS
				//return $css;
			//}

			// Match the quotation character used and capture it in a group
			$normalizedLine = preg_replace_callback("/(@import\s+)(['\"])([^;\s]+)(['\"])([\s;])|url\(([\"']?)(.*?)\\6\)/i", function ($matches) use ($baseURL) {
				// Check if it's an @import or url() and perform the corresponding replacement
				if (!empty($matches[1])) {
					$quote = $matches[2] ?? '';
					// Construct the proxified URL
					return $matches[1] . "url(" . $quote . PROXY_PREFIX . $this->rel2abs($matches[3], $baseURL) . $quote . ")" . $matches[5];
				} else {
					$quote = $matches[6] ?? ''; // Get the quotation character used (or empty string if not provided)
					$url = $matches[7];

					if (stripos($url, "data:") === 0) {
						return "url(" . $quote . $url . $quote . ")";
					} // The URL isn't an HTTP URL but is actual binary data. Don't proxify it.

					// Construct the proxified URL
					return "url(" . $quote . PROXY_PREFIX . $this->rel2abs($url, $baseURL) . $quote . ")";
				}
			}, $line);

			$normalizedLines[] = $normalizedLine !== null ? $normalizedLine : $line; // Ensure null is handled
		}

		// Join the normalized lines back into a single string
		$normalizedCSS = implode("\n", $normalizedLines);

		
		return $normalizedCSS ? $normalizedCSS : $css;
	}

	/**
	 * Proxifies the srcset attribute by replacing image URLs with proxified URLs.
	 *
	 * This function takes a srcset attribute string and a base URL, splits the srcset
	 * into individual sources, proxifies each image URL, and recombines the sources into
	 * a single proxified srcset attribute string.
	 */
	public function proxifySrcset($srcset, $baseURL) {
		$sources = array_map("trim", explode(",", $srcset)); //Split all contents by comma and trim each value
		
		// Function to handle zero values and prevent PHP warning codes
		$nozeros = function($ss) {
			if ($ss > 0.0) {
				return strrpos($ss, " ");
			}
			else {
				return 1; //intval($x);
			}
		};
		
		// Proxify each source URL and recombine into a single srcset string
		$proxifiedSources = array_map(function ($source) use ($baseURL, $nozeros) {
			$sauce = $nozeros($source);
			if($sauce = 1) {
				$components = array_map("trim", explode(" ", $source)); // Split by space
			} else {
				$components = array_map("trim", explode(" ", substr($source, 0, $sauce))); // Split by space and consider substring
			}
			$components[0] = PROXY_PREFIX . $this->rel2abs(ltrim(array_key_exists(0, $components) ? $components[0] : '', "/") , $baseURL); //First component of the split source string should be an image URL; proxify it
			
			/*$result = [];
			foreach ($components as $item) {
				if (preg_match("/'(.*?)' => '(.*?)'/", $item, $matches)) {
					$result[$matches[1]] = $matches[2];
				}
			}*/

			return implode(" ", $components); //Recombine the components into a single source //MODIFIED to include space separator
			
		}
		, $sources);
		return implode(", ", $proxifiedSources); //Recombine the sources into a single "srcset"
	}
	
	/**
	 * Handles captcha verification for a given URL.
	 *
	 * This function extracts the domain from the provided URL and checks if it matches
	 * any of the captcha sites or if the user agent matches any of the captcha agents.
	 * If a captcha verification is required, it generates a captcha challenge and handles
	 * the user input validation.
	 *
	 * Note: This function requires the PHP GD extension and the Gregwar Captcha library.
	 */
	public function HandleCaptcha($url) {
		$domain = isset(parse_url($url)["host"]) ? $this->getDomain(parse_url($url)["host"]) : "";
		$isUserAgentMatch = false;
		
		foreach ($this->CaptchaAgents as $uaString) {
			if (strpos($_SERVER['HTTP_USER_AGENT'], $uaString) !== false) {
				$isUserAgentMatch = true;
				break;
			}
		}

		// Set session configuration
		@ini_set('session.cookie_httponly', '1'); // Prevent client-side script access to cookies

		if ((in_array($domain, $this->CaptchaSites) || $isUserAgentMatch) &&
			(class_exists('Gregwar\\Captcha\\PhraseBuilder') && class_exists('Gregwar\\Captcha\\CaptchaBuilder')) && extension_loaded("gd")) {
			if (!extension_loaded("gd")) {
						die("PocketProxy requires PHP's \"" . "gd" . "\" extension for Captcha functionality. Please install/enable it on your server and try again.");
			}
			
			$validatedCaptcha = false;
			$sessionFlag = false;
			// Start session
			session_start();
			if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_SESSION["phrase"])) {
				
				if(!isset($_POST["phrase"])) {
					$output = "<h1>Captcha is not valid!</h1>";
				}
				else if (Gregwar\Captcha\PhraseBuilder::comparePhrases($_SESSION["phrase"], $_POST["phrase"])) { //PHP Warning:  Undefined array key "phrase"
					$validatedCaptcha = true;

					if (!isset($_SESSION["CREATED"])) {
						$_SESSION["CREATED"] = time();
					} elseif (time() - $_SESSION["CREATED"] > 1800) {
						session_regenerate_id(true);
						$_SESSION["CREATED"] = time();
					}
				} else {
					$output = "<h1>Captcha is not valid!</h1>";
				}
			}

			unset($_SESSION["phrase"]);

			if (isset($_SESSION["CREATED"])) {
				if (time() - $_SESSION["CREATED"] > 1800) {
					$sessionFlag = true;
				}
			} else {
				$sessionFlag = true;
			}

			if (!$validatedCaptcha && $sessionFlag) {
				// Set session expiration and implement session timeout
				if (isset($_SESSION['LAST_ACTIVITY']) && time() - $_SESSION['LAST_ACTIVITY'] > 1800) { // 30 minutes (in seconds)
					session_unset(); // Unset all session variables
					session_destroy(); // Destroy the session
					// Redirect the user to the login page or display an appropriate message
					die("<h1>Session expired. Please refresh the page and try again.</h1>");
				} else {
					$_SESSION['LAST_ACTIVITY'] = time(); // Update the last activity timestamp
				}

				// Logging session activity
				//$log_data = "Session activity: " . $_SERVER['REMOTE_ADDR'] . " - " . $_SERVER['HTTP_USER_AGENT'] . " - " . date('Y-m-d H:i:s');
				// Write $log_data to a log file or database table to monitor session activity

				?>
				<h1>The website you're trying to visit is on the Suspicious Website List!</h1>
				<form method="post">
					Please Copy the Captcha (30 minute Sessions)
					<?php
					$phraseBuilder = new Gregwar\Captcha\PhraseBuilder(4);
					$captcha = new Gregwar\Captcha\CaptchaBuilder(null, $phraseBuilder);
					$captcha->build();
					$_SESSION["phrase"] = $captcha->getPhrase();
					?>
					<img src="<?php echo $captcha->inline(); ?>"/><br/>
					<?php
					if ($this->cce) {
						if (isset($output)) {
							echo $output;
						}
						echo "Cheat Code: " . $captcha->getPhrase();
					}
					?>
					<input type="text" name="phrase"/>
					<input type="hidden" name="csrf_token" value="<?php echo bin2hex(random_bytes(32)); ?>">
					<input type="submit"/>
				</form>
				<?php
				die();
			}
		}
	
	}
	
	
	/**
	 * Processes the HTML body of a response
	 *
	 * This function performs various modifications to the HTML body to ensure proper proxifying
	 * when accessed through the proxy. It normalizes character encoding, modifies form actions,
	 * proxifies URLs, and fixes issues with meta tags and stylesheets.
	 */
	public function processHTMLBody($responseBody, $url, $jsContent){
		//Attempt to normalize character encoding.
		if (mb_detect_encoding($responseBody, "UTF-8, ISO-8859-1")) {
			$responseBody = htmlspecialchars_decode($responseBody);
		}
		
		//added, make $source not empty, to remove php error codes
		if (empty($responseBody)) {
			$responseBody = " ";
		}
		
		//Parse the DOM.
		$doc = new DomDocument();
		@$doc->loadHTML($responseBody);
		$xpath = new DOMXPath($doc);

		//Rewrite forms so that their actions point back to the proxy.
		foreach ($xpath->query("//form") as $form) {
			$method = $form->getAttribute("method");
			$action = $form->getAttribute("action");
			//If the form doesn't have an action, the action is the page itself.
			//Otherwise, change an existing action to an absolute version.
			$action = empty($action) ? $url : $this->rel2abs($action, $url);
			//Rewrite the form action to point back at the proxy.
			$form->setAttribute("action", rtrim(PROXY_PREFIX, "?"));
			//Add a hidden form field that the proxy can later use to retreive the original form action.
			$actionInput = $doc->createDocumentFragment();
			$actionInput->appendXML('<input type="hidden" name="ProxyForm" value="' . htmlspecialchars($action) . '" />');
			$form->appendChild($actionInput);
		}
		
		//Proxify <meta> tags with an 'http-equiv="refresh"' attribute.
		foreach ($xpath->query("//meta[@http-equiv]") as $element) {
			if (strcasecmp($element->getAttribute("http-equiv") , "refresh") === 0) {
				$content = $element->getAttribute("content");
				if (!empty($content)) {
					$splitContent = preg_split("/=/", $content);
					if (isset($splitContent[1])) {
						$element->setAttribute("content", $splitContent[0] . "=" . PROXY_PREFIX . $this->rel2abs($splitContent[1], $url));
					}
				}
			}
		}
		
		//Profixy <style> tags.
		foreach ($xpath->query("//style") as $element) {
			$element->nodeValue = $this->proxifyCSS($element->nodeValue, $url);
		}
		
		//Proxify tags with a "style" attribute.
		foreach ($xpath->query("//*[@style]") as $element) {
			$element->setAttribute("style", $this->proxifyCSS($element->getAttribute("style") , $url));
		}
		
		//Proxify "srcset" attributes in <img> tags.
		foreach ($xpath->query("//*[@srcset]") as $element) {
			$element->setAttribute("srcset", $this->proxifySrcset($element->getAttribute("srcset") , $url));
		}
		
		//Proxify any of these attributes appearing in any tag.
		$proxifyAttributes = ["href", "src",
			//These are untested but assumed to work rather well
			'data-image-url', 'data-audio-url', 'data-source', 'data-iframe-url', 'data-script-url', 'data-style-url', 
			'data-redirect-url', 'data-thumbnail-url', 'data-avatar-url', 'data-srcset', 'data-video-src', 'data-poster', 
			'data-ajax-url', 'data-background-image', 'data-action', 'data-file', 'data-download-url', 'data-url', 'data-link', 
			'data-source-url', 'data-href', 'data-target', 'data-redirect', 'data-external-link', 'data-thumbnail', 
			'data-image-link', 'data-external-url', 'data-video-link', 'data-audio-link', 'data-script-src', 'data-style-src', 
			'data-download-link', 'data-embed-url', 'data-iframe-link', 'data-source-link', 'data-embed-src', 
			'data-redirect-link', 'data-source-src', 'data-download-source', 'data-source-download-url', 
			'data-file-link', 'data-file-url', 'data-url-link', 'data-link-url', 'data-content-url', 'data-url-content', 
			'data-external-content', 'data-content-external', 'data-download-content', 'data-content-download', 
			'data-image-source', 'data-source-image', 'data-download-image', 'data-image-download', 
			'data-thumbnail-source', 'data-source-thumbnail', 'data-download-thumbnail', 'data-thumbnail-download',
		];
		
		$noMatchRegex = "/^(about|javascript|magnet|mailto|tel|data|chrome-extension|sms|itms|itms-apps|android-app|ios-app):|#/i";
		$noMatchAttributes = ['src', 'href', 'action'];
		
		$processAttribute = function ($element, $attrName) use ($noMatchRegex, $url, $noMatchAttributes) {
			//For every element with the given attribute...
			$attrContent = $element->getAttribute($attrName);
			
			if (in_array($attrName, $noMatchAttributes) && preg_match($noMatchRegex, $attrContent)) {
				return;
			}
			
			$attrContent = $this->rel2abs($attrContent, $url);
			$attrContent = PROXY_PREFIX . $attrContent;
			$element->setAttribute($attrName, $attrContent);
		};
		
		foreach ($proxifyAttributes as $attrName) {
			foreach ($xpath->query("//*[@" . $attrName . "]") as $element) {
				//For every element with the given attribute...
				$processAttribute($element, $attrName);
			}
		}
		
		// Iterate over iframe tags with srcdoc attribute
		foreach ($xpath->query("//iframe[@srcdoc]") as $iframe) {
			// Get the content of srcdoc attribute
			$srcdocContent = $iframe->getAttribute("srcdoc");
			
			// Create a new DOMDocument to parse the content of srcdoc
			$srcdocDoc = new DOMDocument();
			@$srcdocDoc->loadHTML($srcdocContent);
			$srcdocXPath = new DOMXPath($srcdocDoc);
			
			// Iterate over all tags inside srcdoc
			foreach ($srcdocXPath->query("//*") as $srcdocElement) {
				// Process each element inside srcdoc using the $processAttribute function
				foreach ($proxifyAttributes as $attrName) {
					if ($srcdocElement->hasAttribute($attrName)) {
						$processAttribute($srcdocElement, $attrName);
					}
				}
			}
			
			// Convert the modified srcdoc content back to a string and update the iframe's srcdoc attribute
			$iframe->setAttribute("srcdoc", $srcdocDoc->saveHTML());
		}
		
		// Find all <object> elements
		$objects = $doc->getElementsByTagName('object');
		foreach ($objects as $object) {
			// Get the value of the data attribute
			$data = $object->getAttribute('data');
			
			// Modify the data attribute value as needed
			$modifiedData = PROXY_PREFIX . $this->rel2abs($data, $url); // Implement your modification logic
			
			// Set the modified data attribute value
			$object->setAttribute('data', $modifiedData);
		}

		$head = $xpath->query("//head")->item(0);
		$body = $xpath->query("//body")->item(0);
		$prependElem = $head != null ? $head : $body;
		
		if ($prependElem != null) {
			$scriptElem = $doc->createElement("script", $jsContent);
			
			$scriptElem->setAttribute("type", "text/javascript");
			$prependElem->insertBefore($scriptElem, $prependElem->firstChild);
		}
		
		//I noticed Google results were ?url=https:/ and not ?url=https:// causing them to not function
		//Edit: This should** no longer be needed but let's keep it just incase
		foreach ($doc->getElementsByTagName('a') as $link) {
		   $link->setAttribute('href', preg_replace(array('/https\:\/(?!\/)/', '/http\:\/(?!\/)/'), array('https://', 'http://'), $link->getAttribute('href')));
		}

		$output = $doc->saveHTML($doc->documentElement); //Fixed a UTF-8 ecoding error https://stackoverflow.com/questions/8218230/php-domdocument-loadhtml-not-encoding-utf-8-correctly
		
		return $output;
	}
}

$proxy = new Proxy($config);
$proxy->handleAccess();
$html = "
<html>

<head>
	<title>PocketProxy</title>
</head>

<body>
	<h1>Welcome to PocketProxy!</h1>
	PocketProxy can be directly invoked like this: <a href=\"" . PROXY_PREFIX . $proxy->landingExampleURL . "\">" . PROXY_PREFIX . $proxy->landingExampleURL . "</a><br /><br />Or, you can simply enter a URL below:<br /><br />
	<form onsubmit=\"window.location.href='" . PROXY_PREFIX . "' + document.getElementById('site').value; return false;\">
		<input id='site' type='text' size='50' placeholder='" . $proxy->landingExampleURL . "'><input type=\"submit\" value=\"Proxy It!\" /></form>
</body>
</html>
";

//Extract and sanitize the requested URL, handling cases where forms have been rewritten to point to the proxy.
if (isset($_POST["ProxyForm"])) {
	$url = $_POST["ProxyForm"];
	//var_dump($url);
	unset($_POST["ProxyForm"]);
}
else {
	$queryParams = [];
	parse_str($_SERVER["QUERY_STRING"], $queryParams);
	//If the ProxyForm field appears in the query string, make $url start with its value, and rebuild the the query string without it.
	if (isset($queryParams["ProxyForm"])) {
		$formAction = $queryParams["ProxyForm"];
		unset($queryParams["ProxyForm"]);
		
		$url = $formAction . "?" . http_build_query($queryParams);
		//echo $url;
	}
	else { //This now allows pocketProxy.php to be index.php!
		$parsedUri = parse_url($_SERVER["REQUEST_URI"]);
		$url = isset($parsedUri['query']) ? '?' . $parsedUri['query'] : '';
		if (substr($url, 0, 1) === '?') {
			$url = substr($url, 1);
		}
	}
}

if (function_exists('ob_gzhandler')) {
	ob_start("ob_gzhandler");
} else {
	ob_start();
}

if (empty($url)) {
	if (empty($proxy->startURL)) {
		die($html);
	}
	else {
		$url = $proxy->startURL;
	}
}
elseif (strpos($url, ":/") !== strpos($url, "://")) {
	//Work around the fact that some web servers (e.g. IIS 8.5) change double slashes appearing in the URL to a single slash.
	//See https://github.com/joshdick/miniProxy/pull/14
	$pos = strpos($url, ":/");
	$url = substr_replace($url, "://", $pos, strlen(":/"));
}

// Added for captcha functionality
$proxy->HandleCaptcha($url);


$scheme = parse_url($url, PHP_URL_SCHEME);
#var_dump($scheme);
if (empty($scheme)) {
	// If the URL doesn't contain a scheme
	if (strpos($url, "//") === 0) {
		// Assume that any supplied URLs starting with // are HTTP URLs.
		$url = "http:" . $url;
	} elseif (preg_match('~^https?://~i', $url) !== 1) {
		// If the URL doesn't start with http:// or https://, assume it's HTTP.
		$url = "http://" . $url;
	}
}
elseif (!preg_match("/^https?$/i", $scheme)) {
	die('Error: Detected a "' . $scheme . '" URL. PocketProxy exclusively supports http[s] URLs.');
}

//could cause captcha bypass issues
$url = str_replace(array('http://?','https://?'), '', $url);//This is going to fix a lot of weirds but potentially not all!
$url = str_replace(array('?http://','?https://'), array('http://','https://'), $url);


if (!$proxy->isValidURL($url)) {
	if (preg_match($proxy->getHostnamePattern($_SERVER['HTTP_HOST']), $url)) {
		header('Content-Type: text/plain');
		die(''); //prevent some errors when urls are mishandled and sent to ORIGINDOMAIN.COM/pocketproxy.php?ORIGINDOMAIN.COM
	}
	
	$proxy->logcbl($url);
	die("Error: The requested URL was disallowed by the server administrator. ");
}
//Error where google links are ?https:/ and not ://

$response = $proxy->makeRequest($url);
$rawResponseHeaders = $response["headers"];
$responseBody = $response["body"];
$responseInfo = $response["responseInfo"];

//If CURLOPT_FOLLOWLOCATION landed the proxy at a diferent URL than
//what was requested, explicitly redirect the proxy there.
if ($responseInfo["url"] !== $url) {
	header("Location: " . PROXY_PREFIX . $responseInfo["url"], true);
	exit(0);
}

//A regex that indicates which server response headers should be stripped out of the proxified response.
$header_blacklist_pattern = "/^Content-Length|^Transfer-Encoding|^Content-Encoding.*gzip/i";

//cURL can make multiple requests internally (for example, if CURLOPT_FOLLOWLOCATION is enabled), and reports
//headers for every request it makes. Only proxy the last set of received response headers,
//corresponding to the final request made by cURL for any given call to makeRequest().
$values = array_diff(explode("\r\n\r\n", $rawResponseHeaders) , ["permissions-policy", "strict-transport-security", "report-to", "x-content-type-options", "X-Content-Type-Options", "cross-origin-opener-policy-report-only", "content-security-policy", "x-frame-options", "x-robots-tag", "x-xss-protection", "X-Frame-Options"]);
$responseHeaderBlocks = $values;
//$responseHeaderBlocks = array_filter(explode("\r\n\r\n", $rawResponseHeaders));
$lastHeaderBlock = end($responseHeaderBlocks);
$headerLines = explode("\r\n", $lastHeaderBlock);
foreach ($headerLines as $header) {
	$header = trim($header);
	if (!preg_match($header_blacklist_pattern, $header)) {
		header($header, false);
	}
}
//Prevent robots from indexing proxified pages
header("X-Robots-Tag: noindex, nofollow", true);

if ($proxy->forceCORS) {
	//This logic is based on code found at: http://stackoverflow.com/a/9866124/278810
	//CORS headers sent below may conflict with CORS headers from the original response,
	//so these headers are sent after the original response headers to ensure their values
	//are the ones that actually end up getting sent to the browser.
	//Explicit [ $replace = true ] is used for these headers even though this is PHP's default behavior.
	//Allow access from any origin.
	header("Access-Control-Allow-Origin: *", true);
	header_remove("X-Frame-Options"); //Doesn't seem to be necessary
	header("Access-Control-Allow-Credentials: true", true);

	//Handle CORS headers received during OPTIONS requests.
	if ($_SERVER["REQUEST_METHOD"] == "OPTIONS") {
		if (isset($_SERVER["HTTP_ACCESS_CONTROL_REQUEST_METHOD"])) {
			header("Access-Control-Allow-Methods: GET, POST, OPTIONS", true);
		}
		if (isset($_SERVER["HTTP_ACCESS_CONTROL_REQUEST_HEADERS"])) {
			header("Access-Control-Allow-Headers: {$_SERVER["HTTP_ACCESS_CONTROL_REQUEST_HEADERS"]}", true);
		}
		//No further action is needed for OPTIONS requests.
		exit(0);
	}
}

$contentType = "";
if (isset($responseInfo["content_type"])) {
	$contentType = $responseInfo["content_type"];
}

$compressibleMimeTypes = [
	//'text/css',
	'text/javascript',
	'application/javascript',
	'application/json',
	'application/xml',
	'text/xml',
	'text/plain',
	'application/xhtml+xml',
	'text/csv',
	'application/atom+xml',
	'image/svg+xml',
	'application/rss+xml',
];

//This is presumably a web page, so attempt to proxify the DOM.
if (stripos($contentType, "text/html") !== false) {
	$proxyPrefix = PROXY_PREFIX;
	//This is wrapped like this so when I'm using Notepad++ , i can fricken collapse this segment
	if(true){
	$jsContent = <<<EOF
(function() {
	// Initialize a proxy prefix variable to modify URLs for routing through a proxy.
	var proxyPrefix = "{$proxyPrefix}";

	// Extract the base URL from the current location to use in URL modifications.
	var currentURL = window.location.href;
	var params = currentURL.split("{$_SERVER["SCRIPT_NAME"]}?")[1];
	var baseURL = decodeURIComponent(params || "");
	
	// List of attributes that potentially contain URLs to be modified.
	var potentialUrlAttributes = ["src", "rel", "href", "data-src", "data-href", "action", "srcset", "poster", "hreflang", "cite", "data-url", "data-link", "data-file", "data-image", "data-video", "data-audio", "data-source", "formaction"];
	var events = ["onclick", "onsubmit", "onload", "onerror", "onchange", "onmouseover", "onmouseout", "onkeydown", "onkeyup", "onfocus", "onblur", "ondblclick", "oncontextmenu", "onwheel", "onselect", "oninput", "oncopy", "oncut", "onpaste", "onmousemove", "onmouseup", "onmousedown", "onmouseenter", "onmouseleave", "onresize", "onscroll", "ontouchstart", "ontouchend", "ontouchmove", "onabort", "onbeforeunload", "oncanplay", "oncanplaythrough", "onmouseenter", "ondurationchange", "onended", "oninput", "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onloadstart", "onloadeddata", "onloadedmetadata", "onloadend", "onmessage", "onoffline", "ononline", "onpagehide", "onpageshow", "onpause", "onplay", "onplaying", "onprogress", "onratechange", "onreset", "onseeked", "onseeking", "onstalled", "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting",];

	function extractDomain(url) {
		var domain;
		// Find & remove protocol (http, ftp, etc.) and get domain
		if (url.indexOf("://") > -1) {
			domain = url.split('/')[2];
		} else {
			domain = url.split('/')[0];
		}

		// Find & remove port number
		domain = domain.split(':')[0];

		return domain;
	}

	// Function to dynamically extract a domain from a URL provided in the query parameters
	function extractDomainFromQueryParams() {
		// Parse the current URL to access query parameters
		var currentUrl = new URL(window.location.href);
		var queryParams = currentUrl.searchParams;

		// Initialize a variable to hold the domain extracted from a URL parameter
		var extractedDomain = '';

		// Specify the query parameter that contains the URL from which the domain should be extracted
		var urlParam = queryParams.get('ProxyForm') || queryParams.toString();

		// Check if the URL parameter is present and contains a value
		if (urlParam) {
			try {
				// Attempt to construct a URL object from the parameter value to extract the hostname
				var url = new URL(decodeURIComponent(urlParam));
				extractedDomain = url.hostname;
			} catch (e) {
				console.error("Error extracting domain from URL parameter:", e);
				return ''; // Return empty string in case of error
			}
		}

		// Simplify the extracted domain to ensure it's a valid cookie name part
		// Removing periods and replacing them with underscores
		return extractedDomain;
	}

	function extractUrl(cssValue) {
		// Extracts URL from the cssValue like "url('http://example.com')"
		const matches = cssValue.match(/url\(['"]?(.*?)['"]?\)/);
		return matches ? matches[1] : '';
	}

	function modifyCSSRule(cssText) {
		// Replaces all url() values within a CSS text with modified URLs
		return cssText.replace(/url\((['"]?)(.+?)\1\)/g, (match, quote, url) => `url(\${quote}\${modifyUrl(url)}\${quote})`);
	}

	// Helper functions for URL parsing and modifications.
	function parseURI(url) {
		// Parses a URL and returns its components.
		try {
			var m = String(url).replace(/^\s+|\s+$/g, "").match(/^([^:\/?#]+:)?(\/\/(?:[^:@]*(?::[^:@]*)?@)?(([^:\/?#]*)(?::(\d*))?))?([^?#]*)(\?[^#]*)?(#[\s\S]*)?/);
			return (m ? {
				href: m[0] || "",
				protocol: m[1] || "",
				authority: m[2] || "",
				host: m[3] || "",
				hostname: m[4] || "",
				port: m[5] || "",
				pathname: m[6] || "",
				search: m[7] || "",
				hash: m[8] || ""
			} : null);
		} catch (error) {
			console.error("Error in parseURI:", error);
			return null;
		}
	}

	/**
	 * Not perfect but pretty good
	 *
	 * { rel: "../../../updir/page2.html", base: "http://www.example.com/dir/subdir/another/page1.html", expected: "http://www.example.com/updir/page2.html" },
	 * FAIL: Expected http://www.example.com/updir/page2.html, got http://www.example.com/dir/updir/page2.html rel2abs.php:161:17
	 * { rel: "../../../page2.html", base: "http://www.example.com/dir1/dir2/dir3/dir4/", expected: "http://www.example.com/page2.html" }, 
	 * FAIL: Expected http://www.example.com/page2.html, got http://www.example.com/dir1/dir2/page2.html
	 *
	 **/
	function rel2abs(rel, base) {
		if (!rel) {
			//rel = ".";
		}
		if (new URL(rel, base).href === rel || rel.startsWith("//")) {
			return rel; // Return if already an absolute URL
		}
		if (rel[0] === "#" || rel[0] === "?") {
			return base + rel; // Queries and anchors
		}

		// Validate the base URL
		let parsedBase;
		try {
			parsedBase = new URL(base);
		} catch (e) {
			// Handle error: invalid base URL
			return false; // Or handle as appropriate for your use case
		}

		let {
			pathname
		} = parsedBase;
		pathname = pathname.replace(/\/[^\/]*$/, ""); // Remove non-directory element from path
		if (rel[0] === "/") {
			pathname = ""; // Destroy path if relative url points to root
		}

		// Add condition for default HTTPS port (443)
		// in javascript, host already has the port!
		//const port = parsedBase.port && parsedBase.port !== "80" && parsedBase.port !== "443" ? ":" + parsedBase.port : "";

		const auth = parsedBase.username ? parsedBase.username + (parsedBase.password ? ":" + parsedBase.password : "") + "@" : "";

		let abs = `\${auth}\${parsedBase.host}\${pathname}/\${rel}`; // Dirty absolute URL

		// Ensure the loop that resolves "../" is safe against malformed inputs
		let loopSafetyCounter = 0;
		while (abs.includes('../') && loopSafetyCounter++ < 20) { // Prevent infinite loops
			const before = abs;
			abs = abs.replace(/\/([^\/]+\/)?\.\.\//g, '/'); // Resolve "../"
			if (before === abs) {
				break; // Exit if no replacements were made
			}
		}

		abs = abs.replace(/\/\.\//g, '/'); // Resolve "/./"
		abs = abs.replace(/\/\/+/g, '/'); // Remove duplicate slashes

		return parsedBase.protocol + "//" + abs; // Absolute URL is ready
	}

	function modifyUrl(url) {
		try {
			// Modifies the given URL to include the proxy prefix.
			if (typeof url === 'object') {
				url = JSON.stringify(url);
			}
			
			if (typeof url === 'string') {
				if (!url.includes(proxyPrefix)) {
					var urlObj = parseURI(url);
					if (urlObj) {
						url = rel2abs(urlObj.href, "http://" + extractDomainFromQueryParams());
						if (url.indexOf(proxyPrefix) === -1) {
							url = proxyPrefix + url;
							//console.log("ModifyURL: Modified " + url);
						}
					}
				}
			} else if (url instanceof Blob) {
				// Convert Blob to data URL
				const reader = new FileReader();
				reader.readAsDataURL(url);
				reader.onload = function() {
					const dataUrl = reader.result;
					// Apply modifications if necessary
					const modifiedUrl = modifyUrl(dataUrl);
					return modifiedUrl;
				};
			} else {
				console.error(`Error in modifyUrl: URL is not a string. Received type: \${typeof url}`);
				if (typeof url === 'object') {
					console.log(`Object JSON: \${JSON.stringify(url)}`);
				}
				//console.trace(); // Log stack trace
			}
			return url;
		} catch (error) {
			console.error("Error in modifyUrl:", error);
			console.trace();
			return url; // Return the original URL on error.
		}
	}

	try {
		// Overriding the default createElement method to intercept element creation.
		// This modification allows us to alter URL attributes for new elements.
		var originalCreateElement = document.createElement;
		document.createElement = function(tagName) {
			var element = originalCreateElement.call(document, tagName);

			// Function to modify the URL attribute of an element.
			function modifyUrlAttribute(attributeName) {
				Object.defineProperty(element, attributeName, {
					set: function(url) {
						this.setAttribute(attributeName, modifyUrl(url));
					}
				});
			}

			potentialUrlAttributes.forEach(function(attributeName) {
				if (element[attributeName] !== undefined) {
					modifyUrlAttribute(attributeName);
				}
			});

			return element;
		};
	} catch (error) {
		console.error("Error in modifying document.createElement:", error);
	}

	// Ensuring compatibility with DOMParser and Object.defineProperty.
	if (typeof DOMParser === "undefined") {
		console.error("DOMParser is not supported in this browser.");
	} else if (typeof Object.defineProperty === "undefined") {
		console.error("Object.defineProperty is not supported in this browser.");
	} else {
		
		function modifyInlineScripts(htmlString) {
			// Parses the HTML string and modifies script src attributes.
			try {
				var parser = new DOMParser();
				var doc = parser.parseFromString(htmlString, "text/html");
				var scripts = doc.getElementsByTagName("script");

				// Iterates over script tags to modify their src attributes.
				for (var i = 0; i < scripts.length; i++) {
					var script = scripts[i];
					if (script.src) {
						script.src = modifyUrl(script.src);
					}
				}

				return new XMLSerializer().serializeToString(doc);
			} catch (error) {
				console.error("Error in modifyInlineScripts:", error);
				return htmlString; // Return the original HTML string on error.
			}
		}
		
		// Overriding innerHTML and outerHTML to modify inline scripts and URLs.
		try {
			Object.defineProperty(Element.prototype, "innerHTML", {
				set: function(htmlString) {
					try {
						this.appendChild(document.createRange().createContextualFragment(modifyInlineScripts(htmlString)));
					} catch (error) {
						console.error("Error in innerHTML setter:", error);
						this.innerHTML = htmlString; // Revert to the original HTML on error.
					}
				}
			});
		} catch (error) {
			console.error("Error in defining innerHTML:", error);
		}

		try {
			Object.defineProperty(Element.prototype, "outerHTML", {
				set: function(htmlString) {
					try {
						this.replaceWith(...document.createRange().createContextualFragment(modifyInlineScripts(htmlString)).childNodes);
					} catch (error) {
						console.error("Error in outerHTML setter:", error);
						this.outerHTML = htmlString; // Revert to the original HTML on error.
					}
				}
			});
		} catch (error) {
			console.error("Error in defining outerHTML:", error);
		}
	}

	// Modifying XMLHttpRequest and fetch to route requests through the proxy.
	try {
		if (window.XMLHttpRequest) {
			var originalOpen = XMLHttpRequest.prototype.open;
			window.XMLHttpRequest.prototype.open = function() {
				if (arguments[1] !== null && arguments[1] !== undefined) {
					var url = arguments[1];
					url = modifyUrl(url);
					arguments[1] = url;
				}
				return originalOpen.apply(this, [].slice.call(arguments));
			};
		}
	} catch (error) {
		console.error("Error in modifying XMLHttpRequest:", error);
	}
	
	// Fetch
	try {
		if (window.fetch) {
			var originalFetch = window.fetch;
			window.fetch = function(url, init) {
				if (typeof url === 'string') {
					arguments[0] = modifyUrl(url);
				} else if (typeof url === 'object' && url.url) {
					url.url = modifyUrl(url.url);
				}
				return originalFetch.apply(this, arguments);
			};
		}
	} catch (error) {
		console.error("Error in modifying fetch:", error);
	}

	// Additional modifications to handle WebSocket, ServiceWorker, and form submissions.
	try {
		// WebSocket modification to route connections through the proxy.
		var originalWebSocket = window.WebSocket;
		window.WebSocket = function(url, protocols) {
			var modifiedUrl = modifyUrl(url);
			return new originalWebSocket(modifiedUrl, protocols);
		};

		// Disabling ServiceWorker registration to prevent caching issues with the proxy.
		if (navigator.serviceWorker) {
			navigator.serviceWorker.register = function() {
				console.warn("Service Worker registration is disabled.");
				return Promise.reject(new Error("Service Worker registration is disabled."));
			};
		}

		// Ensuring that form submissions are routed through the proxy.
		document.addEventListener("submit", function(event) {
			var form = event.target;
			if (form.tagName === "FORM") {
				form.action = modifyUrl(form.action);
			}
		});

		// Modification to the window.open method to handle URL routing.
		var originalWindowOpen = window.open;
		window.open = function(url) {
			return originalWindowOpen.call(window, modifyUrl(url));
		};

		// Disabling Worker creation to prevent uncontrolled network requests.
		var originalWorker = window.Worker;
		window.Worker = function() {
			throw new Error("Web Workers are disabled on this page.");
		};
	} catch (error) {
		console.error("Error in WebSocket/ServiceWorker/Form/WindowOpen/Worker modification:", error);
	}

	// History manipulation to ensure navigation is consistent with proxy routing.
	try {
		(function(history) {
			var pushState = history.pushState;
			var replaceState = history.replaceState;

			history.pushState = function(state, title, url) {
				var modifiedUrl = modifyUrl(url);
				if (typeof history.onpushstate == "function") {
					history.onpushstate({
						state: state,
						title: title,
						url: modifiedUrl
					});
				}
				return pushState.apply(history, [state, title, modifiedUrl]);
			};

			history.replaceState = function(state, title, url) {
				var modifiedUrl = modifyUrl(url);
				if (typeof history.onreplacestate == "function") {
					history.onreplacestate({
						state: state,
						title: title,
						url: modifiedUrl
					});
				}
				return replaceState.apply(history, [state, title, modifiedUrl]);
			};

			window.addEventListener("popstate", function(event) {
				// Handle back/forward button navigation.
				var modifiedUrl = modifyUrl(event.state ? event.state.url : window.location.href);
				if (window.location.href !== modifiedUrl) {
					window.location.replace(modifiedUrl);
				}
			});
		})(window.history);
	} catch (error) {
		console.error("Error in history manipulation:", error);
	}

	// Modifying document.write and writeln to search for and modify URLs in content.
	try {
		var originalDocumentWrite = document.write;
		var originalDocumentWriteln = document.writeln;

		function modifyUrlInContent(content) {
			// Regular expression pattern to match URLs in content.
			var urlPattern = /((?:https?|ftp):\/\/[^\s/$.?#].[^\s]*)/gi;

			// Replace URLs in the content with modified URLs.
			var modifiedContent = content.replace(urlPattern, function(match, quote, url) {
				// Check if the URL already contains the proxy prefix.
				if (!url.includes(proxyPrefix)) {
					//console.log('Debug1');
					// Modify the URL by adding the proxy prefix.
					url = proxyPrefix + url;
					return quote ? quote + url : url;
				}
				return match; // Return unchanged if already modified.
			});

			return modifiedContent;
		}

		function modifiedWrite(content) {
			// Modify URLs in document.write content.
			var modifiedContent = modifyUrlInContent(content);
			originalDocumentWrite.call(document, modifiedContent);
		}

		function modifiedWriteln(content) {
			// Modify URLs in document.writeln content.
			var modifiedContent = modifyUrlInContent(content);
			originalDocumentWriteln.call(document, modifiedContent);
		}

		document.write = modifiedWrite;
		document.writeln = modifiedWriteln;
	} catch (error) {
		console.error("Error in modifying document.write and writeln:", error);
	}

	//Rewrite $.ajax
	if (typeof jQuery !== 'undefined') {
		(function($) {
			var originalAjax = $.ajax;

			$.ajax = function(options) {
				// Modify the URL before making the AJAX request
				if (options.url) {
					options.url = modifyUrl(options.url);
				}

				// Call the original $.ajax function with the modified options
				return originalAjax.call(this, options);
			};
		})(jQuery);
	}

	//Rewrite window.axios
	if (typeof window.axios !== 'undefined') {
		try {
			// Intercept Axios requests
			var originalAxios = window.axios;
			window.axios = function(config) {
				// Modify the URL in the Axios config object before making the request
				if (config.url) {
					config.url = modifyUrl(config.url);
				}
				return originalAxios(config);
			};
		} catch (error) {
			console.error("Error in modifying Axios:", error);
		}
	}

	//newly added

	/**
	 * Intercept and modify specified attributes of HTML elements that contain URL-like values.
	 * This code snippet overrides the setAttribute method of the Element prototype to modify
	 * the values of attributes like 'src', 'href', 'data', etc., ensuring they are valid URLs
	 * by applying the modifyUrl function.
	 */
	(function() {
		const originalSetAttribute = Element.prototype.setAttribute;

		Element.prototype.setAttribute = function(name, value) {
			// Check if the attribute name is one of the specified attributes to modify
			if (potentialUrlAttributes.includes(name.toLowerCase())) {
				try {
					// Only modify the attribute if the value looks like a URL.
					// You might want to refine this check based on your needs.
					if (typeof value === 'string' && (value.startsWith('http') || value.startsWith('//'))) {
						value = modifyUrl(value); // Use your existing modifyUrl function
					}
				} catch (error) {
					console.error("Error modifying URL for attribute " + name + ": ", error);
					// Optionally log the error or handle it as needed.
				}
			}

			// Call the original setAttribute function with the (potentially modified) value
			return originalSetAttribute.call(this, name, value);
		};
	})();

	// Apply modifications to existing stylesheets
	for (let sheet of document.styleSheets) {
		try {
			if (sheet.cssRules) {
				for (let rule of sheet.cssRules) {
					if (rule.style) {
						for (let property of rule.style) {
							const value = rule.style.getPropertyValue(property);
							if (value && typeof value === 'string' && value.includes('url(')) {
								rule.style.setProperty(property, `url(\${modifyUrl(extractUrl(value))})`, rule.style.getPropertyPriority(property));
							}
						}
					}
				}
			}
		} catch (e) {
			console.error("Cross-origin stylesheet modification attempt.", e);
		}
	}

	try {
		// Enhance interception for future modifications
		// Override CSSStyleSheet methods for dynamic rule additions
		['addRule', 'insertRule'].forEach(method => {
			const originalMethod = CSSStyleSheet.prototype[method];
			CSSStyleSheet.prototype[method] = function(...args) {
				try {
					args[method === 'addRule' ? 1 : 0] = modifyCSSRule(args[method === 'addRule' ? 1 : 0]);
				} catch (error) {
					console.error(`Error intercepting CSSStyleSheet method '\${method}':`, error);
				}
				return originalMethod.apply(this, args);
			};
		});
	} catch (error) {
		console.error("Error in CSSStyleSheet interception setup:", error);
	}

	try {
		// Intercept inline styles and <style> elements for dynamic modifications
		const originalSetAttribute = Element.prototype.setAttribute;
		Element.prototype.setAttribute = function(name, value) {
			try {
				if (typeof name === 'string' && typeof value === 'string') {
					const lowerCaseName = name.toLowerCase();
					if (lowerCaseName === 'style' && value.includes && value.includes('url')) {
						value = modifyCSSRule(value);
					}
				}
			} catch (error) {
				console.error("Error intercepting Element's setAttribute:", error);
			}
			return originalSetAttribute.call(this, name, value);
		};
	} catch (error) {
		console.error("Error in Element's setAttribute interception setup:", error);
	}

	/**
	 * Intercept and modify HTMLStyleElement textContent for URLs.
	 */
	try {
		const originalTextContent = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');
		Object.defineProperty(HTMLStyleElement.prototype, 'textContent', {
			set(value) {
				try {
					if (value.includes('url')) {
						value = modifyCSSRule(value);
					}
					originalTextContent.set.call(this, value);
				} catch (error) {
					console.error("Error intercepting HTMLStyleElement's textContent setter:", error);
				}
			},
			get() {
				return originalTextContent.get.call(this);
			}
		});
	} catch (error) {
		console.error("Error in HTMLStyleElement's textContent interception setup:", error);
	}

	try {
		const OriginalImage = Image;
		// Override the Image constructor to modify the 'src' attribute
		Object.defineProperty(window, 'Image', {
			value: function Image() {
				try {
					const img = new OriginalImage();
					Object.defineProperty(img, 'src', {
						set(value) {
							this.setAttribute('src', modifyUrl(value));
						},
						get() {
							return this.getAttribute('src');
						}
					});
					return img;
				} catch (error) {
					console.error("Error intercepting Image constructor:", error);
				}
			},
			configurable: true,
			writable: true
		});
	} catch (error) {
		console.error("Error in Image constructor interception setup:", error);
	}

	try {
		// Intercept Request Constructor
		const originalRequest = window.Request;
		window.Request = function(input, init) {
			try {
				// Check if input is a string and not a local or blob URL before modification
				if (typeof input === 'string' && !input.startsWith('blob:') && !input.startsWith('/')) {
					input = modifyUrl(input);
				} else if (input instanceof Request && !input.url.startsWith('blob:') && !input.url.startsWith('/')) {
					// If input is a Request instance, create a new Request with modified URL, preserving the original request's properties
					input = new originalRequest(modifyUrl(input.url), input);
				}
			} catch (error) {
				console.error("Error intercepting Request:", error);
			}
			// Proceed with the original Request construction
			return new originalRequest(input, init);
		};
	} catch (error) {
		console.error("Error in Request interception setup:", error);
	}

	try {
		// Intercept navigation methods
		['replace', 'assign'].forEach(method => {
			const originalMethod = window.location[method].bind(window.location);
			window.location[method] = (url) => {
				try {
					// Check if the URL starts with http:// or https:// before modification
					//if (/^https?:\/\//i.test(url)) {
						url = modifyUrl(url);
					//}
				} catch (error) {
					console.error(`Error intercepting location.\${method}:`, error);
				}
				return originalMethod(url);
			};
		});
	} catch (error) {
		console.error("Error in location interception setup:", error);
	}

	try {
		document.execCommand = ((original) => function(command, ui, value) {
			try {
				if (["createlink", "insertimage"].includes(command.toLowerCase())) {
					value = modifyUrl(value);
				}
				return original.call(document, command, ui, value);
			} catch (error) {
				console.error("Error intercepting document.execCommand:", error);
			}
		})(document.execCommand);
	} catch (error) {
		console.error("Error in document.execCommand interception setup:", error);
	}

	try {
		// Robust handling for meta refresh and anchor pings
		Object.defineProperty(HTMLMetaElement.prototype, 'content', {
			set(value) {
				try {
					if (this.httpEquiv.toLowerCase() === 'refresh' && value.includes(';url=')) {
						const parts = value.split(';url=');
						parts[1] = modifyUrl(parts[1]);
						value = parts.join(';url=');
					}
					HTMLMetaElement.prototype.setAttribute.call(this, 'content', value);
				} catch (error) {
					console.error("Error intercepting HTMLMetaElement 'content' setter:", error);
				}
			},
			get() {
				return HTMLMetaElement.prototype.getAttribute.call(this, 'content');
			},
			configurable: true
		});

		Object.defineProperty(HTMLAnchorElement.prototype, 'ping', {
			set(value) {
				try {
					HTMLAnchorElement.prototype.setAttribute.call(this, 'ping', modifyUrl(value));
				} catch (error) {
					console.error("Error intercepting HTMLAnchorElement 'ping' setter:", error);
				}
			},
			get() {
				return HTMLAnchorElement.prototype.getAttribute.call(this, 'ping');
			},
			configurable: true
		});
	} catch (error) {
		console.error("Error in HTMLMetaElement and HTMLAnchorElement interception setup:", error);
	}

	// A function to sanitize inline event handlers
	function sanitizeInlineEventHandlers(element) {
		events.forEach(function(event) {
			if (element.hasAttribute(event)) {
				// Get the original event handler code
				var originalHandler = element.getAttribute(event);
				
				// Modify the URL(s) in the event handler code directly
				var modifiedHandler = originalHandler.replace(/(https?:\/\/\S+)/g, function(matchedURL) {
					// Modify the matched URL as needed
					return modifyUrl(matchedURL);
				});
				
				// Set the modified event handler back to the element
				element.setAttribute(event, modifiedHandler);
			}
		});
	}

	// Apply the sanitization to the entire document body
	try {
		var allElements = document.getElementsByTagName("*");
		for (var i = 0; i < allElements.length; i++) {
			sanitizeInlineEventHandlers(allElements[i]);
		}
	} catch (error) {
		console.error("Error in sanitizeInlineEventHandlers:", error);
	}

	var originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');

	Object.defineProperty(document, 'cookie', {
		get: function() {
			return originalCookieDescriptor.get.call(this); // Use the original getter
		},
		set: function(value) {
			// Extract the domain from the query parameters
			var domainPrefix = extractDomainFromQueryParams().replace(/\./g, '');;

			// Proceed only if a domain was successfully extracted
			if (domainPrefix) {
				// Prefix the cookie name with the extracted domain
				var firstEqualIndex = value.indexOf('=');
				var cookieName = value.substring(0, firstEqualIndex);
				var modifiedCookieName = domainPrefix + '_' + cookieName;
				var newValue = modifiedCookieName + value.substring(firstEqualIndex);

				var newValue = newValue.replace(/domain=[^;]+/, 'domain=.' + extractDomain(proxyPrefix));

				console.log("Modified Cookie: ", newValue);

				// Call the original setter with the modified cookie value
				originalCookieDescriptor.set.call(this, newValue);
			} else {
				// If no domain was extracted, set the cookie normally
				originalCookieDescriptor.set.call(this, value);
			}
		},
		configurable: true // Ensure it can be redefined later if necessary
	});

	const originalActiveXObject = window.ActiveXObject;
	try {
		if (originalActiveXObject) {
			window.ActiveXObject = function(type) {
				if (type === "Msxml2.XMLHTTP" || type === "Msxml3.XMLHTTP" || type === "Microsoft.XMLHTTP") {
					console.log(`Intercepted ActiveXObject creation of type: \${type}`);

					// Create the original ActiveXObject instance
					var originalObject = new originalActiveXObject(type);

					// Wrap the 'open' method
					var originalOpen = originalObject.open;
					originalObject.open = function(method, url, async, user, password) {
						// Modify the URL
						var modifiedUrl = modifyUrl(url);
						console.log(`Original URL: \${url}, Modified URL: \${modifiedUrl}`);

						// Call the original 'open' method with the modified URL
						return originalOpen.call(this, method, modifiedUrl, async, user, password);
					};

					// Return the modified ActiveXObject instance
					return originalObject;
				}
				// For other types of ActiveXObject, return an unmodified instance
				return new originalActiveXObject(type);
			};
		}
	} catch (error) {
		console.error("Error intercepting ActiveXObject:", error);
	}

	
	try {
		// Intercepting navigator.sendBeacon
		navigator.sendBeacon = ((original) => (url, data) => original(modifyUrl(url), data))(navigator.sendBeacon.bind(navigator));
	
	} catch (error) {
		console.error("Error in navigator.sendBeacon interception setup:", error);
	}

	// Override dynamic script imports
	const originalImport = window.importScripts;
	try {
		if (originalImport) {
			window.importScripts = function(...urls) {
				try {
					const modifiedUrls = urls.map(url => modifyUrl(url));
					return originalImport.apply(this, modifiedUrls);
				} catch (error) {
					console.error("Error modifying URLs for importScripts:", error);
				}
			};
		}
	} catch (error) {
		console.error("Error intercepting importScripts:", error);
	}

	if (window.XDomainRequest) {
		try {
			// Save a reference to the original XDomainRequest
			var originalXDomainRequest = window.XDomainRequest;

			// Define a new implementation of XDomainRequest
			window.XDomainRequest = function() {
				var xdr = new originalXDomainRequest();

				// Override the open method
				var originalOpen = xdr.open;
				xdr.open = function(method, url) {
					try {
						// Here you can modify the URL or log the request
						console.log('XDomainRequest opened for URL:', url);
						// Call the original open method with potentially modified arguments
						return originalOpen.apply(this, [method, modifyUrl(url)]);
					} catch (error) {
						console.error("Error intercepting XDomainRequest open:", error);
					}
				};

				// Implement similar overrides for other methods like send() if needed

				return xdr;
			};
		} catch (error) {
			console.error("Error intercepting XDomainRequest:", error);
		}
	}


		/*
  // Use Object.defineProperty to override sendBeacon and make it non-writable
  Object.defineProperty(navigator, 'sendBeacon', {
	value: modifiedSendBeacon,
	writable: false, // This prevents further modifications
	configurable: false, // This prevents the property from being deleted or reconfigured
  });
	
	*/
	
	
	//Things to disable
	
	// Unregister existing ServiceWorkers
	navigator.serviceWorker.getRegistrations().then(function(registrations) {
		registrations.forEach(function(registration) {
			registration.unregister().then(function(success) {
				console.log('ServiceWorker unregistered:', success);
			}).catch(function(error) {
				console.error('Failed to unregister ServiceWorker:', error);
			});
		});
	}).catch(function(error) {
		console.error('Failed to get ServiceWorker registrations:', error);
	});
	
	// Override ServiceWorker registration to prevent new registrations
	navigator.serviceWorker.register = function() {
		console.log('ServiceWorker registration is disabled.');
		return Promise.resolve(undefined); // Resolving with null to indicate successful registration (even though it's disabled)
	};


	// Terminate any existing Worker instances
	if (typeof Worker !== 'undefined') {
		let workers = [];
		// Collect all existing Worker instances
		for (let key in window) {
			if (window[key] instanceof Worker) {
				workers.push(window[key]);
			}
		}
		// Terminate each Worker instance
		workers.forEach(function(worker) {
			worker.terminate();
		});
	}

	// Override Worker constructor to prevent new instances
	window.Worker = function() {
		console.log('Web Worker creation is disabled.');
	};

	// Terminate any existing SharedWorker instances
	if (typeof SharedWorker !== 'undefined') {
		let sharedWorkers = [];
		// Collect all existing SharedWorker instances
		for (let key in window) {
			if (window[key] instanceof SharedWorker) {
				sharedWorkers.push(window[key]);
			}
		}
		// Terminate each SharedWorker instance
		sharedWorkers.forEach(function(sharedWorker) {
			sharedWorker.port.close();
		});
	}

	// Override SharedWorker constructor to prevent new instances
	window.SharedWorker = function() {
		console.log('SharedWorker creation is disabled.');
	};
	
	// Terminate any existing EventSource instances
	if (typeof EventSource !== 'undefined') {
		let eventSources = [];
		// Collect all existing EventSource instances
		for (let key in window) {
			if (window[key] instanceof EventSource) {
				eventSources.push(window[key]);
			}
		}
		// Close each EventSource instance
		eventSources.forEach(function(eventSource) {
			eventSource.close();
		});
	}
	
	// Override EventSource constructor to prevent new instances
	window.EventSource = function() {
		console.log('Attempt to create EventSource was made.');
	};

	// Define the disabled property getter function
	function disabledGetter(propName) {
		console.log(propName + " is disabled.");
		return null;
	}

	// Define a dummy object to replace window.WebAssembly
	const disabledWebAssembly = {};

	// Override window.WebAssembly with the dummy object
	window.WebAssembly = disabledWebAssembly;

	// Override any attempted usage of WebAssembly methods
	Object.getOwnPropertyNames(window.WebAssembly).forEach(prop => {
		if (typeof window.WebAssembly[prop] === 'function') {
			window.WebAssembly[prop] = disabledGetter;
		}
	});

	// Properties to disable
	const propertiesToDisable = [
		'geolocation', 'getCurrentPosition', 'watchPosition', 'geolocationServicesEnabled', 'geolocationPermissionGranted',
		'webkitGeolocation', 'hardwareConcurrency', 'platform', 'oscpu', 'plugins', 'product', 'vendor', 'appVersion',
		'productSub', 'vendorSub', 'deviceMemory', 'userAgent', 'appName', 'maxTouchPoints', 'mediaDevices', 'getBattery',
		'battery', 'getUserMedia', 'webkitStorageInfo', 'webkitVisibilityState', 'webkitHidden', 'webkitGetUserMedia',
		'webkitDirectory', 'webkitIntent', 'mozApps', 'document.referrer', 'performance', 'history',
	];

	// Override properties
	var targetObjects = [Navigator.prototype, Window.prototype, Window];
	targetObjects.forEach(target => {
		propertiesToDisable.forEach(prop => {
			// Check if the property is already defined before overwriting it
			if (prop in target) {
				Object.defineProperty(target, prop, {
					get: function() { return disabledGetter(prop); },
					configurable: false
				});
			}
		});
	});
	
	var targetObjects = [history, History.prototype, navigator, Worker, Worker.prototype,  MediaDevices.prototype, MediaRecorder.prototype, ];
	var excludeProperties = ['plugins', 'storage', 'serviceWorker', 'webdriver', 'clipboard', 'language', 'languages', 'credentials'];
	
	// Iterate over all properties and methods of the navigator object
	targetObjects.forEach(target => {
		for (const prop in target) {
			if (!excludeProperties.includes(prop)) {
				// Override the property with the disabled function
				Object.defineProperty(target, prop, {
					get: function() { return disabledGetter(prop); },
					configurable: false,
				});
			}
		}
	});
})();

function countFailedNetworkRequests() {
	failedNetworkRequests = performance.getEntriesByType('resource')
		.filter(entry => entry.duration === 0).length;
	// Log failed network requests count to console
	console.log(`Failed network requests: \${failedNetworkRequests}`);
}


EOF;
	}
	
	echo $proxy->processHTMLBody($responseBody, $url, $jsContent);

}
elseif (stripos($contentType, "text/css") !== false) {
	//This is CSS, so proxify url() references.
	echo $proxy->proxifyCSS($responseBody, $url);
	header("Content-Type: text/css");
}
elseif(in_array($contentType, $compressibleMimeTypes)){
	// if it is a type that is allowed to be compressed via gzip
	header("Content-Type: " . $contentType);
	header('Content-Disposition: filename="'.basename(parse_url($url, PHP_URL_PATH).'"'));
	
	echo $responseBody;
}
elseif (stripos($contentType, "multipart/form-data") !== false) {
	ob_end_clean();
	//Cannot declare content type, something like boundary=----WebKitFormBoundaryyEmKNDsBKjB7QEqu never makes it into the Content-Type: header
	echo $responseBody;
}
else {
	ob_end_clean(); // images and videos wont load without this!
	//This isn't a web page or CSS, so serve unmodified through the proxy with the correct headers (images, JavaScript, etc.)
	header("Content-Type: " . $contentType); //not having this was causing a bunch of issues
	header('Content-Disposition: filename="'.basename(parse_url($url, PHP_URL_PATH).'"'));//Keep same filename when downloading from server, doesn't always work but is better
	echo $responseBody;
}

