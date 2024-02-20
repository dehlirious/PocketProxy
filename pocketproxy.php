<?php
//Too many captcha bypassing methods; I did not set it up with security in mind, rather, bot prevention!

$captchascript = "Captcha/AIO-Captcha.php";
if (file_exists($captchascript)) {
	include_once $captchascript;
}


/**
 * Set the path for the blacklist log file or the functionality will be disabled
 *
 * For privacy protection, ensure to customize this path to a secure location.
 * Logging functionality will remain disabled until this variable is modified.
 *
 * $blacklistlog : The path to the blacklist log file.
 */

class Proxy {
	public $a, $maxdl, $forceCORS, $blacklistlog, $cce, $prefixPort, $prefixHost, $blacklistPatterns, $captchasitesz,
	$httpvariable, $whitelistPatterns, $disallowLocal, $startURL, $landingExampleURL, $requiredExtensions;
	public function __construct() {
		//To allow proxying any URL, set $whitelistPatterns to an empty array (the default).
		$this->whitelistPatterns = [
		//Usage example: To whitelist any URL at example.net, including sub-domains, uncomment the
		//line below (which is equivalent to [ @^https?://([a-z0-9-]+\.)*example\.net@i ]):
		//$this->getHostnamePattern("example.net")
		];

		$this->blacklistPatterns = [
		//$this->getHostnamePattern("example.net")
		$this->getHostnamePattern($_SERVER['HTTP_HOST']) , $this->getHostnamePattern($_SERVER['SERVER_NAME']) ,
		$this->getHostnamePattern("httpbin.org"),
		];

		//To make a user enter a captcha for specified website(s) "archive.org"
		$this->captchasitesz =
		["archive.ph", "archive.md", "archive.is", "archive.li", "archive.vn", "archive.org", "archive.com"];
		
		$this->captchaua = ["Amazonbot/0.1", "Googlebot/2.1", "Bingbot/2.0", "Slackbot/1.0", "Facebookbot/2.1", "Twitterbot/2.0",
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
		"LinkedInBot/2.0", "PHP/9.0", "Go-http-client/2.0", "Googlebot-Mobile/1.0", "Bingbot-Mobile/1.0"] ;

		// If you have a HTTPS:// website,  you need to set this to "https" otherwise there will be bugs and content(css/js) won't load properly!
		// If you are on HTTP, this needs to be set to "http"
		$this->httpvariable = "https";

		//Change this to false to disable captcha codes from being displayed in plaintext
		$this->cce = true;

		//To enable CORS (cross-origin resource sharing) for proxied sites, set forceCORS to true.
		$this->forceCORS = true;

		//Set to false to allow sites on the local network (where PocketProxy is running) to be proxied.
		$this->disallowLocal = true;

		//Start/default URL that that will be proxied when PocketProxy is first loaded in a browser/accessed directly with no URL to proxy.
		//If empty, PocketProxy will show its own landing page.
		$this->startURL = "";

		$this->maxdl = 2444440000; //1.44gb downloaded file size limitation(like mp4's and such)
		
		//When no $startURL is configured above, PocketProxy will show its own landing page with a URL form field
		//and the configured example URL. The example URL appears in the instructional text on the PocketProxy landing page,
		//and is proxied when pressing the 'Proxy It!' button on the landing page if its URL form is left blank.
		$this->landingExampleURL = "https://example.net";
		
		//To protect Privacy, change this! Logging will be DISABLED until this variable is changed
		$this->blacklistlog = "logxzx/captchablacklist.log";

		$this->requiredExtensions = ["curl", "mbstring", "xml"];

		//Use HTTP_HOST to support client-configured DNS (instead of SERVER_NAME), but remove the port if one is present
		$this->prefixHost = $_SERVER["HTTP_HOST"];
		$this->prefixPort = "";
		$this->prefixHost = strpos($this->prefixHost, ":") ? implode(":", explode(":", $_SERVER["HTTP_HOST"], -1)) : $this->prefixHost;
		define("PROXY_PREFIX", $this->httpvariable . "://" . $this->prefixHost .
			($_SERVER['SERVER_PORT'] != 80 ? ':' . $_SERVER['SERVER_PORT'] : '') . $_SERVER["SCRIPT_NAME"] . "?");

		if (version_compare(PHP_VERSION, "5.4.7", "<")) {
			die("PocketProxy requires PHP version 5.4.7 or later.");
		}

		foreach ($this->requiredExtensions as $requiredExtension) {
			if (!extension_loaded($requiredExtension)) {
				die("PocketProxy requires PHP's \"" . $requiredExtension . "\" extension. Please install/enable it on your server and try again.");
			}
		}
	}
	
	//Remove the http(s):// and the /file.php?query=here from a url (and subdomains too)
	public function getDomain($url) {
		$domain = parse_url((strpos($url, "://") === false ? "http://" : "") . trim($url) , PHP_URL_HOST);
		if (preg_match('/[a-z0-9][a-z0-9\-]{0,63}\.[a-z]{2,6}(\.[a-z]{1,2})?$/i', $domain, $match)) {
			return $match[0];
		}
	}

	//Helper function for use inside $whitelistPatterns/$blacklistPatterns.
	//Returns a regex that matches all HTTP[S] URLs for a given hostname.
	public function getHostnamePattern($hostname) {
		$escapedHostname = str_replace(".", "\.", $hostname);
		return "@^https?://([a-z0-9-]+\.)*" . $escapedHostname . "@i";
	}

	public function logcbl($url) {
		$logDirectory = dirname($this->blacklistlog);
		
		if (file_exists($this->blacklistlog) && is_readable($this->blacklistlog) 
			&& is_writable($this->blacklistlog) && is_dir($logDirectory) && is_writable($logDirectory)
			&& $this->blacklistlog !== "logxzx/captchablacklist.log") {
			// Read the contents of the blacklist log file
			$file = file($this->blacklistlog);
			$line_count_pre = count($file);
			// Construct the content to be logged
			$content = $this->getUserIp() . "; #" . $url . PHP_EOL;
			// Check if the URL is not already logged to prevent duplicates
			if (!in_array($content, $file)) {
				// Append the content to the file
				file_put_contents($this->blacklistlog, $content, FILE_APPEND | LOCK_EX);
			}
			// Release the file handle
			unset($file);
		}
	}
	
	//Validates a URL against the whitelist
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
	//Validates a URL against the blacklist.
	public function passesBlacklist($url) {
		foreach ($this->blacklistPatterns as $pattern) {
			if (preg_match($pattern, $url)) {
				return false;
			}
		}
		return true;
	}

	public function isLocal($url) {
		//BUG (ish~)
		//normal https://example.net/ - example.net
		//https://example.net/  with two slashes before script http://?https://example.net/  - (blank)
		
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
	
	//Helper function that determines whether to allow proxying of a given URL.
	public function isValidURL($url) {
		return $this->passesWhitelist($url) && $this->passesBlacklist($url) && ($this->disallowLocal ? !$this->isLocal($url) : true);
	}

	public function getUserIp() {
		$client = @$_SERVER['HTTP_CLIENT_IP']; //Use @ or get "PHP Notice:  Undefined index: HTTP_CLIENT_IP"  errors
		//$forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
		$cf_ip = @$_SERVER['HTTP_CF_CONNECTING_IP']; //Cloudflare+nginx w/ realip module
		$remote = $_SERVER['REMOTE_ADDR'];
		if (filter_var($client, FILTER_VALIDATE_IP)) {
			$ip = $client;
		}
		//elseif (filter_var($forward, FILTER_VALIDATE_IP)) {
		//	$ip = $forward;
		//}
		elseif (filter_var($cf_ip, FILTER_VALIDATE_IP)) {
			$ip = $cf_ip;
		}
		else {
			$ip = filter_var($remote, FILTER_VALIDATE_IP);
		}

		$this->ip = $ip;
		return $ip;
	}

	//Helper function used to removes/unset keys from an associative array using case insensitive matching
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


	//Makes an HTTP request via cURL, using request data that was passed directly to this script.
	public function makeRequest($url) {
		//Tell cURL to make the request using the brower's user-agent if there is one, or a fallback user-agent otherwise.
		$user_agent = $_SERVER["HTTP_USER_AGENT"];
		if (empty($user_agent)) {
			$user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.3";
		}
		
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);

		//Get ready to proxy the browser's request headers...
		$browserRequestHeaders = getallheaders();

		//Let cURL set some headers on its own and strip away bad headers that reveal too much information!
		$removedHeaders = $this->removeKeys($browserRequestHeaders, [
		// "Accept-Encoding", // Removed because it gave me issues! I don't know why yet.
		"Content-Length", "permissions-policy",
		"strict-transport-security", "report-to", "Host",
		"x-content-type-options", "cross-origin-opener-policy-report-only",
		"content-security-policy", "x-frame-options", "x-robots-tag",
		"x-xss-protection", "X-Frame-Options", "Origin",
		"Client-IP", "X-Real-IP", "X-Forwarded-For",
		"HTTP_CF_CONNECTING_IP", "REMOTE_ADDR", "HTTP_X_FORWARDED_FOR", "HTTP_CLIENT_IP",
		"X-Forwarded-Host", "HTTP_X_REAL_IP", "HTTP_VIA", "Forwarded", "CF-Connecting-IP", "X-Cluster-Client-Ip",
		"X-Forwarded-Server", "X-ProxyUser-Ip", "X-Real-Host", "X-Original-URL", "X-Original-Forwarded-For",
		"X-Client-IP", "X-Originating-IP", "X-User-IP", "X-Remote-Addr",
		]);

		$removedHeaders = array_map("strtolower", $removedHeaders);

		curl_setopt($ch, CURLOPT_ENCODING, "");
		//Transform the associative array from getallheaders() into an
		//indexed array of header strings to be passed to cURL.
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

		return ["headers" => $responseHeaders, "body" => $responseBody, "responseInfo" => $responseInfo, ];
	}

	//Converts relative URLs to absolute ones, given a base URL.
	//Modified version of code found at https://web.archive.org/web/20121014113424/https://nashruddin.com/PHP_Script_for_Converting_Relative_to_Absolute_URL
	public function rel2abs($rel, $base) {
		if (empty($rel)) {
			$rel = ".";
		}
		if (parse_url($rel, PHP_URL_SCHEME) != "" || strpos($rel, "//") === 0) {
			return $rel;
		} //Return if already an absolute URL
		if ($rel[0] == "#" || $rel[0] == "?") {
			return $base . $rel;
		} //Queries and anchors
		extract(parse_url($base)); //Parse base URL and convert to local variables: $scheme, $host, $path
		$path = isset($path) ? preg_replace("#/[^/]*$#", "", $path) : "/"; //Remove non-directory element from path
		if ($rel[0] == "/") {
			$path = "";
		} //Destroy path if relative url points to root
		$port = isset($port) && $port != 80 ? ":" . $port : "";
		$auth = "";
		if (isset($user)) {
			$auth = $user;
			if (isset($pass)) {
				$auth .= ":" . $pass;
			}
			$auth .= "@";
		}
		$abs = "$auth$host$port$path/$rel"; //Dirty absolute URL
		for ($n = 1;$n > 0;$abs = preg_replace(["#(/\.?/)#", "#/(?!\.\.)[^/]+/\.\./#"], "/", $abs, -1, $n)) {
		} //Replace '//' or '/./' or '/foo/../' with '/'
		return $scheme . "://" . $abs; //Absolute URL is ready.
		
	}
	
	//Convert a memory limit value to bytes.
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

	//Proxify contents of url() references in blocks of CSS text.
	public function proxifyCSS($css, $baseURL) {
		$memoryLimit = ini_get('memory_limit');
		// If memory limit is set to -1 (unlimited), manually set it to 1GB for our checks
		$memoryLimitBytes = ($memoryLimit == -1) ? $this->memoryLimitToBytes('128M') : $this->memoryLimitToBytes($memoryLimit);
		$safeMemoryLimit = $memoryLimitBytes * 0.8; // Stay 20% below the memory limit

		$sourceLines = explode("\n", $css);
		$normalizedLines = [];
		foreach ($sourceLines as $line) {
			if (memory_get_usage() > $safeMemoryLimit) {
				// Memory limit nearing exhaustion, stop processing and return the original CSS
				return $css;
			}

			if (preg_match("/@import\s+url/i", $line) || preg_match("/@font-face/i", $line)) {
				$normalizedLines[] = $line;
			} else {
				$normalizedLines[] = preg_replace_callback("/(@import\s+)([^;\s]+)([\s;])/i", function ($matches) use ($baseURL) {
					return $matches[1] . "url(" . $matches[2] . ")" . $matches[3];
				}, $line);
			}
		}
		$normalizedCSS = implode("\n", $normalizedLines);

		// Perform the final replacement with a memory check
		$processedCSS = preg_replace_callback("/url\((.*?)\)/i", function ($matches) use ($baseURL, $safeMemoryLimit) {
			if (memory_get_usage() > $safeMemoryLimit) {
				// If this point is reached, it's too late to return the original CSS without partial processing,
				return $matches[0]; // Return the match unchanged
			}

			$url = $matches[1];
			// Remove any surrounding single or double quotes from the URL so it can be passed to rel2abs - the quotes are optional in CSS
			// Assume that if there is a leading quote then there should be a trailing quote, so just use trim() to remove them
			if (strpos($url, "'") === 0) {
				$url = trim($url, "'");
			}
			if (strpos($url, "\"") === 0) {
				$url = trim($url, "\"");
			}
			if (stripos($url, "data:") === 0) {
				return "url(" . $url . ")";
			} // The URL isn't an HTTP URL but is actual binary data. Don't proxify it.
			return "url(" . PROXY_PREFIX . $this->rel2abs($url, $baseURL) . ")";
		}, $normalizedCSS);
		
		return $processedCSS ? $processedCSS : $css;
	}
	
	//Added to prevent empty responses and remove php warning codes
	public function nozeros($ss) {
		if ($ss > 0.0) {
			return strrpos($ss, " ");
		}
		else {
			return 1; //intval($x);
		}
	}

	//Proxify "srcset" attributes (normally associated with <img> tags.)
	public function proxifySrcset($srcset, $baseURL) {
		$sources = array_map("trim", explode(",", $srcset)); //Split all contents by comma and trim each value
		$proxifiedSources = array_map(function ($source) use ($baseURL) {
			$sauce = $this->nozeros($source);
			if($sauce = 1) {
				$components = array_map("trim", str_split($source));
			} else {
				$components = array_map("trim", str_split($source,$sauce));//Split by last space and trim
			}
			$components[0] = PROXY_PREFIX . $this->rel2abs(ltrim(array_key_exists(0, $components) ? $components[0] : '', "/") , $baseURL); //First component of the split source string should be an image URL; proxify it
			$result = [];
			foreach ($components as $item) {
				if (preg_match("/'(.*?)' => '(.*?)'/", $item, $matches)) {
					$result[$matches[1]] = $matches[2];
				}
			}

			return implode(" ", $components); //Recombine the components into a single source //MODIFIED to remove error
			
		}
		, $sources);
		return implode(", ", $proxifiedSources); //Recombine the sources into a single "srcset"
	}
}
$proxy = new Proxy();
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

if (function_exists('ob_gzhandler')) {
	ob_start("ob_gzhandler");
} else {
	ob_start();
}

if (!function_exists("getallheaders")) {
	//Adapted from http://www.php.net/manual/en/function.getallheaders.php#99814
	function getallheaders() {
		$result = [];
		foreach ($_SERVER as $key => $value) {
			if (substr($key, 0, 5) == "HTTP_") {
				$key = str_replace(" ", "-", ucwords(strtolower(str_replace("_", " ", substr($key, 5)))));
				$result[$key] = $value;
			}
		}
		return $result;
	}
}

//Extract and sanitize the requested URL, handling cases where forms have been rewritten to point to the proxy.
if (isset($_POST["ProxyForm"])) {
	$url = $_POST["ProxyForm"];
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
	}
	else { //This now allows pocketProxy.php to be index.php!
		$parsedUri = parse_url($_SERVER["REQUEST_URI"]);
		$url = isset($parsedUri['query']) ? '?' . $parsedUri['query'] : '';
		if (substr($url, 0, 1) === '?') {
			$url = substr($url, 1);
		}
	}
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
$variable1 = isset(parse_url($url)["host"]) ? $proxy->getDomain(parse_url($url)["host"]) : "";
$userAgent = $_SERVER['HTTP_USER_AGENT'];
$matchesCaptchaUA = false;
foreach ($proxy->captchaua as $uaString) {
	if (strpos($userAgent, $uaString) !== false) {
		$matchesCaptchaUA = true;
		break;
	}
}

// Set session configuration
ini_set('session.cookie_secure', '1'); // Enforce secure cookie handling over HTTPS
ini_set('session.cookie_httponly', '1'); // Prevent client-side script access to cookies

// Start session
session_start();

if ((in_array($variable1, $proxy->captchasitesz) || $matchesCaptchaUA) &&
	(class_exists('Gregwar\\Captcha\\PhraseBuilder') && class_exists('Gregwar\\Captcha\\CaptchaBuilder')) && extension_loaded("gd")) {
	
	$variable2 = false;
	$variable3 = false;

	if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_SESSION["phrase"])) {
		
		if(!isset($_POST["phrase"]))
		{
			$ehrx = "<h1>Captcha is not valid!</h1>";
		}
		else if (Gregwar\Captcha\PhraseBuilder::comparePhrases($_SESSION["phrase"], $_POST["phrase"])) { //PHP Warning:  Undefined array key "phrase"
			$variable2 = true;

			if (!isset($_SESSION["CREATED"])) {
				$_SESSION["CREATED"] = time();
			} elseif (time() - $_SESSION["CREATED"] > 1800) {
				session_regenerate_id(true);
				$_SESSION["CREATED"] = time();
			}
		} else {
			$ehrx = "<h1>Captcha is not valid!</h1>";
		}
	}

	unset($_SESSION["phrase"]);

	if (isset($_SESSION["CREATED"])) {
		if (time() - $_SESSION["CREATED"] > 1800) {
			$variable3 = true;
		}
	} else {
		$variable3 = true;
	}

	if (!$variable2 && $variable3) {
		// Set session expiration and implement session timeout
		$session_timeout = 1800; // 30 minutes (in seconds)
		if (isset($_SESSION['LAST_ACTIVITY']) && time() - $_SESSION['LAST_ACTIVITY'] > $session_timeout) {
			session_unset(); // Unset all session variables
			session_destroy(); // Destroy the session
			// Redirect the user to the login page or display an appropriate message
			die("<h1>Session expired. Please refresh the page and try again.</h1>");
		} else {
			$_SESSION['LAST_ACTIVITY'] = time(); // Update the last activity timestamp
		}

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
			if ($proxy->cce) {
				if (isset($ehrx)) {
					echo $ehrx;
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

$scheme = parse_url($url, PHP_URL_SCHEME);

if (empty($scheme)) {
	/*To-do! CHECK! if http or https exists!*/
	if (strpos($url, "//") === 0) {
		//Assume that any supplied URLs starting with // are HTTP URLs.
		$url = "http:" . $url;
	}
	else {
		//Assume that any supplied URLs without a scheme (just a host) are HTTP URLs.
		// This may cause issues.
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
	die("Error: The requested URL was disallowed by the server administrator.");
}
//Error where google links are ?https:/ and not ://

$response = $proxy->makeRequest($url);
$rawResponseHeaders = $response["headers"];
$responseBody = $response["body"];
$responseInfo = $response["responseInfo"];

//If CURLOPT_FOLLOWLOCATION landed the proxy at a diferent URL than
//what was requested, explicitly redirect the proxy there.
$responseURL = $responseInfo["url"];
if ($responseURL !== $url) {
	header("Location: " . PROXY_PREFIX . $responseURL, true);
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
	//Attempt to normalize character encoding.
	$detectedEncoding = mb_detect_encoding($responseBody, "UTF-8, ISO-8859-1");
	if ($detectedEncoding) {
		$responseBody = htmlspecialchars_decode($responseBody);
	}
	//added, make $source not empty, to remove php error codes
	if (empty($responseBody)) {
		$responseBody = " ";
	}
	/*
	
	I don't know if I ever fixed these or not! I think I just added "@" to supress it!
	
	//HP message: PHP Warning:  DOMDocument::loadHTML(): Tag nav invalid in Entity
	//PHP message: PHP Warning:  DOMDocument::loadHTML(): Tag footer invalid in Entity, line: 349 in /var/www/html/pocketproxy.php on line 663" while reading response header from upstream,
	
	*/
	
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
		$action = empty($action) ? $url : $proxy->rel2abs($action, $url);
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
					$element->setAttribute("content", $splitContent[0] . "=" . PROXY_PREFIX . $proxy->rel2abs($splitContent[1], $url));
				}
			}
		}
	}
	//Profixy <style> tags.
	foreach ($xpath->query("//style") as $style) {
		//BUG: main(): unterminated entity reference skey=c491285d6722e4fa&amp;v=v12) format('woff')}
		// &amp; < should probably be & , isssuuuuues
		$style->nodeValue = $proxy->proxifyCSS($style->nodeValue, $url);
	}
	//Proxify tags with a "style" attribute.
	foreach ($xpath->query("//*[@style]") as $element) {
		$element->setAttribute("style", $proxy->proxifyCSS($element->getAttribute("style") , $url));
	}
	//Proxify "srcset" attributes in <img> tags.
	foreach ($xpath->query("//img[@srcset]") as $element) {
		$element->setAttribute("srcset", $proxy->proxifySrcset($element->getAttribute("srcset") , $url));
	}
	//Proxify any of these attributes appearing in any tag.
	$proxifyAttributes = ["href", "src"];
	foreach ($proxifyAttributes as $attrName) {
		foreach ($xpath->query("//*[@" . $attrName . "]") as $element) {
			//For every element with the given attribute...
			$attrContent = $element->getAttribute($attrName);
			if ($attrName == "href" && preg_match("/^(about|javascript|magnet|mailto):|#/i", $attrContent)) {
				continue;
			}
			if ($attrName == "src" && preg_match("/^(data):/i", $attrContent)) {
				continue;
			}
			$attrContent = $proxy->rel2abs($attrContent, $url);
			$attrContent = PROXY_PREFIX . $attrContent;
			$element->setAttribute($attrName, $attrContent);
		}
	}

	//Attempt to force AJAX requests to be made through the proxy by
	//wrapping window.XMLHttpRequest.prototype.open in order to make
	//all request URLs absolute and point back to the proxy.
	//The rel2abs() JavaScript function serves the same purpose as the server-side one in this file,
	//but is used in the browser to ensure all AJAX request URLs are absolute and not relative.
	//Uses code from these sources:
	//http://stackoverflow.com/questions/7775767/javascript-overriding-xmlhttprequest-open
	//https://gist.github.com/1088850
	//TODO: implement more than just xmlhttp
	$head = $xpath->query("//head")
		->item(0);
	$body = $xpath->query("//body")
		->item(0);
	$prependElem = $head != null ? $head : $body;

	//Only bother trying to apply this hack if the DOM has a <head> or <body> element;
	//insert some JavaScript at the top of whichever is available first.
	//Protects against cases where the server sends a Content-Type of "text/html" when
	//what's coming back is most likely not actually HTML.
	if ($prependElem != null) {
		$proxyPrefix = PROXY_PREFIX;
		$scriptElem = $doc->createElement("script", <<<EOF
(function() {
	// Initialize a proxy prefix variable to modify URLs for routing through a proxy.
	var proxyPrefix = "{$proxyPrefix}";

	// Extract the base URL from the current location to use in URL modifications.
	var currentURL = window.location.href;
	var params = currentURL.split("{$_SERVER["SCRIPT_NAME"]}?")[1];
	var baseURL = decodeURIComponent(params || "");

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

			// List of attributes that potentially contain URLs to be modified.
			var potentialUrlAttributes = ["src", "rel", "href", "data-src", "data-href", "action", "srcset", "poster", "hreflang", "cite", "data-url", "data-link", "data-file", "data-image", "data-video", "data-audio", "data-source"];
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
			const attributesToCheck = ['src', 'href', 'data', 'action', 'srcset', 'cite', 'formaction'];

			// Check if the attribute name is one of the specified attributes to modify
			if (attributesToCheck.includes(name.toLowerCase())) {
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

	function extractUrl(cssValue) {
		// Extracts URL from the cssValue like "url('http://example.com')"
		const matches = cssValue.match(/url\(['"]?(.*?)['"]?\)/);
		return matches ? matches[1] : '';
	}

	function modifyCSSRule(cssText) {
		// Replaces all url() values within a CSS text with modified URLs
		return cssText.replace(/url\((['"]?)(.+?)\1\)/g, (match, quote, url) => `url(\${quote}\${modifyUrl(url)}\${quote})`);
	}

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
		// Intercepting navigator.sendBeacon
		navigator.sendBeacon = ((original) => (url, data) => original(modifyUrl(url), data))(navigator.sendBeacon.bind(navigator));
	} catch (error) {
		console.error("Error in navigator.sendBeacon interception setup:", error);
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
		// Intercept Fetch API and Request Constructor
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
					if (/^https?:\/\//i.test(url)) {
						url = modifyUrl(url);
					}
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
		// Interception for SharedWorker, EventSource, and document.execCommand
		const workerTypes = {
			SharedWorker: window.SharedWorker,
			EventSource: window.EventSource
		};
		Object.entries(workerTypes).forEach(([type, OriginalConstructor]) => {
			window[type] = function(url, options) {
				try {
					return new OriginalConstructor(modifyUrl(url), options);
				} catch (error) {
					console.error(`Error intercepting \${type} creation:`, error);
				}
			};
		});
	} catch (error) {
		console.error("Error in SharedWorker and EventSource interception setup:", error);
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

	//beta
	/*// A function to sanitize inline event handlers
	function sanitizeInlineEventHandlers(element) {
		var events = ["onclick", "onsubmit", "onload", "onerror", "onchange", "onmouseover", "onmouseout", "onkeydown", "onkeyup"];
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
	function sanitizeAllInlineEventHandlers() {
		var allElements = document.getElementsByTagName("*");
		for (var i = 0; i < allElements.length; i++) {
			sanitizeInlineEventHandlers(allElements[i]);
		}
	}*/

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

	function rel2abs(base, href) { // RFC 3986
		// Converts a relative URL to an absolute URL based on a base URL.
		try {
			function removeDotSegments(input) {
				var output = [];
				input.replace(/^(\.\.?(\/|$))+/, "")
					.replace(/\/(\.(\/|$))+/g, "/")
					.replace(/\/\.\.$/, "/../")
					.replace(/\/?[^\/]*/g, function(p) {
						if (p === "/..") {
							output.pop();
						} else {
							output.push(p);
						}
					});
				return output.join("").replace(/^\//, input.charAt(0) === "/" ? "/" : "");
			}

			href = parseURI(href || "");
			base = parseURI(base || "");

			// Combines the base URL and relative URL into an absolute URL.
			return !href || !base ? null : (href.protocol || base.protocol) +
				(href.protocol || href.authority ? href.authority : base.authority) +
				removeDotSegments(href.protocol || href.authority || href.pathname.charAt(0) === "/" ? href.pathname : (href.pathname ? ((base.authority && !base.pathname ? "/" : "") + base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1) + href.pathname) : base.pathname)) +
				(href.protocol || href.authority || href.pathname ? href.search : (href.search || base.search)) +
				href.hash;
		} catch (error) {
			console.error("Error in rel2abs:", error);
			return null;
		}
	}

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

	function modifyUrl(url) {
		try {
			// Modifies the given URL to include the proxy prefix.
			if (typeof url === 'string') {
				if (url.includes('pl.zrr.us')) {
					return url; // Return the original URL for 'pl.zrr.us'
				}
				if (!url.includes(proxyPrefix)) {
					var urlObj = parseURI(url);
					if (urlObj) {
						url = rel2abs(window.location.href, urlObj.href);
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
			return url; // Return the original URL on error.
		}
	}

})();

EOF
);

		$prependElem->insertBefore($scriptElem, $prependElem->firstChild);
	}

	//I noticed Google results were ?url=https:/ and not ?url=https:// causing them to not function
	//This does not fix the root issue
	foreach ($doc->getElementsByTagName('a') as $link) {
	   $link->setAttribute('href', preg_replace(array('/https\:\/(?!\/)/', '/http\:\/(?!\/)/'), array('https://', 'http://'), $link->getAttribute('href')));
	}
	
	echo $doc->saveHTML($doc->documentElement); //Fixed a UTF-8 ecoding error https://stackoverflow.com/questions/8218230/php-domdocument-loadhtml-not-encoding-utf-8-correctly
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

