<?php
include "Captcha/AIO-Captcha.php";
use Gregwar\Captcha\CaptchaBuilder;
use Gregwar\Captcha\PhraseBuilder;

class Proxy {
	public $a, $maxdl, $forceCORS, $cce, $prefixPort, $blacklistlog, $prefixHost, $blacklistPatterns, $captchasitesz, $httpvariable, $whitelistPatterns, $disallowLocal, $anonymize, $startURL, $landingExampleURL, $requiredExtensions;
	public function __construct() {
		//To allow proxying any URL, set $whitelistPatterns to an empty array (the default).
		$this->whitelistPatterns = [
		//Usage example: To whitelist any URL at example.net, including sub-domains, uncomment the
		//line below (which is equivalent to [ @^https?://([a-z0-9-]+\.)*example\.net@i ]):
		//$this->getHostnamePattern("example.net")
		];

		$this->blacklistPatterns = [
		//$this->getHostnamePattern("example.net")
		];

		//To make a user enter a captcha for specified website(s)
		$this->captchasitesz = ["badactorwebsite9512521.org", "archive.is", "archive.li", ];

		// If you have a HTTPS:// website,  you need to set this to "https" otherwise there will be bugs and content(css/js) won't load properly!
		// If you are on HTTP, this needs to be set to "http"
		$this->httpvariable = "https";

		//Change this to false to disable captcha codes from being displayed in plaintext
		$this->cce = false;

		//To enable CORS (cross-origin resource sharing) for proxied sites, set forceCORS to true.
		$this->forceCORS = true;

		//Set to false to allow sites on the local network (where PocketProxy is running) to be proxied.
		$this->disallowLocal = true;

		//Set to false to report the client machine's IP address to proxied sites via the HTTP `x-forwarded-for` header.
		//Setting to false may improve compatibility with some sites, but also exposes more information about end users to proxied sites.
		$this->anonymize = true;

		//Start/default URL that that will be proxied when PocketProxy is first loaded in a browser/accessed directly with no URL to proxy.
		//If empty, PocketProxy will show its own landing page.
		$this->startURL = "";

		$this->maxdl = 1444440000; //1.44gb downloaded file size limitation(like mp4's and such)
		
		//When no $startURL is configured above, PocketProxy will show its own landing page with a URL form field
		//and the configured example URL. The example URL appears in the instructional text on the PocketProxy landing page,
		//and is proxied when pressing the 'Proxy It!' button on the landing page if its URL form is left blank.
		$this->landingExampleURL = "https://example.net";
		
		//Please change this
		$this->blacklistlog = "no/captcha.log";

		$this->requiredExtensions = ["curl", "mbstring", "xml"];

		//Use HTTP_HOST to support client-configured DNS (instead of SERVER_NAME), but remove the port if one is present
		$this->prefixHost = $_SERVER["HTTP_HOST"];
		$this->prefixPort = "";
		$this->prefixHost = strpos($this->prefixHost, ":") ? implode(":", explode(":", $_SERVER["HTTP_HOST"], -1)) : $this->prefixHost;
		define("PROXY_PREFIX", $this->httpvariable . (isset($_SERVER["HTTPS"]) ? "s" : "") . "://" . $this->prefixHost . "" //.$prefixPort //was removed because it displayed port 80 and i haven't fixed it yet, will need uncommented if you are on a port other than :80
		 . $_SERVER["SCRIPT_NAME"] . "?");

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
	public function get_domain($url) {
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
		if(file_exists($this->blacklistlog)){
			$file = file($this->blacklistlog);
			$line_count_pre = count($file);
			$content = "" . $this->getUserIp() . "; #" . ".$url.". PHP_EOL; 
			$file[] = $content;
			$line_count_post = count(array_unique($file));
			unset($file);
			if ($line_count_post > $line_count_pre) { //Note: this isn't going to work as intended, to disallow duplicate results unless the url is the same, when . ".$url." is added;
				file_put_contents($this->blacklistlog, "" . $this->getUserIp() . "; #" . ".$url.". PHP_EOL, FILE_APPEND | LOCK_EX);
			}
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
		$forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
		$cf_ip = @$_SERVER['HTTP_CF_CONNECTING_IP']; //Cloudflare+nginx w/ realip module
		$remote = $_SERVER['REMOTE_ADDR'];
		if (filter_var($client, FILTER_VALIDATE_IP)) {
			$ip = $client;
		}
		elseif (filter_var($forward, FILTER_VALIDATE_IP)) {
			$ip = $forward;
		}
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
			$user_agent = "Mozilla/5.0 (compatible; PocketProxy)";
		}
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);

		//Get ready to proxy the browser's request headers...
		$browserRequestHeaders = getallheaders();

		//...but let cURL set some headers on its own.
		$removedHeaders = $this->removeKeys($browserRequestHeaders, [
		"Content-Length", "permissions-policy", "strict-transport-security", "report-to", "Host", "x-content-type-options", "cross-origin-opener-policy-report-only", "content-security-policy", "x-frame-options", "x-robots-tag", "x-xss-protection", "X-Frame-Options", //Added but not necessary it seems
		"Origin", ]);

		$removedHeaders = array_map("strtolower", $removedHeaders);

		curl_setopt($ch, CURLOPT_ENCODING, "");
		//Transform the associative array from getallheaders() into an
		//indexed array of header strings to be passed to cURL.
		$curlRequestHeaders = [];
		foreach ($browserRequestHeaders as $name => $value) {
			$curlRequestHeaders[] = $name . ": " . $value;
		}
		if (!$this->anonymize) {
			$curlRequestHeaders[] = "X-Forwarded-For: " . $_SERVER["REMOTE_ADDR"];
		}
		//Any `origin` header sent by the browser will refer to the proxy itself.
		//If an `origin` header is present in the request, rewrite it to point to the correct origin.
		if (in_array("origin", $removedHeaders)) {
			$urlParts = parse_url($url);
			$port = array_key_exists("port", $urlParts) == null ? "" : $urlParts["port"]; // Modified to remove a PHP Warning code
			$curlRequestHeaders[] = "Origin: " . $urlParts["scheme"] . "://" . $urlParts["host"] . (empty($port) ? "" : ":" . $port);
		}
		curl_setopt($ch, CURLOPT_HTTPHEADER, $curlRequestHeaders);

		//Proxy any received GET/POST/PUT data.
		switch ($_SERVER["REQUEST_METHOD"]) {
			case "POST":
				curl_setopt($ch, CURLOPT_POST, true);
				//For some reason, $HTTP_RAW_POST_DATA isn't working as documented at
				//http://php.net/manual/en/reserved.variables.httprawpostdata.php
				//but the php://input method works. This is likely to be flaky
				//across different server environments.
				//More info here: http://stackoverflow.com/questions/8899239/http-raw-post-data-not-being-populated-after-upgrade-to-php-5-3
				//If the ProxyForm field appears in the POST data, remove it so the destination server doesn't receive it.
				$postData = [];
				parse_str(file_get_contents("php://input") , $postData);
				if (isset($postData["ProxyForm"])) {
					unset($postData["ProxyForm"]);
				}
				curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
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
	//Modified version of code found at http://nashruddin.com/PHP_Script_for_Converting_Relative_to_Absolute_URL
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

	//Proxify contents of url() references in blocks of CSS text.
	public function proxifyCSS($css, $baseURL) {
		//Add a "url()" wrapper to any CSS @import rules that only specify a URL without the wrapper,
		//so that they're proxified when searching for "url()" wrappers below.
		$sourceLines = explode("\n", $css);
		$normalizedLines = [];
		foreach ($sourceLines as $line) {
			if (preg_match("/@import\s+url/i", $line)) {
				$normalizedLines[] = $line;
			}
			else {
				$normalizedLines[] = preg_replace_callback("/(@import\s+)([^;\s]+)([\s;])/i", function ($matches) use ($baseURL) {
					return $matches[1] . "url(" . $matches[2] . ")" . $matches[3];
				}
				, $line);
			}
		}
		$normalizedCSS = implode("\n", $normalizedLines);
		return preg_replace_callback("/url\((.*?)\)/i", function ($matches) use ($baseURL) {
			$url = $matches[1];
			//Remove any surrounding single or double quotes from the URL so it can be passed to rel2abs - the quotes are optional in CSS
			//Assume that if there is a leading quote then there should be a trailing quote, so just use trim() to remove them
			if (strpos($url, "'") === 0) {
				$url = trim($url, "'");
			}
			if (strpos($url, "\"") === 0) {
				$url = trim($url, "\"");
			}
			if (stripos($url, "data:") === 0) {
				return "url(" . $url . ")";
			} //The URL isn't an HTTP URL but is actual binary data. Don't proxify it.
			return "url(" . PROXY_PREFIX . $this->rel2abs($url, $baseURL) . ")";
		}
		, $normalizedCSS);
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
			
			//UPDATED TO POTENTIALLY FIX  Undefined array key 0
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
		$proxifiedSrcset = implode(", ", $proxifiedSources); //Recombine the sources into a single "srcset"
		return $proxifiedSrcset;
	}
}
$proxy = new Proxy();
$html = "<html><head><title>PocketProxy</title></head><body><h1>Welcome to PocketProxy!</h1>
PocketProxy can be directly invoked like this: <a href=\"" . PROXY_PREFIX . $proxy->landingExampleURL . "\">" . PROXY_PREFIX . $proxy->landingExampleURL . "</a><br /><br />Or, you can simply enter a URL below:<br /><br />
<form onsubmit=\"window.location.href='" . PROXY_PREFIX . "' + document.getElementById('site').value; return false;\">
<input id='site' type='text' size='50' placeholder='" . $proxy->landingExampleURL . "'><input type=\"submit\" value=\"Proxy It!\" /></form></body></html>";
ob_start("ob_gzhandler");

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
	else {
		$url = substr($_SERVER["REQUEST_URI"], strlen($_SERVER["SCRIPT_NAME"]) + 1);
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

//Added for captcha functionality
$variable1 = array_key_exists("host", parse_url($url)) == null ? "" : $proxy->get_domain(parse_url($url) ["host"]);
session_start();
if (in_array($variable1, $proxy->captchasitesz)) {
	$variable2 = false;
	$variable3 = false;
	if (isset($_SESSION["phrase"])) {
			if(PhraseBuilder::comparePhrases($_SESSION["phrase"], $_POST["phrase"])){
				$variable2 = true;
				//if (!empty($_SESSION['CREATED'])) {//Originally added to remove a php warning code, but ruined functionality
				if (!isset($_SESSION["CREATED"])) {
					$_SESSION["CREATED"] = time();
				}
				else if (time() - $_SESSION['CREATED'] > 1800) {
					// session started more than 30 minutes ago
					session_regenerate_id(true);    // change session ID for the current session and invalidate old session ID
					$_SESSION['CREATED'] = time();  // update creation time
				}
			}
			else{
				$ehrx = "<h1>Captcha is not valid!</h1>";
			}
		}
	}
	// The phrase can't be used twice
	unset($_SESSION["phrase"]);
	if (array_key_exists("CREATED", $_SESSION)) {
		if (time() - $_SESSION["CREATED"] > 1800) {
			$variable3 = true;
		}
	}
	else {
		$variable3 = true;
	}
	if (!$variable2 && $variable3) { ?>
		<h1>The website you're trying to visit is on the Suspicious Website List!</h1>
	<form method="post">Please Copy the Captcha (30 minute Sessions)
        <?php
		$phraseBuilder = new PhraseBuilder(4);
		$captcha = new CaptchaBuilder(null, $phraseBuilder);
		$captcha->build();
		$_SESSION["phrase"] = $captcha->getPhrase();
?>
         <img src="<?php echo $captcha->inline(); ?>"/><br/>
        <?php if ($proxy->cce) {
			if(isset($ehrx)){echo $ehrx;}
			echo "Cheat Code: " . $captcha->getPhrase();
		} ?>
        <input type="text" name="phrase" />
        <input type="submit" />
    </form>
		<?php die();
	}
}

$scheme = parse_url($url, PHP_URL_SCHEME);
if (empty($scheme)) {
	if (strpos($url, "//") === 0) {
		//Assume that any supplied URLs starting with // are HTTP URLs.
		$url = "http:" . $url;
	}
	else {
		//Assume that any supplied URLs without a scheme (just a host) are HTTP URLs.
		$url = "http://" . $url;
	}
}
elseif (!preg_match("/^https?$/i", $scheme)) {
	die('Error: Detected a "' . $scheme . '" URL. PocketProxy exclusively supports http[s] URLs.');
}
$url = str_replace(array('http://?','https://?'), '', $url);//This is going to fix a lot of weirds but potentially not all!
$url = str_replace(array('?http://','?https://'), array('http://','https://'), $url);

if (!$proxy->isValidURL($url)) {
	$proxy->logcbl($url);
	die("Error: The requested URL was disallowed by the server administrator.");
}

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

//This is presumably a web page, so attempt to proxify the DOM.
if (stripos($contentType, "text/html") !== false) {
	//Attempt to normalize character encoding.
	$detectedEncoding = mb_detect_encoding($responseBody, "UTF-8, ISO-8859-1");
	if ($detectedEncoding) {
		$responseBody = mb_convert_encoding($responseBody, "HTML-ENTITIES", $detectedEncoding);
	}
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
	//TODO: This is obviously only useful for browsers that use XMLHttpRequest but
	//it's better than nothing.
	$head = $xpath->query("//head")
		->item(0);
	$body = $xpath->query("//body")
		->item(0);
	$prependElem = $head != null ? $head : $body;

	//Only bother trying to apply this hack if the DOM has a <head> or <body> element;
	//insert some JavaScript at the top of whichever is available first.
	//Protects against cases where the server sends a Content-Type of "text/html" when
	//what's coming back is most likely not actually HTML.
	//TODO: Do this check before attempting to do any sort of DOM parsing?
	if ($prependElem != null) {
		$scriptElem = $doc->createElement("script", '(function() {

        if (window.XMLHttpRequest) {

          function parseURI(url) {
            var m = String(url).replace(/^\s+|\s+$/g, "").match(/^([^:\/?#]+:)?(\/\/(?:[^:@]*(?::[^:@]*)?@)?(([^:\/?#]*)(?::(\d*))?))?([^?#]*)(\?[^#]*)?(#[\s\S]*)?/);
            // authority = "//" + user + ":" + pass "@" + hostname + ":" port
            return (m ? {
              href : m[0] || "",
              protocol : m[1] || "",
              authority: m[2] || "",
              host : m[3] || "",
              hostname : m[4] || "",
              port : m[5] || "",
              pathname : m[6] || "",
              search : m[7] || "",
              hash : m[8] || ""
            } : null);
          }

          function rel2abs(base, href) { // RFC 3986

            function removeDotSegments(input) {
              var output = [];
              input.replace(/^(\.\.?(\/|$))+/, "")
                .replace(/\/(\.(\/|$))+/g, "/")
                .replace(/\/\.\.$/, "/../")
                .replace(/\/?[^\/]*/g, function (p) {
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

            return !href || !base ? null : (href.protocol || base.protocol) +
            (href.protocol || href.authority ? href.authority : base.authority) +
            removeDotSegments(href.protocol || href.authority || href.pathname.charAt(0) === "/" ? href.pathname : (href.pathname ? ((base.authority && !base.pathname ? "/" : "") + base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1) + href.pathname) : base.pathname)) +
            (href.protocol || href.authority || href.pathname ? href.search : (href.search || base.search)) +
            href.hash;

          }

          var proxied = window.XMLHttpRequest.prototype.open;
          window.XMLHttpRequest.prototype.open = function() {
              if (arguments[1] !== null && arguments[1] !== undefined) {
                var url = arguments[1];
                url = rel2abs("' . $url . '", url);
                if (url.indexOf("' . PROXY_PREFIX . '") == -1) {
                  url = "' . PROXY_PREFIX . '" + url;
                }
                arguments[1] = url;
              }
              return proxied.apply(this, [].slice.call(arguments));
          };

        }

      })();');
		$scriptElem->setAttribute("type", "text/javascript");

		$prependElem->insertBefore($scriptElem, $prependElem->firstChild);
	}
	
	//I noticed Google results were ?url=https:/ and not ?url=https:// causing them to not function
	foreach ($doc->getElementsByTagName('a') as $link) {
	   $link->setAttribute('href', preg_replace(array('/https\:\/(?!\/)/', '/http\:\/(?!\/)/'), array('https://', 'http://'), $link->getAttribute('href')));
	}

	echo "<!-- Proxified page constructed by PocketProxy -->\n" . $doc->saveHTML($doc->documentElement);//Should fix my UTF-8 ecoding error https://stackoverflow.com/questions/8218230/php-domdocument-loadhtml-not-encoding-utf-8-correctly
}
//Trying to figure out why PHP exhausted 6383730688 bytes , trying to allocate more 2093393984 bytes.. Memory leak or big downloads, not sure, but trying to reduce processing in the meantime
#elseif (stripos($contentType, "text/css") !== false) {
	//This is CSS, so proxify url() references.
#	echo $proxy->proxifyCSS($responseBody, $url);
#	header("Content-Type: text/css");
#}
#elseif (stripos($contentType, "text/javascript") !== false) {
	//This is CSS, so proxify url() references.
#	header("Content-Length: " . strlen($responseBody) , true);
#	header("Content-Type: text/javascript");
#	echo $responseBody;
#}
elseif (stripos($contentType, "multipart/form-data") !== false) { 
//The problem here is that the boundary, something like
//boundary=----WebKitFormBoundaryyEmKNDsBKjB7QEqu
//never makes it into the Content-Type: header
//So remove the content-type and the browser will fill in the rest
	header("Content-Length: " . strlen($responseBody) , true);
	echo $responseBody;
}
else {
	//This isn't a web page or CSS, so serve unmodified through the proxy with the correct headers (images, JavaScript, etc.)
	header("Content-Length: " . strlen($responseBody) , true);
	header("Content-Type: " . $contentType); //not having this was causing a bunch of issues
	header('Content-Disposition: filename="'.basename(parse_url($url, PHP_URL_PATH).'"'));//Keep same filename when downloading from server, doesn't always work but is better
	echo $responseBody;
}

