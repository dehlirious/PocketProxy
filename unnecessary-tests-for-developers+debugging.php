<?php
//Comment this if you want to run the weird tests
die();

//Note: rel2abs + the javascript version  aren't included in this test file.

function runRel2AbsTests($tests) {
	foreach ($tests as $test) {
		$result = rel2abs($test["rel"], $test["base"]);
		if ($result === $test["expected"]) {
			echo "PASS: {$test['rel']} + {$test['base']} = $result\n";
		} else {
			echo "FAIL: Expected {$test['expected']}, got $result\n";
		}
	}
}

// Test cases
$tests = [
	["rel" => "page2.html", "base" => "http://www.example.com/page1.html", "expected" => "http://www.example.com/page2.html"],
	["rel" => "../page2.html", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/page2.html"],
	["rel" => "page2.html", "base" => "http://www.example.com/dir/", "expected" => "http://www.example.com/dir/page2.html"],
	["rel" => "/page2.html", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/page2.html"],
	["rel" => "", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/"],
	["rel" => "?query=1", "base" => "http://www.example.com/page1.html", "expected" => "http://www.example.com/page1.html?query=1"],
	["rel" => "#fragment", "base" => "http://www.example.com/page1.html", "expected" => "http://www.example.com/page1.html#fragment"],
	["rel" => "//cdn.example.com/lib.js", "base" => "http://www.example.com/page1.html", "expected" => "//cdn.example.com/lib.js"],
	["rel" => "https://cdn.example.com/lib.js", "base" => "http://www.example.com/page1.html", "expected" => "https://cdn.example.com/lib.js"],
	["rel" => "./page2.html", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/page2.html"],
	["rel" => "../dir2/page2.html", "base" => "http://www.example.com/dir1/dir/page1.html", "expected" => "http://www.example.com/dir1/dir2/page2.html"],
	["rel" => "/page2.html", "base" => "https://www.example.com:8080/dir/page1.html", "expected" => "https://www.example.com:8080/page2.html"],
	["rel" => "page2.html", "base" => "http://www.example.com/dir1/dir/", "expected" => "http://www.example.com/dir1/dir/page2.html"],
	["rel" => "page2.html?query=1", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/page2.html?query=1"],
	["rel" => "page2.html#fragment", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/page2.html#fragment"],
	// Testing with user info and port in base URL
	["rel" => "page2.html", "base" => "http://user:pass@www.example.com:8080/page1.html", "expected" => "http://user:pass@www.example.com:8080/page2.html"],
	// Base URL ends with a filename
	["rel" => "../page2.html", "base" => "http://www.example.com/dir1/page1.html", "expected" => "http://www.example.com/page2.html"],
	// Base URL ends with a slash
	["rel" => "../page2.html", "base" => "http://www.example.com/dir1/", "expected" => "http://www.example.com/page2.html"],
	
	
	// Complex relative path
	["rel" => "../../../page2.html", "base" => "http://www.example.com/dir1/dir2/dir3/dir4/", "expected" => "http://www.example.com/page2.html"],
	// Relative URL goes beyond the root directory
	["rel" => "../../../../../../page2.html", "base" => "http://www.example.com/dir1/dir2/", "expected" => "http://www.example.com/page2.html"],
	
	
	// Query strings and fragments in base URL
	["rel" => "page2.html", "base" => "http://www.example.com/page1.html?query=123", "expected" => "http://www.example.com/page2.html"],
	["rel" => "page2.html", "base" => "http://www.example.com/page1.html#anchor", "expected" => "http://www.example.com/page2.html"],
	// Relative URL with query string and fragment
	["rel" => "page2.html?query=123#anchor", "base" => "http://www.example.com/dir/", "expected" => "http://www.example.com/dir/page2.html?query=123#anchor"],
	// Testing with different schemes
	["rel" => "page2.html", "base" => "ftp://www.example.com/dir/", "expected" => "ftp://www.example.com/dir/page2.html"],
	
	// Testing with file scheme
	["rel" => "file2.txt", "base" => "file:///C:/dir1/file1.txt", "expected" => "file:///C:/dir1/file2.txt"],
	
	// Testing without trailing slash in directory
	["rel" => "page2.html", "base" => "http://www.example.com", "expected" => "http://www.example.com/page2.html"],
	// Testing protocol-relative URL with https base
	["rel" => "//cdn.example.com/lib.js", "base" => "https://www.example.com/page1.html", "expected" => "//cdn.example.com/lib.js"],
	// Testing base URL with subdomain
	["rel" => "page2.html", "base" => "http://sub.example.com/dir/", "expected" => "http://sub.example.com/dir/page2.html"],
	// Testing with IPv6 address in base URL
	["rel" => "page2.html", "base" => "http://[::1]/dir/", "expected" => "http://[::1]/dir/page2.html"],

	["rel" => "page2.html", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/page2.html"],


	["rel" => "page2.html?query=1", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/page2.html?query=1"],


	["rel" => "page2.html#fragment", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/page2.html#fragment"],


	["rel" => "http://www.otherdomain.com/page.html", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.otherdomain.com/page.html"],


	["rel" => "//www.otherdomain.com/page.html", "base" => "http://www.example.com/dir/page1.html", "expected" => "//www.otherdomain.com/page.html"],

	["rel" => "/rootfile.html", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/rootfile.html"],

	["rel" => "../updir/page3.html", "base" => "http://www.example.com/dir/subdir/page1.html", "expected" => "http://www.example.com/dir/updir/page3.html"],

	["rel" => "../../../updir/page2.html", "base" => "http://www.example.com/dir/subdir/another/page1.html", "expected" => "http://www.example.com/updir/page2.html"],

	["rel" => "../../../../updir/page2.html", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/updir/page2.html"],

	["rel" => "secure/page2.html", "base" => "https://www.example.com/dir/page1.html", "expected" => "https://www.example.com/dir/secure/page2.html"],


	["rel" => "secure/page2.html", "base" => "https://www.example.com:443/dir/page1.html", "expected" => "https://www.example.com/dir/secure/page2.html"],


	["rel" => "page2.html", "base" => "http://www.example.com:8080/dir/page1.html", "expected" => "http://www.example.com:8080/dir/page2.html"],


	["rel" => "", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/"],

	["rel" => "?newquery=1", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/page1.html?newquery=1"],

	["rel" => "#newfragment", "base" => "http://www.example.com/dir/page1.html", "expected" => "http://www.example.com/dir/page1.html#newfragment"],


	["rel" => "file2.txt", "base" => "ftp://ftp.example.com/dir1/file1.txt", "expected" => "ftp://ftp.example.com/dir1/file2.txt"],
	["rel" => "subdir/file2.txt", "base" => "ftp://ftp.example.com/dir1/file1.txt", "expected" => "ftp://ftp.example.com/dir1/subdir/file2.txt"],
	["rel" => "file2.txt", "base" => "ftp://ftp.example.com/dir1/", "expected" => "ftp://ftp.example.com/dir1/file2.txt"],
	["rel" => "/file2.txt", "base" => "ftp://ftp.example.com/dir1/", "expected" => "ftp://ftp.example.com/file2.txt"],
	["rel" => "ftp://ftp.example2.com/file2.txt", "base" => "ftp://ftp.example.com/dir1/", "expected" => "ftp://ftp.example2.com/file2.txt"],
];

runTests($tests);

?>

<script>
/* Run the tests on the javascript alternative, note: the function isn't included here, you must do that yourself*/

const tests = [
	{ rel: "page2.html", base: "http://www.example.com/page1.html", expected: "http://www.example.com/page2.html" },
	{ rel: "../page2.html", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/page2.html" },
	{ rel: "page2.html", base: "http://www.example.com/dir/", expected: "http://www.example.com/dir/page2.html" },
	{ rel: "/page2.html", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/page2.html" },
	{ rel: "", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/" },
	{ rel: "?query=1", base: "http://www.example.com/page1.html", expected: "http://www.example.com/page1.html?query=1" },
	{ rel: "#fragment", base: "http://www.example.com/page1.html", expected: "http://www.example.com/page1.html#fragment" },
	{ rel: "//cdn.example.com/lib.js", base: "http://www.example.com/page1.html", expected: "//cdn.example.com/lib.js" },
	{ rel: "https://cdn.example.com/lib.js", base: "http://www.example.com/page1.html", expected: "https://cdn.example.com/lib.js" },
	{ rel: "./page2.html", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/page2.html" },
	{ rel: "../dir2/page2.html", base: "http://www.example.com/dir1/dir/page1.html", expected: "http://www.example.com/dir1/dir2/page2.html" },
	{ rel: "/page2.html", base: "https://www.example.com:8080/dir/page1.html", expected: "https://www.example.com:8080/page2.html" },
	{ rel: "page2.html", base: "http://www.example.com/dir1/dir/", expected: "http://www.example.com/dir1/dir/page2.html" },
	{ rel: "page2.html?query=1", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/page2.html?query=1" },
	{ rel: "page2.html#fragment", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/page2.html#fragment" },
	{ rel: "http://www.otherdomain.com/page.html", base: "http://www.example.com/dir/page1.html", expected: "http://www.otherdomain.com/page.html" },
	{ rel: "//www.otherdomain.com/page.html", base: "http://www.example.com/dir/page1.html", expected: "//www.otherdomain.com/page.html" },
	{ rel: "/rootfile.html", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/rootfile.html" },
	{ rel: "../updir/page3.html", base: "http://www.example.com/dir/subdir/page1.html", expected: "http://www.example.com/dir/updir/page3.html" },
	{ rel: "../../../updir/page2.html", base: "http://www.example.com/dir/subdir/another/page1.html", expected: "http://www.example.com/updir/page2.html" },
	{ rel: "../../../../updir/page2.html", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/updir/page2.html" },
	{ rel: "secure/page2.html", base: "https://www.example.com/dir/page1.html", expected: "https://www.example.com/dir/secure/page2.html" },
	{ rel: "secure/page2.html", base: "https://www.example.com:443/dir/page1.html", expected: "https://www.example.com/dir/secure/page2.html" },
	{ rel: "page2.html", base: "http://www.example.com:8080/dir/page1.html", expected: "http://www.example.com:8080/dir/page2.html" },
	{ rel: "", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/" },
	{ rel: "?newquery=1", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/page1.html?newquery=1" },
	{ rel: "#newfragment", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/page1.html#newfragment" },
	{ rel: "../../../page2.html", base: "http://www.example.com/dir1/dir2/dir3/dir4/", expected: "http://www.example.com/page2.html" },
	{ rel: "../../../../../../page2.html", base: "http://www.example.com/dir1/dir2/", expected: "http://www.example.com/page2.html" },
	{ rel: "page2.html", base: "http://www.example.com/page1.html?query=123", expected: "http://www.example.com/page2.html" },
	{ rel: "page2.html", base: "http://www.example.com/page1.html#anchor", expected: "http://www.example.com/page2.html" },
	{ rel: "page2.html?query=123#anchor", base: "http://www.example.com/dir/", expected: "http://www.example.com/dir/page2.html?query=123#anchor" },
	{ rel: "page2.html", base: "ftp://www.example.com/dir/", expected: "ftp://www.example.com/dir/page2.html" },
	{ rel: "file2.txt", base: "file:///C:/dir1/file1.txt", expected: "file:///C:/dir1/file2.txt" },
	{ rel: "page2.html", base: "http://www.example.com", expected: "http://www.example.com/page2.html" },
	{ rel: "//cdn.example.com/lib.js", base: "https://www.example.com/page1.html", expected: "//cdn.example.com/lib.js" },
	{ rel: "page2.html", base: "http://sub.example.com/dir/", expected: "http://sub.example.com/dir/page2.html" },
	{ rel: "page2.html", base: "http://[::1]/dir/", expected: "http://[::1]/dir/page2.html" },
	{ rel: "page2.html", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/page2.html" },
	{ rel: "page2.html?query=1", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/page2.html?query=1" },
	{ rel: "page2.html#fragment", base: "http://www.example.com/dir/page1.html", expected: "http://www.example.com/dir/page2.html#fragment" },
	{ rel: "file2.txt", base: "ftp://ftp.example.com/dir1/file1.txt", expected: "ftp://ftp.example.com/dir1/file2.txt" },
	{ rel: "subdir/file2.txt", base: "ftp://ftp.example.com/dir1/file1.txt", expected: "ftp://ftp.example.com/dir1/subdir/file2.txt" },
	{ rel: "file2.txt", base: "ftp://ftp.example.com/dir1/", expected: "ftp://ftp.example.com/dir1/file2.txt" },
	{ rel: "/file2.txt", base: "ftp://ftp.example.com/dir1/", expected: "ftp://ftp.example.com/file2.txt" },
	{ rel: "ftp://ftp.example2.com/file2.txt", base: "ftp://ftp.example.com/dir1/", expected: "ftp://ftp.example2.com/file2.txt" },
];


// Run tests
tests.forEach(test => {
	const result = rel2abs(test.rel, test.base);
	if (result === test.expected) {
		//console.log(`PASS: ${test.rel} + ${test.base} = ${result}`);
	} else {
		console.log(`FAIL: Expected ${test.expected}, got ${result}`);
	}
});
</script>


<?php

//Test proxifyCSS

// Base URL for testing relative URLs
$baseURL = 'http://example.com/';

// Test cases
$testCases = [
	// Simple URL
	"body { background-image: url('image.jpg'); }",
	// URL with spaces
	"div { background: url('image with spaces.jpg'); }",
	"div { background: url('image with spa:\"ces.jpg'); }",
	// URL with special characters
	"div::before { content: url(\"special&char*acters?.jpg\"); }",
	"div::before { content: url(\"specia'l&char*acters?.jpg\"); }",
	// HTTPS URL
	"footer { background-image: url(https://example.com/image.jpg); }",
	// Data URL
	"p { cursor: url('data:image/png;base64,...'), auto; }",
	"p { cursor: 'data:image/png;base64,...', auto; }",
	"p { cursor: \"data:image/png;base64,...\", auto; }",
	// @import rules
	"@import url('style.css');",
	"@import 'another-style.css';",
	// @font-face rule
	"@font-face { font-family: 'MyFont'; src: url('fonts/MyFont.woff2') format('woff2'); }",
	// Complex case with multiple URLs
	"div { background-image: url(image.jpg); }\n@import url('style.css');\np { cursor: url(data:image/png;base64,...), auto; }",
	// Edge cases: empty url, missing quotes
	"a { background: url(); }",
	"a { background: url(''); }",
	"a { background: url(\"\"); }",
	"a { background: url(unquoted.jpg); }",
	"
@import url('child1.css');
@import 'child1.css';

@import url('child2.css');
@import 'child2.css';

@import url(\"child3.css\");
@import \"child3.css\";

@import url('child4.css');
@import 'child4.css';


"
];

// Run tests
foreach ($testCases as $testCase) {
	//echo "Original CSS:\n$testCase\n\n";
	$proxifiedCSS = proxifyCSS($testCase, $baseURL);
	if ($testCase == $proxifiedCSS) {
		echo 'FUCK FUCK' . $proxifiedCSS;
	}
}

// After all tests, echo proxified CSS
foreach ($testCases as $testCase) {
	$proxifiedCSS = proxifyCSS($testCase, $baseURL);
	echo "Proxified CSS:\n$proxifiedCSS\n";
	echo "--------------------------------\n";
}


//Test proxifySrcset

$testCases = [
	[
		'srcset' => 'photos/pic1.jpg 1x, photos/pic1@2x.jpg 2x, photos/pic1@3x.jpg 3x',
		'baseURL' => 'http://example.com/',
		'expectedResult' => 'http://proxy.example.com/photos/pic1.jpg 1x, http://proxy.example.com/photos/pic1@2x.jpg 2x, http://proxy.example.com/photos/pic1@3x.jpg 3x'
	],
	[
		'srcset' => 'gallery/picture2.jpg 1x, gallery/picture2@2x.jpg 2x, gallery/picture2@3x.jpg 3x',
		'baseURL' => 'http://sub.example.com/path/',
		'expectedResult' => 'http://proxy.example.com/path/gallery/picture2.jpg 1x, http://proxy.example.com/path/gallery/picture2@2x.jpg 2x, http://proxy.example.com/path/gallery/picture2@3x.jpg 3x'
	],
	[
		'srcset' => 'assets/img3.jpg 1x, assets/img3@2x.jpg 2x, assets/img3@3x.jpg 3x',
		'baseURL' => 'https://example.net/',
		'expectedResult' => 'http://proxy.example.com/assets/img3.jpg 1x, http://proxy.example.com/assets/img3@2x.jpg 2x, http://proxy.example.com/assets/img3@3x.jpg 3x'
	],
	[
		'srcset' => 'pictures/photo_4.jpg 1x, pictures/photo_4@2x.jpg 2x, pictures/photo_4@3x.jpg 3x',
		'baseURL' => 'http://subdomain.example.net/path2/',
		'expectedResult' => 'http://proxy.example.com/path2/pictures/photo_4.jpg 1x, http://proxy.example.com/path2/pictures/photo_4@2x.jpg 2x, http://proxy.example.com/path2/pictures/photo_4@3x.jpg 3x'
	],
	[
		'srcset' => 'images/img5.jpg 1x, images/img5@2x.jpg 2x, images/img5@3x.jpg 3x',
		'baseURL' => 'http://sub2.example.org/',
		'expectedResult' => 'http://proxy.example.com/images/img5.jpg 1x, http://proxy.example.com/images/img5@2x.jpg 2x, http://proxy.example.com/images/img5@3x.jpg 3x'
	],
	[
		'srcset' => 'pictures/image6.jpg 1x, pictures/image6@2x.jpg 2x, pictures/image6@3x.jpg 3x',
		'baseURL' => 'http://example.org/',
		'expectedResult' => 'http://proxy.example.com/pictures/image6.jpg 1x, http://proxy.example.com/pictures/image6@2x.jpg 2x, http://proxy.example.com/pictures/image6@3x.jpg 3x'
	],
	[
		'srcset' => 'photos/pic7.jpg 1x, photos/pic7@2x.jpg 2x, photos/pic7@3x.jpg 3x',
		'baseURL' => 'https://subdomain.example.org/path3/',
		'expectedResult' => 'http://proxy.example.com/path3/photos/pic7.jpg 1x, http://proxy.example.com/path3/photos/pic7@2x.jpg 2x, http://proxy.example.com/path3/photos/pic7@3x.jpg 3x'
	],
	[
		'srcset' => 'images/picture8.jpg 1x, images/picture8@2x.jpg 2x, images/picture8@3x.jpg 3x',
		'baseURL' => 'http://example.net/',
		'expectedResult' => 'http://proxy.example.com/images/picture8.jpg 1x, http://proxy.example.com/images/picture8@2x.jpg 2x, http://proxy.example.com/images/picture8@3x.jpg 3x'
	],
	[
		'srcset' => 'photos/img9.jpg 1x, photos/img9@2x.jpg 2x, photos/img9@3x.jpg 3x',
		'baseURL' => 'https://sub.example.net/',
		'expectedResult' => 'http://proxy.example.com/photos/img9.jpg 1x, http://proxy.example.com/photos/img9@2x.jpg 2x, http://proxy.example.com/photos/img9@3x.jpg 3x'
	],
	[
		'srcset' => 'pictures/pic10.jpg 1x, pictures/pic10@2x.jpg 2x, pictures/pic10@3x.jpg 3x',
		'baseURL' => 'http://sub.example.net/path4/',
		'expectedResult' => 'http://proxy.example.com/path4/pictures/pic10.jpg 1x, http://proxy.example.com/path4/pictures/pic10@2x.jpg 2x, http://proxy.example.com/path4/pictures/pic10@3x.jpg 3x'
	],
	// Add more unique test cases here...
];
// Test the proxifySrcset function for each test case
foreach ($testCases as $index => $testCase) {
	$srcset = $testCase['srcset'];
	$baseURL = $testCase['baseURL'];
	$expectedResult = PROXY_PREFIX . $testCase['expectedResult'];

	// Call the proxifySrcset function
	$proxifiedSrcset = proxifySrcset($srcset, $baseURL);

	// Output the original and proxified srcset attributes for comparison
	//echo "Test Case $index:" . PHP_EOL;
	echo "Original srcset: $srcset" . PHP_EOL;
   // echo "Base URL: $baseURL" . PHP_EOL;
	echo "Expected result: $expectedResult" . PHP_EOL;
	echo "Actual result:   $proxifiedSrcset" . PHP_EOL;
	echo "Test Result: " . (($proxifiedSrcset === $expectedResult) ? "Pass" : "Fail") . PHP_EOL;
	echo PHP_EOL;
}
