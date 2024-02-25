# PocketProxy

<p align="center">
    <a href="https://badgen.net/github/commits/dehlirious/PocketProxy">
        <img src="https://badgen.net/github/commits/dehlirious/PocketProxy" alt="GitHub commits" />
    </a>
    <a href="https://GitHub.com/dehlirious/PocketProxy/stargazers/">
        <img src="https://badgen.net/github/stars/dehlirious/PocketProxy" alt="GitHub stars" />
    </a>
    <a href="https://GitHub.com/dehlirious/PocketProxy/network/">
        <img src="https://badgen.net/github/forks/dehlirious/PocketProxy/" alt="GitHub forks" />
    </a>
    <a href="https://GitHub.com/dehlirious/PocketProxy/watchers/">
        <img src="https://badgen.net/github/watchers/dehlirious/PocketProxy/" alt="GitHub watchers" />
    </a>
    <a href="https://GitHub.com/dehlirious/PocketProxy/pull/">
        <img src="https://badgen.net/github/prs/dehlirious/PocketProxy" alt="GitHub total pull requests" />
    </a>
    <a href="https://github.com/dehlirious/PocketProxy/issues">
        <img src="https://img.shields.io/github/issues/dehlirious/PocketProxy" alt="GitHub issues" />
    </a>
    <a href="http://isitmaintained.com/project/dehlirious/PocketProxy">
        <img src="http://isitmaintained.com/badge/open/dehlirious/PocketProxy.svg" alt="Percentage of issues still open" />
    </a>
    <a href="https://github.com/dehlirious/PocketProxy/contributors">
        <img src="https://badgen.net/github/contributors/dehlirious/PocketProxy" alt="GitHub contributors" />
    </a>
    <br/>
    <!-- Support -->
    <a href="https://buymeacoffee.com/devsir">
        <img src="https://badgen.net/badge/icon/buymeacoffee?icon=buymeacoffee&label" alt="Buymeacoffee" />
    </a>
</p>

PocketProxy is an advanced PHP web proxy designed for easy bypassing of internet content filters, boosting online privacy, and anonymous browsing, catering specifically to users in need of a simple yet powerful online experience.

Experience PocketProxy in action: [https://zrr.us/pocketproxy.php](https://zrr.us/pocketproxy.php)

## Acknowledgements

PocketProxy builds upon the groundwork established by Joshua Dick with [miniProxy](https://github.com/joshdick/miniProxy). After the original project was discontinued, I took it upon myself to not only maintain its presence but also enhance its functionalities, aligning it with the evolving requirements of users and myself. Additionally, significant modifications have been implemented to augment anonymity, security, and privacy for our users, ensuring a safer and more confidential browsing experience.

## About PocketProxy

PocketProxy facilitates advanced capabilities for anonymous web browsing and bypassing content filters. It is crafted with PHP, harnessing the power of simplicity to ensure a seamless user experience, whether you opt to utilize it or host it yourself. 

While PocketProxy aims to provide anonymity, it's essential to acknowledge that no web proxy can ensure absolute privacy, particularly when attempting to browse the web anonymously with JavaScript enabled.

## Prerequisites

 - PocketProxy should be able to run on any web server with PHP 5.4.7 or later. *untested 
 - PocketProxy requires PHP's `curl`, `mbstring` and `xml` extensions to be installed alongside the optional `gd` extension for captcha usage.

## Installation and Use

Simply copy `pocketproxy.php` to your web server and access it directly. That's it! You'll be presented with further usage instructions.

PocketProxy doesn't require any configuration out of the box, but configuration options are available; see the top of `pocketproxy.php` for details.

## Known Limitations

PocketProxy has several known limitations. Some of them may be fixed in future releases. For now, they include:

* YouTube does not work (try [youtubeunblocked.live](youtubeunblocked.live))
* Many MANY websites can display broken qualities when they are javascript dependant.
* WebSocket connections are not supported yet
* Service Workers (all types) are disabled / not supported
* Maybe more! Let me know!

## Network Interceptions and Disabled Features

Unfortunately, JavaScript poses significant challenges. While I intercept and rewrite numerous URLs, there are still gaps to address. 
Here are several methods I intercept and overwrite to ensure that network requests are routed through the proxy script instead of directly to the original website:

<details>
  <summary>Click to reveal spoiler</summary>

| Method | Description | Method | Description |
| ------ | ----------- | ------ | ----------- |
| document.createElement + Element.prototype.setAttribute | Alter URL attributes for new elements. `var potentialUrlAttributes = ["src", "rel", "href", "data-src", "data-href", "action", "srcset", "poster", "hreflang", "cite", "data-url", "data-link", "data-file", "data-image", "data-video", "data-audio", "data-source", "formaction"];` | "modifyInlineScripts()" | Modifies script src attributes, inline scripts, and URLs. |
| XMLHttpRequest | Ensure all URLs are prefixed with the proxyPrefix | Fetch | Ensure all URLs are prefixed with the proxyPrefix |
| WebSocket | Not yet supported via PocketProxy but the URL is rewritten anyway. | Form submissions | Handled via php typically but covered regardless. |
| window.open | Ensure all URLs are prefixed with the proxyPrefix | X | X |
| document.write and writeln | Search for and modify URLs in content. | $.ajax | Ensure all URLs are prefixed with the proxyPrefix |
| window.axios | Ensure all URLs are prefixed with the proxyPrefix | Modifications to existing stylesheets | Replace any url() calls in `document.styleSheets` and intercept inline styles. |
| window.Image | Ensure all URLs are prefixed with the proxyPrefix | window.fetch | Ensure all URLs are prefixed with the proxyPrefix |
| window.Request | Ensure all URLs are prefixed with the proxyPrefix | Navigation methods | 'replace' and 'assign' |
| document.execCommand | ["createlink", "insertimage"] | meta refresh | Ensure all URLs are prefixed with the proxyPrefix |
| anchor pings | Ensure all URLs are prefixed with the proxyPrefix | window.ActiveXObject.open | Ensure all URLs are prefixed with the proxyPrefix |
| document.cookie | Rewritten so that cookies are functional. | window.importScripts |  |
| window.XDomainRequest | Ensure all URLs are prefixed with the proxyPrefix | And More! | This readme.md is not consistently updated, this list *should* forever be growing |

**Disabled Javascript objects:**
This column lists specific JavaScript global objects, APIs, or functionalities that have been intentionally disabled or restricted.
These items typically offer various capabilities or access to system resources and information, which, for security, privacy, or performance reasons have been disabled.

| Disabled Feature | Description | Disabled Feature | Description |
| ---------------- | ----------- | ---------------- | ----------- |
| window.webkitStorageInfo |  | document.webkitVisibilityState |  |
| document.webkitHidden |  | window.webkitDirectory |  |
| window.webkitIntent |  | document.referrer |  |
| window.performance |  |   |  |
|   |   | And More! | This readme.md is not consistently updated, this list *should* forever be growing |


**Disabled Javascript Objects/Prototypes:**
This column details the prototypes associated with certain JavaScript objects that have been disabled. In JavaScript, the prototype is a mechanism through which objects inherit features from one another. By disabling specific prototypes, the ability for objects to inherit properties or methods from these prototypes is removed or altered.

| Disabled Object | Description | Disabled Prototype | Description |
| --------------- | ----------- | ------------------ | ----------- |
| navigator | Excludes 'plugins', 'storage', 'serviceWorker', 'webdriver', 'clipboard', 'language', 'languages', 'credentials'. | Worker.prototype | Methods and properties specific to Worker instances. |
| Worker | Global scope for web workers. | MediaDevices.prototype | Methods and properties specific to MediaDevices instances. |
| MediaRecorder | Global scope for media recording functionality. | MediaRecorder.prototype | Methods and properties specific to MediaRecorder instances. |
| history | Global scope for history API. | History.prototype | Methods and properties specific to History instances. |


**Future Thoughts for modification/removal:**

- WebRTC
- WebGL
- OffscreenCanvas 


</details>


## Contribute

Your contributions are welcome! Whether it's reporting bugs, suggesting features, or contributing to the code, your input helps make PocketProxy better for everyone.

