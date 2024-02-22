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

PocketProxy is a straightforward PHP web proxy tailored for individuals seeking an uncomplicated method to bypass internet content filters, enhance online privacy, or browse the internet anonymously.

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
* WebSocket connections are not enabled as of yet
* Probably more, but as I come across limitations I tend to forget them before writing them down

## Contribute

Your contributions are welcome! Whether it's reporting bugs, suggesting features, or contributing to the code, your input helps make PocketProxy better for everyone.

