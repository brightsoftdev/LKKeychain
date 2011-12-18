# About LKKeychain #

_Are you frustrated by the Mac OS X Keychain API?_

_Do you ever wish it was a little less inconvenient? Less inconsistent? Less Carbon?_

_Are you dreaming of a Cocoa Keychain?_

_**You can now `git clone` your dreams!**_

LKKeychain is a full-featured Objective-C wrapper for Mac OS X's Keychain API and some related subsystems in the Security Framework.

It supports listing, finding, creating, modifying and deleting all kinds of keychain items, including generic passwords, internet passwords, certificates, and public, private and symmetric keys. It'll soon be able sign, encrypt and decrypt data, verify signatures, validate certificates, and whatever else strikes my fancy while perusing the [Security Framework Reference](http://developer.apple.com/library/mac/#documentation/Security/Reference/SecurityFrameworkReference/_index.html).

I'm rapidly adding new functionality, but I don't think LKKeychain is ready for production use yet.

LKKeychain currently requires Mac OS 10.7 Lion; I have vague plans to add (possibly limited) support for 10.6.
An iOS port is also possible, if there is any interest. ([Tell me about it.](mailto:karoly@lorentey.hu))

# Documentation #

The [LKKeychain Reference](http://lorentey.github.com/LKKeychain/reference) is available online.
To integrate it into Xcode, simply add the following feed URL in the Downloads tab of the Documentation
section of Xcode's Preferences:

    http://lorentey.github.com/LKKeychain/downloads/hu.lorentey.LKKeychain.atom

This adds the LKKeychain API docs right into your Organizer window, Quick Help panel and Option-click
popups.

# Installation #

Prebuilt binaries aren't available yet, so for now you have to clone the LKKeychain repository and
build them yourself. The single Xcode project file has targets for both a dynamic framework and a 
static library. Use whichever you prefer.

The [LKKeychain Reference](http://lorentey.github.com/LKKeychain/reference) is produced by 
the excellent [appledoc](https://github.com/tomaz/appledoc) tool. You can build the docs yourself
using the Documentation target in `LKKeychain.xcodeproj`. 
Building this target will automatically integrate the resulting docset into your Xcode installation.

# License #

LKKeychain is licensed with the three-clause BSD license. In plain language: you're allowed to do
whatever you wish with the code, modify, redistribute, embed in your products (free or commercial), 
but you must include copyright, terms of usage and disclaimer as stated in the license, the same way
as any other BSD licensed code.

If for whatever reason you cannot agree to these terms, please [contact me](mailto:karoly@lorentey.hu),
and I'll do my best to find a solution for you.

Copyright © 2011, Károly Lőrentey. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

* Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following
  disclaimer in the documentation and/or other materials provided
  with the distribution.
* Neither the name of Károly Lőrentey nor the names of its
  contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL KÁROLY LŐRENTEY BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
