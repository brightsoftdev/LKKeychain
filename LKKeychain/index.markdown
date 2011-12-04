LKKeychain is a full-featured Objective-C wrapper for Mac OS X's Keychain API and some related subsystems in the Security Framework.

It supports listing, finding, creating, modifying and deleting all kinds of keychain items, including generic passwords, internet passwords, certificates, and public, private and symmetric keys. It'll soon be able sign, encrypt and decrypt data, verify signatures, validate certificates, and whatever else strikes my fancy while perusing the [Security Framework Reference](http://developer.apple.com/library/mac/#documentation/Security/Reference/SecurityFrameworkReference/_index.html).

I'm rapidly adding new functionality, but I don't think LKKeychain is ready for production use yet.

LKKeychain currently requires Mac OS 10.7 Lion; I have vague plans to add (possibly limited) support for 10.6.
An iOS port is also possible, if there is any interest. ([Tell me about it.](mailto:karoly@lorentey.hu))
