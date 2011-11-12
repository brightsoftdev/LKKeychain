# LKKeychain #

LKKeychain is a full-featured Objective-C wrapper for Mac OS X's Keychain API and some related subsystems in the Security Framework.
It requires Mac OS 10.6 Snow Leopard but it works even better on 10.7 Lion.

It supports listing, finding, adding, modifying and deleting generic passwords, internet passwords, certificates, public, private and symmetric keys.

I'm rapidly adding new functionality, but LKKeychain is not yet intended for production use.

## Generic Passwords ##

You can create a new generic password by calling the class method `+[LKKCGenericPassword createPassword:service:account:]`. 
It returns a floating password item that isn't on a keychain yet. The password's attributes (such as its label and comment)
are accessible as simple read-write properties. Once you've set up the attributes you want, call 
`-[LKKCKeychainItem addToKeychain:withError:]` to add the item to a keychain.

    LKKCGenericPassword *password = [LKKCGenericPassword createPassword:@"secretPassword" 
                                                                service:[[NSBundle mainBundle] bundleIdentifier]
                                                                account:@"sample account"];
    password.label = [NSString stringWithFormat:@"%@ (%@)", password.service, password.account];
    
    BOOL result = [password addToKeychain:[LKKCKeychain defaultKeychain] withError:NULL];
    if (!result) {
        // Oops
    }

`LKKCKeychain` instances have methods for retrieving passwords stored on a particular keychain.

    LKKCKeychain *keychain = [LKKCKeychain defaultKeychain];
    LKKCGenericPassword *password = [keychain genericPasswordWithService:[[NSBundle mainBundle] bundleIdentifier] 
                                                                 account:@"sample account"];
    NSLog(@"Password: %@", password.password);

To modify an existing password, simply assign new values to its properties and save the changes using `-[LKKCKeychainItem saveItemWithError:]`.

    password.password = @"NewP4ssword";
    password.comment = @"This is a comment for the sample account password.";
    
    result = [password saveItemWithError:NULL];
    if (!result) {
        // Oops
    }
    
To delete a password, just call `-[LKKCKeychainItem deleteItemWithError:]`.

    result = [password deleteItemWithError:NULL];
    if (!result) {
        // Oops
    }
    
## Internet Passwords ##

Internet passwords associate a password with a URL (extended by an optional authentication type and security domain string).
The URL is not stored directly on the keychain; it is instead split up into its components (protocol, account, server, port, and path),
each of which is stored separately in its own attribute. `LKKCInternetPassword` has a separate readwrite property for
all of these components, but it also provides a `url` shortcut property that converts to/from simple `NSURL` instances.

    LKKCInternetPassword *item = [LKKCInternetPassword createPassword];
    item.url = [NSURL urlWithString:@"http://username@example.com:8080/admin/login.php"];
    item.authenticationType = LKKCAuthenticationTypeHTMLBasic;
    item.securityDomain = @"Administration Interface";
    item.password = @"bananas";
    
    result = [item addToKeychain:[LKKCKeychain defaultKeychain] withError:NULL];
    if (!result) {
        // Oops
    }
    
To retrieve a password for a URL, iterate over all passwords with the same server, and find the one that's the best match.

    for (LKKCInternetPassword *item in [[LKKCKeychain defaultKeychain] internetPasswordsForServer:@"example.com"]) {
        if (item.authenticationType == LKKCAuthenticationTypeHTMLBasic
            && [item.securityDomain isEqualToString:@"Administration Interface"]) {
            return item.password;
        }
    }

## Certificates ##

To be done. You'll be able to validate certificates using LKKeychain.

## Public and private keys ##

To be done. You'll be able to use an assymetric `LKKCKey` to encrypt/decrypt data, and to create/verify signatures.

## Identities ##

To be done. You'll be able to encrypt/decrypt data, and to create/verify signatures.

## Symmetric keys ##

To be done. You'll be able to use a symmetric `LKKCKey` to encrypt or decrypt data.
